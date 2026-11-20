using DotNetPacket.Examples;
using Xunit;

namespace DotNetPacket.Core.Tests;

/// <summary>
/// Credential target-string parsing (<see cref="Creds"/>). The expected (domain, user, password, host)
/// values are the byte-for-byte output of impacket's <c>parse_target</c> for the same inputs
/// (scratchpad comparison), so this pins full parity — including passwords that contain <c>@</c>,
/// <c>:</c> and <c>/</c> (the host separator is the LAST <c>@</c>, via impacket's @-in-password fixup).
/// </summary>
public class CredsTests
{
    [Theory]
    // target                                        domain       user            password        host         hasPassword
    [InlineData("LAB/Administrator:LabAdm1n!Pass@127.0.0.1", "LAB", "Administrator", "LabAdm1n!Pass", "127.0.0.1", true)]
    [InlineData("Administrator:LabAdm1n!Pass@127.0.0.1", "", "Administrator", "LabAdm1n!Pass", "127.0.0.1", true)]
    [InlineData("Administrator@127.0.0.1", "", "Administrator", "", "127.0.0.1", false)]
    [InlineData("lab.local/alice@dc01", "lab.local", "alice", "", "dc01", false)]
    [InlineData("lab.local/alice:p@ss@dc01", "lab.local", "alice", "p@ss", "dc01", true)]      // @ in password
    [InlineData("lab.local/alice:pa/ss@dc01", "lab.local", "alice", "pa/ss", "dc01", true)]    // / in password
    [InlineData("lab.local/alice:pa:ss@dc01", "lab.local", "alice", "pa:ss", "dc01", true)]    // : in password
    [InlineData("alice:@dc01", "", "alice", "", "dc01", true)]                                 // explicit empty password
    [InlineData("lab.local/:secret@dc01", "lab.local", "", "secret", "dc01", true)]            // empty user
    [InlineData("127.0.0.1", "", "", "", "127.0.0.1", false)]                                  // bare host, no creds
    [InlineData("lab.local/alice:P@ss:w/rd!@dc01", "lab.local", "alice", "P@ss:w/rd!", "dc01", true)] // all specials
    public void ParseTarget_MatchesImpacket(
        string target, string domain, string user, string password, string host, bool hasPassword)
    {
        (string d, string u, string p, string h, bool hp) = Creds.ParseTarget(target);
        Assert.Equal(domain, d);
        Assert.Equal(user, u);
        Assert.Equal(password, p);
        Assert.Equal(host, h);
        Assert.Equal(hasPassword, hp);
    }

    [Fact]
    public void Resolve_PasswordInTarget_IsUsed()
    {
        Creds c = Creds.Resolve(new[] { "cmd", "LAB/alice:p@ss:w/rd@host" }, 1, "usage");
        Assert.Equal("host", c.Host);
        Assert.Equal("alice", c.User);
        Assert.Equal("LAB", c.Domain);
        Assert.Equal("p@ss:w/rd", c.Password);
        Assert.Equal(2, c.NextIndex);
    }

    [Fact]
    public void Resolve_ExplicitEmptyPassword_IsEmptyNotNull()
    {
        Creds c = Creds.Resolve(new[] { "cmd", "alice:@host" }, 1, "usage");
        Assert.Equal(string.Empty, c.Password); // authenticate with an empty password
    }

    [Fact]
    public void Resolve_NoPasswordAndNoOverride_Throws()
    {
        // alice@host (no colon) with no -hashes/-k/-no-pass: a no-prompt CLI must refuse rather than
        // silently try an empty password.
        Assert.Throws<CredsUsageException>(() =>
            Creds.Resolve(new[] { "cmd", "alice@host" }, 1, "usage"));
    }

    [Fact]
    public void Resolve_NoPasswordButOverrideActive_PasswordIsNull()
    {
        GlobalOptions.NoPass = true;
        try
        {
            Creds c = Creds.Resolve(new[] { "cmd", "alice@host" }, 1, "usage");
            Assert.Null(c.Password);
            Assert.Equal("alice", c.User);
            Assert.Equal("host", c.Host);
        }
        finally
        {
            GlobalOptions.NoPass = false;
        }
    }

    [Fact]
    public void Resolve_BareHost_Throws()
    {
        Assert.Throws<CredsUsageException>(() =>
            Creds.Resolve(new[] { "cmd", "127.0.0.1" }, 1, "usage"));
    }

    [Fact]
    public void Resolve_EmptyUserAllowed_ForAnonymous()
    {
        // get-npusers roast-one mode: lab.local/@host with no user is permitted.
        Creds c = Creds.Resolve(new[] { "cmd", "lab.local/@host" }, 1, "usage", allowEmptyUser: true);
        Assert.Equal(string.Empty, c.User);
        Assert.Equal("lab.local", c.Domain);
        Assert.Equal("host", c.Host);
    }
}
