using DotNetPacket.Examples;
using Xunit;

namespace DotNetPacket.Core.Tests;

/// <summary>
/// Parsing of the impacket-style global flags (<see cref="GlobalOptions"/>). The TLS transport itself is
/// validated live against the lab DC (as the other on-the-wire paths are); these pin the flag handling
/// and that recognised options are stripped from the argument array the commands then parse.
/// </summary>
public class GlobalOptionsTests
{
    [Fact]
    public void Ldaps_Flag_SetsUseLdapsAndIsStripped()
    {
        GlobalOptions.UseLdaps = false;
        try
        {
            string[] rest = GlobalOptions.Apply(new[] { "get-adusers", "lab.local/a:b@host", "-ldaps", "all" });

            Assert.True(GlobalOptions.UseLdaps);
            Assert.Equal(new[] { "get-adusers", "lab.local/a:b@host", "all" }, rest);  // -ldaps removed
        }
        finally
        {
            GlobalOptions.UseLdaps = false;
        }
    }

    [Fact]
    public void NoLdapsFlag_LeavesUseLdapsFalse()
    {
        GlobalOptions.UseLdaps = false;
        string[] rest = GlobalOptions.Apply(new[] { "get-adusers", "lab.local/a:b@host" });

        Assert.False(GlobalOptions.UseLdaps);
        Assert.Equal(new[] { "get-adusers", "lab.local/a:b@host" }, rest);
    }
}
