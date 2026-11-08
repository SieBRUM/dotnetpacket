using DotNetPacket.Protocols.Ldap;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class RbcdTests
{
    private const string TestSid = "S-1-5-21-1111111111-2222222222-3333333333-1105";

    private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

    // rbcd.create_empty_sd(): Control 0x8004, owner BUILTIN\Administrators, empty DACL.
    private static NtSecurityDescriptor EmptySd() => new()
    {
        Control = 0x8004,
        OwnerSid = LdapSid.FromCanonical("S-1-5-32-544"),
        Dacl = new NtAcl(),
    };

    // rbcd.create_allow_ace(sid): ACCESS_ALLOWED_ACE, mask 983551 (0xF01FF), the delegate-from SID.
    private static NtAce AllowAce(string sid) => new()
    {
        AceType = NtAce.AccessAllowed,
        Mask = 983551,
        Sid = LdapSid.FromCanonical(sid),
    };

    [Fact]
    public void EmptySd_MatchesImpacketBytes()
    {
        Assert.Equal(
            "010004801c000000000000000000000014000000040008000000000001020000000000052000000020020000",
            Hex(EmptySd().GetData()));
    }

    [Fact]
    public void EmptySd_PlusAllowAce_MatchesImpacketWriteBytes()
    {
        NtSecurityDescriptor sd = EmptySd();
        sd.Dacl!.Aces.Add(AllowAce(TestSid));
        Assert.Equal(
            "010004804000000000000000000000001400000004002c000100000000002400ff010f00010500000000000515000000c7353a428e6b748455a1aec65104000001020000000000052000000020020000",
            Hex(sd.GetData()));
    }

    [Fact]
    public void ParseWriteSd_RoundTripsOwnerAndAce()
    {
        const string writeSd =
            "010004804000000000000000000000001400000004002c000100000000002400ff010f00010500000000000515000000c7353a428e6b748455a1aec65104000001020000000000052000000020020000";
        NtSecurityDescriptor sd = NtSecurityDescriptor.Parse(Convert.FromHexString(writeSd));

        Assert.Equal("S-1-5-32-544", LdapSid.ToCanonical(sd.OwnerSid));
        Assert.Single(sd.Dacl!.Aces);
        Assert.Equal(TestSid, LdapSid.ToCanonical(sd.Dacl.Aces[0].Sid));
        Assert.Equal(983551u, sd.Dacl.Aces[0].Mask);
        Assert.Equal(writeSd, Hex(sd.GetData())); // re-serialize is identity
    }
}
