using DotNetPacket.Protocols.Ldap;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class LdapSecurityTests
{
    private const string Sid = "S-1-5-21-111-222-333-1105";
    private const string SidHex = "0105000000000005150000006f000000de0000004d01000051040000";

    [Fact]
    public void LdapSid_RoundTrips_AndMatchesImpacket()
    {
        Assert.Equal(SidHex, Convert.ToHexString(LdapSid.FromCanonical(Sid)).ToLowerInvariant());
        Assert.Equal(Sid, LdapSid.ToCanonical(LdapSid.FromCanonical(Sid)));
        Assert.Equal("S-1-5-32-544", LdapSid.ToCanonical(LdapSid.FromCanonical("S-1-5-32-544")));
    }

    // The msDS-GroupMSAMembership / nTSecurityDescriptor badsuccessor builds — byte-for-byte equal
    // to impacket's ldaptypes build for the same SID (DACL-first self-relative layout, Control 0x8004,
    // two ACCESS_ALLOWED ACEs: 0x000F01FF and GenericAll 0x10000000).
    private const string GroupMsaSd =
        "0100048064000000000000000000000014000000040050000200000000002400ff010f0001050000000000" +
        "05150000006f000000de0000004d0100005104000000002400000000100105000000000005150000006f00" +
        "0000de0000004d010000510400000105000000000005150000006f000000de0000004d01000051040000";

    [Fact]
    public void BuildGroupMsaMembership_MatchesImpacket()
    {
        Assert.Equal(GroupMsaSd,
            Convert.ToHexString(LdapSecurityDescriptor.BuildGroupMsaMembership(Sid)).ToLowerInvariant());
    }

    [Fact]
    public void ParseSecurityDescriptor_ExtractsOwnerAndDaclAces()
    {
        LdapSecurityDescriptor sd = LdapSecurityDescriptor.Parse(Convert.FromHexString(GroupMsaSd));

        Assert.Equal(Sid, sd.OwnerSid);
        Assert.Equal(2, sd.DaclAces.Count);
        Assert.All(sd.DaclAces, a => Assert.Equal(LdapSecurityDescriptor.AccessAllowedAceType, a.AceType));
        Assert.All(sd.DaclAces, a => Assert.Equal(Sid, a.Sid));
        Assert.Equal(0x000F01FFu, sd.DaclAces[0].Mask);
        Assert.Equal(0x10000000u, sd.DaclAces[1].Mask);
        Assert.Null(sd.DaclAces[0].ObjectType); // plain ACCESS_ALLOWED (no object GUID)
    }
}
