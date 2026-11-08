using DotNetPacket.Protocols.Ldap;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class OwnereditTests
{
    // An OWNER-only security descriptor as a DC returns it under the SD-flags control sdflags=0x01
    // (Control 0x8001, OffsetOwner=20, group/sacl/dacl absent). Owner = Domain Admins (…-512).
    private const string OwnerOnlySd =
        "010001801400000000000000000000000000000001050000000000051500000085c2e0c4ea6e4421377b88db00020000";

    // The same SD after owneredit sets a new OwnerSid (…-1105), re-serialized by impacket getData().
    private const string WriteSd =
        "0100018014000000000000000000000000000000010500000000000515000000c7353a428e6b748455a1aec651040000";

    private const string NewOwner = "S-1-5-21-1111111111-2222222222-3333333333-1105";

    private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

    [Fact]
    public void ParseOwnerOnlySd_ReadsOwnerAndControl()
    {
        NtSecurityDescriptor sd = NtSecurityDescriptor.Parse(Convert.FromHexString(OwnerOnlySd));

        Assert.Equal(0x8001, sd.Control);
        Assert.Null(sd.Dacl);
        Assert.Null(sd.Sacl);
        Assert.Empty(sd.GroupSid);
        Assert.Equal("S-1-5-21-3303064197-558132970-3683154743-512", LdapSid.ToCanonical(sd.OwnerSid));
    }

    [Fact]
    public void SetOwner_ReserializesToImpacketBytes()
    {
        // owneredit write: read the owner-only SD, replace OwnerSid, push getData().
        NtSecurityDescriptor sd = NtSecurityDescriptor.Parse(Convert.FromHexString(OwnerOnlySd));
        sd.OwnerSid = LdapSid.FromCanonical(NewOwner);
        Assert.Equal(WriteSd, Hex(sd.GetData()));
    }

    [Fact]
    public void OwnerSdFlagsControlValue_MatchesLdap3()
    {
        // ldap3 security_descriptor_control(sdflags=0x01) -> controlValue 30 03 02 01 01.
        Assert.Equal("3003020101", Hex(LdapConnection.EncodeSdFlagsControlValue(LdapConnection.SdFlagsOwner)));
    }
}
