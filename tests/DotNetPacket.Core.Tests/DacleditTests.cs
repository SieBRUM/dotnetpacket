using DotNetPacket.Protocols.Ldap;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class DacleditTests
{
    // A fixed lab/sample trustee SID used across the vectors (not a real target).
    private const string TestSid = "S-1-5-21-1111111111-2222222222-3333333333-1105";

    private static NtAce StandardAce(byte type, uint mask) => new()
    {
        AceType = type,
        AceFlags = 0x00,
        Mask = mask,
        Sid = LdapSid.FromCanonical(TestSid),
    };

    private static NtAce ObjectAce(uint mask, string guid) => new()
    {
        AceType = NtAce.AccessAllowedObject,
        AceFlags = 0x00,
        Mask = mask,
        ObjectType = new Guid(guid),
        Sid = LdapSid.FromCanonical(TestSid),
    };

    private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

    [Fact]
    public void StandardAce_MatchesImpacketBytes()
    {
        // create_ace(FullControl, sid, 'allowed') / 'denied' from dacledit.py.
        Assert.Equal(
            "00002400ff010f00010500000000000515000000c7353a428e6b748455a1aec651040000",
            Hex(StandardAce(NtAce.AccessAllowed, 0xf01ff).Serialize()));
        Assert.Equal(
            "01002400ff010f00010500000000000515000000c7353a428e6b748455a1aec651040000",
            Hex(StandardAce(NtAce.AccessDenied, 0xf01ff).Serialize()));
    }

    [Fact]
    public void ObjectAce_MatchesImpacketBytes()
    {
        // create_object_ace(...) for the three well-known rights dacledit builds.
        Assert.Equal( // DCSync: DS-Replication-Get-Changes (CONTROL_ACCESS mask)
            "050038000001000001000000aaf63111079cd111f79f00c04fc2dcd2010500000000000515000000c7353a428e6b748455a1aec651040000",
            Hex(ObjectAce(NtAce.AdsRightDsControlAccess, "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2").Serialize()));
        Assert.Equal( // ResetPassword (extended right)
            "050038000001000001000000709529006d24d011a76800aa006e0529010500000000000515000000c7353a428e6b748455a1aec651040000",
            Hex(ObjectAce(NtAce.AdsRightDsControlAccess, "00299570-246d-11d0-a768-00aa006e0529").Serialize()));
        Assert.Equal( // WriteMembers (READ_PROP | WRITE_PROP)
            "050038003000000001000000c07996bfe60dd011a28500aa003049e2010500000000000515000000c7353a428e6b748455a1aec651040000",
            Hex(ObjectAce(NtAce.AdsRightDsReadProp | NtAce.AdsRightDsWriteProp, "bf9679c0-0de6-11d0-a285-00aa003049e2").Serialize()));
    }

    [Fact]
    public void SdFlagsControlValue_MatchesLdap3()
    {
        // ldap3 security_descriptor_control(sdflags=0x04) -> controlValue 30 03 02 01 04.
        Assert.Equal("3003020104", Hex(LdapConnection.EncodeSdFlagsControlValue(LdapConnection.SdFlagsDacl)));
    }

    [Fact]
    public void SecurityDescriptor_BuildAndAppend_MatchImpacketGetData()
    {
        // A DACL-only SD with two existing ACEs, as impacket's getData() serializes it.
        const string before =
            "01000480000000000000000000000000140000000400340002000000000014009400020001010000000000051200000001001800ff010f0001020000000000052000000020020000";
        const string after =
            "01000480000000000000000000000000140000000400580003000000000014009400020001010000000000051200000001001800ff010f000102000000000005200000002002000000002400ff010f00010500000000000515000000c7353a428e6b748455a1aec651040000";

        var sd = new NtSecurityDescriptor { Control = 0x8004 };
        sd.Dacl = new NtAcl();
        sd.Dacl.Aces.Add(StandardAce(NtAce.AccessAllowed, 0x20094)); // Read for S-1-5-18
        sd.Dacl.Aces[0].Sid = LdapSid.FromCanonical("S-1-5-18");
        sd.Dacl.Aces.Add(StandardAce(NtAce.AccessDenied, 0xf01ff));  // Denied FC for S-1-5-32-544
        sd.Dacl.Aces[1].Sid = LdapSid.FromCanonical("S-1-5-32-544");
        Assert.Equal(before, Hex(sd.GetData()));

        // Append a FullControl ACE for the trustee — the dacledit write path.
        sd.Dacl.Aces.Add(StandardAce(NtAce.AccessAllowed, 0xf01ff));
        Assert.Equal(after, Hex(sd.GetData()));
    }

    [Fact]
    public void SecurityDescriptor_ParseReserialize_IsIdentity()
    {
        // Round-trip the appended SD: parse then re-serialize reproduces the same bytes.
        const string after =
            "01000480000000000000000000000000140000000400580003000000000014009400020001010000000000051200000001001800ff010f000102000000000005200000002002000000002400ff010f00010500000000000515000000c7353a428e6b748455a1aec651040000";
        byte[] data = Convert.FromHexString(after);
        NtSecurityDescriptor sd = NtSecurityDescriptor.Parse(data);

        Assert.Equal(3, sd.Dacl!.Aces.Count);
        Assert.Null(sd.Sacl);
        Assert.Empty(sd.OwnerSid);
        Assert.Equal(after, Hex(sd.GetData()));
    }

    [Fact]
    public void ObjectAce_ParsePreservesGuidAndSid()
    {
        NtAce original = ObjectAce(NtAce.AdsRightDsControlAccess, "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2");
        var r = new DotNetPacket.Core.ByteReader(original.Serialize(), DotNetPacket.Core.ByteOrder.Little);
        NtAce parsed = NtAce.Parse(r);

        Assert.Equal(NtAce.AccessAllowedObject, parsed.AceType);
        Assert.Equal(new Guid("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"), parsed.ObjectType);
        Assert.Equal(TestSid, LdapSid.ToCanonical(parsed.Sid));
    }
}
