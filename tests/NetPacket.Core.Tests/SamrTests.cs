using NetPacket.Protocols.Dcerpc;
using Xunit;

namespace NetPacket.Core.Tests;

public class SamrTests
{
    // Build a synthetic SAMPR_ENUM_INFORMATION_BUFFER response (two RID entries) in
    // NDR deferral order and assert the shared enumeration parser decodes it.
    // Real server bytes are validated by the rpc-enumusers example.
    [Fact]
    public void ParseRidEnumeration_DecodesEntries()
    {
        var ndr = new NdrWriter();
        ndr.WriteUInt32(2);          // EnumerationContext (out)
        ndr.WriteReferent(true);     // Buffer pointer
        ndr.WriteUInt32(2);          // EntriesRead
        ndr.WriteReferent(true);     // array pointer
        ndr.WriteUInt32(2);          // array MaxCount

        ndr.WriteUInt32(1000);       // RelativeId
        ndr.WriteUInt16(14); ndr.WriteUInt16(14); ndr.WriteReferent(true);
        ndr.WriteUInt32(1001);       // RelativeId
        ndr.WriteUInt16(10); ndr.WriteUInt16(10); ndr.WriteReferent(true);

        ndr.WriteConformantVaryingString("labuser");
        ndr.WriteConformantVaryingString("admin");

        ndr.WriteUInt32(2);          // CountReturned
        ndr.WriteUInt32(0);          // return status

        SamrEnumResult result = Samr.ParseRidEnumeration(ndr.ToArray());

        Assert.Equal(0u, result.ReturnCode);
        Assert.Equal(2, result.Entries.Count);
        Assert.Equal(1000u, result.Entries[0].Rid);
        Assert.Equal("labuser", result.Entries[0].Name);
        Assert.Equal(1001u, result.Entries[1].Rid);
        Assert.Equal("admin", result.Entries[1].Name);
    }

    [Fact]
    public void SamrSid_FormatsCanonically()
    {
        var sid = new SamrSid(1, new byte[] { 0, 0, 0, 0, 0, 5 }, new uint[] { 21, 100, 200, 300 });
        Assert.Equal("S-1-5-21-100-200-300", sid.ToString());
    }
}
