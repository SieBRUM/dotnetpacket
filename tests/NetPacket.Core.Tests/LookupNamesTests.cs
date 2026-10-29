using NetPacket.Protocols.Dcerpc;
using Xunit;

namespace NetPacket.Core.Tests;

public class LookupNamesTests
{
    // Synthetic LsarLookupNames response: two referenced domains (LABSRV with a
    // full SID, and the S-1-1 authority) and two translated SIDs, in NDR deferral
    // order. The full SID is domain SID + RID. Real bytes validated by rpc-lookupnames.
    [Fact]
    public void ParseLookupNames_BuildsFullSids()
    {
        var ndr = new NdrWriter();

        // ReferencedDomains: two domains.
        ndr.WriteReferent(true);          // ReferencedDomains pointer
        ndr.WriteUInt32(2);               // Entries
        ndr.WriteReferent(true);          // Domains pointer
        ndr.WriteUInt32(32);              // MaxEntries
        ndr.WriteUInt32(2);               // array MaxCount
        // trust-info headers
        ndr.WriteUInt16(12); ndr.WriteUInt16(14); ndr.WriteReferent(true); ndr.WriteReferent(true); // LABSRV
        ndr.WriteUInt16(0); ndr.WriteUInt16(2); ndr.WriteReferent(true); ndr.WriteReferent(true);   // ""
        // deferred: domain0 name + sid
        ndr.WriteConformantVaryingString("LABSRV");
        ndr.WriteSid(1, new byte[] { 0, 0, 0, 0, 0, 5 }, new uint[] { 21, 2786383041, 2443124272, 643774106 });
        // deferred: domain1 name + sid (S-1-1, no sub-authorities)
        ndr.WriteConformantVaryingString(string.Empty);
        ndr.WriteSid(1, new byte[] { 0, 0, 0, 0, 0, 1 }, System.Array.Empty<uint>());

        // TranslatedSids: labuser -> domain0 RID 1000; Everyone -> domain1 RID 0.
        ndr.WriteUInt32(2);               // Entries
        ndr.WriteReferent(true);          // Sids pointer
        ndr.WriteUInt32(2);               // array MaxCount
        ndr.WriteUInt16((ushort)SidNameUse.User); ndr.Align(4); ndr.WriteUInt32(1000); ndr.WriteUInt32(0);
        ndr.WriteUInt16((ushort)SidNameUse.WellKnownGroup); ndr.Align(4); ndr.WriteUInt32(0); ndr.WriteUInt32(1);

        ndr.WriteUInt32(2);               // MappedCount
        ndr.WriteUInt32(0);               // return status

        var names = new[] { "labuser", "Everyone" };
        IReadOnlyList<LsaResolvedName> resolved = Lsat.ParseLookupNames(ndr.ToArray(), names);

        Assert.Equal(2, resolved.Count);
        Assert.Equal("labuser", resolved[0].InputName);
        Assert.Equal("S-1-5-21-2786383041-2443124272-643774106-1000", resolved[0].Sid);
        Assert.Equal(SidNameUse.User, resolved[0].Use);
        Assert.Equal("Everyone", resolved[1].InputName);
        Assert.Equal("S-1-1-0", resolved[1].Sid);
        Assert.Equal(SidNameUse.WellKnownGroup, resolved[1].Use);
    }
}
