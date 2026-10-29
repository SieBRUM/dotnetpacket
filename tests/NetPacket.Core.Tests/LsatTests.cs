using NetPacket.Protocols.Dcerpc;
using Xunit;

namespace NetPacket.Core.Tests;

public class LsatTests
{
    // Build a synthetic LsarLookupSids response (one referenced domain, two
    // translated names) in NDR deferral order, then assert the parser decodes it.
    // Real server bytes are validated by the rpc-lookupsid example.
    [Fact]
    public void LookupSids_ParsesSyntheticResponse()
    {
        var ndr = new NdrWriter();

        // ReferencedDomains: LSAPR_REFERENCED_DOMAIN_LIST with one domain (BUILTIN).
        ndr.WriteReferent(true);          // ReferencedDomains pointer
        ndr.WriteUInt32(1);               // Entries
        ndr.WriteReferent(true);          // Domains pointer
        ndr.WriteUInt32(32);              // MaxEntries
        ndr.WriteUInt32(1);               // array MaxCount
        ndr.WriteUInt16(14);              // Name.Length  (BUILTIN = 7 chars)
        ndr.WriteUInt16(16);              // Name.MaximumLength
        ndr.WriteReferent(true);          // Name.Buffer pointer
        ndr.WriteReferent(true);          // Sid pointer
        ndr.WriteConformantVaryingString("BUILTIN");
        ndr.WriteSid(1, new byte[] { 0, 0, 0, 0, 0, 5 }, new uint[] { 32 });

        // TranslatedNames: two names, both in domain index 0.
        ndr.WriteUInt32(2);               // Entries
        ndr.WriteReferent(true);          // Names pointer
        ndr.WriteUInt32(2);               // array MaxCount

        ndr.WriteUInt16((ushort)SidNameUse.Alias);
        ndr.Align(4);
        ndr.WriteUInt16(28); ndr.WriteUInt16(28); ndr.WriteReferent(true); ndr.WriteUInt32(0);

        ndr.WriteUInt16((ushort)SidNameUse.WellKnownGroup);
        ndr.Align(4);
        ndr.WriteUInt16(16); ndr.WriteUInt16(16); ndr.WriteReferent(true); ndr.WriteUInt32(0);

        ndr.WriteConformantVaryingString("Administrators");
        ndr.WriteConformantVaryingString("Everyone");

        ndr.WriteUInt32(2);               // MappedCount
        ndr.WriteUInt32(0);               // return status

        var sids = new[] { "S-1-5-32-544", "S-1-5-32-545" };
        IReadOnlyList<LsaResolvedSid> resolved = Lsat.ParseResponse(ndr.ToArray(), sids);

        Assert.Equal(2, resolved.Count);
        Assert.Equal(@"BUILTIN\Administrators", resolved[0].Display);
        Assert.Equal(SidNameUse.Alias, resolved[0].Use);
        Assert.Equal("S-1-5-32-544", resolved[0].InputSid);
        Assert.Equal(@"BUILTIN\Everyone", resolved[1].Display);
        Assert.Equal(SidNameUse.WellKnownGroup, resolved[1].Use);
    }
}
