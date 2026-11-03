using DotNetPacket.Protocols.Dcerpc;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class LsatLookupSids2Tests
{
    // Verbatim LsarLookupSids2 (opnum 57) response stub captured against a Samba AD DC for
    // SIDs [S-1-5-32-544, S-1-1-0]: ReferencedDomains (BUILTIN + the well-known-group domain),
    // LSAPR_TRANSLATED_NAMES_EX with two entries (Administrators = Alias/4 domIdx 0, Everyone =
    // WellKnownGroup/5 domIdx 1, each with the extra EX Flags field), MappedCount, NTSTATUS 0.
    private const string LookupSids2Resp =
        "0c000200020000001000020040000000020000000e0010001400020018000200000002001c000200200002000800000000000000070000004200550049004c00540049004e00eeee010000000101000000000005200000000100000000000000000000000000000001000000000000010200000024000200020000000400abab1c001c002800020000000000000000000500abab100010002c00020001000000000000000e000000000000000e000000410064006d0069006e006900730074007200610074006f0072007300080000000000000008000000450076006500720079006f006e0065000200000000000000";

    [Fact]
    public void ParseResponse_Extended_ReadsExTranslatedNames()
    {
        var sids = new[] { "S-1-5-32-544", "S-1-1-0" };
        var rows = Lsat.ParseResponse(Convert.FromHexString(LookupSids2Resp), sids, extended: true);

        Assert.Equal(2, rows.Count);

        Assert.Equal("S-1-5-32-544", rows[0].InputSid);
        Assert.Equal("Administrators", rows[0].Name);
        Assert.Equal("BUILTIN", rows[0].Domain);
        Assert.Equal(SidNameUse.Alias, rows[0].Use);

        Assert.Equal("Everyone", rows[1].Name);
        Assert.Equal(SidNameUse.WellKnownGroup, rows[1].Use);
    }
}
