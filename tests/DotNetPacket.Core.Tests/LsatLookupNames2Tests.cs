using DotNetPacket.Protocols.Dcerpc;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class LsatLookupNames2Tests
{
    // Verbatim LsarLookupNames2 (opnum 58) response stub captured against a Samba AD DC for
    // names [Administrator, Guest]: ReferencedDomains (one domain "LAB" + its SID),
    // LSAPR_TRANSLATED_SIDS_EX with two LSAPR_TRANSLATED_SID_EX entries
    // (Use=User, RID 500/501, domIdx 0, plus the extra EX Flags field), MappedCount, NTSTATUS 0.
    private const string LookupNames2Resp =
        "08000200010000000c00020020000000010000000600080010000200140002000400000000000000030000004c0041004200eeee0400000001040000000000051500000085c2e0c4ea6e4421377b88db0200000018000200020000000100bfbff401000000000000000000000100bfbff501000000000000000000000200000000000000";

    [Fact]
    public void ParseLookupNames_Extended_ReadsExTranslatedSids()
    {
        var names = new[] { "Administrator", "Guest" };
        var rows = Lsat.ParseLookupNames(Convert.FromHexString(LookupNames2Resp), names, extended: true);

        Assert.Equal(2, rows.Count);

        Assert.Equal("Administrator", rows[0].InputName);
        Assert.Equal(SidNameUse.User, rows[0].Use);
        Assert.EndsWith("-500", rows[0].Sid);

        Assert.Equal("Guest", rows[1].InputName);
        Assert.EndsWith("-501", rows[1].Sid);
        Assert.StartsWith("S-1-5-21-", rows[1].Sid);
    }
}
