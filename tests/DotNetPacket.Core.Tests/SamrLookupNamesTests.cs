using DotNetPacket.Protocols.Dcerpc;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class SamrLookupNamesTests
{
    // Verbatim SamrLookupNamesInDomain (opnum 17) response stub captured against a Samba AD DC
    // for names ["Administrator","Guest"]: RelativeIds SAMPR_ULONG_ARRAY {Count=2, ptr, [500,501]},
    // Use SAMPR_ULONG_ARRAY {Count=2, ptr, [1,1]}, then NTSTATUS 0. Pins the response parser.
    private const string LookupNamesResp =
        "020000000800020002000000f4010000f5010000020000000c00020002000000010000000100000000000000";

    [Fact]
    public void ParseLookupNames_MapsNamesToRidsAndUse()
    {
        var names = new[] { "Administrator", "Guest" };
        var rows = Samr.ParseLookupNames(Convert.FromHexString(LookupNamesResp), names);

        Assert.Equal(2, rows.Count);

        Assert.Equal("Administrator", rows[0].Name);
        Assert.Equal(500u, rows[0].Rid);
        Assert.Equal(1u, rows[0].Use);
        Assert.Equal("User", rows[0].UseName);
        Assert.True(rows[0].Resolved);

        Assert.Equal("Guest", rows[1].Name);
        Assert.Equal(501u, rows[1].Rid);
        Assert.Equal("User", rows[1].UseName);
    }

    [Fact]
    public void UseName_MapsUnknownAsUnresolved()
    {
        var row = new SamrNameMapping("nope", 0, 8);
        Assert.Equal("Unknown", row.UseName);
        Assert.False(row.Resolved);
    }
}
