using DotNetPacket.Protocols.Dcerpc;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class SamrLookupIdsTests
{
    // Verbatim SamrLookupIdsInDomain (opnum 18) response stub captured against a Samba AD DC for
    // RIDs [500,513,512]: SAMPR_RETURNED_USTRING_ARRAY {Count=3, ptr, MaxCount=3, three
    // RPC_UNICODE_STRING headers, then the deferred no-NUL name buffers
    // "Administrator"/"Domain Users"/"Domain Admins"}, Use SAMPR_ULONG_ARRAY {3, ptr, [1,2,2]},
    // NTSTATUS 0. Pins the response parser.
    private const string LookupIdsResp =
        "0300000000000200030000001a001a000400020018001800080002001a001a000c0002000d000000000000000d000000410064006d0069006e006900730074007200610074006f007200abab0c000000000000000c00000044006f006d00610069006e002000550073006500720073000d000000000000000d00000044006f006d00610069006e002000410064006d0069006e007300abab03000000100002000300000001000000020000000200000000000000";

    [Fact]
    public void ParseLookupIds_MapsRidsToNamesAndUse()
    {
        var rids = new uint[] { 500, 513, 512 };
        var rows = Samr.ParseLookupIds(Convert.FromHexString(LookupIdsResp), rids);

        Assert.Equal(3, rows.Count);

        Assert.Equal(500u, rows[0].Rid);
        Assert.Equal("Administrator", rows[0].Name);
        Assert.Equal("User", rows[0].UseName);

        Assert.Equal(513u, rows[1].Rid);
        Assert.Equal("Domain Users", rows[1].Name);
        Assert.Equal("Group", rows[1].UseName);

        Assert.Equal(512u, rows[2].Rid);
        Assert.Equal("Domain Admins", rows[2].Name);
        Assert.Equal("Group", rows[2].UseName);
        Assert.True(rows[2].Resolved);
    }
}
