using DotNetPacket.Protocols.Dcerpc;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class SamrDisplayInfoTests
{
    // Verbatim SamrQueryDisplayInformation (opnum 40) DomainDisplayUser response stub captured
    // against a Samba AD DC: TotalAvailable/TotalReturned, a SAMPR_DISPLAY_INFO_BUFFER union
    // (tag 1) with EntriesRead=3 and a referenced conformant SAMPR_DOMAIN_DISPLAY_USER array
    // (krbtgt/502, Guest/501, Administrator/500 — each Index/Rid/AccountControl + three
    // RPC_UNICODE_STRING headers, referents 0x00020004..0x00020024 sequential +4), then the
    // deferred name/description/full-name buffers (full names empty), then NTSTATUS 0.
    private const string DisplayInfoResp =
        "03000000030000000100000003000000000002000300000001000000f6010000000000000c000c00" +
        "040002004e004e0008000200000000000c00020002000000f5010000000000000a000a0010000200" +
        "7000700014000200000000001800020003000000f4010000000000001a001a001c0002006c006c00" +
        "2000020000000000240002000600000000000000060000006b00720062007400670074002700" +
        "00000000000027000000" +
        "4b0065007900200044006900730074007200690062007500740069006f006e002000430065006e00" +
        "7400650072002000530065007200760069006300650020004100630063006f0075006e0074000000" +
        "0000000000000000000000000500000000000000050000004700750065007300740000003800" +
        "000000000000380000004200750069006c0074002d0069006e002000610063" +
        "0063006f0075006e007400200066006f0072002000670075006500730074002000610063006300650073" +
        "00730020007400" +
        "6f002000740068006500200063006f006d00700075007400650072002f0064006f006d00610069006e00" +
        "0000000000000000000000000d000000000000000d000000" +
        "410064006d0069006e006900730074007200610074006f00720000003600000000000000360000004200" +
        "750069006c0074002d0069006e0020006100630063006f0075006e007400200066006f00720020006100" +
        "64006d0069006e006900730074006500720069006e0067002000740068006500200063006f006d007000" +
        "75007400650072002f0064006f006d00610069006e0000000000000000000000000000000000";

    [Fact]
    public void ParseDisplayUsers_ReadsEveryUserWithNameDescriptionAndRid()
    {
        (var users, uint total, uint status) =
            Samr.ParseDisplayUsers(Convert.FromHexString(DisplayInfoResp));

        Assert.Equal(0u, status);
        Assert.Equal(3u, total);
        Assert.Equal(3, users.Count);

        Assert.Equal(1u, users[0].Index);
        Assert.Equal(502u, users[0].Rid);
        Assert.Equal("krbtgt", users[0].AccountName);
        Assert.Equal("Key Distribution Center Service Account", users[0].AdminComment);
        Assert.Equal(string.Empty, users[0].FullName);

        Assert.Equal(501u, users[1].Rid);
        Assert.Equal("Guest", users[1].AccountName);
        Assert.StartsWith("Built-in account for guest", users[1].AdminComment);

        Assert.Equal(500u, users[2].Rid);
        Assert.Equal("Administrator", users[2].AccountName);
        Assert.StartsWith("Built-in account for administering", users[2].AdminComment);
    }
}
