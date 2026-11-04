using DotNetPacket.Protocols.Dcerpc;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class SrvsvcServerInfo102Tests
{
    // Verbatim NetrServerGetInfo (opnum 21) level-102 response stub captured against a Samba AD DC:
    // union tag 102 + a SERVER_INFO_102 referent (platform 500; name "VM"; version 6.1; type
    // 0x00809a03; comment "vm server (Samba, Ubuntu)"; users 0xffffffff; disc 15; hidden 0;
    // announce 240; anndelta 3000; licenses 100000; userpath "C:\"), the deferred name/comment/
    // userpath buffers, then NTSTATUS 0.
    private const string ServerInfo102Resp =
        "6600000004000200f4010000080002000600000001000000039a80000c000200" +
        "ffffffff0f00000000000000f0000000b80b0000a08601001000020003000000" +
        "000000000300000056004d00000000001a000000000000001a00000076006d00" +
        "200073006500720076006500720020002800530061006d00620061002c002000" +
        "5500620075006e00740075002900000004000000000000000400000043003a00" +
        "5c00000000000000";

    [Fact]
    public void ParseServerInfo102_ReadsTunablesAndStrings()
    {
        var info = Srvsvc.ParseServerInfo102(Convert.FromHexString(ServerInfo102Resp));

        Assert.Equal(500u, info.PlatformId);
        Assert.Equal("VM", info.Name);
        Assert.Equal(6u, info.VersionMajor);
        Assert.Equal(1u, info.VersionMinor);
        Assert.Equal(0x00809a03u, info.Type);
        Assert.Equal("vm server (Samba, Ubuntu)", info.Comment);
        Assert.Equal(0xFFFFFFFFu, info.Users);
        Assert.Equal(15u, info.Disc);
        Assert.Equal(0u, info.Hidden);
        Assert.Equal(240u, info.Announce);
        Assert.Equal(3000u, info.AnnDelta);
        Assert.Equal(100000u, info.Licenses);
        Assert.Equal(@"C:\", info.UserPath);
    }
}
