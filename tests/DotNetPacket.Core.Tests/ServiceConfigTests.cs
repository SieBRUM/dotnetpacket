using DotNetPacket.Protocols.Dcerpc;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class ServiceConfigTests
{
    // Response stub of a real svcctl RQueryServiceConfigW data call captured against a
    // Samba AD DC for the Spooler service: the QUERY_SERVICE_CONFIGW fixed fields (type,
    // start type, error control, five string-pointer referents, tag), then the deferred
    // binary-path / account / display-name strings, then pcbBytesNeeded + return. The
    // live rpc-svcconfig example drives the two-call sizing; this pins the parser.
    private const string QueryConfigStub =
        "10000000" + "03000000" + "01000000" +           // type 0x10, start 3 (DEMAND), error 1
        "00000200" + "00000000" + "00000000" +           // lpBinaryPathName ref, lpLoadOrderGroup null, dwTagId 0
        "00000000" + "04000200" + "08000200" +           // lpDependencies null, lpServiceStartName ref, lpDisplayName ref
        "2c000000000000002c000000" +                     // binary path: max=0x2c, off=0, actual=0x2c
        "2f007500730072002f006c00690062002f007800380036005f00360034002d006c0069006e00750078002d0067006e0075002f00730061006d00620061002f00730076006300630074006c002f0073006d006200640000" +
        "000c000000000000000c000000" +                   // (pad) + account: max=0xc, off=0, actual=0xc
        "4c006f00630061006c00530079007300740065006d0000" +
        "000e000000000000000e000000" +                   // (pad) + display: max=0xe, off=0, actual=0xe
        "5000720069006e0074002000530070006f006f006c0065007200000" +
        "0d400000000000000";                             // pcbBytesNeeded 0xd4, return 0

    [Fact]
    public void ParseServiceConfig_ReadsPathStartTypeAndAccount()
    {
        (ServiceConfig cfg, uint needed, uint ret) = Svcctl.ParseServiceConfig(Convert.FromHexString(QueryConfigStub));

        Assert.Equal("/usr/lib/x86_64-linux-gnu/samba/svcctl/smbd", cfg.BinaryPath);
        Assert.Equal("LocalSystem", cfg.StartName);
        Assert.Equal("Print Spooler", cfg.DisplayName);
        Assert.Equal("DEMAND_START", cfg.StartTypeName);
        Assert.Equal(0x10u, cfg.ServiceType);
        Assert.Equal(0xD4u, needed);
        Assert.Equal(0u, ret);
    }
}
