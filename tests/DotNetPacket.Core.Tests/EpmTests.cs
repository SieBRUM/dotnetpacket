using DotNetPacket.Protocols.Dcerpc;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class EpmTests
{
    // Response stub of a real epm ept_map call captured from impacket against a Samba
    // AD DC, resolving the samr interface over ncacn_ip_tcp: entry_handle (20),
    // num_towers=1, the ITowers array, then the returned twr_t whose TCP floor carries
    // the dynamic port (0xC002 = 49154, big-endian in the tower). The live rpc-epm-map
    // example drives the full round trip; this pins the tower parse to known bytes.
    private const string EptMapResponseStub =
        "0000000000000000000000000000000000000000" + // entry_handle
        "01000000" +                                  // num_towers
        "04000000" + "00000000" + "01000000" +        // ITowers max_count, offset, actual_count
        "03000000" +                                  // tower[0] referent
        "4b000000" + "4b000000" +                     // twr_t max_count, tower_length (75)
        "050013000d785734123412cdabef000123456789ac010002000000" + // floors 1-2 (iface + NDR)
        "13000d045d888aeb1cc9119fe808002b104860020002000000" +
        "01000b020000000100070200c002010009040000000000" +         // floors 3-5 (RPC, TCP:0xc002, IP)
        "000000" +                                    // tower pad to 4
        "00000000";                                   // status

    [Fact]
    public void ParseFirstTower_ExtractsTcpEndpoint()
    {
        EpmMapResult? result = Epm.ParseFirstTower(Convert.FromHexString(EptMapResponseStub));

        Assert.NotNull(result);
        Assert.Equal("ncacn_ip_tcp", result!.Protocol);
        Assert.Equal(49154, result.Port); // 0xC002, read big-endian from the TCP floor
    }

    [Fact]
    public void ParseFirstTower_ReturnsNullWhenNoTowers()
    {
        // entry_handle (20) + num_towers = 0.
        byte[] stub = Convert.FromHexString(new string('0', 40) + "00000000");
        Assert.Null(Epm.ParseFirstTower(stub));
    }
}
