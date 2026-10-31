using DotNetPacket.Protocols.Dcerpc;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class ServicesTests
{
    // The packed ENUM_SERVICE_STATUSW buffer from a real svcctl REnumServicesStatusW
    // data call captured against a Samba AD DC (4 services). Four 36-byte records at
    // the front (two name byte-offsets + a 7-DWORD SERVICE_STATUS), then the
    // UTF-16LE names at those offsets. The live rpc-services example drives the
    // two-call sizing dance; this pins the offset-buffer parser.
    private const string EnumBuffer =
        "90000000a000000010010000040000000100000000000000000000000000000000000000" +
        "bc000000ce00000020000000040000000000000035040000000000000000000000000000" +
        "e20000000001000020000000040000000000000000000000000000000000000000000000" +
        "300100003a01000010000000010000000000000035040000000000000000000000000000" +
        "530070006f006f006c006500720000005000720069006e0074002000530070006f006f006c006500720000" +
        "004e00450054004c004f0047004f004e0000004e006500740020004c006f0067006f006e000000" +
        "520065006d006f0074006500520065006700690073007400720079000000" +
        "520065006d006f0074006500200052006500670069007300740072007900200053006500720076006900630065000000" +
        "570049004e0053000000" +
        "570069006e0064006f0077007300200049006e007400650072006e006500740020004e0061006d0065002000530065007200760069006300650020002800570049004e00530029000000";

    [Fact]
    public void ParseServices_ReadsNamesStatesAndDisplayNames()
    {
        byte[] buffer = Convert.FromHexString(EnumBuffer);

        IReadOnlyList<ServiceStatusEntry> services = Svcctl.ParseServices(buffer, 4);

        Assert.Equal(4, services.Count);
        Assert.Equal("Spooler", services[0].Name);
        Assert.Equal("Print Spooler", services[0].DisplayName);
        Assert.Equal("RUNNING", services[0].State);      // dwCurrentState 4
        Assert.Equal("NETLOGON", services[1].Name);
        Assert.Equal("RemoteRegistry", services[2].Name);
        Assert.Equal("WINS", services[3].Name);
        Assert.Equal("STOPPED", services[3].State);       // dwCurrentState 1
    }
}
