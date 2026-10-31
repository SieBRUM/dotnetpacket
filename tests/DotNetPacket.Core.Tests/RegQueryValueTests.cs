using DotNetPacket.Protocols.Dcerpc;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class RegQueryValueTests
{
    // Response stub of a real winreg BaseRegQueryValue call captured against a Samba AD
    // DC, reading HKLM\...\CurrentVersion\SystemRoot: lpType (REG_SZ=1), the lpData
    // conformant-varying byte array ("c:\Windows\0"), lpcbData/lpcbLen (22), return 0.
    // The live rpc-regquery example drives the two-call sizing; this pins the parser.
    private const string QueryValueResponseStub =
        "14000200" + "01000000" +                           // lpType ref, type = 1 (REG_SZ)
        "18000200" + "16000000" + "00000000" + "16000000" + // lpData ref, max=22, offset=0, actual=22
        "63003a005c00570069006e0064006f00770073000000" +    // "c:\Windows\0"
        "0000" +                                            // align(4)
        "1c000200" + "16000000" +                           // lpcbData ref, value = 22
        "20000200" + "16000000" +                           // lpcbLen ref, value = 22
        "00000000";                                         // return = 0

    [Fact]
    public void ParseQueryValueResponse_ReadsRegSzValue()
    {
        (uint type, byte[] data, uint needed, uint ret) =
            Winreg.ParseQueryValueResponse(Convert.FromHexString(QueryValueResponseStub));

        Assert.Equal(1u, type); // REG_SZ
        Assert.Equal(0u, ret);
        Assert.Equal(22u, needed);
        var value = new Winreg.RegValue(type, data, ret);
        Assert.Equal("REG_SZ", value.TypeName);
        Assert.Equal(@"c:\Windows", value.AsText);
    }
}
