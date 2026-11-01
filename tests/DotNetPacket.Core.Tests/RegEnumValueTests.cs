using DotNetPacket.Protocols.Dcerpc;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class RegEnumValueTests
{
    // Response stub of a real winreg BaseRegEnumValue(index=0) call captured against a
    // Samba AD DC on HKLM\...\CurrentVersion: lpValueNameOut ("SystemRoot"), lpType
    // (REG_SZ=1), lpData ("c:\Windows\0"), lpcbData/lpcbLen (22), return 0. The live
    // rpc-regenum example drives the index loop + sizing; this pins the parser.
    private const string EnumValueResponseStub =
        "16000002" + "14000200" +                           // lpValueNameOut: Length=22, MaxLen=512, Buffer ref
        "00010000" + "00000000" + "0b000000" +              //   name buffer: max=256, offset=0, actual=11
        "530079007300740065006d0052006f006f0074000000" +    //   "SystemRoot\0"
        "0000" +                                            //   align(4)
        "18000200" + "01000000" +                           // lpType ref, type = 1 (REG_SZ)
        "1c000200" + "16000000" + "00000000" + "16000000" + // lpData ref, max=22, offset=0, actual=22
        "63003a005c00570069006e0064006f00770073000000" +    //   "c:\Windows\0"
        "0000" +                                            //   align(4)
        "20000200" + "16000000" +                           // lpcbData ref, value = 22
        "24000200" + "16000000" +                           // lpcbLen ref, value = 22
        "00000000";                                         // return = 0

    [Fact]
    public void ParseEnumValueResponse_ReadsNameTypeAndData()
    {
        (Winreg.RegNamedValue? value, uint needed, uint ret) =
            Winreg.ParseEnumValueResponse(Convert.FromHexString(EnumValueResponseStub));

        Assert.Equal(0u, ret);
        Assert.Equal(22u, needed);
        Assert.NotNull(value);
        Assert.Equal("SystemRoot", value!.Name);
        Assert.Equal("REG_SZ", value.TypeName);
        Assert.Equal(@"c:\Windows", value.AsText);
    }
}
