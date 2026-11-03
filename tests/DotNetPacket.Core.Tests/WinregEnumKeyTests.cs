using DotNetPacket.Protocols.Dcerpc;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class WinregEnumKeyTests
{
    // Verbatim BaseRegEnumKey (opnum 9) response stub captured against a Samba AD DC enumerating
    // HKLM\SOFTWARE\Microsoft at index 0: lpNameOut RPC_UNICODE_STRING (buffer "Windows NT\0",
    // 11 chars), lplpClassOut (empty), NULL lpftLastWriteTime, NTSTATUS 0. Pins the parser.
    private const string EnumKeyResp =
        "160000040c00020000020000000000000b000000570069006e0064006f007700730020004e0054000000aaaa1000020000008000140002004000000000000000000000000000000000000000";

    [Fact]
    public void ParseEnumKeyResponse_ReadsSubkeyName()
    {
        (string? name, uint ret) = Winreg.ParseEnumKeyResponse(Convert.FromHexString(EnumKeyResp));

        Assert.Equal(0u, ret);
        Assert.Equal("Windows NT", name);
    }

}
