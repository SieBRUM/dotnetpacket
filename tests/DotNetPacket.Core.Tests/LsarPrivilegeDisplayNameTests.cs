using DotNetPacket.Protocols.Dcerpc;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class LsarPrivilegeDisplayNameTests
{
    // Verbatim LsarLookupPrivilegeDisplayName (opnum 33) response for "SeDebugPrivilege" captured
    // against a Samba AD DC: a referenced RPC_UNICODE_STRING (Length 30 / MaxLength 32, Buffer
    // referent) whose conformant-varying buffer (MaxCount 16 / Offset 0 / ActualCount 15) is
    // "Debug processes", then a UCHAR LanguageReturned (0), then NTSTATUS 0.
    private const string DisplayNameResp =
        "040002001e0020000800020010000000000000000f000000" +
        "440065006200750067002000700072006f00630065007300730065007300" +
        "000000000000";

    [Fact]
    public void ParsePrivilegeDisplayName_ReadsDisplayNameLanguageAndStatus()
    {
        (string display, byte language, uint status) =
            Lsarpc.ParsePrivilegeDisplayName(Convert.FromHexString(DisplayNameResp));

        Assert.Equal(0u, status);
        Assert.Equal("Debug processes", display);
        Assert.Equal(0, language);
    }
}
