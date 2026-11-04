using DotNetPacket.Protocols.Dcerpc;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class LsarPrivilegeLookupTests
{
    // Verbatim LsarLookupPrivilegeValue (opnum 31) response for "SeDebugPrivilege" captured
    // against a Samba AD DC: a LUID {LowPart=20, HighPart=0} then NTSTATUS 0.
    private const string LookupValueResp = "140000000000000000000000";

    // Verbatim LsarLookupPrivilegeName (opnum 32) response for LUID {20,0} captured against the
    // same DC: a referenced RPC_UNICODE_STRING (Length 32 / MaxLength 34, Buffer referent) whose
    // conformant-varying buffer (MaxCount 17 / Offset 0 / ActualCount 16) is "SeDebugPrivilege",
    // then NTSTATUS 0.
    private const string LookupNameResp =
        "0000020020002200040002001100000000000000100000005300650044006500" +
        "620075006700500072006900760069006c0065006700650000000000";

    [Fact]
    public void ParsePrivilegeValue_ReadsLuidAndStatus()
    {
        (uint low, int high, uint status) = Lsarpc.ParsePrivilegeValue(Convert.FromHexString(LookupValueResp));

        Assert.Equal(0u, status);
        Assert.Equal(20u, low);
        Assert.Equal(0, high);
    }

    [Fact]
    public void ParsePrivilegeName_ReadsReferencedNameAndStatus()
    {
        (string name, uint status) = Lsarpc.ParsePrivilegeName(Convert.FromHexString(LookupNameResp));

        Assert.Equal(0u, status);
        Assert.Equal("SeDebugPrivilege", name);
    }
}
