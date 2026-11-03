using DotNetPacket.Protocols.Dcerpc;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class LsarAccountRightsTests
{
    // Verbatim LsarEnumerateAccountRights (opnum 36) response stub captured against a Samba AD DC
    // for SID S-1-5-32-550 (Print Operators): an LSAPR_USER_RIGHT_SET with EntriesRead=3 and a
    // referenced conformant RPC_UNICODE_STRING array (3 Length/MaxLength/Buffer-referent headers,
    // referents 0x00020000/4/8/c — sequential +4, as Windows/MIDL emit), then the 3 deferred
    // conformant-varying name buffers, then NTSTATUS 0.
    private const string AccountRightsResp =
        "0300000000000200030000002a002c000400020026002800080002002e0030000c000200" +
        "160000000000000015000000530065004c006f0061006400440072006900760065007200500072006900760069006c00650067006500000" +
        "014000000000000001300000053006500530068007500740064006f0077006e00500072006900760069006c0065006700650000" +
        "001800000000000000170000005300650049006e007400650072006100630074006900760065004c006f0067006f006e0052006900670068007400000000000000";

    [Fact]
    public void ParseAccountRights_ReadsRightNamesAndStatus()
    {
        var parsed = Lsarpc.ParseAccountRights(Convert.FromHexString(AccountRightsResp), "S-1-5-32-550");

        Assert.True(parsed.Success);
        Assert.Equal("S-1-5-32-550", parsed.Sid);
        Assert.Equal(3, parsed.Rights.Count);
        Assert.Equal("SeLoadDriverPrivilege", parsed.Rights[0]);
        Assert.Equal("SeShutdownPrivilege", parsed.Rights[1]);
        Assert.Equal("SeInteractiveLogonRight", parsed.Rights[2]);
    }
}
