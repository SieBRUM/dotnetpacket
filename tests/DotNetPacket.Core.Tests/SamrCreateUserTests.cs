using DotNetPacket.Protocols.Dcerpc;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class SamrCreateUserTests
{
    [Fact]
    public void EncodeCreateUser2Request_MachineAccount_HasExpectedNdrLayout()
    {
        // Deterministic SamrCreateUser2InDomain stub: a fixed 20-byte domain handle, name
        // "PWNLAB01$" (RPC_UNICODE_STRING, NO trailing NUL — Length 0x12 = 18 bytes = 9 chars),
        // AccountType USER_WORKSTATION_TRUST_ACCOUNT (0x80), DesiredAccess MAXIMUM_ALLOWED
        // (0x02000000). The lab DC accepted this exact request shape (it created the account).
        byte[] handle = Enumerable.Range(0, 20).Select(i => (byte)i).ToArray();

        byte[] stub = Samr.EncodeCreateUser2Request(handle, "PWNLAB01$", Samr.UserWorkstationTrustAccount, 0x02000000);

        const string expected =
            "000102030405060708090a0b0c0d0e0f10111213" + // DomainHandle (20 bytes)
            "12001200000002000900000000000000090000005000570" +
            "04e004c0041004200300031002400" +              // "PWNLAB01$" UTF-16LE, no NUL
            "0000" +                                       // NDR align(4) pad
            "80000000" +                                   // AccountType = 0x80
            "00000002";                                    // DesiredAccess = 0x02000000

        Assert.Equal(expected, Convert.ToHexString(stub).ToLowerInvariant());
    }
}
