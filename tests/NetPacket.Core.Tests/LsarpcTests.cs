using NetPacket.Protocols.Dcerpc;
using Xunit;

namespace NetPacket.Core.Tests;

public class LsarpcTests
{
    [Fact]
    public void FormatSid_Canonical()
    {
        string sid = Lsarpc.FormatSid(
            1,
            new byte[] { 0, 0, 0, 0, 0, 5 },
            new uint[] { 21, 2786383041, 2443124272, 643774106 });
        Assert.Equal("S-1-5-21-2786383041-2443124272-643774106", sid);
    }

    // Known-bytes: the exact PolicyAccountDomainInformation response Samba returned
    // (captured from impacket's LsarQueryInformationPolicy against the lab server).
    [Fact]
    public void ParseAccountDomain_FromCapturedBytes()
    {
        byte[] stub = Convert.FromHexString(
            "00000200050000000c000e0004000200080002000700000000000000060000004c00" +
            "4100420053005200560004000000010400000000000515000000c1d414a6301e9f91" +
            "9a365f2600000000");

        LsaAccountDomain account = Lsarpc.ParseAccountDomain(stub);

        Assert.Equal("LABSRV", account.Name);
        Assert.Equal("S-1-5-21-2786383041-2443124272-643774106", account.Sid);
        Assert.Equal(0u, account.Status);
        Assert.True(account.Success);
    }
}
