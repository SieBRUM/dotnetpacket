using DotNetPacket.Protocols.Ntlm;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class NetNtlmv2Tests
{
    // A deterministic NTLMSSP AUTHENTICATE (Type 3) produced by stock impacket (getNTLMSSPType3) for
    // user Administrator / domain LAB against server challenge 1122334455667788, and the exact hashcat
    // line impacket's outputToJohnFormat emits for it. Pins the Type 3 parse + NetNTLMv2 format.
    private const string Type3Hex = "4e544c4d535350000300000018001800640000009e009e007c00000006000600400000001a001a00460000000400040060000000000000001a010000050280804c0041004200410064006d0069006e006900730074007200610074006f00720057005300b636f1d41f813f3d28fd240be5b6d32d3150544c42724c427370c81d6abc7a72c6ad540cd7074f2e010100000000000011111111111111113150544c42724c420000000001000c00560049004300540049004d0003002000760069006300740069006d002e006c00610062002e006c006f00630061006c0007000800111111111111111109002a0063006900660073002f00760069006300740069006d002e006c00610062002e006c006f00630061006c0000000000";

    private static readonly byte[] ServerChallenge = Convert.FromHexString("1122334455667788");

    private const string ExpectedJohn = "Administrator::LAB:1122334455667788:7370c81d6abc7a72c6ad540cd7074f2e:010100000000000011111111111111113150544c42724c420000000001000c00560049004300540049004d0003002000760069006300740069006d002e006c00610062002e006c006f00630061006c0007000800111111111111111109002a0063006900660073002f00760069006300740069006d002e006c00610062002e006c006f00630061006c0000000000";

    [Fact]
    public void ParseType3_ExtractsUserDomainAndNtResponse()
    {
        NtlmAuthenticate auth = NtlmAuthenticate.Parse(Convert.FromHexString(Type3Hex));

        Assert.Equal("Administrator", auth.UserName);
        Assert.Equal("LAB", auth.DomainName);
        Assert.Equal("WS", auth.Workstation);
        Assert.True(auth.IsNtlmV2);
        Assert.Equal(158, auth.NtChallengeResponse.Length);
    }

    [Fact]
    public void Format_MatchesImpacketOutputToJohnFormat()
    {
        NtlmAuthenticate auth = NtlmAuthenticate.Parse(Convert.FromHexString(Type3Hex));
        Assert.Equal(ExpectedJohn, NetNtlmv2.Format(ServerChallenge, auth));
    }
}
