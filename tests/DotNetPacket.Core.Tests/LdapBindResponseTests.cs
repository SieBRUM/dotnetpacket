using DotNetPacket.Protocols.Ldap;
using DotNetPacket.Protocols.Ntlm;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class LdapBindResponseTests
{
    // Verbatim LDAP BindResponse (RFC 4511) PDUs captured from an unsigned GSS-SPNEGO NTLM bind
    // against a Samba AD DC that requires LDAP signing.

    // First leg: saslBindInProgress (14) carrying the server's SPNEGO NegTokenResp (NTLM CHALLENGE).
    private const string SaslInProgressResp =
        "3081c4020452771f2f6181bb0a010e040004008781b1a181ae3081aba0030a0101a10c060a2b06010401" +
        "823702020aa281950481924e544c4d53535000020000000600060038000000358289e2f063d1080ebb56" +
        "4b0000000000000000540054003e000000060100000000000f4c0041004200020006004c004100420001" +
        "00040056004d00040012006c00610062002e006c006f00630061006c000300180076006d002e006c0061" +
        "0062002e006c006f00630061006c00070008003ad49c8a376ddd0100000000";

    // Final leg: strongerAuthRequired (8) with the diagnostic message and an empty serverSaslCreds.
    private const string StrongerAuthResp =
        "303e02040501f80361360a01080400042d5341534c3a5b4753532d53504e45474f5d3a205369676e206f" +
        "72205365616c206172652072657175697265642e8700";

    [Fact]
    public void ParseBindResponse_StrongerAuthRequired_SignalsSigning()
    {
        LdapBindResponse r = LdapConnection.ParseBindResponse(Convert.FromHexString(StrongerAuthResp));

        Assert.Equal(LdapResultCode.StrongerAuthRequired, r.ResultCode);
        Assert.True(r.StrongerAuthRequired);
        Assert.Contains("Sign or Seal are required", r.DiagnosticMessage);
    }

    [Fact]
    public void ParseBindResponse_SaslInProgress_CarriesExtractableChallenge()
    {
        LdapBindResponse r = LdapConnection.ParseBindResponse(Convert.FromHexString(SaslInProgressResp));

        Assert.Equal(LdapResultCode.SaslBindInProgress, r.ResultCode);
        Assert.True(r.SaslInProgress);
        Assert.NotEmpty(r.ServerSaslCreds);

        // The server SASL creds are an SPNEGO NegTokenResp wrapping the NTLM CHALLENGE (Type 2).
        byte[] challenge = Spnego.ExtractResponseToken(r.ServerSaslCreds);
        NtlmChallenge parsed = NtlmChallenge.Parse(challenge);
        Assert.Equal(8, parsed.ServerChallenge.Length);
    }
}
