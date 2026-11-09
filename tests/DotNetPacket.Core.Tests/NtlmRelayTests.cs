using DotNetPacket.Core;
using DotNetPacket.Protocols.Ntlm;
using DotNetPacket.Protocols.Smb;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class NtlmRelayTests
{
    private static byte[] FakeNtlm(byte marker) => new byte[]
    {
        0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00, marker, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF,
    };

    [Fact]
    public void InitialToken_RoundTrips_ServerExtractsVictimType1()
    {
        byte[] type1 = FakeNtlm(0x01);
        byte[] spnego = Spnego.WrapInitialToken(type1);
        Assert.Equal(type1, Spnego.ExtractInitialToken(spnego));
    }

    [Fact]
    public void Challenge_RoundTrips_VictimExtractsRelayedType2()
    {
        // The server wraps the TARGET's challenge; the victim's SPNEGO reader extracts it.
        byte[] type2 = FakeNtlm(0x02);
        byte[] spnego = Spnego.WrapChallenge(type2);
        Assert.Equal(type2, Spnego.ExtractResponseToken(spnego));
    }

    [Fact]
    public void ResponseWithMic_RoundTrips_ServerExtractsType3AndMic()
    {
        byte[] type3 = FakeNtlm(0x03);
        byte[] mic = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        byte[] spnego = Spnego.WrapResponseToken(type3, mic);

        (byte[] token, byte[]? extractedMic) = Spnego.ExtractResponseTokenWithMic(spnego);
        Assert.Equal(type3, token);
        Assert.Equal(mic, extractedMic);
    }

    [Fact]
    public void ResponseWithoutMic_RoundTrips_WithNullMic()
    {
        byte[] type3 = FakeNtlm(0x03);
        (byte[] token, byte[]? mic) = Spnego.ExtractResponseTokenWithMic(Spnego.WrapResponseToken(type3));
        Assert.Equal(type3, token);
        Assert.Null(mic);
    }

    [Fact]
    public void SessionSetupRequest_SecurityBuffer_ParsesBackFromWire()
    {
        // The relay server parses the SPNEGO out of a victim's SESSION_SETUP *request* message.
        byte[] blob = Spnego.WrapInitialToken(FakeNtlm(0x01));
        var header = new Smb2Header { Command = (ushort)Smb2Command.SessionSetup, MessageId = 7 };
        var body = new Smb2SessionSetupRequest { SecurityBuffer = blob };

        var w = new ByteWriter(ByteOrder.Little);
        w.WriteBytes(header.Pack());
        w.WriteBytes(body.Pack());

        Assert.Equal(blob, Smb2SessionSetupRequest.ParseSecurityBuffer(w.ToArray()));
    }

    [Fact]
    public void ServerNegotiateHint_IsGssWrappedToken()
    {
        // The NEGOTIATE response SPNEGO hint is a GSS-API token (starts with APPLICATION [0] = 0x60).
        byte[] hint = Spnego.WrapServerNegotiateHint();
        Assert.Equal(0x60, hint[0]);
    }
}
