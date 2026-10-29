using NetPacket.Core;
using NetPacket.Protocols.Ntlm;
using Xunit;

namespace NetPacket.Core.Tests;

public class AvPairsTests
{
    [Fact]
    public void RoundTrips_And_Set_Replaces()
    {
        var pairs = new AvPairs();
        pairs.Set(NtlmAvId.NbDomainName, new byte[] { 1, 2 });
        pairs.Set(NtlmAvId.Flags, new byte[] { 0, 0, 0, 0 });
        pairs.Set(NtlmAvId.Flags, new byte[] { 2, 0, 0, 0 }); // replace

        var reparsed = AvPairs.Parse(pairs.ToArray());
        Assert.Equal(new byte[] { 1, 2 }, reparsed.Get(NtlmAvId.NbDomainName));
        Assert.Equal(new byte[] { 2, 0, 0, 0 }, reparsed.Get(NtlmAvId.Flags));
        Assert.Null(reparsed.Get(NtlmAvId.Timestamp));
    }
}

public class NtlmClientMessageTests
{
    [Fact]
    public void Negotiate_HasSignatureTypeAndVersion()
    {
        byte[] type1 = new NtlmClient().CreateNegotiate();
        Assert.Equal(Ntlm.Signature, type1[..8]);
        Assert.Equal(new byte[] { 0x01, 0x00, 0x00, 0x00 }, type1[8..12]); // message type 1
    }

    [Fact]
    public void Authenticate_IsWellFormed_WithMic()
    {
        byte[] challenge = BuildChallenge();
        NtlmAuthResult result = new NtlmClient().CreateAuthenticate(challenge, "WORKGROUP", "labuser", "Passw0rd!");
        byte[] type3 = result.Message;

        Assert.Equal(Ntlm.Signature, type3[..8]);
        Assert.Equal(new byte[] { 0x03, 0x00, 0x00, 0x00 }, type3[8..12]); // message type 3
        Assert.Equal(16, result.SessionKey.Length);

        // MIC lives at offset 72 and must be populated (not left as zeros).
        byte[] mic = type3[72..88];
        Assert.Contains(mic, b => b != 0);
    }

    // A minimal CHALLENGE (Type 2) with Unicode + TargetInfo flags and an EOL-only target info.
    private static byte[] BuildChallenge()
    {
        var writer = new ByteWriter(ByteOrder.Little);
        writer.WriteBytes(Ntlm.Signature);
        writer.WriteUInt32(Ntlm.ChallengeMessage);
        writer.WriteUInt16(0); writer.WriteUInt16(0); writer.WriteUInt32(0); // TargetName fields (empty)
        uint flags = (uint)(NtlmNegotiateFlags.NegotiateUnicode | NtlmNegotiateFlags.NegotiateTargetInfo);
        writer.WriteUInt32(flags);
        writer.WriteBytes(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }); // ServerChallenge
        writer.WriteBytes(new byte[8]);                            // Reserved
        writer.WriteUInt16(4); writer.WriteUInt16(4); writer.WriteUInt32(48); // TargetInfo fields
        writer.WriteBytes(new byte[] { 0, 0, 0, 0 });              // target info: EOL only (at offset 48)
        return writer.ToArray();
    }
}

public class SpnegoTests
{
    [Fact]
    public void InitialToken_IsGssApiFramed()
    {
        byte[] token = Spnego.WrapInitialToken(new byte[] { 0xAA, 0xBB });
        Assert.Equal(0x60, token[0]); // [APPLICATION 0] GSS-API tag
    }

    [Fact]
    public void ResponseToken_RoundTrips()
    {
        byte[] inner = { 0x4E, 0x54, 0x4C, 0x4D, 0x01, 0x02, 0x03 };
        byte[] wrapped = Spnego.WrapResponseToken(inner, mechListMic: new byte[16]);
        byte[] extracted = Spnego.ExtractResponseToken(wrapped);
        Assert.Equal(inner, extracted);
    }
}
