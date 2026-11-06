using DotNetPacket.Protocols.Dcerpc;
using DotNetPacket.Protocols.Ntlm;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class SamrChangePasswordTests
{
    // Fixed-password vectors, cross-checked against impacket (ntlm.NTOWFv1 + crypto.SamEncryptNTLMHash).
    private const string OldNt = "584146e8241bf8a12eab9df1d0c413cc"; // NtHash("OldPass1!")
    private const string NewNt = "49912ca506762d3107e2ebce04d14dbd"; // NtHash("NewPass2@")

    [Fact]
    public void NtHash_And_SamEncrypt_MatchImpacket()
    {
        Assert.Equal(OldNt, Convert.ToHexString(NtlmCrypto.NtHash("OldPass1!")).ToLowerInvariant());
        Assert.Equal(NewNt, Convert.ToHexString(NtlmCrypto.NtHash("NewPass2@")).ToLowerInvariant());

        // SamEncryptNTLMHash(oldNt, newNt) — the DES primitive that proves the old hash.
        byte[] enc = NtlmCrypto.SamEncryptNtlmHash(
            Convert.FromHexString(OldNt), Convert.FromHexString(NewNt));
        Assert.Equal("ce7cda1706343daabad708bbab59ea14", Convert.ToHexString(enc).ToLowerInvariant());
    }

    [Fact]
    public void EncodeUnicodeChangePassword_HasExpectedShapeAndCrypto()
    {
        byte[] stub = Samr.EncodeUnicodeChangePassword("pwchange", "OldPass1!", "NewPass2@");

        // Same total length as impacket's request (deterministic: no random salt in the buffers).
        Assert.Equal(616, stub.Length);

        // Tail: OldNtOwfPasswordEncryptedWithNewNt (16), LmPresent (0) + 3 pad, two NULL referents.
        Assert.Equal(
            "ce7cda1706343daabad708bbab59ea14000000000000000000000000",
            Convert.ToHexString(stub[^28..]).ToLowerInvariant());
    }
}
