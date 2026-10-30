using NetPacket.Protocols.Ntlm;
using Xunit;

namespace NetPacket.Core.Tests;

public class DcerpcAuthTests
{
    // Golden vectors extracted from impacket's ntlm module with a fixed exported
    // session key and the extended-session-security + key-exchange flag set (the
    // shape a Windows RPC client negotiates for sign/seal). These pin the GSS
    // sign/seal math byte-for-byte; the live rpc-shares-sealed example validates the
    // full on-the-wire exchange against a server.
    private static readonly byte[] Esk = Convert.FromHexString("0123456789abcdef0123456789abcdef");
    private static readonly byte[] Message = Convert.FromHexString("6d0100000100000000000000010000000000abab");
    private static readonly byte[] Message2 = Convert.FromHexString("deadbeefcafe00112233445566778899aabbccdd");

    [Fact]
    public void SignAndSealKeys_MatchImpacket()
    {
        Assert.Equal("3a87f8467278fcd3b14b970cec740793", Hex(NtlmCrypto.SignKey(Esk, clientToServer: true)));
        Assert.Equal("4098adbe51df22352f011a4533cc5edb", Hex(NtlmCrypto.SealKey(Esk, clientToServer: true)));
        Assert.Equal("0d6191e275fba7ac677438fa19e6b081", Hex(NtlmCrypto.SignKey(Esk, clientToServer: false)));
        Assert.Equal("71b2a70caf0623866a1f1be5c0318739", Hex(NtlmCrypto.SealKey(Esk, clientToServer: false)));
    }

    [Fact]
    public void Wrap_Integrity_SignsWithoutSealingAndAdvancesSequence()
    {
        var ctx = new NtlmSecurityContext(Esk);

        (byte[] sealed0, byte[] sig0) = ctx.Wrap(Message, toSeal: null);
        Assert.Empty(sealed0); // integrity does not encrypt the body
        Assert.Equal("01000000fcd86d5313ffe69900000000", Hex(sig0));

        (_, byte[] sig1) = ctx.Wrap(Message, toSeal: null);
        Assert.Equal("01000000e67d21da364f8be801000000", Hex(sig1));
    }

    [Fact]
    public void Wrap_Privacy_SealsBodyAndSignsOnOneKeystream()
    {
        var ctx = new NtlmSecurityContext(Esk);

        (byte[] data0, byte[] sig0) = ctx.Wrap(Message, toSeal: Message);
        Assert.Equal("7a23d105ca943c26f698ea97b64303d2f8b13f59", Hex(data0));
        Assert.Equal("0100000050620e5ba5a5e79b00000000", Hex(sig0));

        (byte[] data1, byte[] sig1) = ctx.Wrap(Message2, toSeal: Message2);
        Assert.Equal("a9aa9f757439a0e24ae4b41181156dd756784e92", Hex(data1));
        Assert.Equal("01000000e7899768edb4cd0901000000", Hex(sig1));
    }

    [Fact]
    public void UnsealAndVerify_Privacy_DecryptsAndVerifiesServerMessage()
    {
        var ctx = new NtlmSecurityContext(Esk);
        byte[] sealedBody = Convert.FromHexString("f71806251541f23d3cd1a8ac");
        byte[] signature = Convert.FromHexString("01000000fae296db16dec2e600000000");

        byte[] plain = ctx.Unseal(sealedBody);
        ctx.Verify(plain, signature); // must not throw

        Assert.Equal("cafebabe0011223344556677", Hex(plain));
    }

    [Fact]
    public void Verify_RejectsTamperedSignature()
    {
        var ctx = new NtlmSecurityContext(Esk);
        byte[] sealedBody = Convert.FromHexString("f71806251541f23d3cd1a8ac");
        byte[] bad = Convert.FromHexString("01000000ffffffffffffffff00000000");

        byte[] plain = ctx.Unseal(sealedBody);
        Assert.Throws<InvalidDataException>(() => ctx.Verify(plain, bad));
    }

    private static string Hex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();
}
