using NetPacket.Protocols.Smb;
using Xunit;

namespace NetPacket.Core.Tests;

public class Smb2CryptoTests
{
    private static byte[] Hex(string hex) => Convert.FromHexString(hex.Replace(" ", string.Empty));

    private static string Hex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    // RFC 4493 AES-128-CMAC test vectors (key 2b7e1516...).
    private static readonly byte[] CmacKey = Hex("2b7e151628aed2a6abf7158809cf4f3c");

    [Fact]
    public void AesCmac_EmptyMessage()
    {
        Assert.Equal("bb1d6929e95937287fa37d129b756746", Hex(Smb2Crypto.AesCmac(CmacKey, Array.Empty<byte>())));
    }

    [Fact]
    public void AesCmac_OneBlock()
    {
        byte[] message = Hex("6bc1bee22e409f96e93d7e117393172a");
        Assert.Equal("070a16b46b4d4144f79bdd9dd04a287c", Hex(Smb2Crypto.AesCmac(CmacKey, message)));
    }

    [Fact]
    public void AesCmac_PartialBlock()
    {
        byte[] message = Hex("6bc1bee22e409f96e93d7e117393172aae2d8a57");
        Assert.Equal("7d85449ea6ea19c823a7bf78837dfade", Hex(Smb2Crypto.AesCmac(CmacKey, message)));
    }

    [Fact]
    public void Sign_SetsFlagAndFillsSignature()
    {
        var message = new byte[128];
        message[0] = 0xFE; // a token SMB2 header start
        byte[] key = Hex("000102030405060708090a0b0c0d0e0f");

        byte[] signed = Smb2Crypto.Sign(key, message);

        Assert.Equal((byte)Smb2HeaderFlags.Signed, (byte)(signed[16] & (byte)Smb2HeaderFlags.Signed));
        byte[] signature = signed[48..64];
        Assert.Contains(signature, b => b != 0);
        Assert.True(Smb2Crypto.Verify(key, signed));
    }

    [Fact]
    public void Preauth_IsOrderDependent()
    {
        byte[] start = Smb2Crypto.PreauthInit();
        Assert.Equal(64, start.Length);

        byte[] a = Smb2Crypto.PreauthUpdate(Smb2Crypto.PreauthUpdate(start, new byte[] { 1 }), new byte[] { 2 });
        byte[] b = Smb2Crypto.PreauthUpdate(Smb2Crypto.PreauthUpdate(start, new byte[] { 2 }), new byte[] { 1 });
        Assert.NotEqual(Hex(a), Hex(b));
    }
}
