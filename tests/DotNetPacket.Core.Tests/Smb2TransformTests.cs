using System.Security.Cryptography;
using DotNetPacket.Protocols.Smb;
using Xunit;

namespace DotNetPacket.Core.Tests;

/// <summary>
/// SMB 3.x message encryption (<see cref="Smb2Transform"/>, MS-SMB2 2.2.41 / 3.1.4.3). The client and
/// server derive mirrored key pairs (the client's encrypt key is the server's decrypt key); these pin
/// that a message round-trips across that mirror for every negotiated cipher, that the header is a
/// well-formed TRANSFORM_HEADER, and that the AEAD tag rejects tampering. The on-the-wire interop
/// (Samba decrypting our messages and vice-versa) is validated live.
/// </summary>
public class Smb2TransformTests
{
    private static (Smb2Transform Client, Smb2Transform Server) Pair(ushort cipher)
    {
        int bytes = Smb2Transform.KeyBits(cipher) / 8;
        byte[] c2s = RandomNumberGenerator.GetBytes(bytes); // client encrypts / server decrypts
        byte[] s2c = RandomNumberGenerator.GetBytes(bytes); // server encrypts / client decrypts
        const ulong sid = 0x1122334455667788;
        return (new Smb2Transform(c2s, s2c, cipher, sid), new Smb2Transform(s2c, c2s, cipher, sid));
    }

    [Theory]
    [InlineData(Smb2Cipher.Aes128Ccm)]
    [InlineData(Smb2Cipher.Aes128Gcm)]
    [InlineData(Smb2Cipher.Aes256Ccm)]
    [InlineData(Smb2Cipher.Aes256Gcm)]
    public void Encrypt_ThenPeerDecrypt_RoundTrips(ushort cipher)
    {
        (Smb2Transform client, Smb2Transform server) = Pair(cipher);
        byte[] plain = RandomNumberGenerator.GetBytes(137); // not block-aligned

        byte[] wire = client.Encrypt(plain);
        byte[] back = server.Decrypt(wire);

        Assert.Equal(plain, back);
    }

    [Fact]
    public void Encrypt_ProducesTransformHeader()
    {
        (Smb2Transform client, _) = Pair(Smb2Cipher.Aes128Gcm);
        byte[] plain = new byte[64];

        byte[] wire = client.Encrypt(plain);

        Assert.True(Smb2Transform.IsEncrypted(wire));          // 0xFD 'S' 'M' 'B'
        Assert.Equal(52 + plain.Length, wire.Length);          // 52-byte header + ciphertext
        Assert.Equal((uint)plain.Length,                        // OriginalMessageSize at offset 36
            System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(wire.AsSpan(36, 4)));
    }

    [Fact]
    public void Decrypt_TamperedCiphertext_Throws()
    {
        (Smb2Transform client, Smb2Transform server) = Pair(Smb2Cipher.Aes128Gcm);
        byte[] wire = client.Encrypt(RandomNumberGenerator.GetBytes(80));

        wire[^1] ^= 0xFF; // flip a ciphertext byte

        Assert.Throws<AuthenticationTagMismatchException>(() => server.Decrypt(wire));
    }

    [Fact]
    public void Decrypt_TamperedHeaderAad_Throws()
    {
        (Smb2Transform client, Smb2Transform server) = Pair(Smb2Cipher.Aes128Gcm);
        byte[] wire = client.Encrypt(RandomNumberGenerator.GetBytes(80));

        wire[44] ^= 0x01; // flip a SessionId byte (part of the AEAD associated data)

        Assert.Throws<AuthenticationTagMismatchException>(() => server.Decrypt(wire));
    }

    [Theory]
    [InlineData(Smb2Cipher.Aes128Ccm, 128)]
    [InlineData(Smb2Cipher.Aes256Gcm, 256)]
    [InlineData((ushort)0, 0)]
    public void KeyBits_MapsCipherToKeyLength(ushort cipher, int expected)
    {
        Assert.Equal(expected, Smb2Transform.KeyBits(cipher));
    }
}
