using System.Buffers.Binary;
using System.Security.Cryptography;

namespace DotNetPacket.Protocols.Smb;

/// <summary>
/// SMB 3.x message encryption: the SMB2 TRANSFORM_HEADER (MS-SMB2 2.2.41) plus AES-CCM / AES-GCM
/// authenticated encryption of a whole SMB2 message (MS-SMB2 3.1.4.3 / 3.2.4.1.1). Port of impacket's
/// <c>smb3.SMB3.encryptData</c> / <c>decryptData</c>. An encrypted PDU is a 52-byte transform header
/// (the 16-byte AEAD tag lives in its Signature field) followed by the ciphertext; the nonce and the
/// header fields after it are the AEAD associated data, so a flipped bit anywhere fails the tag.
/// </summary>
/// <remarks>
/// One instance per session: it holds the derived client→server (encrypt) and server→client (decrypt)
/// keys and a per-message nonce counter. AES-GCM uses an 11-byte nonce here (matching Windows/impacket,
/// which zero the 12th byte to avoid colliding with the CCM layout); AES-CCM uses an 11-byte nonce too.
/// Both carry a 16-byte tag. The nonce field on the wire is 16 bytes, left-aligned and zero-padded.
/// </remarks>
public sealed class Smb2Transform
{
    /// <summary>TRANSFORM_HEADER ProtocolId: 0xFD 'S' 'M' 'B'.</summary>
    public static readonly byte[] ProtocolId = { 0xFD, 0x53, 0x4D, 0x42 };

    private const int HeaderSize = 52;
    private const int NonceFieldSize = 16;
    private const int TagSize = 16;
    private const ushort EncryptedFlag = 0x0001; // SMB 3.1.1 Flags = Encrypted

    private readonly byte[] _encryptKey;
    private readonly byte[] _decryptKey;
    private readonly bool _gcm;
    private readonly int _nonceLength;  // AES-GCM requires a 12-byte nonce; SMB AES-CCM uses 11
    private readonly ulong _sessionId;
    private ulong _nonceCounter;

    public Smb2Transform(byte[] encryptKey, byte[] decryptKey, ushort cipher, ulong sessionId)
    {
        _encryptKey = encryptKey;
        _decryptKey = decryptKey;
        _gcm = cipher is Smb2Cipher.Aes128Gcm or Smb2Cipher.Aes256Gcm;
        _nonceLength = _gcm ? 12 : 11;
        _sessionId = sessionId;
    }

    /// <summary>The key length (bits) a cipher id uses, for key derivation. 0 if not an encryption cipher.</summary>
    public static int KeyBits(ushort cipher) => cipher switch
    {
        Smb2Cipher.Aes128Ccm or Smb2Cipher.Aes128Gcm => 128,
        Smb2Cipher.Aes256Ccm or Smb2Cipher.Aes256Gcm => 256,
        _ => 0,
    };

    /// <summary>Wraps one plaintext SMB2 message into a TRANSFORM_HEADER + ciphertext (client→server).</summary>
    public byte[] Encrypt(byte[] plain)
    {
        var nonce = new byte[NonceFieldSize];
        BinaryPrimitives.WriteUInt64LittleEndian(nonce, ++_nonceCounter);

        byte[] header = BuildHeader(nonce, plain.Length);
        byte[] aad = header[20..HeaderSize];   // Nonce .. SessionId (the Signature field is excluded)

        var cipherText = new byte[plain.Length];
        var tag = new byte[TagSize];
        byte[] shortNonce = nonce[.._nonceLength];

        if (_gcm)
        {
            using var gcm = new AesGcm(_encryptKey, TagSize);
            gcm.Encrypt(shortNonce, plain, cipherText, tag, aad);
        }
        else
        {
            using var ccm = new AesCcm(_encryptKey);
            ccm.Encrypt(shortNonce, plain, cipherText, tag, aad);
        }

        Array.Copy(tag, 0, header, 4, TagSize); // Signature field

        var outBuf = new byte[HeaderSize + cipherText.Length];
        Array.Copy(header, outBuf, HeaderSize);
        Array.Copy(cipherText, 0, outBuf, HeaderSize, cipherText.Length);
        return outBuf;
    }

    /// <summary>True if <paramref name="message"/> starts with the TRANSFORM_HEADER ProtocolId (0xFD'SMB').</summary>
    public static bool IsEncrypted(byte[] message) =>
        message.Length >= 4 && message[0] == 0xFD && message[1] == 0x53 && message[2] == 0x4D && message[3] == 0x42;

    /// <summary>Unwraps a TRANSFORM_HEADER + ciphertext back to the plaintext SMB2 message (server→client).</summary>
    public byte[] Decrypt(byte[] message)
    {
        if (message.Length < HeaderSize || !IsEncrypted(message))
        {
            throw new InvalidDataException("Not an SMB2 TRANSFORM_HEADER message.");
        }

        byte[] tag = message[4..20];
        byte[] shortNonce = message[20..(20 + _nonceLength)];
        int originalSize = BinaryPrimitives.ReadInt32LittleEndian(message.AsSpan(36, 4));
        byte[] aad = message[20..HeaderSize];
        byte[] cipherText = message[HeaderSize..];

        var plain = new byte[cipherText.Length];
        if (_gcm)
        {
            using var gcm = new AesGcm(_decryptKey, TagSize);
            gcm.Decrypt(shortNonce, cipherText, tag, plain, aad);
        }
        else
        {
            using var ccm = new AesCcm(_decryptKey);
            ccm.Decrypt(shortNonce, cipherText, tag, plain, aad);
        }

        // OriginalMessageSize should equal the plaintext length; trust the AEAD result and clamp defensively.
        return originalSize == plain.Length ? plain : plain[..originalSize];
    }

    // TRANSFORM_HEADER: ProtocolId(4) Signature(16, filled later) Nonce(16) OriginalMessageSize(4)
    // Reserved(2) Flags(2) SessionId(8).
    private byte[] BuildHeader(byte[] nonce, int originalSize)
    {
        var h = new byte[HeaderSize];
        Array.Copy(ProtocolId, h, 4);
        // Signature (offset 4..20) left zero until the tag is known.
        Array.Copy(nonce, 0, h, 20, NonceFieldSize);
        BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(36, 4), (uint)originalSize); // OriginalMessageSize
        // Reserved (offset 40..42) stays 0.
        BinaryPrimitives.WriteUInt16LittleEndian(h.AsSpan(42, 2), EncryptedFlag);      // Flags = Encrypted
        BinaryPrimitives.WriteUInt64LittleEndian(h.AsSpan(44, 8), _sessionId);         // SessionId
        return h;
    }
}
