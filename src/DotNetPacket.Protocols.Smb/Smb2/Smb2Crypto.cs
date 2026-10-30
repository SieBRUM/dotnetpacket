using System.Security.Cryptography;
using System.Text;

namespace DotNetPacket.Protocols.Smb;

/// <summary>
/// SMB 3.x cryptographic helpers: the SMB 3.1.1 preauth-integrity hash chain
/// (MS-SMB2 3.1.4.1), SP800-108 counter-mode key derivation (3.1.4.2), and
/// AES-128-CMAC request signing (RFC 4493 — the BCL has no CMAC).
/// </summary>
public static class Smb2Crypto
{
    private const int SignatureOffset = 48; // within the 64-byte SMB2 header
    private const int SignatureLength = 16;

    /// <summary>Initial preauth-integrity hash value: 64 zero bytes (SHA-512 width).</summary>
    public static byte[] PreauthInit() => new byte[64];

    /// <summary>Rolls the preauth hash forward with one message: SHA-512(current || message).</summary>
    public static byte[] PreauthUpdate(byte[] current, byte[] message) =>
        SHA512.HashData(Concat(current, message));

    /// <summary>SMB 3.1.1 signing key = KDF(SessionKey, "SMBSigningKey\0", preauthHash) (MS-SMB2 3.1.4.2).</summary>
    public static byte[] Smb311SigningKey(byte[] sessionKey, byte[] preauthHash) =>
        KdfCounterMode(Fit16(sessionKey), Encoding.ASCII.GetBytes("SMBSigningKey\0"), preauthHash, 128);

    /// <summary>
    /// SP800-108 counter-mode KDF with HMAC-SHA256. Fixed input is
    /// <c>i(4 BE) || label || 0x00 || context || L(4 BE)</c> (the 0x00 is the
    /// SP800-108 separator between label and context). Only single-block outputs
    /// (L &lt;= 256) are used here.
    /// </summary>
    public static byte[] KdfCounterMode(byte[] key, byte[] label, byte[] context, int lengthBits)
    {
        var input = new List<byte>();
        input.AddRange(BigEndian(1));
        input.AddRange(label);
        input.Add(0x00); // SP800-108 label/context separator
        input.AddRange(context);
        input.AddRange(BigEndian((uint)lengthBits));

        using var hmac = new HMACSHA256(key);
        byte[] prf = hmac.ComputeHash(input.ToArray());
        return prf[..(lengthBits / 8)];
    }

    /// <summary>
    /// Signs an SMB2 message in place: sets SMB2_FLAGS_SIGNED, zeroes the signature
    /// field, computes AES-128-CMAC over the whole message, and writes it back.
    /// </summary>
    public static byte[] Sign(byte[] signingKey, byte[] message)
    {
        var signed = (byte[])message.Clone();

        // Set SMB2_FLAGS_SIGNED (header Flags is a little-endian uint at offset 16).
        signed[16] |= (byte)Smb2HeaderFlags.Signed;

        // Zero the signature field before computing the MAC.
        Array.Clear(signed, SignatureOffset, SignatureLength);
        byte[] mac = AesCmac(signingKey, signed);
        Array.Copy(mac, 0, signed, SignatureOffset, SignatureLength);
        return signed;
    }

    /// <summary>Verifies an SMB2 message signature (recomputes the CMAC over a zeroed-signature copy).</summary>
    public static bool Verify(byte[] signingKey, byte[] message)
    {
        if (message.Length < SignatureOffset + SignatureLength)
        {
            return false;
        }

        var expected = new byte[SignatureLength];
        Array.Copy(message, SignatureOffset, expected, 0, SignatureLength);

        var copy = (byte[])message.Clone();
        Array.Clear(copy, SignatureOffset, SignatureLength);
        byte[] actual = AesCmac(signingKey, copy);

        return CryptographicOperations.FixedTimeEquals(expected, actual);
    }

    /// <summary>AES-128-CMAC (RFC 4493).</summary>
    public static byte[] AesCmac(byte[] key, byte[] message)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;

        byte[] zero = new byte[16];
        byte[] l = aes.EncryptEcb(zero, PaddingMode.None);
        byte[] k1 = LeftShiftWithRb(l);
        byte[] k2 = LeftShiftWithRb(k1);

        int blockCount = (message.Length + 15) / 16;
        bool lastComplete;
        if (blockCount == 0)
        {
            blockCount = 1;
            lastComplete = false;
        }
        else
        {
            lastComplete = message.Length % 16 == 0;
        }

        var lastBlock = new byte[16];
        int lastStart = (blockCount - 1) * 16;
        if (lastComplete)
        {
            Array.Copy(message, lastStart, lastBlock, 0, 16);
            Xor(lastBlock, k1);
        }
        else
        {
            int remaining = message.Length - lastStart;
            Array.Copy(message, lastStart, lastBlock, 0, remaining);
            lastBlock[remaining] = 0x80; // padding
            Xor(lastBlock, k2);
        }

        var x = new byte[16];
        for (int i = 0; i < blockCount - 1; i++)
        {
            var block = new byte[16];
            Array.Copy(message, i * 16, block, 0, 16);
            Xor(x, block);
            x = aes.EncryptEcb(x, PaddingMode.None);
        }

        Xor(x, lastBlock);
        return aes.EncryptEcb(x, PaddingMode.None);
    }

    private static byte[] LeftShiftWithRb(byte[] input)
    {
        var output = new byte[16];
        int carry = 0;
        for (int i = 15; i >= 0; i--)
        {
            int value = (input[i] << 1) | carry;
            output[i] = (byte)(value & 0xFF);
            carry = (value >> 8) & 0x01;
        }

        if ((input[0] & 0x80) != 0)
        {
            output[15] ^= 0x87; // Rb for 128-bit blocks
        }

        return output;
    }

    private static void Xor(byte[] target, byte[] other)
    {
        for (int i = 0; i < target.Length; i++)
        {
            target[i] ^= other[i];
        }
    }

    private static byte[] Fit16(byte[] key)
    {
        if (key.Length == 16)
        {
            return key;
        }

        var result = new byte[16];
        Array.Copy(key, result, Math.Min(key.Length, 16));
        return result;
    }

    private static byte[] BigEndian(uint value) =>
        new[] { (byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value };

    private static byte[] Concat(byte[] left, byte[] right)
    {
        var result = new byte[left.Length + right.Length];
        Array.Copy(left, 0, result, 0, left.Length);
        Array.Copy(right, 0, result, left.Length, right.Length);
        return result;
    }
}
