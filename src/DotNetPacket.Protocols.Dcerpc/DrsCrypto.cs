using System.Buffers.Binary;
using System.Security.Cryptography;
using DotNetPacket.Protocols.Ntlm;

namespace DotNetPacket.Protocols.Dcerpc;

/// <summary>
/// The replication-secret cryptography for DCSync, ported from impacket's
/// <c>dcerpc.v5.drsuapi</c> (<c>DecryptAttributeValue</c>, <c>deriveKey</c>,
/// <c>removeDESLayer</c>) and <c>examples/secretsdump.py</c>. Secret attributes come off
/// the wire in two wrappers: an outer <see cref="DecryptAttributeValue"/> layer keyed by
/// the DCERPC session key, and — for password hashes — an inner per-RID DES layer removed
/// by <see cref="RemoveDesLayer"/>.
/// </summary>
/// <remarks>
/// Outer layer (MS-DRSR 5.48.2, ENCRYPTED_PAYLOAD): <c>Salt(16) || RC4(CheckSum(4) ||
/// EncryptedData)</c>, where the RC4 key is <c>MD5(sessionKey || Salt)</c> and CheckSum is a
/// CRC-32 of the decrypted data. Inner layer (MS-SAMR 2.2.11.1): two single-DES blocks whose
/// keys are derived from the account RID. This file is decrypt-only and lab-first: it exists
/// to let the SOC observe and detect replication-based secret extraction, not to enable it.
/// </remarks>
public static class DrsCrypto
{
    /// <summary>
    /// Removes the outer ENCRYPTED_PAYLOAD layer of a replicated attribute value, returning the
    /// inner plaintext (the CRC-32 checksum prefix stripped). <paramref name="payload"/> is the
    /// raw attribute value: 16-byte Salt, 4-byte CheckSum, then the RC4-encrypted data.
    /// When <paramref name="verifyChecksum"/> is set, throws if the CRC-32 does not match.
    /// </summary>
    public static byte[] DecryptAttributeValue(byte[] sessionKey, byte[] payload, bool verifyChecksum = true)
    {
        if (payload.Length < 20)
        {
            throw new ArgumentException("ENCRYPTED_PAYLOAD too short (need Salt(16)+CheckSum(4)).", nameof(payload));
        }

        byte[] salt = payload[..16];
        byte[] rc4Key = Md5Concat(sessionKey, salt);
        byte[] clear = NtlmCrypto.Rc4(rc4Key, payload[16..]); // CheckSum(4) || data

        byte[] data = clear[4..];
        if (verifyChecksum)
        {
            uint stored = BinaryPrimitives.ReadUInt32LittleEndian(clear);
            uint actual = Crc32(data);
            if (stored != actual)
            {
                throw new InvalidDataException(
                    $"ENCRYPTED_PAYLOAD checksum mismatch (stored 0x{stored:X8}, computed 0x{actual:X8}).");
            }
        }

        return data;
    }

    /// <summary>
    /// Removes the inner per-RID DES layer from a 16-byte encrypted hash (MS-SAMR 2.2.11.1.3 /
    /// impacket <c>removeDESLayer</c>): two single-DES ECB decrypts under keys derived from the
    /// account's RID. Used for unicodePwd, dBCSPwd, and the password-history blobs.
    /// </summary>
    public static byte[] RemoveDesLayer(byte[] encryptedHash16, uint rid)
    {
        if (encryptedHash16.Length != 16)
        {
            throw new ArgumentException("Encrypted hash must be 16 bytes.", nameof(encryptedHash16));
        }

        (byte[] key1, byte[] key2) = DeriveKey(rid);
        byte[] first = NtlmCrypto.DesDecryptBlock(key1, encryptedHash16[..8]);
        byte[] second = NtlmCrypto.DesDecryptBlock(key2, encryptedHash16[8..]);
        return first.Concat(second).ToArray();
    }

    /// <summary>
    /// Derives the two 8-byte DES keys from a little-endian RID (MS-SAMR 2.2.11.1.3): the RID's
    /// four bytes are shuffled into two 7-byte seeds, then each is parity-expanded to 8 bytes.
    /// </summary>
    public static (byte[] Key1, byte[] Key2) DeriveKey(uint rid)
    {
        Span<byte> i = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(i, rid);
        byte[] seed1 = { i[0], i[1], i[2], i[3], i[0], i[1], i[2] };
        byte[] seed2 = { i[3], i[0], i[1], i[2], i[3], i[0], i[1] };
        return (NtlmCrypto.ExpandDesKey(seed1), NtlmCrypto.ExpandDesKey(seed2));
    }

    /// <summary>CRC-32 (IEEE 802.3, reflected, poly 0xEDB88320) — the ENCRYPTED_PAYLOAD checksum.</summary>
    public static uint Crc32(byte[] data)
    {
        uint crc = 0xFFFFFFFF;
        foreach (byte b in data)
        {
            crc ^= b;
            for (int k = 0; k < 8; k++)
            {
                crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320 : crc >> 1;
            }
        }

        return ~crc;
    }

    private static byte[] Md5Concat(byte[] a, byte[] b)
    {
        using var md5 = MD5.Create();
        md5.TransformBlock(a, 0, a.Length, null, 0);
        md5.TransformFinalBlock(b, 0, b.Length);
        return md5.Hash!;
    }
}
