using System.Security.Cryptography;
using System.Text;
using DotNetPacket.Protocols.Ntlm;

namespace DotNetPacket.Protocols.Krb5;

/// <summary>
/// The RC4-HMAC Kerberos encryption profile (RFC 4757), ported from impacket's
/// <c>impacket.krb5.crypto._RC4</c>. The long-term key is the NT hash (MD4 of the UTF-16LE
/// password); encryption/decryption and the key-usage number mapping follow RFC 4757. Reuses
/// <see cref="NtlmCrypto"/> for MD4 / HMAC-MD5 / RC4 (the NTLM stack already implements them).
/// AES profiles (RFC 3962) are not ported; the lab KDC accepts RC4, which keeps this tractable.
/// </summary>
public static class Krb5Crypto
{
    /// <summary>RC4-HMAC string-to-key: the NT hash (MD4 of the UTF-16LE password).</summary>
    public static byte[] Rc4StringToKey(string password) => NtlmCrypto.NtHash(password);

    /// <summary>
    /// RC4-HMAC encrypt (RFC 4757 section 5). <paramref name="confounder"/> is the 8-byte random
    /// prefix (pass a fixed value for deterministic tests). Returns checksum(16) || RC4(confounder||plaintext).
    /// </summary>
    public static byte[] Encrypt(byte[] key, int keyUsage, byte[] plaintext, byte[] confounder)
    {
        byte[] ki = NtlmCrypto.HmacMd5(key, UsageStr(keyUsage));
        byte[] data = Concat(confounder, plaintext);
        byte[] cksum = NtlmCrypto.HmacMd5(ki, data);
        byte[] ke = NtlmCrypto.HmacMd5(ki, cksum);
        return Concat(cksum, NtlmCrypto.Rc4(ke, data));
    }

    /// <summary>RC4-HMAC decrypt: verifies the HMAC checksum and strips the 8-byte confounder.</summary>
    public static byte[] Decrypt(byte[] key, int keyUsage, byte[] ciphertext)
    {
        if (ciphertext.Length < 24)
        {
            throw new InvalidDataException("RC4-HMAC ciphertext too short.");
        }

        byte[] cksum = ciphertext[..16];
        byte[] basic = ciphertext[16..];
        byte[] ki = NtlmCrypto.HmacMd5(key, UsageStr(keyUsage));
        byte[] ke = NtlmCrypto.HmacMd5(ki, cksum);
        byte[] plaintext = NtlmCrypto.Rc4(ke, basic);

        byte[] expected = NtlmCrypto.HmacMd5(ki, plaintext);
        if (!CryptographicEquals(expected, cksum))
        {
            throw new InvalidDataException("RC4-HMAC integrity check failed (wrong key / password).");
        }

        return plaintext[8..]; // drop the confounder
    }

    /// <summary>
    /// RC4-HMAC keyed checksum (HMAC-MD5, cksumtype -138; RFC 4757 section 4), ported from
    /// impacket's <c>_HMACMD5.checksum</c>. Used for the TGS-REQ authenticator checksum over the
    /// KDC-REQ-BODY (key usage 6), which the Heimdal/Samba KDC requires.
    /// </summary>
    public static byte[] Rc4HmacChecksum(byte[] key, int keyUsage, byte[] text)
    {
        byte[] ksign = NtlmCrypto.HmacMd5(key, Encoding.ASCII.GetBytes("signaturekey\0"));
        byte[] md5hash = MD5.HashData(Concat(UsageStr(keyUsage), text));
        return NtlmCrypto.HmacMd5(ksign, md5hash);
    }

    // RFC 4757 key-usage mapping: 3 -> 8, 23 -> 13; everything else unchanged. Packed little-endian.
    internal static byte[] UsageStr(int keyUsage)
    {
        int ms = keyUsage switch { 3 => 8, 23 => 13, _ => keyUsage };
        return new[] { (byte)(ms & 0xFF), (byte)((ms >> 8) & 0xFF), (byte)((ms >> 16) & 0xFF), (byte)((ms >> 24) & 0xFF) };
    }

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var r = new byte[a.Length + b.Length];
        Array.Copy(a, 0, r, 0, a.Length);
        Array.Copy(b, 0, r, a.Length, b.Length);
        return r;
    }

    private static bool CryptographicEquals(byte[] a, byte[] b)
    {
        if (a.Length != b.Length)
        {
            return false;
        }

        int diff = 0;
        for (int i = 0; i < a.Length; i++)
        {
            diff |= a[i] ^ b[i];
        }

        return diff == 0;
    }
}
