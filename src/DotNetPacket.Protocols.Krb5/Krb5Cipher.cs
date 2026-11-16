using System.Security.Cryptography;

namespace DotNetPacket.Protocols.Krb5;

/// <summary>
/// Dispatches Kerberos encryption, decryption, keyed checksums and string-to-key to the right
/// encryption profile by etype: RC4-HMAC (23, <see cref="Krb5Crypto"/>), aes128-cts-hmac-sha1-96 (17)
/// and aes256-cts-hmac-sha1-96 (18, <see cref="AesCtsCrypto"/>). This is the single place the rest of
/// the Kerberos stack (AS-REQ, TGS-REQ, AP-REQ, AS-REP/TGS-REP decrypt) selects crypto, so every path
/// works for whichever etype the KDC negotiates — matching impacket, whose default is AES-256.
/// </summary>
public static class Krb5Cipher
{
    /// <summary>True if this etype is one of the profiles we implement (RC4 / AES-128 / AES-256).</summary>
    public static bool IsSupported(int etype) => etype is Krb5Constants.Rc4Hmac
        or Krb5Constants.Aes128CtsHmacSha1 or Krb5Constants.Aes256CtsHmacSha1;

    /// <summary>Base-key length in bytes for an etype (RC4/AES-128 = 16, AES-256 = 32).</summary>
    public static int KeySize(int etype) => etype switch
    {
        Krb5Constants.Aes256CtsHmacSha1 => 32,
        _ => 16,
    };

    /// <summary>Confounder length in bytes: RC4 uses 8 (one DES block era), AES uses 16 (the AES block).</summary>
    public static int ConfounderSize(int etype) => etype == Krb5Constants.Rc4Hmac ? 8 : 16;

    /// <summary>A fresh random confounder sized for the etype.</summary>
    public static byte[] NewConfounder(int etype) => RandomNumberGenerator.GetBytes(ConfounderSize(etype));

    /// <summary>
    /// impacket's etype preference when choosing from the KDC's ETYPE-INFO2 list: AES-256, then
    /// AES-128, then RC4. Higher is preferred; 0 for an etype we do not support.
    /// </summary>
    public static int Preference(int etype) => etype switch
    {
        Krb5Constants.Aes256CtsHmacSha1 => 3,
        Krb5Constants.Aes128CtsHmacSha1 => 2,
        Krb5Constants.Rc4Hmac => 1,
        _ => 0,
    };

    /// <summary>The keyed-checksum type that pairs with an etype's authenticator (RC4 -138, AES-128 15, AES-256 16).</summary>
    public static int ChecksumType(int etype) => etype switch
    {
        Krb5Constants.Rc4Hmac => Krb5Constants.Rc4HmacChecksumType,
        Krb5Constants.Aes128CtsHmacSha1 => Krb5Constants.HmacSha1Aes128ChecksumType,
        Krb5Constants.Aes256CtsHmacSha1 => Krb5Constants.HmacSha1Aes256ChecksumType,
        _ => throw Unsupported(etype),
    };

    /// <summary>Encrypts with <paramref name="etype"/>. A null confounder means a fresh random one (the live path).</summary>
    public static byte[] Encrypt(int etype, byte[] key, int usage, byte[] plaintext, byte[]? confounder = null) => etype switch
    {
        Krb5Constants.Rc4Hmac => Krb5Crypto.Encrypt(key, usage, plaintext, confounder ?? RandomNumberGenerator.GetBytes(8)),
        Krb5Constants.Aes128CtsHmacSha1 or Krb5Constants.Aes256CtsHmacSha1 => AesCtsCrypto.Encrypt(key, usage, plaintext, confounder),
        _ => throw Unsupported(etype),
    };

    /// <summary>Decrypts with <paramref name="etype"/>, verifying the integrity checksum.</summary>
    public static byte[] Decrypt(int etype, byte[] key, int usage, byte[] ciphertext) => etype switch
    {
        Krb5Constants.Rc4Hmac => Krb5Crypto.Decrypt(key, usage, ciphertext),
        Krb5Constants.Aes128CtsHmacSha1 or Krb5Constants.Aes256CtsHmacSha1 => AesCtsCrypto.Decrypt(key, usage, ciphertext),
        _ => throw Unsupported(etype),
    };

    /// <summary>The keyed checksum over <paramref name="text"/> for the authenticator (TGS-REQ req-body, usage 6).</summary>
    public static byte[] Checksum(int etype, byte[] key, int usage, byte[] text) => etype switch
    {
        Krb5Constants.Rc4Hmac => Krb5Crypto.Rc4HmacChecksum(key, usage, text),
        Krb5Constants.Aes128CtsHmacSha1 or Krb5Constants.Aes256CtsHmacSha1 => AesCtsCrypto.Checksum(key, usage, text),
        _ => throw Unsupported(etype),
    };

    /// <summary>
    /// Derives the long-term key from a password. For RC4 the salt and iteration count are ignored (the
    /// key is the NT hash); for AES the salt and iteration count come from the KDC's ETYPE-INFO2.
    /// </summary>
    public static byte[] StringToKey(int etype, string password, byte[] salt, int iterations) => etype switch
    {
        Krb5Constants.Rc4Hmac => Krb5Crypto.Rc4StringToKey(password),
        Krb5Constants.Aes128CtsHmacSha1 => AesCtsCrypto.StringToKey(password, salt, iterations, 16),
        Krb5Constants.Aes256CtsHmacSha1 => AesCtsCrypto.StringToKey(password, salt, iterations, 32),
        _ => throw Unsupported(etype),
    };

    private static NotSupportedException Unsupported(int etype) =>
        new($"Kerberos etype {etype} is not supported (implemented: RC4-HMAC 23, AES128 17, AES256 18).");
}
