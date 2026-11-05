using System.Security.Cryptography;
using System.Text;

namespace DotNetPacket.Protocols.Gpp;

/// <summary>
/// Decrypts Group Policy Preferences "cpassword" blobs (MS-GPPREF). GPP stored credentials
/// in SYSVOL XML, AES-256-CBC-encrypted under a <b>key Microsoft published in the protocol
/// documentation</b> with a fixed all-zero IV — so any domain-reader can recover them. The
/// feature was removed in MS14-025 (2014); finding a cpassword is a misconfiguration /
/// detection signal, not a secret. Port of the <c>decrypt_password</c> routine in impacket's
/// <c>examples/Get-GPPPassword.py</c>.
/// </summary>
public static class GppCrypto
{
    // The 32-byte AES key published by Microsoft in [MS-GPPREF] 2.2.1.1.3 (section cited in
    // the impacket source). Public by design; decrypting GPP cpassword needs no secret.
    private static readonly byte[] PublishedKey =
    {
        0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9, 0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8,
        0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90, 0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b,
    };

    /// <summary>
    /// Decrypts a base64 cpassword value to its UTF-16LE plaintext. Returns an empty string
    /// for an empty input (as impacket does). The base64 is re-padded the same way impacket
    /// does before decoding.
    /// </summary>
    public static string DecryptCpassword(string cpasswordBase64)
    {
        if (string.IsNullOrEmpty(cpasswordBase64))
        {
            return string.Empty;
        }

        string b64 = FixBase64Padding(cpasswordBase64);
        byte[] ciphertext = Convert.FromBase64String(b64);

        using var aes = Aes.Create();
        aes.Key = PublishedKey;
        aes.IV = new byte[16];            // Microsoft's fixed all-zero IV
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;  // GPP pads with PKCS7

        using ICryptoTransform decryptor = aes.CreateDecryptor();
        byte[] plaintext = decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
        return Encoding.Unicode.GetString(plaintext);
    }

    // GPP cpassword base64 is often stored without correct padding. impacket: if len % 4 == 1,
    // drop the last char; if 2 or 3, pad with '=' up to a multiple of 4.
    private static string FixBase64Padding(string b64)
    {
        int pad = b64.Length % 4;
        if (pad == 1)
        {
            return b64[..^1];
        }

        if (pad is 2 or 3)
        {
            return b64 + new string('=', 4 - pad);
        }

        return b64;
    }
}
