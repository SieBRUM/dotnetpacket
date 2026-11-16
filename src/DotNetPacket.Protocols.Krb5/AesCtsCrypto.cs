using System.Security.Cryptography;
using System.Text;

namespace DotNetPacket.Protocols.Krb5;

/// <summary>
/// The AES-CTS-HMAC-SHA1-96 Kerberos encryption profiles (RFC 3962, building on RFC 3961):
/// <c>aes128-cts-hmac-sha1-96</c> (etype 17) and <c>aes256-cts-hmac-sha1-96</c> (etype 18). The key
/// size is taken from the base key length (16 -&gt; AES-128, 32 -&gt; AES-256). Ported from impacket's
/// <c>impacket.krb5.crypto._AESEnctype</c> / <c>_SHA1AES128</c> / <c>_SHA1AES256</c> and the
/// RFC 3961 <c>_nfold</c> / derive-key helpers, so the on-wire ciphertext matches stock impacket.
/// This is the modern default both Active Directory and Samba prefer; porting it is what lets the
/// Kerberos (<c>-k</c>) path match impacket's default enctype on the wire.
/// </summary>
public static class AesCtsCrypto
{
    private const int BlockSize = 16;

    // The derive-key base constant for string-to-key: the ASCII string "kerberos".
    private static readonly byte[] KerberosConstant = Encoding.ASCII.GetBytes("kerberos");

    /// <summary>Default PBKDF2 iteration count when the KDC supplies no s2kparams (RFC 3962).</summary>
    public const int DefaultIterations = 4096;

    /// <summary>
    /// RFC 3962 string-to-key: <c>DK(PBKDF2-HMAC-SHA1(password, salt, iter, keySize), "kerberos")</c>.
    /// <paramref name="keySize"/> is 16 (AES-128) or 32 (AES-256). random-to-key is the identity for AES.
    /// </summary>
    public static byte[] StringToKey(string password, byte[] salt, int iterations, int keySize)
    {
        byte[] tkey = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password), salt, iterations, HashAlgorithmName.SHA1, keySize);
        return DK(tkey, KerberosConstant, keySize);
    }

    /// <summary>
    /// RFC 3961 derive-key: <c>DK(key, constant) = random-to-key(DR(key, constant))</c>. DR encrypts the
    /// n-folded constant repeatedly under the base key (CBC with a zero IV; each block feeds the next)
    /// until <paramref name="keySize"/> bytes are produced.
    /// </summary>
    public static byte[] DK(byte[] key, byte[] constant, int keySize)
    {
        byte[] block = Nfold(constant, BlockSize);
        var outBuf = new byte[keySize];
        int filled = 0;
        while (filled < keySize)
        {
            block = EcbEncryptBlock(key, block);
            int take = Math.Min(BlockSize, keySize - filled);
            Array.Copy(block, 0, outBuf, filled, take);
            filled += take;
        }

        return outBuf;
    }

    /// <summary>
    /// AES-CTS-HMAC-SHA1-96 encrypt (RFC 3962 section 6): with <c>Ke = DK(key, usage|0xAA)</c> and
    /// <c>Ki = DK(key, usage|0x55)</c>, returns <c>AES-CTS(Ke, confounder||plaintext) || HMAC-SHA1(Ki, …)[:12]</c>.
    /// Pass a fixed <paramref name="confounder"/> (16 bytes) for deterministic tests; otherwise one is random.
    /// </summary>
    public static byte[] Encrypt(byte[] baseKey, int usage, byte[] plaintext, byte[]? confounder = null)
    {
        byte[] ke = DK(baseKey, UsageConstant(usage, 0xAA), baseKey.Length);
        byte[] ki = DK(baseKey, UsageConstant(usage, 0x55), baseKey.Length);
        confounder ??= RandomNumberGenerator.GetBytes(BlockSize);

        byte[] data = Concat(confounder, plaintext);
        byte[] ctext = CtsEncrypt(ke, data);
        byte[] mac = HmacSha1_96(ki, data); // RFC 3961 5.3: HMAC over the plaintext (conf|plaintext), not the ciphertext
        return Concat(ctext, mac);
    }

    /// <summary>AES-CTS-HMAC-SHA1-96 decrypt: verifies the truncated HMAC, then strips the 16-byte confounder.</summary>
    public static byte[] Decrypt(byte[] baseKey, int usage, byte[] ciphertext)
    {
        if (ciphertext.Length < BlockSize + 12)
        {
            throw new InvalidDataException("AES-CTS ciphertext too short.");
        }

        byte[] ke = DK(baseKey, UsageConstant(usage, 0xAA), baseKey.Length);
        byte[] ki = DK(baseKey, UsageConstant(usage, 0x55), baseKey.Length);

        byte[] ctext = ciphertext[..^12];
        byte[] mac = ciphertext[^12..];
        byte[] data = CtsDecrypt(ke, ctext);

        // RFC 3961 5.3: the HMAC is taken over the recovered plaintext (conf|plaintext), not the ciphertext.
        byte[] expected = HmacSha1_96(ki, data);
        if (!FixedEquals(expected, mac))
        {
            throw new InvalidDataException("AES-CTS integrity check failed (wrong key / password).");
        }

        return data[BlockSize..]; // drop the confounder
    }

    /// <summary>
    /// HMAC-SHA1-96-AES keyed checksum (RFC 3962; cksumtype 15 for AES-128, 16 for AES-256): the first
    /// 96 bits of <c>HMAC-SHA1(DK(key, usage|0x99), text)</c>. Used for the TGS-REQ authenticator checksum.
    /// </summary>
    public static byte[] Checksum(byte[] baseKey, int usage, byte[] text)
    {
        byte[] kc = DK(baseKey, UsageConstant(usage, 0x99), baseKey.Length);
        return HmacSha1_96(kc, text);
    }

    // Key-derivation constant: the 4-byte big-endian key usage followed by the one-byte key type.
    private static byte[] UsageConstant(int usage, byte keyType) =>
        new[] { (byte)(usage >> 24), (byte)(usage >> 16), (byte)(usage >> 8), (byte)usage, keyType };

    private static byte[] HmacSha1_96(byte[] key, byte[] data) => HMACSHA1.HashData(key, data)[..12];

    // --- AES-CBC with ciphertext stealing (CBC-CS3; RFC 3962), IV = 0 ------------------------------
    // Done over an AES-ECB block primitive with manual chaining, mirroring impacket's basic_encrypt.

    internal static byte[] CtsEncrypt(byte[] key, byte[] plaintext)
    {
        if (plaintext.Length < BlockSize)
        {
            throw new InvalidDataException("CTS input must be at least one block.");
        }

        int padded = (plaintext.Length + BlockSize - 1) / BlockSize * BlockSize;
        var buf = new byte[padded];
        Array.Copy(plaintext, buf, plaintext.Length);

        byte[] ctext = CbcEncrypt(key, buf);
        if (plaintext.Length == BlockSize)
        {
            return ctext;
        }

        // Swap the last two cipher blocks and truncate the final one to the real last-block length.
        int lastLen = plaintext.Length % BlockSize;
        if (lastLen == 0)
        {
            lastLen = BlockSize;
        }

        int n = ctext.Length;
        byte[] head = ctext[..(n - 32)];
        byte[] last = ctext[(n - 16)..];                 // full last cipher block
        byte[] secondLast = ctext[(n - 32)..(n - 16)][..lastLen];
        return Concat(head, last, secondLast);
    }

    internal static byte[] CtsDecrypt(byte[] key, byte[] ciphertext)
    {
        if (ciphertext.Length == BlockSize)
        {
            return EcbDecryptBlock(key, ciphertext); // single block, IV = 0
        }

        int nblocks = (ciphertext.Length + BlockSize - 1) / BlockSize;
        int lastLen = ciphertext.Length - (nblocks - 1) * BlockSize; // 1..16

        var result = new List<byte>(ciphertext.Length);
        byte[] prev = new byte[BlockSize]; // IV = 0
        int off = 0;
        for (int b = 0; b < nblocks - 2; b++)
        {
            byte[] cb = ciphertext[off..(off + BlockSize)];
            byte[] dec = EcbDecryptBlock(key, cb);
            for (int i = 0; i < BlockSize; i++)
            {
                result.Add((byte)(dec[i] ^ prev[i]));
            }

            prev = cb;
            off += BlockSize;
        }

        byte[] c2 = ciphertext[off..(off + BlockSize)];   // second-to-last (full) cipher block
        byte[] cn = ciphertext[(off + BlockSize)..];       // last (partial) cipher block
        byte[] d = EcbDecryptBlock(key, c2);

        var lastPlain = new byte[lastLen];
        for (int i = 0; i < lastLen; i++)
        {
            lastPlain[i] = (byte)(d[i] ^ cn[i]);
        }

        byte[] omitted = d[lastLen..];
        byte[] finalBlock = Concat(cn, omitted);
        byte[] d2 = EcbDecryptBlock(key, finalBlock);
        for (int i = 0; i < BlockSize; i++)
        {
            result.Add((byte)(d2[i] ^ prev[i]));
        }

        result.AddRange(lastPlain);
        return result.ToArray();
    }

    private static byte[] CbcEncrypt(byte[] key, byte[] data)
    {
        var outBuf = new byte[data.Length];
        byte[] prev = new byte[BlockSize]; // IV = 0
        var blk = new byte[BlockSize];
        for (int off = 0; off < data.Length; off += BlockSize)
        {
            for (int i = 0; i < BlockSize; i++)
            {
                blk[i] = (byte)(data[off + i] ^ prev[i]);
            }

            byte[] enc = EcbEncryptBlock(key, blk);
            Array.Copy(enc, 0, outBuf, off, BlockSize);
            prev = enc;
        }

        return outBuf;
    }

    private static byte[] EcbEncryptBlock(byte[] key, byte[] block)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        return aes.EncryptEcb(block, PaddingMode.None);
    }

    private static byte[] EcbDecryptBlock(byte[] key, byte[] block)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        return aes.DecryptEcb(block, PaddingMode.None);
    }

    // --- RFC 3961 n-fold -------------------------------------------------------------------------

    /// <summary>
    /// The RFC 3961 n-fold operation: spreads <paramref name="input"/> across <paramref name="outBytes"/>
    /// bytes by rotating successive copies 13 bits at a time and summing them with end-around carry.
    /// Ported from impacket's <c>_nfold</c>.
    /// </summary>
    public static byte[] Nfold(byte[] input, int outBytes)
    {
        int inLen = input.Length;
        int lcm = Lcm(outBytes, inLen);

        var big = new byte[lcm];
        for (int i = 0; i < lcm / inLen; i++)
        {
            byte[] rot = RotateRight(input, 13 * i);
            Array.Copy(rot, 0, big, i * inLen, inLen);
        }

        var acc = big[..outBytes];
        for (int p = outBytes; p < lcm; p += outBytes)
        {
            acc = AddOnesComplement(acc, big[p..(p + outBytes)]);
        }

        return acc;
    }

    private static byte[] RotateRight(byte[] ba, int nbits)
    {
        int n = ba.Length;
        int byteShift = nbits / 8 % n;
        int bitShift = nbits % 8;
        var outBuf = new byte[n];
        for (int i = 0; i < n; i++)
        {
            int a = ((i - byteShift) % n + n) % n;
            int b = ((i - byteShift - 1) % n + n) % n;
            outBuf[i] = (byte)((ba[a] >> bitShift) | ((ba[b] << (8 - bitShift)) & 0xFF));
        }

        return outBuf;
    }

    private static byte[] AddOnesComplement(byte[] a, byte[] b)
    {
        int n = a.Length;
        var v = new int[n];
        for (int i = 0; i < n; i++)
        {
            v[i] = a[i] + b[i];
        }

        while (HasCarry(v))
        {
            var nv = new int[n];
            for (int i = 0; i < n; i++)
            {
                nv[i] = (v[(i + 1) % n] >> 8) + (v[i] & 0xFF); // v[i-n+1] == v[(i+1) mod n]
            }

            v = nv;
        }

        var outBuf = new byte[n];
        for (int i = 0; i < n; i++)
        {
            outBuf[i] = (byte)(v[i] == 256 ? 0 : v[i]);
        }

        return outBuf;
    }

    private static bool HasCarry(int[] v)
    {
        foreach (int x in v)
        {
            if ((x & ~0xFF) != 0)
            {
                return true;
            }
        }

        return false;
    }

    private static int Lcm(int a, int b) => a / Gcd(a, b) * b;

    private static int Gcd(int a, int b)
    {
        while (b != 0)
        {
            (a, b) = (b, a % b);
        }

        return a;
    }

    private static bool FixedEquals(byte[] a, byte[] b)
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

    private static byte[] Concat(params byte[][] parts)
    {
        int total = 0;
        foreach (byte[] p in parts)
        {
            total += p.Length;
        }

        var result = new byte[total];
        int offset = 0;
        foreach (byte[] p in parts)
        {
            Buffer.BlockCopy(p, 0, result, offset, p.Length);
            offset += p.Length;
        }

        return result;
    }
}
