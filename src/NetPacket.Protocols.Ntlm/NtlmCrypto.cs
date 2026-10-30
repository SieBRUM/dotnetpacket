using System.Security.Cryptography;
using System.Text;

namespace NetPacket.Protocols.Ntlm;

/// <summary>
/// NTLM cryptographic primitives (MS-NLMP 3.3.2, NTLMv2). Implements the pieces
/// the BCL does not provide: MD4 (NT hash) and RC4 (key exchange). HMAC-MD5 comes
/// from <see cref="HMACMD5"/>.
/// </summary>
public static class NtlmCrypto
{
    /// <summary>Result of the NTLMv2 response computation.</summary>
    public readonly record struct NtlmV2Response(byte[] NtChallengeResponse, byte[] LmChallengeResponse, byte[] SessionBaseKey);

    /// <summary>NT hash: MD4 of the UTF-16LE password.</summary>
    public static byte[] NtHash(string password) => Md4(Encoding.Unicode.GetBytes(password));

    /// <summary>NTOWFv2 = HMAC-MD5(NT hash, UTF-16LE(upper(user) + domain)) (MS-NLMP 3.3.2).</summary>
    public static byte[] NtowfV2(string password, string user, string domain)
    {
        byte[] ntHash = NtHash(password);
        byte[] identity = Encoding.Unicode.GetBytes(user.ToUpperInvariant() + domain);
        using var hmac = new HMACMD5(ntHash);
        return hmac.ComputeHash(identity);
    }

    /// <summary>
    /// Computes the NTLMv2 NT/LM challenge responses and session base key
    /// (MS-NLMP 3.3.2). <paramref name="timestamp"/> is an 8-byte Windows FILETIME;
    /// <paramref name="targetInfo"/> is the server's AV_PAIR list (plus any client additions).
    /// </summary>
    public static NtlmV2Response ComputeV2(
        byte[] ntowfV2,
        byte[] serverChallenge,
        byte[] clientChallenge,
        byte[] timestamp,
        byte[] targetInfo)
    {
        // temp = RespVer(1) HiRespVer(1) Z(6) Time(8) ClientChallenge(8) Z(4) TargetInfo Z(4)
        var temp = new List<byte> { 0x01, 0x01, 0, 0, 0, 0, 0, 0 };
        temp.AddRange(timestamp);
        temp.AddRange(clientChallenge);
        temp.AddRange(new byte[4]);
        temp.AddRange(targetInfo);
        temp.AddRange(new byte[4]);
        byte[] tempBytes = temp.ToArray();

        using var hmac = new HMACMD5(ntowfV2);
        byte[] ntProof = hmac.ComputeHash(Concat(serverChallenge, tempBytes));
        byte[] ntResponse = Concat(ntProof, tempBytes);
        byte[] sessionBaseKey = hmac.ComputeHash(ntProof);

        byte[] lmProof = hmac.ComputeHash(Concat(serverChallenge, clientChallenge));
        byte[] lmResponse = Concat(lmProof, clientChallenge);

        return new NtlmV2Response(ntResponse, lmResponse, sessionBaseKey);
    }

    /// <summary>HMAC-MD5 convenience wrapper.</summary>
    public static byte[] HmacMd5(byte[] key, byte[] data)
    {
        using var hmac = new HMACMD5(key);
        return hmac.ComputeHash(data);
    }

    /// <summary>
    /// Client-to-server signing key (MS-NLMP 3.4.5.2): MD5(sessionKey + magic constant).
    /// Used to sign the SPNEGO mechListMIC.
    /// </summary>
    public static byte[] ClientSigningKey(byte[] exportedSessionKey) => SignKey(exportedSessionKey, clientToServer: true);

    /// <summary>
    /// SIGNKEY (MS-NLMP 3.4.5.2) for extended session security: MD5(sessionKey + the
    /// directional magic constant). <paramref name="clientToServer"/> picks the direction.
    /// </summary>
    public static byte[] SignKey(byte[] exportedSessionKey, bool clientToServer)
    {
        string who = clientToServer ? "client-to-server" : "server-to-client";
        byte[] magic = Encoding.ASCII.GetBytes($"session key to {who} signing key magic constant\0");
        return MD5.HashData(Concat(exportedSessionKey, magic));
    }

    /// <summary>
    /// SEALKEY (MS-NLMP 3.4.5.3) for extended session security with a 128-bit key:
    /// MD5(sessionKey + the directional sealing magic constant).
    /// </summary>
    public static byte[] SealKey(byte[] exportedSessionKey, bool clientToServer)
    {
        string who = clientToServer ? "client-to-server" : "server-to-client";
        byte[] magic = Encoding.ASCII.GetBytes($"session key to {who} sealing key magic constant\0");
        return MD5.HashData(Concat(exportedSessionKey, magic));
    }

    /// <summary>
    /// NTLM message signature with extended session security and no sealing
    /// (MS-NLMP 3.4.4): version(1) || HMAC-MD5(signingKey, seq || message)[0..8] || seq.
    /// This is the shape of the SPNEGO mechListMIC.
    /// </summary>
    public static byte[] GssMic(byte[] signingKey, uint sequenceNumber, byte[] message)
    {
        byte[] seq = BitConverter.GetBytes(sequenceNumber);
        byte[] mac = HmacMd5(signingKey, Concat(seq, message));

        var signature = new byte[16];
        signature[0] = 0x01; // Version = 0x00000001 (little-endian)
        Array.Copy(mac, 0, signature, 4, 8);
        Array.Copy(seq, 0, signature, 12, 4);
        return signature;
    }

    /// <summary>A Windows FILETIME (100ns ticks since 1601-01-01) for <paramref name="utc"/>, little-endian.</summary>
    public static byte[] FileTime(DateTime utc) => BitConverter.GetBytes(utc.ToFileTimeUtc());

    /// <summary>RC4 keystream cipher (symmetric; encrypt == decrypt).</summary>
    public static byte[] Rc4(byte[] key, byte[] data)
    {
        var s = new byte[256];
        for (int i = 0; i < 256; i++)
        {
            s[i] = (byte)i;
        }

        int j = 0;
        for (int i = 0; i < 256; i++)
        {
            j = (j + s[i] + key[i % key.Length]) & 0xFF;
            (s[i], s[j]) = (s[j], s[i]);
        }

        var output = new byte[data.Length];
        int x = 0, y = 0;
        for (int k = 0; k < data.Length; k++)
        {
            x = (x + 1) & 0xFF;
            y = (y + s[x]) & 0xFF;
            (s[x], s[y]) = (s[y], s[x]);
            output[k] = (byte)(data[k] ^ s[(s[x] + s[y]) & 0xFF]);
        }

        return output;
    }

    /// <summary>MD4 message digest (RFC 1320). Needed for the NT hash; not available in the BCL.</summary>
    public static byte[] Md4(byte[] input)
    {
        uint a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;

        // Pad: 0x80, zeros to 56 mod 64, then 64-bit little-endian bit length.
        long bitLength = (long)input.Length * 8;
        int padded = input.Length + 1;
        while (padded % 64 != 56)
        {
            padded++;
        }

        var msg = new byte[padded + 8];
        Array.Copy(input, msg, input.Length);
        msg[input.Length] = 0x80;
        for (int i = 0; i < 8; i++)
        {
            msg[padded + i] = (byte)(bitLength >> (8 * i));
        }

        var x = new uint[16];
        unchecked
        {
            for (int block = 0; block < msg.Length; block += 64)
            {
                for (int i = 0; i < 16; i++)
                {
                    x[i] = (uint)(msg[block + i * 4]
                                  | (msg[block + i * 4 + 1] << 8)
                                  | (msg[block + i * 4 + 2] << 16)
                                  | (msg[block + i * 4 + 3] << 24));
                }

                uint aa = a, bb = b, cc = c, dd = d;

                // Round 1
                a = FF(a, b, c, d, x[0], 3); d = FF(d, a, b, c, x[1], 7); c = FF(c, d, a, b, x[2], 11); b = FF(b, c, d, a, x[3], 19);
                a = FF(a, b, c, d, x[4], 3); d = FF(d, a, b, c, x[5], 7); c = FF(c, d, a, b, x[6], 11); b = FF(b, c, d, a, x[7], 19);
                a = FF(a, b, c, d, x[8], 3); d = FF(d, a, b, c, x[9], 7); c = FF(c, d, a, b, x[10], 11); b = FF(b, c, d, a, x[11], 19);
                a = FF(a, b, c, d, x[12], 3); d = FF(d, a, b, c, x[13], 7); c = FF(c, d, a, b, x[14], 11); b = FF(b, c, d, a, x[15], 19);

                // Round 2
                a = GG(a, b, c, d, x[0], 3); d = GG(d, a, b, c, x[4], 5); c = GG(c, d, a, b, x[8], 9); b = GG(b, c, d, a, x[12], 13);
                a = GG(a, b, c, d, x[1], 3); d = GG(d, a, b, c, x[5], 5); c = GG(c, d, a, b, x[9], 9); b = GG(b, c, d, a, x[13], 13);
                a = GG(a, b, c, d, x[2], 3); d = GG(d, a, b, c, x[6], 5); c = GG(c, d, a, b, x[10], 9); b = GG(b, c, d, a, x[14], 13);
                a = GG(a, b, c, d, x[3], 3); d = GG(d, a, b, c, x[7], 5); c = GG(c, d, a, b, x[11], 9); b = GG(b, c, d, a, x[15], 13);

                // Round 3
                a = HH(a, b, c, d, x[0], 3); d = HH(d, a, b, c, x[8], 9); c = HH(c, d, a, b, x[4], 11); b = HH(b, c, d, a, x[12], 15);
                a = HH(a, b, c, d, x[2], 3); d = HH(d, a, b, c, x[10], 9); c = HH(c, d, a, b, x[6], 11); b = HH(b, c, d, a, x[14], 15);
                a = HH(a, b, c, d, x[1], 3); d = HH(d, a, b, c, x[9], 9); c = HH(c, d, a, b, x[5], 11); b = HH(b, c, d, a, x[13], 15);
                a = HH(a, b, c, d, x[3], 3); d = HH(d, a, b, c, x[11], 9); c = HH(c, d, a, b, x[7], 11); b = HH(b, c, d, a, x[15], 15);

                a += aa; b += bb; c += cc; d += dd;
            }
        }

        var digest = new byte[16];
        WriteLe(digest, 0, a);
        WriteLe(digest, 4, b);
        WriteLe(digest, 8, c);
        WriteLe(digest, 12, d);
        return digest;
    }

    private static uint FF(uint a, uint b, uint c, uint d, uint x, int s) =>
        Rol(unchecked(a + ((b & c) | (~b & d)) + x), s);

    private static uint GG(uint a, uint b, uint c, uint d, uint x, int s) =>
        Rol(unchecked(a + ((b & c) | (b & d) | (c & d)) + x + 0x5a827999), s);

    private static uint HH(uint a, uint b, uint c, uint d, uint x, int s) =>
        Rol(unchecked(a + (b ^ c ^ d) + x + 0x6ed9eba1), s);

    private static uint Rol(uint value, int bits) => (value << bits) | (value >> (32 - bits));

    private static void WriteLe(byte[] buffer, int offset, uint value)
    {
        buffer[offset] = (byte)value;
        buffer[offset + 1] = (byte)(value >> 8);
        buffer[offset + 2] = (byte)(value >> 16);
        buffer[offset + 3] = (byte)(value >> 24);
    }

    private static byte[] Concat(byte[] left, byte[] right)
    {
        var result = new byte[left.Length + right.Length];
        Array.Copy(left, 0, result, 0, left.Length);
        Array.Copy(right, 0, result, left.Length, right.Length);
        return result;
    }
}
