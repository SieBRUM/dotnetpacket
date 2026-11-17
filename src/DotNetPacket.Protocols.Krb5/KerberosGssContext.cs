using System.Security.Cryptography;
using System.Text;
using DotNetPacket.Protocols.Ntlm;

namespace DotNetPacket.Protocols.Krb5;

/// <summary>
/// A GSS-API Kerberos per-message security context for the SASL GSS-SPNEGO "sign and seal" that a
/// Kerberos LDAP bind negotiates. Implements both wrap profiles, ported from impacket's
/// <c>krb5.gssapi</c>: the RFC 4121 CFX Wrap tokens for AES (etype 17/18, <c>GSSAPI_AES.GSS_Wrap_LDAP</c>)
/// and the RFC 1964 / RFC 4757 RC4-HMAC Wrap token for RC4 (etype 23, <c>GSSAPI_RC4.GSS_Wrap_LDAP</c>),
/// so sealed LDAP traffic matches stock impacket on the wire. The session key is the service-ticket
/// session key; AES seals with key usage 24 (initiator) / 22 (acceptor).
/// </summary>
public sealed class KerberosGssContext
{
    private const int HeaderLen = 16;
    private const int Rrc = 28;                    // rotate count when encryption is requested (RFC 4121 4.2.5)
    private const int InitiatorSeal = 24;          // KG_USAGE_INITIATOR_SEAL
    private const int AcceptorSeal = 22;           // KG_USAGE_ACCEPTOR_SEAL

    // GSS-API KRB5 mechanism OID, DER-encoded — the MechIndepToken framing for the RC4 wrap.
    private static readonly byte[] Krb5Oid = { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02 };

    private readonly byte[] _key;
    private readonly int _etype;
    private ulong _sequence;

    /// <summary>True for the etypes this context can seal: AES-128/256 (RFC 4121) and RC4-HMAC (RFC 1964).</summary>
    public static bool Supports(int etype) => etype is Krb5Constants.Aes128CtsHmacSha1
        or Krb5Constants.Aes256CtsHmacSha1 or Krb5Constants.Rc4Hmac;

    public KerberosGssContext(byte[] sessionKey, int etype, ulong initialSequence = 0)
    {
        if (!Supports(etype))
        {
            throw new NotSupportedException(
                $"GSS LDAP sealing is implemented for AES and RC4 only (etype {etype} not supported).");
        }

        _key = sessionKey;
        _etype = etype;
        _sequence = initialSequence;
    }

    private bool IsRc4 => _etype == Krb5Constants.Rc4Hmac;

    /// <summary>
    /// Wraps (seals) one plaintext LDAP message. The caller frames the result with the 4-byte SASL length.
    /// </summary>
    public byte[] Wrap(byte[] data) => Wrap(data, null);

    // Confounder seam for byte-exact tests against the impacket oracle; production passes null (random).
    internal byte[] Wrap(byte[] data, byte[]? confounder)
    {
        if (IsRc4)
        {
            return Rc4Wrap(data, confounder);
        }

        // Header appended to the plaintext before encryption carries RRC = 0, EC = 0 (no padding for LDAP).
        byte[] innerHeader = BuildHeader(rrc: 0, ec: 0, _sequence);
        byte[] plaintext = Concat(data, innerHeader);
        byte[] cipher = Krb5Cipher.Encrypt(_etype, _key, InitiatorSeal, plaintext, confounder);

        // The wire header advertises RRC = 28; the whole ciphertext is right-rotated by RRC + EC.
        byte[] wireHeader = BuildHeader(rrc: Rrc, ec: 0, _sequence);
        byte[] rotated = Rotate(cipher, Rrc);

        _sequence++;
        return Concat(wireHeader, rotated);
    }

    /// <summary>
    /// Unwraps (decrypts) one received Wrap token back into the plaintext LDAP message. The caller strips
    /// the 4-byte SASL length prefix first.
    /// </summary>
    public byte[] Unwrap(byte[] token)
    {
        if (IsRc4)
        {
            return Rc4Unwrap(token);
        }

        if (token.Length < HeaderLen)
        {
            throw new InvalidDataException("GSS wrap token too short.");
        }

        int ec = (token[4] << 8) | token[5];
        int rrc = (token[6] << 8) | token[7];

        byte[] rotated = token[HeaderLen..];
        byte[] cipher = Unrotate(rotated, rrc + ec);
        byte[] plaintext = Krb5Cipher.Decrypt(_etype, _key, AcceptorSeal, cipher);

        // Strip the trailing inner header (16) plus any EC filler the acceptor added.
        return plaintext[..^(ec + HeaderLen)];
    }

    // --- RC4-HMAC Wrap (RFC 1964 / RFC 4757), ported from impacket GSSAPI_RC4.GSS_Wrap_LDAP ---------

    private byte[] Rc4Wrap(byte[] data, byte[]? confounder)
    {
        confounder ??= RandomNumberGenerator.GetBytes(8);
        uint seq = (uint)_sequence;

        byte[] payload = Concat(data, new byte[] { 0x01 });                 // the LDAP pad byte
        byte[] tokHead = { 0x02, 0x01, 0x11, 0x00, 0x10, 0x00, 0xFF, 0xFF }; // TOK_ID/SGN_ALG/SEAL_ALG/Filler (LE)
        byte[] sndSeq = Concat(Be32(seq), new byte[4]);                     // init direction: seq || 00000000

        byte[] ksign = NtlmCrypto.HmacMd5(_key, Encoding.ASCII.GetBytes("signaturekey\0"));
        byte[] sgnCksum = NtlmCrypto.HmacMd5(ksign, MD5.HashData(Concat(Le32(13), tokHead, confounder, payload)))[..8];

        byte[] klocal = Xor(_key, 0xF0);
        byte[] kcrypt = NtlmCrypto.HmacMd5(NtlmCrypto.HmacMd5(klocal, Le32(0)), Be32(seq));
        byte[] kseq = NtlmCrypto.HmacMd5(NtlmCrypto.HmacMd5(_key, Le32(0)), sgnCksum);
        byte[] encSeq = NtlmCrypto.Rc4(kseq, sndSeq);

        // One continuous RC4 stream over confounder || payload.
        byte[] enc = NtlmCrypto.Rc4(kcrypt, Concat(confounder, payload));
        byte[] token = Concat(tokHead, encSeq, sgnCksum, enc[..8]);          // 32-byte WRAP token (confounder is enc[..8])
        _sequence++;
        return WrapApplication0(Concat(Krb5Oid, token, enc[8..]));           // 0x60 <len> KRB5-OID token cipher
    }

    private byte[] Rc4Unwrap(byte[] framed)
    {
        byte[] inner = UnwrapApplication0(framed);                           // KRB5-OID || token(32) || cipher
        byte[] token = inner[Krb5Oid.Length..(Krb5Oid.Length + 32)];
        byte[] cipher = inner[(Krb5Oid.Length + 32)..];

        byte[] encSeq = token[8..16];
        byte[] sgnCksum = token[16..24];
        byte[] encConfounder = token[24..32];

        byte[] klocal = Xor(_key, 0xF0);
        byte[] kseq = NtlmCrypto.HmacMd5(NtlmCrypto.HmacMd5(_key, Le32(0)), sgnCksum);
        byte[] sndSeq = NtlmCrypto.Rc4(kseq, encSeq);                        // decrypt the sender's sequence
        byte[] kcrypt = NtlmCrypto.HmacMd5(NtlmCrypto.HmacMd5(klocal, Le32(0)), sndSeq[..4]);

        byte[] dec = NtlmCrypto.Rc4(kcrypt, Concat(encConfounder, cipher));
        return dec[8..^1];                                                   // drop the 8-byte confounder and the pad byte
    }

    private static byte[] Be32(uint v) => new[] { (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v };

    private static byte[] Le32(uint v) => new[] { (byte)v, (byte)(v >> 8), (byte)(v >> 16), (byte)(v >> 24) };

    private static byte[] Xor(byte[] key, byte mask)
    {
        var r = new byte[key.Length];
        for (int i = 0; i < key.Length; i++)
        {
            r[i] = (byte)(key[i] ^ mask);
        }

        return r;
    }

    // GSS-API [APPLICATION 0] framing (0x60, DER length) around the mechanism-independent token.
    private static byte[] WrapApplication0(byte[] content)
    {
        byte[] len = EncodeDerLength(content.Length);
        var outBuf = new byte[1 + len.Length + content.Length];
        outBuf[0] = 0x60;
        Buffer.BlockCopy(len, 0, outBuf, 1, len.Length);
        Buffer.BlockCopy(content, 0, outBuf, 1 + len.Length, content.Length);
        return outBuf;
    }

    private static byte[] UnwrapApplication0(byte[] token)
    {
        if (token.Length < 2 || token[0] != 0x60)
        {
            throw new InvalidDataException("RC4 GSS token is not [APPLICATION 0]-framed.");
        }

        int i = 1;
        int b = token[i++];
        if ((b & 0x80) != 0)
        {
            i += b & 0x7F;      // skip the long-form length octets
        }

        return token[i..];
    }

    private static byte[] EncodeDerLength(int length)
    {
        if (length < 0x80)
        {
            return new[] { (byte)length };
        }

        var bytes = new List<byte>();
        int v = length;
        while (v > 0)
        {
            bytes.Insert(0, (byte)(v & 0xFF));
            v >>= 8;
        }

        bytes.Insert(0, (byte)(0x80 | bytes.Count));
        return bytes.ToArray();
    }

    // WRAP header: TOK_ID 0x0504, Flags 0x06 (Sealed|AcceptorSubkey), Filler 0xFF, EC, RRC, SND_SEQ(8) — all big-endian.
    private static byte[] BuildHeader(int rrc, int ec, ulong seq)
    {
        var h = new byte[HeaderLen];
        h[0] = 0x05;
        h[1] = 0x04;
        h[2] = 0x06;         // Flags: Sealed (2) | AcceptorSubkey (4)
        h[3] = 0xFF;         // Filler
        h[4] = (byte)(ec >> 8);
        h[5] = (byte)ec;
        h[6] = (byte)(rrc >> 8);
        h[7] = (byte)rrc;
        for (int i = 0; i < 8; i++)
        {
            h[8 + i] = (byte)(seq >> (8 * (7 - i)));
        }

        return h;
    }

    // Right-rotate by numBytes: data[len-n:] + data[:len-n].
    private static byte[] Rotate(byte[] data, int numBytes)
    {
        int n = data.Length == 0 ? 0 : numBytes % data.Length;
        int left = data.Length - n;
        return Concat(data[left..], data[..left]);
    }

    // Inverse of Rotate: data[n:] + data[:n].
    private static byte[] Unrotate(byte[] data, int numBytes)
    {
        int n = data.Length == 0 ? 0 : numBytes % data.Length;
        return Concat(data[n..], data[..n]);
    }

    private static byte[] Concat(params byte[][] parts)
    {
        int total = 0;
        foreach (byte[] p in parts)
        {
            total += p.Length;
        }

        var r = new byte[total];
        int offset = 0;
        foreach (byte[] p in parts)
        {
            Buffer.BlockCopy(p, 0, r, offset, p.Length);
            offset += p.Length;
        }

        return r;
    }
}
