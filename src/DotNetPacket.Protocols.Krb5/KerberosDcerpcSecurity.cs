namespace DotNetPacket.Protocols.Krb5;

/// <summary>
/// A GSS-API Kerberos per-message security context for DCERPC packet integrity / privacy, ported from
/// impacket's <c>krb5.gssapi.GSSAPI_AES</c> (<c>GSS_Wrap</c> / <c>GSS_Unwrap</c> / <c>GSS_GetMIC</c>) as
/// driven by <c>dcerpc.v5.rpcrt</c>. Unlike the LDAP wrap (one self-contained token), the DCERPC wrap
/// splits each RFC 4121 CFX Wrap token into the sealed stub body (left in the PDU) and a separate
/// signature (the 16-byte wire header plus the rotated front slice) carried as the auth verifier.
/// </summary>
/// <remarks>
/// The session key is the AP-REP acceptor subkey from the DCE-style handshake; AES seals with key usage
/// 24 (initiator) and the acceptor's replies are unsealed with usage 22. Sequence numbers advance per
/// message in each direction. AES (etype 17/18) only — the etypes a modern Windows/DC Kerberos bind uses.
/// </remarks>
public sealed class KerberosDcerpcSecurity
{
    private const int HeaderLen = 16;
    private const int Rrc = 28;              // rotate count with encryption (RFC 4121 4.2.5)
    private const int InitiatorSeal = 24;    // KG_USAGE_INITIATOR_SEAL
    private const int AcceptorSeal = 22;     // KG_USAGE_ACCEPTOR_SEAL
    private const int InitiatorSign = 25;    // KG_USAGE_INITIATOR_SIGN
    private const int AcceptorSign = 23;     // KG_USAGE_ACCEPTOR_SIGN
    private const int AesBlock = 16;

    private readonly byte[] _key;
    private readonly int _etype;
    private ulong _outSeq;
    private ulong _inSeq;

    public KerberosDcerpcSecurity(byte[] sessionKey, int etype, ulong initialSequence = 0)
    {
        if (etype is not (Krb5Constants.Aes128CtsHmacSha1 or Krb5Constants.Aes256CtsHmacSha1))
        {
            throw new NotSupportedException($"Kerberos DCERPC sealing is implemented for AES only (etype {etype}).");
        }

        _key = sessionKey;
        _etype = etype;
        _outSeq = initialSequence;
    }

    /// <summary>
    /// Seals <paramref name="plainData"/> (the 4-byte-padded stub) and returns the sealed body (same
    /// length) plus the auth verifier signature. Mirrors impacket <c>GSSAPI_AES.GSS_Wrap</c>.
    /// </summary>
    public (byte[] Sealed, byte[] Signature) Wrap(byte[] plainData, byte[]? confounder = null)
    {
        int ec = (AesBlock - plainData.Length % AesBlock) & 15;
        byte[] padded = Concat(plainData, Fill(ec, 0xFF));
        byte[] innerHeader = Header(ec, rrc: 0, _outSeq);
        byte[] cipher = Krb5Cipher.Encrypt(_etype, _key, InitiatorSeal, Concat(padded, innerHeader), confounder);

        byte[] wireHeader = Header(ec, rrc: Rrc, _outSeq);
        byte[] rotated = Rotate(cipher, Rrc + ec);
        int split = HeaderLen + Rrc + ec;

        byte[] sealedBody = rotated[split..];
        byte[] signature = Concat(wireHeader, rotated[..split]);
        _outSeq++;
        return (sealedBody, signature);
    }

    /// <summary>
    /// Unseals a response: <paramref name="signature"/> is the auth verifier (16-byte header + rotated
    /// front slice) and <paramref name="sealedBody"/> the sealed stub. Returns the padded plaintext
    /// (the caller strips the sec_trailer auth_pad_len). Mirrors impacket <c>GSSAPI_AES.GSS_Unwrap</c>.
    /// </summary>
    public byte[] Unwrap(byte[] sealedBody, byte[] signature)
    {
        if (signature.Length < HeaderLen)
        {
            throw new InvalidDataException("Kerberos wrap signature too short.");
        }

        int ec = (signature[4] << 8) | signature[5];
        int rrc = (signature[6] << 8) | signature[7];
        byte[] rotated = Concat(signature[HeaderLen..], sealedBody);
        byte[] cipher = Unrotate(rotated, rrc + ec);
        byte[] plain = Krb5Cipher.Decrypt(_etype, _key, AcceptorSeal, cipher);
        _inSeq++;
        // Strip the trailing inner header (16) plus the EC filler.
        return plain[..^(ec + HeaderLen)];
    }

    /// <summary>Computes the packet-integrity MIC over <paramref name="plainData"/> (impacket <c>GSS_GetMIC</c>).</summary>
    public byte[] GetMic(byte[] plainData)
    {
        byte[] token = MicHeader(_outSeq);
        // RFC 4121 4.2.6.1: the checksum is over the to-be-signed data followed by the 16-byte token
        // header (no pad for CFX MIC tokens).
        byte[] cksum = Krb5Cipher.Checksum(_etype, _key, InitiatorSign, Concat(plainData, token));
        _outSeq++;
        return Concat(token, cksum);
    }

    // WRAP header: TOK_ID 0x0504, Flags 0x06 (Sealed|AcceptorSubkey), Filler 0xFF, EC, RRC, SND_SEQ(8) big-endian.
    private static byte[] Header(int ec, int rrc, ulong seq)
    {
        var h = new byte[HeaderLen];
        h[0] = 0x05;
        h[1] = 0x04;
        h[2] = 0x06;
        h[3] = 0xFF;
        h[4] = (byte)(ec >> 8);
        h[5] = (byte)ec;
        h[6] = (byte)(rrc >> 8);
        h[7] = (byte)rrc;
        WriteSeq(h, seq);
        return h;
    }

    // MIC header: TOK_ID 0x0404, Flags 0x04, Filler 0xFF*5, SND_SEQ(8).
    private static byte[] MicHeader(ulong seq)
    {
        var h = new byte[16];
        h[0] = 0x04;
        h[1] = 0x04;
        h[2] = 0x04;
        h[3] = 0xFF;
        h[4] = 0xFF;
        h[5] = 0xFF;
        h[6] = 0xFF;
        h[7] = 0xFF;
        WriteSeq(h, seq);
        return h;
    }

    private static void WriteSeq(byte[] h, ulong seq)
    {
        for (int i = 0; i < 8; i++)
        {
            h[8 + i] = (byte)(seq >> (8 * (7 - i)));
        }
    }

    private static byte[] Fill(int count, byte value)
    {
        var b = new byte[count];
        Array.Fill(b, value);
        return b;
    }

    private static byte[] Rotate(byte[] data, int numBytes)
    {
        int n = data.Length == 0 ? 0 : numBytes % data.Length;
        int left = data.Length - n;
        return Concat(data[left..], data[..left]);
    }

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
