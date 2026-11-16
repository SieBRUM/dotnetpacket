namespace DotNetPacket.Protocols.Krb5;

/// <summary>
/// A GSS-API Kerberos per-message security context for the SASL GSS-SPNEGO "sign and seal" that a
/// Kerberos LDAP bind negotiates. Implements the RFC 4121 CFX Wrap tokens for the AES profiles
/// (etype 17/18), ported from impacket's <c>krb5.gssapi.GSSAPI_AES.GSS_Wrap_LDAP</c> /
/// <c>GSS_Unwrap_LDAP</c>, so sealed LDAP traffic matches stock impacket on the wire. The session key
/// is the service-ticket session key; the initiator seals with key usage 24 and the acceptor with 22.
/// </summary>
public sealed class KerberosGssContext
{
    private const int HeaderLen = 16;
    private const int Rrc = 28;                    // rotate count when encryption is requested (RFC 4121 4.2.5)
    private const int InitiatorSeal = 24;          // KG_USAGE_INITIATOR_SEAL
    private const int AcceptorSeal = 22;           // KG_USAGE_ACCEPTOR_SEAL

    private readonly byte[] _key;
    private readonly int _etype;
    private ulong _sequence;

    /// <summary>True for the etypes this context can seal (AES-128/256); RC4 sealing is not implemented.</summary>
    public static bool Supports(int etype) =>
        etype is Krb5Constants.Aes128CtsHmacSha1 or Krb5Constants.Aes256CtsHmacSha1;

    public KerberosGssContext(byte[] sessionKey, int etype, ulong initialSequence = 0)
    {
        if (!Supports(etype))
        {
            throw new NotSupportedException(
                $"GSS LDAP sealing is implemented for AES only (etype {etype} not supported).");
        }

        _key = sessionKey;
        _etype = etype;
        _sequence = initialSequence;
    }

    /// <summary>
    /// Wraps (seals) one plaintext LDAP message into a CFX Wrap token: a 16-byte header followed by
    /// the rotated ciphertext. The caller frames it with the 4-byte SASL length prefix.
    /// </summary>
    public byte[] Wrap(byte[] data) => Wrap(data, null);

    // Confounder seam for byte-exact tests against the impacket oracle; production passes null (random).
    internal byte[] Wrap(byte[] data, byte[]? confounder)
    {
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
    /// Unwraps (decrypts) one received CFX Wrap token (16-byte header + rotated ciphertext) back into
    /// the plaintext LDAP message. The caller strips the 4-byte SASL length prefix first.
    /// </summary>
    public byte[] Unwrap(byte[] token)
    {
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

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var r = new byte[a.Length + b.Length];
        Buffer.BlockCopy(a, 0, r, 0, a.Length);
        Buffer.BlockCopy(b, 0, r, a.Length, b.Length);
        return r;
    }
}
