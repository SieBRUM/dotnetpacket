namespace DotNetPacket.Protocols.Ntlm;

/// <summary>
/// An NTLM connection-oriented security context for GSS message protection
/// (MS-NLMP 3.4), as used by DCERPC packet integrity / privacy. Built from the
/// exported session key negotiated during authentication; derives the directional
/// signing and sealing keys and keeps a continuous RC4 handle per direction plus a
/// per-direction sequence number.
/// </summary>
/// <remarks>
/// Mirrors impacket's <c>ntlm.SIGN</c> / <c>ntlm.SEAL</c> / <c>ntlm.MAC</c> for the
/// extended-session-security + key-exchange case (the shape a modern Windows RPC
/// client negotiates): the 8-byte checksum is itself RC4-encrypted by the sealing
/// handle. Note the DCERPC quirk — the signature covers the <em>whole</em> PDU (minus
/// the verifier) while only the stub body is sealed, so the caller passes the
/// to-sign and to-seal buffers separately. For sealing, the body is encrypted first
/// so the keystream is consumed body-then-checksum.
/// </remarks>
public sealed class NtlmSecurityContext
{
    private const int SignatureSize = 16;

    private readonly byte[] _clientSigningKey;
    private readonly byte[] _serverSigningKey;
    private readonly Rc4State _clientHandle;
    private readonly Rc4State _serverHandle;

    private uint _outgoingSeq;
    private uint _incomingSeq;

    public NtlmSecurityContext(byte[] exportedSessionKey)
    {
        _clientSigningKey = NtlmCrypto.SignKey(exportedSessionKey, clientToServer: true);
        _serverSigningKey = NtlmCrypto.SignKey(exportedSessionKey, clientToServer: false);
        _clientHandle = new Rc4State(NtlmCrypto.SealKey(exportedSessionKey, clientToServer: true));
        _serverHandle = new Rc4State(NtlmCrypto.SealKey(exportedSessionKey, clientToServer: false));
    }

    /// <summary>The fixed on-the-wire size of an NTLM message signature (version + checksum + seqnum).</summary>
    public static int SignatureLength => SignatureSize;

    /// <summary>
    /// Protects an outgoing message. <paramref name="toSign"/> is the data the signature
    /// covers (for DCERPC, the whole PDU without the verifier); <paramref name="toSeal"/>
    /// is the portion to RC4-seal (the stub body) or null for integrity only. Returns the
    /// sealed body (empty when not sealing) and the 16-byte signature, and advances the
    /// outgoing sequence number.
    /// </summary>
    public (byte[] Sealed, byte[] Signature) Wrap(byte[] toSign, byte[]? toSeal)
    {
        byte[] hmac8 = NtlmCrypto.HmacMd5(_clientSigningKey, Prepend(_outgoingSeq, toSign))[..8];

        // Order matters: sealing the body advances the same handle that then encrypts
        // the checksum, so the checksum rides a later slice of the keystream.
        byte[] sealed_ = toSeal is null ? Array.Empty<byte>() : _clientHandle.Process(toSeal);
        byte[] encryptedChecksum = _clientHandle.Process(hmac8);

        byte[] signature = BuildSignature(encryptedChecksum, _outgoingSeq);
        _outgoingSeq++;
        return (sealed_, signature);
    }

    /// <summary>RC4-decrypts an incoming sealed body with the server handle (advances the keystream).</summary>
    public byte[] Unseal(byte[] data) => _serverHandle.Process(data);

    /// <summary>
    /// Verifies an incoming signature over <paramref name="toSign"/> with the
    /// server-direction keys and advances the incoming sequence number. For a sealed
    /// message, <see cref="Unseal"/> the body first and build <paramref name="toSign"/>
    /// from the decrypted bytes. Throws <see cref="InvalidDataException"/> on mismatch.
    /// </summary>
    public void Verify(byte[] toSign, byte[] signature)
    {
        byte[] hmac8 = NtlmCrypto.HmacMd5(_serverSigningKey, Prepend(_incomingSeq, toSign))[..8];
        byte[] expected = _serverHandle.Process(hmac8);
        byte[] actual = signature.Length >= 12 ? signature[4..12] : Array.Empty<byte>();
        _incomingSeq++;

        if (!expected.AsSpan().SequenceEqual(actual))
        {
            throw new InvalidDataException("NTLM response signature verification failed.");
        }
    }

    private static byte[] BuildSignature(byte[] encryptedChecksum, uint sequence)
    {
        var signature = new byte[SignatureSize];
        signature[0] = 0x01; // Version = 0x00000001 (little-endian)
        Array.Copy(encryptedChecksum, 0, signature, 4, 8);
        BitConverter.GetBytes(sequence).CopyTo(signature, 12);
        return signature;
    }

    private static byte[] Prepend(uint sequence, byte[] message)
    {
        var buffer = new byte[4 + message.Length];
        BitConverter.GetBytes(sequence).CopyTo(buffer, 0);
        Array.Copy(message, 0, buffer, 4, message.Length);
        return buffer;
    }
}
