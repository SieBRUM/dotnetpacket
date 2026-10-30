using System.Security.Cryptography;
using System.Text;
using NetPacket.Core;

namespace NetPacket.Protocols.Ntlm;

/// <summary>Result of building an AUTHENTICATE message: the bytes and the exported session key.</summary>
public readonly record struct NtlmAuthResult(byte[] Message, byte[] SessionKey);

/// <summary>
/// Drives the client side of an NTLMv2 exchange: builds the NEGOTIATE (Type 1),
/// consumes the CHALLENGE (Type 2), and builds the AUTHENTICATE (Type 3) the way a
/// modern Windows client does — a Windows-like flag set, a NEGOTIATE_VERSION block,
/// NTLMv2 responses with the server's target info echoed back, key exchange, and
/// the message integrity code (MIC). See <c>docs/REALISM.md</c>.
/// </summary>
public sealed class NtlmClient
{
    /// <summary>Windows 10 (build 19041) version block for the NEGOTIATE_VERSION field.</summary>
    public static readonly byte[] Windows10Version = { 0x0A, 0x00, 0x61, 0x4A, 0x00, 0x00, 0x00, 0x0F };

    // Offset of the 16-byte MIC in the AUTHENTICATE message (after 6 field descriptors,
    // flags and the version block): 8 + 4 + 8*6 + 4 + 8 = 72.
    private const int Type3MicOffset = 72;
    private const int Type3FixedLength = 88; // through the MIC

    public NtlmNegotiateFlags Flags { get; set; } =
        NtlmNegotiateFlags.NegotiateUnicode |
        NtlmNegotiateFlags.RequestTarget |
        NtlmNegotiateFlags.NegotiateSign |
        NtlmNegotiateFlags.NegotiateNtlm |
        NtlmNegotiateFlags.NegotiateAlwaysSign |
        NtlmNegotiateFlags.NegotiateExtendedSessionSecurity |
        NtlmNegotiateFlags.NegotiateTargetInfo |
        NtlmNegotiateFlags.NegotiateVersion |
        NtlmNegotiateFlags.Negotiate128 |
        NtlmNegotiateFlags.Negotiate56;

    public string Workstation { get; set; } = Environment.MachineName;

    /// <summary>
    /// Enables NTLMSSP key exchange: the client picks a random exported session key,
    /// sends it RC4-wrapped under the NTLMv2 key-exchange key, and adds NEGOTIATE_SEAL.
    /// This is what a Windows client does for DCERPC sign/seal; leave it off for the
    /// SMB/SPNEGO path, whose MIC stays deterministic without it.
    /// </summary>
    public bool KeyExchange { get; set; }

    /// <summary>
    /// Whether to include an NTLM message-integrity code (MIC) in the AUTHENTICATE and
    /// signal it via MsvAvFlags. The SMB/SPNEGO path needs it; the DCERPC sign/seal path
    /// (like impacket) omits it, so the server does not expect a MIC over the raw tokens.
    /// </summary>
    public bool IncludeMic { get; set; } = true;

    private byte[] _negotiateMessage = Array.Empty<byte>();

    /// <summary>Builds the NTLMSSP NEGOTIATE (Type 1) message and remembers it for the MIC.</summary>
    public byte[] CreateNegotiate()
    {
        if (KeyExchange)
        {
            Flags |= NtlmNegotiateFlags.NegotiateSeal | NtlmNegotiateFlags.NegotiateKeyExchange;
        }

        var writer = new ByteWriter(ByteOrder.Little);
        writer.WriteBytes(Ntlm.Signature);
        writer.WriteUInt32(Ntlm.NegotiateMessage);
        writer.WriteUInt32((uint)Flags);
        WriteField(writer, 0, 40); // DomainName (empty)
        WriteField(writer, 0, 40); // Workstation (empty)
        writer.WriteBytes(Windows10Version);
        _negotiateMessage = writer.ToArray();
        return _negotiateMessage;
    }

    /// <summary>
    /// Parses the CHALLENGE and builds the AUTHENTICATE (Type 3). Call
    /// <see cref="CreateNegotiate"/> first so the MIC covers the whole exchange.
    /// </summary>
    public NtlmAuthResult CreateAuthenticate(byte[] challengeMessage, string domain, string user, string password)
    {
        NtlmChallenge challenge = NtlmChallenge.Parse(challengeMessage);

        byte[] clientChallenge = RandomNumberGenerator.GetBytes(8);
        AvPairs targetInfo = AvPairs.Parse(challenge.TargetInfo);
        byte[] timestamp = targetInfo.Get(NtlmAvId.Timestamp) ?? NtlmCrypto.FileTime(DateTime.UtcNow);

        // Signal that a MIC is present (MsvAvFlags bit 0x2), like a real client.
        if (IncludeMic)
        {
            byte[] existingFlags = targetInfo.Get(NtlmAvId.Flags) ?? new byte[4];
            uint avFlags = BitConverter.ToUInt32(existingFlags, 0) | 0x00000002;
            targetInfo.Set(NtlmAvId.Flags, BitConverter.GetBytes(avFlags));
        }

        byte[] targetInfoBytes = targetInfo.ToArray();

        byte[] ntowf = NtlmCrypto.NtowfV2(password, user, domain);
        NtlmCrypto.NtlmV2Response v2 = NtlmCrypto.ComputeV2(
            ntowf, challenge.ServerChallenge, clientChallenge, timestamp, targetInfoBytes);

        // Without key exchange the exported session key is the NTLMv2 base key and the
        // encrypted-key field is empty — this keeps the SPNEGO mechListMIC deterministic.
        // With key exchange (the DCERPC sign/seal path) the client picks a random
        // exported session key and ships it RC4-wrapped under the key-exchange key
        // (= the NTLMv2 session base key); the MIC and GSS keys then derive from it.
        byte[] exportedSessionKey;
        byte[] encryptedSessionKey;
        if (KeyExchange)
        {
            exportedSessionKey = RandomNumberGenerator.GetBytes(16);
            encryptedSessionKey = NtlmCrypto.Rc4(v2.SessionBaseKey, exportedSessionKey);
        }
        else
        {
            exportedSessionKey = v2.SessionBaseKey;
            encryptedSessionKey = Array.Empty<byte>();
        }

        byte[] authenticate = BuildType3(
            v2.LmChallengeResponse, v2.NtChallengeResponse, domain, user, Workstation, encryptedSessionKey);

        // MIC = HMAC-MD5(exportedSessionKey, NEGOTIATE || CHALLENGE || AUTHENTICATE[mic=0]).
        if (IncludeMic)
        {
            byte[] mic = NtlmCrypto.HmacMd5(
                exportedSessionKey,
                Concat(_negotiateMessage, challenge.Raw, authenticate));
            Array.Copy(mic, 0, authenticate, Type3MicOffset, 16);
        }

        return new NtlmAuthResult(authenticate, exportedSessionKey);
    }

    private byte[] BuildType3(byte[] lm, byte[] nt, string domain, string user, string workstation, byte[] sessionKey)
    {
        byte[] domainBytes = Encoding.Unicode.GetBytes(domain);
        byte[] userBytes = Encoding.Unicode.GetBytes(user);
        byte[] workstationBytes = Encoding.Unicode.GetBytes(workstation);

        int offset = Type3FixedLength;
        int lmOffset = offset; offset += lm.Length;
        int ntOffset = offset; offset += nt.Length;
        int domainOffset = offset; offset += domainBytes.Length;
        int userOffset = offset; offset += userBytes.Length;
        int wsOffset = offset; offset += workstationBytes.Length;
        int keyOffset = offset;

        var writer = new ByteWriter(ByteOrder.Little);
        writer.WriteBytes(Ntlm.Signature);
        writer.WriteUInt32(Ntlm.AuthenticateMessage);
        WriteField(writer, lm.Length, lmOffset);
        WriteField(writer, nt.Length, ntOffset);
        WriteField(writer, domainBytes.Length, domainOffset);
        WriteField(writer, userBytes.Length, userOffset);
        WriteField(writer, workstationBytes.Length, wsOffset);
        WriteField(writer, sessionKey.Length, keyOffset);
        writer.WriteUInt32((uint)Flags);
        writer.WriteBytes(Windows10Version);
        writer.WriteBytes(new byte[16]); // MIC placeholder (patched by the caller)

        writer.WriteBytes(lm);
        writer.WriteBytes(nt);
        writer.WriteBytes(domainBytes);
        writer.WriteBytes(userBytes);
        writer.WriteBytes(workstationBytes);
        writer.WriteBytes(sessionKey);

        return writer.ToArray();
    }

    private static void WriteField(ByteWriter writer, int length, int offset)
    {
        writer.WriteUInt16((ushort)length); // Len
        writer.WriteUInt16((ushort)length); // MaxLen
        writer.WriteUInt32((uint)offset);   // BufferOffset
    }

    private static byte[] Concat(params byte[][] parts)
    {
        int total = 0;
        foreach (byte[] part in parts)
        {
            total += part.Length;
        }

        var result = new byte[total];
        int position = 0;
        foreach (byte[] part in parts)
        {
            Array.Copy(part, 0, result, position, part.Length);
            position += part.Length;
        }

        return result;
    }
}
