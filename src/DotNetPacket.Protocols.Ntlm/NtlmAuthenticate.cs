using System.Text;
using DotNetPacket.Core;

namespace DotNetPacket.Protocols.Ntlm;

/// <summary>
/// Parser for an NTLMSSP AUTHENTICATE message (Type 3, MS-NLMP 2.2.1.3): the fields a capturing or
/// relaying server needs to harvest a NetNTLM(v2) hash — the user, domain, workstation and the
/// LM/NT challenge responses. Each field is a security buffer (len/maxlen/offset-from-message-start).
/// Port of the read side of impacket's <c>ntlm.NTLMAuthChallengeResponse</c>.
/// </summary>
public sealed class NtlmAuthenticate
{
    public string DomainName { get; private init; } = string.Empty;

    public string UserName { get; private init; } = string.Empty;

    public string Workstation { get; private init; } = string.Empty;

    /// <summary>The NT challenge response (NTProofStr + blob for NTLMv2); &gt;24 bytes means NTLMv2.</summary>
    public byte[] NtChallengeResponse { get; private init; } = Array.Empty<byte>();

    public byte[] LmChallengeResponse { get; private init; } = Array.Empty<byte>();

    public uint NegotiateFlags { get; private init; }

    public bool IsNtlmV2 => NtChallengeResponse.Length > 24;

    public static NtlmAuthenticate Parse(byte[] message)
    {
        var r = new ByteReader(message, ByteOrder.Little);
        r.ReadBytes(8);                       // Signature "NTLMSSP\0"
        if (r.ReadUInt32() != 3)
        {
            throw new InvalidDataException("Not an NTLMSSP AUTHENTICATE (Type 3) message.");
        }

        byte[] lm = ReadSecurityBuffer(message, r);   // LmChallengeResponse
        byte[] nt = ReadSecurityBuffer(message, r);   // NtChallengeResponse
        byte[] domain = ReadSecurityBuffer(message, r); // DomainName
        byte[] user = ReadSecurityBuffer(message, r);   // UserName
        byte[] workstation = ReadSecurityBuffer(message, r); // Workstation
        ReadSecurityBuffer(message, r);               // EncryptedRandomSessionKey (unused here)
        uint flags = r.ReadUInt32();                  // NegotiateFlags

        return new NtlmAuthenticate
        {
            LmChallengeResponse = lm,
            NtChallengeResponse = nt,
            DomainName = Encoding.Unicode.GetString(domain),
            UserName = Encoding.Unicode.GetString(user),
            Workstation = Encoding.Unicode.GetString(workstation),
            NegotiateFlags = flags,
        };
    }

    // Reads a security buffer field (len, maxlen, offset) and slices its payload from the message.
    private static byte[] ReadSecurityBuffer(byte[] message, ByteReader r)
    {
        ushort length = r.ReadUInt16();
        r.ReadUInt16();                   // MaxLen
        uint offset = r.ReadUInt32();     // from the start of the message
        if (length == 0 || offset + length > (uint)message.Length)
        {
            return Array.Empty<byte>();
        }

        return message[(int)offset..(int)(offset + length)];
    }
}
