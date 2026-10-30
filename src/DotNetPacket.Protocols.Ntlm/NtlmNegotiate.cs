using System.Text;
using DotNetPacket.Core;

namespace DotNetPacket.Protocols.Ntlm;

/// <summary>
/// NTLMSSP NEGOTIATE_MESSAGE (MS-NLMP 2.2.1.1). Reference port of impacket's
/// <c>ntlm.NTLMAuthNegotiate</c>.
/// </summary>
/// <remarks>
/// The domain and workstation fields use the NTLM len/maxlen/offset "security
/// buffer" scheme: the descriptors live in the fixed header while the bytes they
/// describe live in a payload section after it. That cross-referencing layout is
/// exactly where the declarative <see cref="NetStructure"/> pattern stops being a
/// good fit, so this type overrides <see cref="PackInto"/> and
/// <see cref="Unpack(ByteReader)"/> and drives the buffer by hand. CHALLENGE and
/// AUTHENTICATE follow the same scheme — use this class as their template.
/// </remarks>
public sealed class NtlmNegotiate : NetStructure
{
    public override ByteOrder ByteOrder => ByteOrder.Little;

    public uint NegotiateFlags { get; set; }

    public string DomainName { get; set; } = string.Empty;

    public string Workstation { get; set; } = string.Empty;

    // Fixed header: signature(8) + message type(4) + flags(4) + two security buffers(8 each).
    private const int FixedLength = 8 + 4 + 4 + 8 + 8;

    public override void PackInto(ByteWriter writer)
    {
        byte[] domain = Encoding.ASCII.GetBytes(DomainName);
        byte[] workstation = Encoding.ASCII.GetBytes(Workstation);

        uint domainOffset = FixedLength;
        uint workstationOffset = (uint)(FixedLength + domain.Length);

        writer.WriteBytes(Ntlm.Signature);
        writer.WriteUInt32(Ntlm.NegotiateMessage);
        writer.WriteUInt32(NegotiateFlags);
        WriteSecurityBuffer(writer, (ushort)domain.Length, domainOffset);
        WriteSecurityBuffer(writer, (ushort)workstation.Length, workstationOffset);

        // Payload section, in the same order the security buffers point to it.
        writer.WriteBytes(domain);
        writer.WriteBytes(workstation);
    }

    public override void Unpack(ByteReader reader)
    {
        byte[] signature = reader.ReadBytes(8);
        if (!signature.AsSpan().SequenceEqual(Ntlm.Signature))
        {
            throw new InvalidDataException("Buffer does not start with the NTLMSSP signature.");
        }

        uint messageType = reader.ReadUInt32();
        if (messageType != Ntlm.NegotiateMessage)
        {
            throw new InvalidDataException($"Expected NEGOTIATE (1) message but found type {messageType}.");
        }

        NegotiateFlags = reader.ReadUInt32();
        SecurityBuffer domainBuffer = ReadSecurityBuffer(reader);
        SecurityBuffer workstationBuffer = ReadSecurityBuffer(reader);

        DomainName = ReadAsciiPayload(reader, domainBuffer);
        Workstation = ReadAsciiPayload(reader, workstationBuffer);
    }

    private static void WriteSecurityBuffer(ByteWriter writer, ushort length, uint offset)
    {
        writer.WriteUInt16(length);
        writer.WriteUInt16(length); // MaxLen == Len
        writer.WriteUInt32(offset);
    }

    private static SecurityBuffer ReadSecurityBuffer(ByteReader reader) => new()
    {
        Length = reader.ReadUInt16(),
        MaxLength = reader.ReadUInt16(),
        Offset = reader.ReadUInt32(),
    };

    private static string ReadAsciiPayload(ByteReader reader, SecurityBuffer buffer)
    {
        if (buffer.Length == 0)
        {
            return string.Empty;
        }

        int saved = reader.Position;
        reader.Position = (int)buffer.Offset;
        byte[] bytes = reader.ReadBytes(buffer.Length);
        reader.Position = saved;
        return Encoding.ASCII.GetString(bytes);
    }
}
