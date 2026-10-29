using NetPacket.Core;

namespace NetPacket.Protocols.Smb;

/// <summary>
/// SMB2 NEGOTIATE response (MS-SMB2 2.2.4). Parses the server's chosen dialect,
/// capabilities, and the SPNEGO/GSS security buffer. Port of the parsing side of
/// impacket's <c>smb3structs.SMB2Negotiate_Response</c>.
/// </summary>
/// <remarks>
/// <see cref="Unpack(ByteReader)"/> expects a reader positioned at the start of the
/// SMB2 header of the full response message (offsets in the response are measured
/// from there).
/// </remarks>
public sealed class Smb2NegotiateResponse : NetStructure
{
    public override ByteOrder ByteOrder => ByteOrder.Little;

    public ushort StructureSize { get; private set; }

    public Smb2SecurityMode SecurityMode { get; private set; }

    public Smb2Dialect DialectRevision { get; private set; }

    public ushort NegotiateContextCount { get; private set; }

    public byte[] ServerGuid { get; private set; } = new byte[16];

    public Smb2Capabilities Capabilities { get; private set; }

    public uint MaxTransactSize { get; private set; }

    public uint MaxReadSize { get; private set; }

    public uint MaxWriteSize { get; private set; }

    public ulong SystemTime { get; private set; }

    public ulong ServerStartTime { get; private set; }

    public ushort SecurityBufferOffset { get; private set; }

    public ushort SecurityBufferLength { get; private set; }

    public uint NegotiateContextOffset { get; private set; }

    /// <summary>The SPNEGO/GSS token the server offers (its supported auth mechanisms).</summary>
    public byte[] SecurityBuffer { get; private set; } = Array.Empty<byte>();

    public override void Unpack(ByteReader reader)
    {
        reader.Position += Smb2Header.Size; // skip the SMB2 header

        StructureSize = reader.ReadUInt16();
        SecurityMode = (Smb2SecurityMode)reader.ReadUInt16();
        DialectRevision = (Smb2Dialect)reader.ReadUInt16();
        NegotiateContextCount = reader.ReadUInt16();
        ServerGuid = reader.ReadBytes(16);
        Capabilities = (Smb2Capabilities)reader.ReadUInt32();
        MaxTransactSize = reader.ReadUInt32();
        MaxReadSize = reader.ReadUInt32();
        MaxWriteSize = reader.ReadUInt32();
        SystemTime = reader.ReadUInt64();
        ServerStartTime = reader.ReadUInt64();
        SecurityBufferOffset = reader.ReadUInt16();
        SecurityBufferLength = reader.ReadUInt16();
        NegotiateContextOffset = reader.ReadUInt32();

        if (SecurityBufferLength > 0)
        {
            reader.Position = SecurityBufferOffset; // offset from the SMB2 header start
            SecurityBuffer = reader.ReadBytes(SecurityBufferLength);
        }
    }
}
