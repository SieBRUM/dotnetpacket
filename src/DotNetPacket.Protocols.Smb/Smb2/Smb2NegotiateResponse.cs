using DotNetPacket.Core;

namespace DotNetPacket.Protocols.Smb;

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

    /// <summary>
    /// The single encryption cipher the server selected from the client's list, read from the SMB 3.1.1
    /// SMB2_ENCRYPTION_CAPABILITIES negotiate context (MS-SMB2 2.2.3.1.2). 0 when the server offered no
    /// cipher (encryption not negotiated). See <see cref="Smb2Cipher"/>.
    /// </summary>
    public ushort Cipher { get; private set; }

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

        if (DialectRevision == Smb2Dialect.Smb311 && NegotiateContextCount > 0 && NegotiateContextOffset > 0)
        {
            ParseNegotiateContexts(reader);
        }
    }

    // Walk the 8-byte-aligned negotiate contexts (each: Type(2) DataLength(2) Reserved(4) Data) and pull
    // the server's chosen cipher out of the SMB2_ENCRYPTION_CAPABILITIES context.
    private void ParseNegotiateContexts(ByteReader reader)
    {
        reader.Position = (int)NegotiateContextOffset; // offset from the SMB2 header start
        for (int i = 0; i < NegotiateContextCount; i++)
        {
            var type = (Smb2NegotiateContextType)reader.ReadUInt16();
            int dataLength = reader.ReadUInt16();
            reader.ReadUInt32(); // Reserved
            int dataStart = reader.Position;

            if (type == Smb2NegotiateContextType.EncryptionCapabilities && dataLength >= 4)
            {
                reader.ReadUInt16();          // CipherCount (the server returns exactly one)
                Cipher = reader.ReadUInt16(); // the selected cipher
            }

            // Advance to the next context, 8-byte aligned from the SMB2 header start.
            int next = dataStart + dataLength;
            reader.Position = (next + 7) & ~7;
        }
    }
}
