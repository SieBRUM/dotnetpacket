using NetPacket.Core;

namespace NetPacket.Protocols.Smb;

/// <summary>SMB2 READ request (MS-SMB2 2.2.19). Port of impacket's <c>smb3structs.SMB2Read</c>.</summary>
public sealed class Smb2ReadRequest : NetStructure
{
    public override ByteOrder ByteOrder => ByteOrder.Little;

    public uint Length { get; set; }

    public ulong Offset { get; set; }

    public byte[] FileId { get; set; } = new byte[16];

    public uint MinimumCount { get; set; }

    public override void PackInto(ByteWriter writer)
    {
        writer.WriteUInt16(49);          // StructureSize (fixed 48, +1)
        writer.WriteByte(0);             // Padding
        writer.WriteByte(0);             // Flags
        writer.WriteUInt32(Length);
        writer.WriteUInt64(Offset);
        writer.WriteBytes(FileId.Length == 16 ? FileId : new byte[16]);
        writer.WriteUInt32(MinimumCount);
        writer.WriteUInt32(0);           // Channel
        writer.WriteUInt32(0);           // RemainingBytes
        writer.WriteUInt16(0);           // ReadChannelInfoOffset
        writer.WriteUInt16(0);           // ReadChannelInfoLength
        writer.WriteByte(0);             // Buffer (>=1 byte)
    }
}

/// <summary>SMB2 READ response (MS-SMB2 2.2.20). Returns the file data read.</summary>
public sealed class Smb2ReadResponse : NetStructure
{
    public override ByteOrder ByteOrder => ByteOrder.Little;

    public uint DataRemaining { get; private set; }

    public byte[] Data { get; private set; } = Array.Empty<byte>();

    public override void Unpack(ByteReader reader)
    {
        reader.Position += Smb2Header.Size; // skip the SMB2 header

        reader.ReadUInt16();              // StructureSize
        byte dataOffset = reader.ReadByte();
        reader.ReadByte();                // Reserved
        uint dataLength = reader.ReadUInt32();
        DataRemaining = reader.ReadUInt32();
        reader.ReadUInt32();              // Reserved2

        if (dataLength > 0)
        {
            reader.Position = dataOffset; // offset from the SMB2 header start
            Data = reader.ReadBytes((int)dataLength);
        }
    }
}

/// <summary>SMB2 CLOSE request (MS-SMB2 2.2.15). Closes an open FileId.</summary>
public sealed class Smb2CloseRequest : NetStructure
{
    public override ByteOrder ByteOrder => ByteOrder.Little;

    public ushort Flags { get; set; }

    public byte[] FileId { get; set; } = new byte[16];

    public override void PackInto(ByteWriter writer)
    {
        writer.WriteUInt16(24);          // StructureSize
        writer.WriteUInt16(Flags);
        writer.WriteUInt32(0);           // Reserved
        writer.WriteBytes(FileId.Length == 16 ? FileId : new byte[16]);
    }
}
