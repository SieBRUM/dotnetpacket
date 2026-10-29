using NetPacket.Core;

namespace NetPacket.Protocols.Smb;

/// <summary>SMB2 WRITE request (MS-SMB2 2.2.21). Port of impacket's <c>smb3structs.SMB2Write</c>.</summary>
public sealed class Smb2WriteRequest : NetStructure
{
    public override ByteOrder ByteOrder => ByteOrder.Little;

    public ulong Offset { get; set; }

    public byte[] FileId { get; set; } = new byte[16];

    public byte[] Data { get; set; } = Array.Empty<byte>();

    public override void PackInto(ByteWriter writer)
    {
        writer.WriteUInt16(49);                              // StructureSize (fixed 48, +1)
        writer.WriteUInt16((ushort)(Smb2Header.Size + 48));  // DataOffset (from header start)
        writer.WriteUInt32((uint)Data.Length);               // Length
        writer.WriteUInt64(Offset);
        writer.WriteBytes(FileId.Length == 16 ? FileId : new byte[16]);
        writer.WriteUInt32(0);                               // Channel
        writer.WriteUInt32(0);                               // RemainingBytes
        writer.WriteUInt16(0);                               // WriteChannelInfoOffset
        writer.WriteUInt16(0);                               // WriteChannelInfoLength
        writer.WriteUInt32(0);                               // Flags
        writer.WriteBytes(Data);
    }
}

/// <summary>SMB2 WRITE response (MS-SMB2 2.2.22). Reports the number of bytes written.</summary>
public sealed class Smb2WriteResponse : NetStructure
{
    public override ByteOrder ByteOrder => ByteOrder.Little;

    public uint Count { get; private set; }

    public override void Unpack(ByteReader reader)
    {
        reader.Position += Smb2Header.Size; // skip the SMB2 header

        reader.ReadUInt16(); // StructureSize
        reader.ReadUInt16(); // Reserved
        Count = reader.ReadUInt32();
    }
}
