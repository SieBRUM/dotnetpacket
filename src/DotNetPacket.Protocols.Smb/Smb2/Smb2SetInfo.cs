using DotNetPacket.Core;

namespace DotNetPacket.Protocols.Smb;

/// <summary>
/// SMB2 SET_INFO request (MS-SMB2 2.2.39): writes an information buffer (e.g. FileBasicInformation)
/// to an open handle. Port of the set-info side of impacket's <c>SMB2SetInfo</c>; used by attrib.py
/// to change a file/directory's attributes.
/// </summary>
public sealed class Smb2SetInfoRequest : NetStructure
{
    public override ByteOrder ByteOrder => ByteOrder.Little;

    public Smb2InfoType InfoType { get; set; } = Smb2InfoType.File;

    public byte FileInfoClass { get; set; }

    public byte[] FileId { get; set; } = new byte[16];

    public byte[] Buffer { get; set; } = Array.Empty<byte>();

    public override void PackInto(ByteWriter writer)
    {
        const int headerToBuffer = Smb2Header.Size + 32; // fixed SET_INFO fields are 32 bytes (incl. the +1 struct size)
        writer.WriteUInt16(33);                      // StructureSize (fixed 32, +1)
        writer.WriteByte((byte)InfoType);
        writer.WriteByte(FileInfoClass);
        writer.WriteUInt32((uint)Buffer.Length);     // BufferLength
        writer.WriteUInt16((ushort)headerToBuffer);  // BufferOffset (from SMB2 header start)
        writer.WriteUInt16(0);                       // Reserved
        writer.WriteUInt32(0);                       // AdditionalInformation
        writer.WriteBytes(FileId.Length == 16 ? FileId : new byte[16]);
        writer.WriteBytes(Buffer);
    }
}

/// <summary>
/// FILE_BASIC_INFORMATION (MS-FSCC 2.4.7): four FILETIME timestamps + FileAttributes + reserved
/// (40 bytes). Used to query and set a file/directory's attributes. A timestamp of 0 on a SET
/// means "do not change".
/// </summary>
public static class FileBasicInformation
{
    public const int Size = 40;

    /// <summary>Builds a FILE_BASIC_INFORMATION buffer that changes only FileAttributes (times left 0).</summary>
    public static byte[] ForAttributes(Smb2FileAttributes attributes)
    {
        var writer = new ByteWriter(ByteOrder.Little);
        writer.WriteUInt64(0); // CreationTime (0 = unchanged)
        writer.WriteUInt64(0); // LastAccessTime
        writer.WriteUInt64(0); // LastWriteTime
        writer.WriteUInt64(0); // ChangeTime
        writer.WriteUInt32((uint)attributes); // FileAttributes
        writer.WriteUInt32(0); // Reserved
        return writer.ToArray();
    }

    /// <summary>Reads the FileAttributes field from a FILE_BASIC_INFORMATION output buffer.</summary>
    public static Smb2FileAttributes ParseAttributes(byte[] buffer)
    {
        if (buffer.Length < 36)
        {
            throw new InvalidDataException("FILE_BASIC_INFORMATION buffer too short.");
        }

        var reader = new ByteReader(buffer, ByteOrder.Little);
        reader.Position = 32; // skip the four 8-byte timestamps
        return (Smb2FileAttributes)reader.ReadUInt32();
    }
}
