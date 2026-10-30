using System.Text;
using NetPacket.Core;

namespace NetPacket.Protocols.Smb;

/// <summary>File information classes for QUERY_DIRECTORY (MS-FSCC 2.4).</summary>
public enum Smb2FileInfoClass : byte
{
    FileDirectoryInformation = 0x01,
    FileFullDirectoryInformation = 0x02,
    FileBothDirectoryInformation = 0x03,
    FileNamesInformation = 0x0C,
    FileIdBothDirectoryInformation = 0x25,
}

/// <summary>One parsed directory entry (name, size, attributes).</summary>
public sealed record Smb2DirectoryEntry(string Name, ulong EndOfFile, Smb2FileAttributes Attributes)
{
    public bool IsDirectory => Attributes.HasFlag(Smb2FileAttributes.Directory);
}

/// <summary>
/// SMB2 QUERY_DIRECTORY request (MS-SMB2 2.2.33): enumerate a directory handle.
/// Port of impacket's <c>smb3structs.SMB2QueryDirectory</c>.
/// </summary>
public sealed class Smb2QueryDirectoryRequest : NetStructure
{
    public override ByteOrder ByteOrder => ByteOrder.Little;

    public Smb2FileInfoClass FileInformationClass { get; set; } = Smb2FileInfoClass.FileDirectoryInformation;

    public byte Flags { get; set; }

    public byte[] FileId { get; set; } = new byte[16];

    /// <summary>Search pattern, e.g. "*".</summary>
    public string SearchPattern { get; set; } = "*";

    public uint OutputBufferLength { get; set; } = 65536;

    public override void PackInto(ByteWriter writer)
    {
        byte[] pattern = Encoding.Unicode.GetBytes(SearchPattern);
        writer.WriteUInt16(33);                               // StructureSize (fixed 32, +1)
        writer.WriteByte((byte)FileInformationClass);
        writer.WriteByte(Flags);
        writer.WriteUInt32(0);                                // FileIndex
        writer.WriteBytes(FileId.Length == 16 ? FileId : new byte[16]);
        writer.WriteUInt16((ushort)(Smb2Header.Size + 32));   // FileNameOffset
        writer.WriteUInt16((ushort)pattern.Length);           // FileNameLength
        writer.WriteUInt32(OutputBufferLength);
        writer.WriteBytes(pattern);
    }
}

/// <summary>
/// SMB2 QUERY_DIRECTORY response (MS-SMB2 2.2.34). Parses the chained
/// FILE_DIRECTORY_INFORMATION entries (MS-FSCC 2.4.10) from the output buffer.
/// </summary>
public static class Smb2QueryDirectoryResponse
{
    public static IReadOnlyList<Smb2DirectoryEntry> Parse(byte[] message)
    {
        var reader = new ByteReader(message, ByteOrder.Little);
        reader.Position = Smb2Header.Size;

        reader.ReadUInt16(); // StructureSize
        ushort outputOffset = reader.ReadUInt16();
        uint outputLength = reader.ReadUInt32();

        var entries = new List<Smb2DirectoryEntry>();
        if (outputLength == 0)
        {
            return entries;
        }

        int bufferStart = outputOffset;
        int position = bufferStart;
        while (true)
        {
            reader.Position = position;
            uint nextEntryOffset = reader.ReadUInt32();
            reader.ReadUInt32();            // FileIndex
            reader.ReadUInt64();            // CreationTime
            reader.ReadUInt64();            // LastAccessTime
            reader.ReadUInt64();            // LastWriteTime
            reader.ReadUInt64();            // ChangeTime
            ulong endOfFile = reader.ReadUInt64();
            reader.ReadUInt64();            // AllocationSize
            var attributes = (Smb2FileAttributes)reader.ReadUInt32();
            uint fileNameLength = reader.ReadUInt32();
            byte[] nameBytes = reader.ReadBytes((int)fileNameLength);
            entries.Add(new Smb2DirectoryEntry(Encoding.Unicode.GetString(nameBytes), endOfFile, attributes));

            if (nextEntryOffset == 0)
            {
                break;
            }

            position += (int)nextEntryOffset;
        }

        return entries;
    }
}
