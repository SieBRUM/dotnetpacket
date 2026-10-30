using System.Text;
using NetPacket.Core;
using NetPacket.Protocols.Smb;
using Xunit;

namespace NetPacket.Core.Tests;

public class QueryDirectoryTests
{
    [Fact]
    public void Request_HasExpectedShape()
    {
        var request = new Smb2QueryDirectoryRequest { FileId = new byte[16], SearchPattern = "*" };
        byte[] body = request.Pack();

        Assert.Equal((ushort)33, BitConverter.ToUInt16(body, 0));                 // StructureSize
        Assert.Equal((byte)Smb2FileInfoClass.FileDirectoryInformation, body[2]);
        Assert.Equal((ushort)(64 + 32), BitConverter.ToUInt16(body, 24));         // FileNameOffset
        Assert.Equal((ushort)2, BitConverter.ToUInt16(body, 26));                 // FileNameLength ("*" = 2 bytes)
    }

    [Fact]
    public void Response_ParsesChainedEntries()
    {
        // Two FILE_DIRECTORY_INFORMATION entries: "." (dir) and "readme.txt" (59 bytes).
        var writer = new ByteWriter(ByteOrder.Little);
        writer.WriteBytes(new byte[Smb2Header.Size]); // header placeholder
        writer.WriteUInt16(9);                         // StructureSize
        writer.WriteUInt16((ushort)(Smb2Header.Size + 8)); // OutputBufferOffset = 72
        int lengthPos = writer.Length;
        writer.WriteUInt32(0);                         // OutputBufferLength (patched below)

        int bufferStart = writer.Length; // == 72

        void WriteEntry(uint nextOffset, string name, ulong size, uint attrs)
        {
            byte[] nameBytes = Encoding.Unicode.GetBytes(name);
            writer.WriteUInt32(nextOffset);
            writer.WriteUInt32(0);        // FileIndex
            writer.WriteUInt64(0);        // CreationTime
            writer.WriteUInt64(0);        // LastAccessTime
            writer.WriteUInt64(0);        // LastWriteTime
            writer.WriteUInt64(0);        // ChangeTime
            writer.WriteUInt64(size);     // EndOfFile
            writer.WriteUInt64(size);     // AllocationSize
            writer.WriteUInt32(attrs);    // FileAttributes
            writer.WriteUInt32((uint)nameBytes.Length);
            writer.WriteBytes(nameBytes);
        }

        // entry0 "." directory; NextEntryOffset = 64 + 2 chars = 66 (padded to 8 -> 72)
        WriteEntry(72, ".", 0, (uint)Smb2FileAttributes.Directory);
        while ((writer.Length - bufferStart) % 72 != 0) { writer.WriteByte(0); } // pad to next entry
        WriteEntry(0, "readme.txt", 59, (uint)Smb2FileAttributes.Archive);

        byte[] message = writer.ToArray();
        // patch OutputBufferLength
        uint outLen = (uint)(message.Length - bufferStart);
        message[lengthPos] = (byte)outLen;
        message[lengthPos + 1] = (byte)(outLen >> 8);

        IReadOnlyList<Smb2DirectoryEntry> entries = Smb2QueryDirectoryResponse.Parse(message);

        Assert.Equal(2, entries.Count);
        Assert.Equal(".", entries[0].Name);
        Assert.True(entries[0].IsDirectory);
        Assert.Equal("readme.txt", entries[1].Name);
        Assert.Equal(59ul, entries[1].EndOfFile);
        Assert.False(entries[1].IsDirectory);
    }
}
