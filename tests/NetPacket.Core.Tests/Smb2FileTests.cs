using System.Text;
using NetPacket.Core;
using NetPacket.Protocols.Smb;
using Xunit;

namespace NetPacket.Core.Tests;

public class Smb2CreateRequestTests
{
    [Fact]
    public void HasExpectedShapeAndName()
    {
        var request = new Smb2CreateRequest { Path = "readme.txt" };
        byte[] body = request.Pack();

        Assert.Equal((ushort)57, BitConverter.ToUInt16(body, 0));                 // StructureSize
        Assert.Equal((uint)Smb2AccessMask.FileGenericRead, BitConverter.ToUInt32(body, 24));
        Assert.Equal((ushort)(64 + 56), BitConverter.ToUInt16(body, 44));         // NameOffset
        ushort nameLength = BitConverter.ToUInt16(body, 46);
        Assert.Equal((ushort)("readme.txt".Length * 2), nameLength);
        Assert.Equal("readme.txt", Encoding.Unicode.GetString(body, 56, nameLength));
    }
}

public class Smb2ReadRequestTests
{
    [Fact]
    public void HasExpectedShape()
    {
        var fileId = new byte[16];
        fileId[0] = 0xAB;
        var request = new Smb2ReadRequest { FileId = fileId, Offset = 0x1000, Length = 59 };
        byte[] body = request.Pack();

        Assert.Equal((ushort)49, BitConverter.ToUInt16(body, 0)); // StructureSize
        Assert.Equal(59u, BitConverter.ToUInt32(body, 4));        // Length
        Assert.Equal(0x1000ul, BitConverter.ToUInt64(body, 8));   // Offset
        Assert.Equal(0xAB, body[16]);                             // FileId[0]
        Assert.Equal(49, body.Length);                            // 48 fixed + 1 pad byte
    }
}

public class Smb2CloseRequestTests
{
    [Fact]
    public void HasExpectedShape()
    {
        byte[] body = new Smb2CloseRequest { FileId = new byte[16] }.Pack();
        Assert.Equal((ushort)24, BitConverter.ToUInt16(body, 0));
        Assert.Equal(24, body.Length);
    }
}

public class Smb2ResponseParseTests
{
    [Fact]
    public void Create_ParsesSizeAndFileId()
    {
        var writer = new ByteWriter(ByteOrder.Little);
        writer.WriteBytes(new byte[Smb2Header.Size]); // header placeholder
        writer.WriteUInt16(89);          // StructureSize
        writer.WriteByte(0);             // OplockLevel
        writer.WriteByte(0);             // Flags
        writer.WriteUInt32(1);           // CreateAction (FILE_OPENED)
        writer.WriteUInt64(0);           // CreationTime
        writer.WriteUInt64(0);           // LastAccessTime
        writer.WriteUInt64(0);           // LastWriteTime
        writer.WriteUInt64(0);           // ChangeTime
        writer.WriteUInt64(0);           // AllocationSize
        writer.WriteUInt64(59);          // EndOfFile
        writer.WriteUInt32(0x80);        // FileAttributes (NORMAL)
        writer.WriteUInt32(0);           // Reserved2
        var fileId = new byte[16];
        fileId[0] = 0x42;
        writer.WriteBytes(fileId);
        writer.WriteUInt32(0);           // CreateContextsOffset
        writer.WriteUInt32(0);           // CreateContextsLength

        var response = new Smb2CreateResponse();
        response.Unpack(writer.ToArray());

        Assert.Equal(59ul, response.EndOfFile);
        Assert.Equal(0x42, response.FileId[0]);
    }

    [Fact]
    public void Read_ParsesData()
    {
        byte[] payload = Encoding.ASCII.GetBytes("hello smb");
        var writer = new ByteWriter(ByteOrder.Little);
        writer.WriteBytes(new byte[Smb2Header.Size]); // header placeholder
        writer.WriteUInt16(17);                        // StructureSize
        writer.WriteByte((byte)(Smb2Header.Size + 16));// DataOffset = 80
        writer.WriteByte(0);                           // Reserved
        writer.WriteUInt32((uint)payload.Length);      // DataLength
        writer.WriteUInt32(0);                         // DataRemaining
        writer.WriteUInt32(0);                         // Reserved2
        writer.WriteBytes(payload);                    // data at offset 80

        var response = new Smb2ReadResponse();
        response.Unpack(writer.ToArray());

        Assert.Equal(payload, response.Data);
    }
}
