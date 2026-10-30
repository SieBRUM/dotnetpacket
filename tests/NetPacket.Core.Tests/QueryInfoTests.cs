using System.Text;
using NetPacket.Core;
using NetPacket.Protocols.Smb;
using Xunit;

namespace NetPacket.Core.Tests;

public class QueryInfoTests
{
    [Fact]
    public void Request_HasExpectedShape()
    {
        var request = new Smb2QueryInfoRequest
        {
            InfoType = Smb2InfoType.FileSystem,
            FileInfoClass = (byte)Smb2FsInfoType.VolumeInformation,
            FileId = new byte[16],
        };
        byte[] body = request.Pack();

        Assert.Equal((ushort)41, BitConverter.ToUInt16(body, 0));          // StructureSize
        Assert.Equal((byte)Smb2InfoType.FileSystem, body[2]);              // InfoType
        Assert.Equal((byte)Smb2FsInfoType.VolumeInformation, body[3]);    // FileInfoClass
        Assert.Equal(40, body.Length);                                     // fixed part, no input buffer
    }

    [Fact]
    public void ParseVolumeInfo_DecodesSerialAndLabel()
    {
        byte[] label = Encoding.Unicode.GetBytes("LABVOL");
        var w = new ByteWriter(ByteOrder.Little);
        w.WriteUInt64(0);                       // VolumeCreationTime
        w.WriteUInt32(0xDEADBEEF);              // VolumeSerialNumber
        w.WriteUInt32((uint)label.Length);      // VolumeLabelLength
        w.WriteByte(0);                         // SupportsObjects
        w.WriteByte(0);                         // Reserved
        w.WriteBytes(label);

        Smb2VolumeInfo info = Smb2QueryInfoResponse.ParseVolumeInfo(w.ToArray());
        Assert.Equal(0xDEADBEEFu, info.SerialNumber);
        Assert.Equal("LABVOL", info.Label);
    }

    [Fact]
    public void ParseFsSizeInfo_ComputesBytes()
    {
        var w = new ByteWriter(ByteOrder.Little);
        w.WriteUInt64(1000);   // TotalAllocationUnits
        w.WriteUInt64(400);    // AvailableAllocationUnits
        w.WriteUInt32(8);      // SectorsPerAllocationUnit
        w.WriteUInt32(512);    // BytesPerSector

        Smb2FsSizeInfo info = Smb2QueryInfoResponse.ParseFsSizeInfo(w.ToArray());
        Assert.Equal(1000ul * 8 * 512, info.TotalBytes);
        Assert.Equal(400ul * 8 * 512, info.AvailableBytes);
    }
}
