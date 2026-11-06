using DotNetPacket.Protocols.Smb;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class Smb2SetInfoTests
{
    [Fact]
    public void FileBasicInformation_ForAttributes_RoundTrips()
    {
        Smb2FileAttributes want = Smb2FileAttributes.ReadOnly | Smb2FileAttributes.Hidden;
        byte[] buf = FileBasicInformation.ForAttributes(want);

        // 40 bytes: four zero FILETIMEs, FileAttributes (0x03), reserved (0).
        Assert.Equal(FileBasicInformation.Size, buf.Length);
        Assert.Equal(
            "00000000000000000000000000000000000000000000000000000000000000000300000000000000",
            Convert.ToHexString(buf).ToLowerInvariant());
        Assert.Equal(want, FileBasicInformation.ParseAttributes(buf));
    }

    [Fact]
    public void SetInfoRequest_FileBasicInformation_HasExpectedLayout()
    {
        // SET_INFO body: StructureSize 0x21, InfoType File (0x01), class FileBasicInformation (0x04),
        // BufferLength 0x28 (40), BufferOffset 0x60 (SMB2 header 64 + 32), then FileId + the buffer.
        var body = new Smb2SetInfoRequest
        {
            InfoType = Smb2InfoType.File,
            FileInfoClass = (byte)Smb2FileInfoType.FileBasicInformation,
            FileId = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray(),
            Buffer = FileBasicInformation.ForAttributes(Smb2FileAttributes.ReadOnly | Smb2FileAttributes.Hidden),
        };

        const string expected =
            "2100010428000000600000000000000000010203040506070809" +
            "0a0b0c0d0e0f00000000000000000000000000000000000000000000000000000000000000000300000000000000";

        Assert.Equal(expected, Convert.ToHexString(body.Pack()).ToLowerInvariant());
    }
}
