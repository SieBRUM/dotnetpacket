using DotNetPacket.Core;
using Xunit;

namespace DotNetPacket.Core.Tests;

public class BufferTests
{
    [Fact]
    public void UInt16_WritesLittleEndian()
    {
        var writer = new ByteWriter(ByteOrder.Little);
        writer.WriteUInt16(0x0102);
        Assert.Equal(new byte[] { 0x02, 0x01 }, writer.ToArray());
    }

    [Fact]
    public void UInt16_WritesBigEndian()
    {
        var writer = new ByteWriter(ByteOrder.Big);
        writer.WriteUInt16(0x0102);
        Assert.Equal(new byte[] { 0x01, 0x02 }, writer.ToArray());
    }

    [Fact]
    public void UInt32_RoundTrips()
    {
        var writer = new ByteWriter(ByteOrder.Little);
        writer.WriteUInt32(0x01020304);

        var reader = new ByteReader(writer.ToArray(), ByteOrder.Little);
        Assert.Equal(0x01020304u, reader.ReadUInt32());
        Assert.Equal(0, reader.Remaining);
    }

    [Fact]
    public void AsciiZ_RoundTrips()
    {
        var writer = new ByteWriter();
        writer.WriteAsciiZ("WORKGROUP");

        byte[] bytes = writer.ToArray();
        Assert.Equal(10, bytes.Length); // 9 chars + NUL
        Assert.Equal(0x00, bytes[^1]);

        var reader = new ByteReader(bytes);
        Assert.Equal("WORKGROUP", reader.ReadAsciiZ());
    }

    [Fact]
    public void Position_IsSeekable()
    {
        var reader = new ByteReader(new byte[] { 1, 2, 3, 4 });
        reader.Position = 2;
        Assert.Equal((byte)3, reader.ReadByte());
    }

    [Fact]
    public void ReadBeyondEnd_Throws()
    {
        var reader = new ByteReader(new byte[] { 1, 2 });
        Assert.Throws<EndOfStreamException>(() => { reader.ReadUInt32(); });
    }
}
