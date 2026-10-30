using System.Text;
using NetPacket.Core;

namespace NetPacket.Protocols.Smb;

/// <summary>QUERY_INFO info types (MS-SMB2 2.2.37).</summary>
public enum Smb2InfoType : byte
{
    File = 0x01,
    FileSystem = 0x02,
    Security = 0x03,
    Quota = 0x04,
}

/// <summary>Common file information classes for QUERY_INFO (MS-FSCC 2.4).</summary>
public enum Smb2FileInfoType : byte
{
    FileBasicInformation = 0x04,
    FileStandardInformation = 0x05,
    FileAllInformation = 0x12,
}

/// <summary>File-system information classes for QUERY_INFO (MS-FSCC 2.5).</summary>
public enum Smb2FsInfoType : byte
{
    VolumeInformation = 0x01,
    SizeInformation = 0x03,
    DeviceInformation = 0x04,
    AttributeInformation = 0x05,
    FullSizeInformation = 0x07,
}

/// <summary>FileFsVolumeInformation (MS-FSCC 2.5.9): volume serial + label.</summary>
public sealed record Smb2VolumeInfo(uint SerialNumber, string Label);

/// <summary>FileFsSizeInformation (MS-FSCC 2.5.8): allocation-unit sizing.</summary>
public sealed record Smb2FsSizeInfo(ulong TotalAllocationUnits, ulong AvailableAllocationUnits, uint SectorsPerUnit, uint BytesPerSector)
{
    public ulong TotalBytes => TotalAllocationUnits * SectorsPerUnit * BytesPerSector;

    public ulong AvailableBytes => AvailableAllocationUnits * SectorsPerUnit * BytesPerSector;
}

/// <summary>
/// SMB2 QUERY_INFO request (MS-SMB2 2.2.37). Port of impacket's
/// <c>smb3structs.SMB2QueryInfo</c>. Queries metadata about an open handle.
/// </summary>
public sealed class Smb2QueryInfoRequest : NetStructure
{
    public override ByteOrder ByteOrder => ByteOrder.Little;

    public Smb2InfoType InfoType { get; set; } = Smb2InfoType.FileSystem;

    public byte FileInfoClass { get; set; }

    public byte[] FileId { get; set; } = new byte[16];

    public uint OutputBufferLength { get; set; } = 65536;

    public override void PackInto(ByteWriter writer)
    {
        writer.WriteUInt16(41);              // StructureSize (fixed 40, +1)
        writer.WriteByte((byte)InfoType);
        writer.WriteByte(FileInfoClass);
        writer.WriteUInt32(OutputBufferLength);
        writer.WriteUInt16(0);               // InputBufferOffset
        writer.WriteUInt16(0);               // Reserved
        writer.WriteUInt32(0);               // InputBufferLength
        writer.WriteUInt32(0);               // AdditionalInformation
        writer.WriteUInt32(0);               // Flags
        writer.WriteBytes(FileId.Length == 16 ? FileId : new byte[16]);
    }
}

/// <summary>Parses the QUERY_INFO response output buffer (MS-SMB2 2.2.38) into known info structures.</summary>
public static class Smb2QueryInfoResponse
{
    /// <summary>Returns the raw output buffer bytes from a QUERY_INFO response message.</summary>
    public static byte[] ExtractOutput(byte[] message)
    {
        var reader = new ByteReader(message, ByteOrder.Little);
        reader.Position = Smb2Header.Size;
        reader.ReadUInt16();                 // StructureSize
        ushort outputOffset = reader.ReadUInt16();
        uint outputLength = reader.ReadUInt32();
        if (outputLength == 0)
        {
            return Array.Empty<byte>();
        }

        reader.Position = outputOffset;
        return reader.ReadBytes((int)outputLength);
    }

    public static Smb2VolumeInfo ParseVolumeInfo(byte[] output)
    {
        var reader = new ByteReader(output, ByteOrder.Little);
        reader.ReadUInt64();                 // VolumeCreationTime
        uint serial = reader.ReadUInt32();
        uint labelLength = reader.ReadUInt32();
        reader.ReadByte();                   // SupportsObjects
        reader.ReadByte();                   // Reserved
        string label = labelLength > 0
            ? Encoding.Unicode.GetString(reader.ReadBytes((int)labelLength))
            : string.Empty;
        return new Smb2VolumeInfo(serial, label);
    }

    public static Smb2FsSizeInfo ParseFsSizeInfo(byte[] output)
    {
        var reader = new ByteReader(output, ByteOrder.Little);
        ulong total = reader.ReadUInt64();
        ulong avail = reader.ReadUInt64();
        uint sectorsPerUnit = reader.ReadUInt32();
        uint bytesPerSector = reader.ReadUInt32();
        return new Smb2FsSizeInfo(total, avail, sectorsPerUnit, bytesPerSector);
    }
}
