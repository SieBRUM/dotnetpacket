using DotNetPacket.Core;

namespace DotNetPacket.Protocols.Smb;

/// <summary>Well-known FSCTL control codes (MS-FSCC 2.3).</summary>
public static class Fsctl
{
    /// <summary>FSCTL_PIPE_TRANSCEIVE: write a request to a named pipe and read the reply atomically.</summary>
    public const uint PipeTransceive = 0x0011C017;
    public const uint PipeWait = 0x00110018;
    public const uint DfsGetReferrals = 0x00060194;
    public const uint ValidateNegotiateInfo = 0x00140204;
}

/// <summary>SMB2 IOCTL request (MS-SMB2 2.2.31). Port of impacket's <c>smb3structs.SMB2Ioctl</c>.</summary>
public sealed class Smb2IoctlRequest : NetStructure
{
    private const uint IsFsctl = 0x00000001; // SMB2_0_IOCTL_IS_FSCTL

    public override ByteOrder ByteOrder => ByteOrder.Little;

    public uint CtlCode { get; set; }

    public byte[] FileId { get; set; } = new byte[16];

    public byte[] Input { get; set; } = Array.Empty<byte>();

    public uint MaxOutputResponse { get; set; } = 65536;

    public override void PackInto(ByteWriter writer)
    {
        writer.WriteUInt16(57);                               // StructureSize (fixed 56, +1)
        writer.WriteUInt16(0);                                // Reserved
        writer.WriteUInt32(CtlCode);
        writer.WriteBytes(FileId.Length == 16 ? FileId : new byte[16]);
        writer.WriteUInt32((uint)(Smb2Header.Size + 56));     // InputOffset
        writer.WriteUInt32((uint)Input.Length);               // InputCount
        writer.WriteUInt32(0);                                // MaxInputResponse
        writer.WriteUInt32((uint)(Smb2Header.Size + 56));     // OutputOffset
        writer.WriteUInt32(0);                                // OutputCount
        writer.WriteUInt32(MaxOutputResponse);                // MaxOutputResponse
        writer.WriteUInt32(IsFsctl);                          // Flags
        writer.WriteUInt32(0);                                // Reserved2
        writer.WriteBytes(Input);
    }
}

/// <summary>SMB2 IOCTL response (MS-SMB2 2.2.32). Returns the FSCTL output buffer.</summary>
public sealed class Smb2IoctlResponse : NetStructure
{
    public override ByteOrder ByteOrder => ByteOrder.Little;

    public byte[] Output { get; private set; } = Array.Empty<byte>();

    public override void Unpack(ByteReader reader)
    {
        reader.Position += Smb2Header.Size; // skip the SMB2 header

        reader.ReadUInt16(); // StructureSize
        reader.ReadUInt16(); // Reserved
        reader.ReadUInt32(); // CtlCode
        reader.ReadBytes(16); // FileId
        reader.ReadUInt32(); // InputOffset
        reader.ReadUInt32(); // InputCount
        uint outputOffset = reader.ReadUInt32();
        uint outputCount = reader.ReadUInt32();

        if (outputCount > 0)
        {
            reader.Position = (int)outputOffset; // offset from the SMB2 header start
            Output = reader.ReadBytes((int)outputCount);
        }
    }
}
