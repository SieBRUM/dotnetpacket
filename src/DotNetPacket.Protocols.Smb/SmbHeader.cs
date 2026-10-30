using DotNetPacket.Core;

namespace DotNetPacket.Protocols.Smb;

/// <summary>
/// 32-byte SMBv1 message header (MS-CIFS 2.2.3.1). Little-endian throughout.
/// Reference port of impacket's <c>smb.SMB.SMBHeader</c>, used to demonstrate the
/// declarative <see cref="NetStructure"/> pattern.
/// </summary>
public sealed class SmbHeader : NetStructure
{
    /// <summary>The SMBv1 protocol signature: <c>0xFF 'S' 'M' 'B'</c>.</summary>
    public static readonly byte[] Signature = { 0xFF, (byte)'S', (byte)'M', (byte)'B' };

    public override ByteOrder ByteOrder => ByteOrder.Little;

    [Field(0, FieldKind.Bytes, Length = 4)]
    public byte[] Protocol { get; set; } = (byte[])Signature.Clone();

    /// <summary>SMB command code (e.g. 0x72 = SMB_COM_NEGOTIATE).</summary>
    [Field(1, FieldKind.UInt8)]
    public byte Command { get; set; }

    /// <summary>NTSTATUS result code.</summary>
    [Field(2, FieldKind.UInt32)]
    public uint Status { get; set; }

    [Field(3, FieldKind.UInt8)]
    public byte Flags { get; set; }

    [Field(4, FieldKind.UInt16)]
    public ushort Flags2 { get; set; }

    [Field(5, FieldKind.UInt16)]
    public ushort PidHigh { get; set; }

    /// <summary>8-byte security signature (or key + reserved, depending on flags).</summary>
    [Field(6, FieldKind.Bytes, Length = 8)]
    public byte[] SecurityFeatures { get; set; } = new byte[8];

    [Field(7, FieldKind.UInt16)]
    public ushort Reserved { get; set; }

    /// <summary>Tree ID.</summary>
    [Field(8, FieldKind.UInt16)]
    public ushort Tid { get; set; }

    [Field(9, FieldKind.UInt16)]
    public ushort PidLow { get; set; }

    /// <summary>User ID.</summary>
    [Field(10, FieldKind.UInt16)]
    public ushort Uid { get; set; }

    /// <summary>Multiplex ID.</summary>
    [Field(11, FieldKind.UInt16)]
    public ushort Mid { get; set; }
}
