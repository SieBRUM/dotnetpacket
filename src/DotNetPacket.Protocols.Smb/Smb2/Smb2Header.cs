using DotNetPacket.Core;

namespace DotNetPacket.Protocols.Smb;

/// <summary>
/// 64-byte SMB2/3 synchronous packet header (MS-SMB2 2.2.1.2). Port of impacket's
/// <c>smb3structs.SMB2Packet</c> header. Fits the declarative pattern — every field
/// is fixed-width.
/// </summary>
public sealed class Smb2Header : NetStructure
{
    /// <summary>The SMB2 header is always exactly this many bytes.</summary>
    public const int Size = 64;

    /// <summary>The SMB2 protocol signature: <c>0xFE 'S' 'M' 'B'</c>.</summary>
    public static readonly byte[] ProtocolId = { 0xFE, (byte)'S', (byte)'M', (byte)'B' };

    public override ByteOrder ByteOrder => ByteOrder.Little;

    [Field(0, FieldKind.Bytes, Length = 4)]
    public byte[] Protocol { get; set; } = (byte[])ProtocolId.Clone();

    [Field(1, FieldKind.UInt16)]
    public ushort StructureSize { get; set; } = Size;

    [Field(2, FieldKind.UInt16)]
    public ushort CreditCharge { get; set; }

    /// <summary>On a request this region is ChannelSequence + Reserved; zero for NEGOTIATE.</summary>
    [Field(3, FieldKind.UInt32)]
    public uint Status { get; set; }

    [Field(4, FieldKind.UInt16)]
    public ushort Command { get; set; }

    [Field(5, FieldKind.UInt16)]
    public ushort CreditRequest { get; set; }

    [Field(6, FieldKind.UInt32)]
    public uint Flags { get; set; }

    [Field(7, FieldKind.UInt32)]
    public uint NextCommand { get; set; }

    [Field(8, FieldKind.UInt64)]
    public ulong MessageId { get; set; }

    [Field(9, FieldKind.UInt32)]
    public uint Reserved { get; set; }

    [Field(10, FieldKind.UInt32)]
    public uint TreeId { get; set; }

    [Field(11, FieldKind.UInt64)]
    public ulong SessionId { get; set; }

    [Field(12, FieldKind.Bytes, Length = 16)]
    public byte[] Signature { get; set; } = new byte[16];
}
