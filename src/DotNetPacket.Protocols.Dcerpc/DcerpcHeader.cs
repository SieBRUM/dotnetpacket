using DotNetPacket.Core;

namespace DotNetPacket.Protocols.Dcerpc;

/// <summary>
/// The 16-byte DCERPC common PDU header (DCE 1.1 / MS-RPCE 2.2.2.6). Port of the
/// header in impacket's <c>dcerpc.v5.rpcrt.MSRPCHeader</c>.
/// </summary>
public sealed class DcerpcHeader : NetStructure
{
    public const int Size = 16;

    public override ByteOrder ByteOrder => ByteOrder.Little;

    [Field(0, FieldKind.UInt8)]
    public byte MajorVersion { get; set; } = 5;

    [Field(1, FieldKind.UInt8)]
    public byte MinorVersion { get; set; }

    [Field(2, FieldKind.UInt8)]
    public byte PduType { get; set; }

    [Field(3, FieldKind.UInt8)]
    public byte PfcFlags { get; set; } = (byte)(DcerpcPfcFlags.FirstFragment | DcerpcPfcFlags.LastFragment);

    [Field(4, FieldKind.Bytes, Length = 4)]
    public byte[] DataRepresentation { get; set; } = (byte[])Dcerpc.LittleEndianDataRepresentation.Clone();

    [Field(5, FieldKind.UInt16)]
    public ushort FragLength { get; set; }

    [Field(6, FieldKind.UInt16)]
    public ushort AuthLength { get; set; }

    [Field(7, FieldKind.UInt32)]
    public uint CallId { get; set; }
}
