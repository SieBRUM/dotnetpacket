using DotNetPacket.Core;

namespace DotNetPacket.Protocols.Smb;

/// <summary>
/// NetBIOS Session Service header (RFC 1002 §4.3.1): the 4-byte framing that
/// precedes SMB over TCP/139. The length field is big-endian — a small example
/// of a structure whose multi-byte fields use network byte order.
/// </summary>
/// <remarks>
/// Simplification: RFC 1002 defines <c>Length</c> as 17 bits, borrowing the low
/// bit of the flags octet. This port treats flags and a 16-bit length separately,
/// which is correct for all session messages whose length fits in 16 bits (the
/// common case over TCP/139). Lengths above 0xFFFF need the manual-override
/// pattern.
/// </remarks>
public sealed class NetBiosSessionHeader : NetStructure
{
    public override ByteOrder ByteOrder => ByteOrder.Big;

    /// <summary>Session packet type (0x00 = Session Message).</summary>
    [Field(0, FieldKind.UInt8)]
    public byte MessageType { get; set; }

    [Field(1, FieldKind.UInt8)]
    public byte Flags { get; set; }

    /// <summary>Length (in bytes) of the payload that follows this header.</summary>
    [Field(2, FieldKind.UInt16)]
    public ushort Length { get; set; }
}
