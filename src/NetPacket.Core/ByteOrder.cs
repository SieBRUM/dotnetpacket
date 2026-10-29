namespace NetPacket.Core;

/// <summary>Byte order (endianness) for multi-byte integer fields.</summary>
public enum ByteOrder
{
    /// <summary>Least-significant byte first (impacket's <c>&lt;</c>).</summary>
    Little,

    /// <summary>Most-significant byte first (impacket's <c>&gt;</c> / network order).</summary>
    Big,
}
