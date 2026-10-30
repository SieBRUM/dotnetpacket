namespace DotNetPacket.Core;

/// <summary>
/// Wire representation of a <see cref="NetStructure"/> field, mirroring the common
/// format codes in impacket's <c>Structure</c> mini-language.
/// </summary>
public enum FieldKind
{
    /// <summary>Unsigned 8-bit (<c>B</c>). CLR property: <see cref="byte"/>.</summary>
    UInt8,

    /// <summary>Signed 8-bit (<c>b</c>). CLR property: <see cref="sbyte"/>.</summary>
    Int8,

    /// <summary>Unsigned 16-bit. CLR property: <see cref="ushort"/>.</summary>
    UInt16,

    /// <summary>Signed 16-bit. CLR property: <see cref="short"/>.</summary>
    Int16,

    /// <summary>Unsigned 32-bit. CLR property: <see cref="uint"/>.</summary>
    UInt32,

    /// <summary>Signed 32-bit. CLR property: <see cref="int"/>.</summary>
    Int32,

    /// <summary>Unsigned 64-bit. CLR property: <see cref="ulong"/>.</summary>
    UInt64,

    /// <summary>Signed 64-bit. CLR property: <see cref="long"/>.</summary>
    Int64,

    /// <summary>
    /// Raw bytes (impacket <c>:</c>). Length is resolved, in order, from the
    /// field's fixed <c>Length</c>, then <c>LengthFrom</c> (another field's
    /// value), then "the rest of the buffer". CLR property: <see cref="byte"/>[].
    /// </summary>
    Bytes,

    /// <summary>NUL-terminated ASCII string (impacket <c>z</c>). CLR property: <see cref="string"/>.</summary>
    AsciiZ,

    /// <summary>NUL-terminated UTF-16LE string (impacket <c>u</c>). CLR property: <see cref="string"/>.</summary>
    UnicodeZ,

    /// <summary>A nested <see cref="NetStructure"/>. CLR property: that structure type.</summary>
    Structure,
}
