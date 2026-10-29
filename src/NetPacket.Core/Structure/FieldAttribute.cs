namespace NetPacket.Core;

/// <summary>
/// Marks a property as a serialized field of a <see cref="NetStructure"/> and
/// describes its wire layout. Fields are packed/unpacked in ascending
/// <see cref="Order"/>.
/// </summary>
[AttributeUsage(AttributeTargets.Property, AllowMultiple = false, Inherited = true)]
public sealed class FieldAttribute : Attribute
{
    public FieldAttribute(int order, FieldKind kind)
    {
        Order = order;
        Kind = kind;
    }

    /// <summary>
    /// Serialization position. Lower values are written first. Must be unique
    /// within a structure; gaps are fine.
    /// </summary>
    public int Order { get; }

    /// <summary>Wire representation of the field.</summary>
    public FieldKind Kind { get; }

    /// <summary>
    /// Fixed byte length for a <see cref="FieldKind.Bytes"/> field. <c>-1</c>
    /// (default) means the length is not fixed here.
    /// </summary>
    public int Length { get; set; } = -1;

    /// <summary>
    /// For a <see cref="FieldKind.Bytes"/> field: the name of another (earlier)
    /// field whose numeric value supplies this field's byte length at unpack
    /// time. Ignored when <see cref="Length"/> is set.
    /// </summary>
    public string? LengthFrom { get; set; }

    /// <summary>
    /// For a numeric field: the name of a <see cref="FieldKind.Bytes"/>/string
    /// field whose serialized byte length this field carries. The value is
    /// auto-computed and written at pack time (a length prefix).
    /// </summary>
    public string? LengthOf { get; set; }
}
