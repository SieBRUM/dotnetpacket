using System.Collections.Concurrent;
using System.Reflection;
using System.Text;

namespace NetPacket.Core;

/// <summary>
/// Base class for protocol structures — the .NET port of impacket's
/// <c>Structure</c>. Two usage patterns are supported:
/// <list type="number">
///   <item>
///     <b>Declarative:</b> decorate properties with <see cref="FieldAttribute"/>
///     and let this class pack/unpack them in order. Best for sequential layouts.
///   </item>
///   <item>
///     <b>Manual override:</b> override <see cref="PackInto"/> and
///     <see cref="Unpack(ByteReader)"/> and drive the buffer directly. Best for
///     pointer/offset layouts (e.g. NTLM security buffers).
///   </item>
/// </list>
/// </summary>
public abstract class NetStructure
{
    private sealed record FieldMeta(PropertyInfo Property, FieldAttribute Attr);

    private static readonly ConcurrentDictionary<Type, FieldMeta[]> FieldCache = new();

    /// <summary>Byte order applied to every multi-byte field. Override per structure.</summary>
    public virtual ByteOrder ByteOrder => ByteOrder.Little;

    /// <summary>Serializes this structure to a new byte array.</summary>
    public byte[] Pack()
    {
        var writer = new ByteWriter(ByteOrder);
        PackInto(writer);
        return writer.ToArray();
    }

    /// <summary>Serializes this structure into an existing writer.</summary>
    public virtual void PackInto(ByteWriter writer)
    {
        FieldMeta[] fields = GetFields();
        foreach (FieldMeta field in fields)
        {
            PackField(field, writer, fields);
        }
    }

    /// <summary>Populates this structure's fields from a reader.</summary>
    public virtual void Unpack(ByteReader reader)
    {
        foreach (FieldMeta field in GetFields())
        {
            UnpackField(field, reader);
        }
    }

    /// <summary>Populates this structure's fields from a byte buffer.</summary>
    public void Unpack(ReadOnlyMemory<byte> data) => Unpack(new ByteReader(data, ByteOrder));

    private FieldMeta[] GetFields() => FieldCache.GetOrAdd(GetType(), static type =>
    {
        var metas = new List<FieldMeta>();
        foreach (PropertyInfo property in type.GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            FieldAttribute? attr = property.GetCustomAttribute<FieldAttribute>();
            if (attr is not null)
            {
                metas.Add(new FieldMeta(property, attr));
            }
        }

        metas.Sort(static (a, b) => a.Attr.Order.CompareTo(b.Attr.Order));
        return metas.ToArray();
    });

    private void PackField(FieldMeta field, ByteWriter writer, FieldMeta[] fields)
    {
        FieldAttribute attr = field.Attr;

        // Auto-populate a length prefix before writing it.
        if (attr.LengthOf is not null)
        {
            long length = ReferencedByteLength(attr.LengthOf, fields);
            field.Property.SetValue(this, Convert.ChangeType(length, UnderlyingType(field.Property.PropertyType)));
        }

        object? value = field.Property.GetValue(this);

        switch (attr.Kind)
        {
            case FieldKind.UInt8:
                writer.WriteByte(Convert.ToByte(value));
                break;
            case FieldKind.Int8:
                writer.WriteSByte(Convert.ToSByte(value));
                break;
            case FieldKind.UInt16:
                writer.WriteUInt16(Convert.ToUInt16(value));
                break;
            case FieldKind.Int16:
                writer.WriteInt16(Convert.ToInt16(value));
                break;
            case FieldKind.UInt32:
                writer.WriteUInt32(Convert.ToUInt32(value));
                break;
            case FieldKind.Int32:
                writer.WriteInt32(Convert.ToInt32(value));
                break;
            case FieldKind.UInt64:
                writer.WriteUInt64(Convert.ToUInt64(value));
                break;
            case FieldKind.Int64:
                writer.WriteInt64(Convert.ToInt64(value));
                break;
            case FieldKind.Bytes:
            {
                byte[] bytes = (byte[]?)value ?? Array.Empty<byte>();
                if (attr.Length >= 0 && bytes.Length != attr.Length)
                {
                    bytes = FitFixed(bytes, attr.Length);
                }

                writer.WriteBytes(bytes);
                break;
            }
            case FieldKind.AsciiZ:
                writer.WriteAsciiZ((string?)value ?? string.Empty);
                break;
            case FieldKind.UnicodeZ:
                writer.WriteUnicodeZ((string?)value ?? string.Empty);
                break;
            case FieldKind.Structure:
                ((NetStructure)value!).PackInto(writer);
                break;
            default:
                throw new NotSupportedException($"Unsupported field kind {attr.Kind}.");
        }
    }

    private void UnpackField(FieldMeta field, ByteReader reader)
    {
        FieldAttribute attr = field.Attr;
        Type propertyType = field.Property.PropertyType;

        switch (attr.Kind)
        {
            case FieldKind.UInt8:
                SetNumeric(field, propertyType, reader.ReadByte());
                return;
            case FieldKind.Int8:
                SetNumeric(field, propertyType, reader.ReadSByte());
                return;
            case FieldKind.UInt16:
                SetNumeric(field, propertyType, reader.ReadUInt16());
                return;
            case FieldKind.Int16:
                SetNumeric(field, propertyType, reader.ReadInt16());
                return;
            case FieldKind.UInt32:
                SetNumeric(field, propertyType, reader.ReadUInt32());
                return;
            case FieldKind.Int32:
                SetNumeric(field, propertyType, reader.ReadInt32());
                return;
            case FieldKind.UInt64:
                SetNumeric(field, propertyType, reader.ReadUInt64());
                return;
            case FieldKind.Int64:
                SetNumeric(field, propertyType, reader.ReadInt64());
                return;
            case FieldKind.Bytes:
                field.Property.SetValue(this, reader.ReadBytes(ResolveLength(attr, reader)));
                return;
            case FieldKind.AsciiZ:
                field.Property.SetValue(this, reader.ReadAsciiZ());
                return;
            case FieldKind.UnicodeZ:
                field.Property.SetValue(this, reader.ReadUnicodeZ());
                return;
            case FieldKind.Structure:
            {
                var nested = (NetStructure)(field.Property.GetValue(this)
                                            ?? Activator.CreateInstance(propertyType)!);
                nested.Unpack(reader);
                field.Property.SetValue(this, nested);
                return;
            }
            default:
                throw new NotSupportedException($"Unsupported field kind {attr.Kind}.");
        }
    }

    private int ResolveLength(FieldAttribute attr, ByteReader reader)
    {
        if (attr.Length >= 0)
        {
            return attr.Length;
        }

        if (attr.LengthFrom is not null)
        {
            FieldMeta target = GetFields().First(f => f.Property.Name == attr.LengthFrom);
            return Convert.ToInt32(target.Property.GetValue(this));
        }

        return reader.Remaining; // impacket ':'
    }

    private long ReferencedByteLength(string propertyName, FieldMeta[] fields)
    {
        FieldMeta target = fields.FirstOrDefault(f => f.Property.Name == propertyName)
                           ?? throw new InvalidOperationException(
                               $"LengthOf references unknown field '{propertyName}'.");
        object? value = target.Property.GetValue(this);
        return target.Attr.Kind switch
        {
            FieldKind.Bytes => ((byte[]?)value)?.Length ?? 0,
            FieldKind.AsciiZ => Encoding.ASCII.GetByteCount((string?)value ?? string.Empty) + 1,
            FieldKind.UnicodeZ => Encoding.Unicode.GetByteCount((string?)value ?? string.Empty) + 2,
            _ => throw new InvalidOperationException(
                $"LengthOf target '{propertyName}' must be a byte or string field."),
        };
    }

    private void SetNumeric(FieldMeta field, Type propertyType, object value)
    {
        Type target = Nullable.GetUnderlyingType(propertyType) ?? propertyType;
        object coerced = target.IsEnum
            ? Enum.ToObject(target, Convert.ToInt64(value))
            : Convert.ChangeType(value, target);
        field.Property.SetValue(this, coerced);
    }

    private static Type UnderlyingType(Type type)
    {
        Type target = Nullable.GetUnderlyingType(type) ?? type;
        return target.IsEnum ? Enum.GetUnderlyingType(target) : target;
    }

    private static byte[] FitFixed(byte[] source, int length)
    {
        var result = new byte[length];
        Array.Copy(source, result, Math.Min(source.Length, length));
        return result;
    }
}
