using System.Buffers.Binary;
using System.Text;

namespace DotNetPacket.Core;

/// <summary>
/// Growable, cursor-free binary writer with explicit endianness. The low-level
/// building block for packing structures; see <see cref="NetStructure"/> for the
/// declarative layer built on top of it.
/// </summary>
public sealed class ByteWriter
{
    private readonly List<byte> _buffer = new();

    /// <summary>Default byte order used when a write call does not specify one.</summary>
    public ByteOrder ByteOrder { get; }

    public ByteWriter(ByteOrder byteOrder = ByteOrder.Little) => ByteOrder = byteOrder;

    /// <summary>Number of bytes written so far.</summary>
    public int Length => _buffer.Count;

    public void WriteByte(byte value) => _buffer.Add(value);

    public void WriteSByte(sbyte value) => _buffer.Add((byte)value);

    public void WriteBytes(ReadOnlySpan<byte> value)
    {
        foreach (byte b in value)
        {
            _buffer.Add(b);
        }
    }

    public void WriteUInt16(ushort value, ByteOrder? order = null)
    {
        Span<byte> tmp = stackalloc byte[2];
        if ((order ?? ByteOrder) == ByteOrder.Little)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(tmp, value);
        }
        else
        {
            BinaryPrimitives.WriteUInt16BigEndian(tmp, value);
        }

        WriteBytes(tmp);
    }

    public void WriteInt16(short value, ByteOrder? order = null) => WriteUInt16((ushort)value, order);

    public void WriteUInt32(uint value, ByteOrder? order = null)
    {
        Span<byte> tmp = stackalloc byte[4];
        if ((order ?? ByteOrder) == ByteOrder.Little)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(tmp, value);
        }
        else
        {
            BinaryPrimitives.WriteUInt32BigEndian(tmp, value);
        }

        WriteBytes(tmp);
    }

    public void WriteInt32(int value, ByteOrder? order = null) => WriteUInt32((uint)value, order);

    public void WriteUInt64(ulong value, ByteOrder? order = null)
    {
        Span<byte> tmp = stackalloc byte[8];
        if ((order ?? ByteOrder) == ByteOrder.Little)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(tmp, value);
        }
        else
        {
            BinaryPrimitives.WriteUInt64BigEndian(tmp, value);
        }

        WriteBytes(tmp);
    }

    public void WriteInt64(long value, ByteOrder? order = null) => WriteUInt64((ulong)value, order);

    /// <summary>Writes an ASCII string followed by a single NUL terminator (impacket 'z').</summary>
    public void WriteAsciiZ(string value)
    {
        WriteBytes(Encoding.ASCII.GetBytes(value));
        WriteByte(0);
    }

    /// <summary>Writes a UTF-16LE string followed by a two-byte NUL terminator (impacket 'u').</summary>
    public void WriteUnicodeZ(string value)
    {
        WriteBytes(Encoding.Unicode.GetBytes(value));
        WriteByte(0);
        WriteByte(0);
    }

    public byte[] ToArray() => _buffer.ToArray();
}
