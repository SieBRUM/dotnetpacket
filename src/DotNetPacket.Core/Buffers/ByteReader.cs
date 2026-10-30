using System.Buffers.Binary;
using System.Text;

namespace DotNetPacket.Core;

/// <summary>
/// Cursor-based binary reader with explicit endianness. <see cref="Position"/> is
/// settable so callers can follow pointer/offset layouts (e.g. NTLM security
/// buffers). The low-level counterpart to <see cref="ByteWriter"/>.
/// </summary>
public sealed class ByteReader
{
    private readonly ReadOnlyMemory<byte> _data;

    /// <summary>Default byte order used when a read call does not specify one.</summary>
    public ByteOrder ByteOrder { get; }

    /// <summary>Current read offset. Settable to seek within the buffer.</summary>
    public int Position { get; set; }

    public ByteReader(ReadOnlyMemory<byte> data, ByteOrder byteOrder = ByteOrder.Little)
    {
        _data = data;
        ByteOrder = byteOrder;
    }

    /// <summary>Total length of the underlying buffer.</summary>
    public int Length => _data.Length;

    /// <summary>Bytes remaining from the current <see cref="Position"/> to the end.</summary>
    public int Remaining => _data.Length - Position;

    public byte ReadByte()
    {
        Require(1);
        return _data.Span[Position++];
    }

    public sbyte ReadSByte() => (sbyte)ReadByte();

    /// <summary>Reads <paramref name="count"/> bytes into a fresh array and advances.</summary>
    public byte[] ReadBytes(int count)
    {
        if (count < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(count));
        }

        Require(count);
        byte[] result = _data.Span.Slice(Position, count).ToArray();
        Position += count;
        return result;
    }

    public ushort ReadUInt16(ByteOrder? order = null)
    {
        ReadOnlySpan<byte> s = Take(2);
        return (order ?? ByteOrder) == ByteOrder.Little
            ? BinaryPrimitives.ReadUInt16LittleEndian(s)
            : BinaryPrimitives.ReadUInt16BigEndian(s);
    }

    public short ReadInt16(ByteOrder? order = null) => (short)ReadUInt16(order);

    public uint ReadUInt32(ByteOrder? order = null)
    {
        ReadOnlySpan<byte> s = Take(4);
        return (order ?? ByteOrder) == ByteOrder.Little
            ? BinaryPrimitives.ReadUInt32LittleEndian(s)
            : BinaryPrimitives.ReadUInt32BigEndian(s);
    }

    public int ReadInt32(ByteOrder? order = null) => (int)ReadUInt32(order);

    public ulong ReadUInt64(ByteOrder? order = null)
    {
        ReadOnlySpan<byte> s = Take(8);
        return (order ?? ByteOrder) == ByteOrder.Little
            ? BinaryPrimitives.ReadUInt64LittleEndian(s)
            : BinaryPrimitives.ReadUInt64BigEndian(s);
    }

    public long ReadInt64(ByteOrder? order = null) => (long)ReadUInt64(order);

    /// <summary>Reads a NUL-terminated ASCII string and consumes the terminator (impacket 'z').</summary>
    public string ReadAsciiZ()
    {
        int start = Position;
        while (Position < _data.Length && _data.Span[Position] != 0)
        {
            Position++;
        }

        string value = Encoding.ASCII.GetString(_data.Span.Slice(start, Position - start));
        if (Position < _data.Length)
        {
            Position++; // consume terminator
        }

        return value;
    }

    /// <summary>Reads a NUL-terminated UTF-16LE string and consumes the terminator (impacket 'u').</summary>
    public string ReadUnicodeZ()
    {
        int start = Position;
        while (Position + 1 < _data.Length && !(_data.Span[Position] == 0 && _data.Span[Position + 1] == 0))
        {
            Position += 2;
        }

        string value = Encoding.Unicode.GetString(_data.Span.Slice(start, Position - start));
        if (Position + 1 < _data.Length)
        {
            Position += 2; // consume terminator
        }

        return value;
    }

    private ReadOnlySpan<byte> Take(int count)
    {
        Require(count);
        ReadOnlySpan<byte> s = _data.Span.Slice(Position, count);
        Position += count;
        return s;
    }

    private void Require(int count)
    {
        if (Remaining < count)
        {
            throw new EndOfStreamException(
                $"Need {count} byte(s) at offset {Position} but only {Remaining} remain.");
        }
    }
}
