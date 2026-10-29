using System.Buffers.Binary;
using System.Text;

namespace NetPacket.Protocols.Dcerpc;

/// <summary>
/// Minimal NDR (DCE 1.1) decoder for little-endian RPC response stubs: primitives
/// with natural alignment, referent ids, and conformant-varying strings. Pointees
/// are read by the caller in NDR deferral order (see <see cref="Srvsvc"/>).
/// </summary>
public sealed class NdrReader
{
    private readonly byte[] _data;
    private int _position;

    public NdrReader(byte[] data) => _data = data;

    public int Position => _position;

    public int Remaining => _data.Length - _position;

    public void Align(int boundary)
    {
        int remainder = _position % boundary;
        if (remainder != 0)
        {
            _position += boundary - remainder;
        }
    }

    public uint ReadUInt32()
    {
        Align(4);
        uint value = BinaryPrimitives.ReadUInt32LittleEndian(_data.AsSpan(_position));
        _position += 4;
        return value;
    }

    public ushort ReadUInt16()
    {
        Align(2);
        ushort value = BinaryPrimitives.ReadUInt16LittleEndian(_data.AsSpan(_position));
        _position += 2;
        return value;
    }

    public byte ReadByte() => _data[_position++];

    /// <summary>Reads a conformant-varying wide string with an explicit character count (no NUL trim).</summary>
    public string ReadWideChars(int characterCount)
    {
        int byteCount = characterCount * 2;
        string value = System.Text.Encoding.Unicode.GetString(_data, _position, byteCount);
        _position += byteCount;
        return value;
    }

    /// <summary>Reads a referent id (0 = NULL pointer).</summary>
    public uint ReadReferent() => ReadUInt32();

    /// <summary>Reads <paramref name="count"/> raw bytes.</summary>
    public byte[] ReadBytes(int count)
    {
        var result = new byte[count];
        Array.Copy(_data, _position, result, 0, count);
        _position += count;
        return result;
    }

    /// <summary>Reads a 20-byte RPC context handle (attributes + 16-byte UUID).</summary>
    public byte[] ReadContextHandle()
    {
        Align(4);
        return ReadBytes(20);
    }

    /// <summary>Reads a conformant-varying wide string and trims the NDR null terminator.</summary>
    public string ReadConformantVaryingString()
    {
        ReadUInt32();                  // MaxCount
        ReadUInt32();                  // Offset
        uint actualCount = ReadUInt32();

        int byteCount = (int)actualCount * 2;
        string value = Encoding.Unicode.GetString(_data, _position, byteCount);
        _position += byteCount;
        return value.TrimEnd('\0');
    }
}
