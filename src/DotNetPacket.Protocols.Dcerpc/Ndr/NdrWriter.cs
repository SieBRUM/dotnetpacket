using System.Buffers.Binary;
using System.Text;

namespace DotNetPacket.Protocols.Dcerpc;

/// <summary>
/// Minimal NDR (Network Data Representation, DCE 1.1) encoder for little-endian
/// marshalling of RPC request stubs: primitives with natural alignment, unique
/// referent pointers, and conformant-varying strings. Enough for the calls ported
/// so far; the full NDR type system is a work in progress (see PORTING_STATUS).
/// </summary>
public sealed class NdrWriter
{
    private readonly List<byte> _buffer = new();

    /// <summary>A conventional non-null referent id for unique pointers.</summary>
    public const uint NonNullReferent = 0x00020000;

    public int Length => _buffer.Count;

    public void Align(int boundary)
    {
        while (_buffer.Count % boundary != 0)
        {
            _buffer.Add(0);
        }
    }

    public void WriteUInt32(uint value)
    {
        Align(4);
        Span<byte> tmp = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(tmp, value);
        foreach (byte b in tmp)
        {
            _buffer.Add(b);
        }
    }

    public void WriteUInt16(ushort value)
    {
        Align(2);
        _buffer.Add((byte)value);
        _buffer.Add((byte)(value >> 8));
    }

    /// <summary>Writes a unique pointer referent id (0 for NULL, else a non-null id).</summary>
    public void WriteReferent(bool present) => WriteUInt32(present ? NonNullReferent : 0);

    public void WriteByte(byte value) => _buffer.Add(value);

    /// <summary>Writes raw bytes verbatim (already-aligned payloads such as handles).</summary>
    public void WriteBytes(byte[] value) => _buffer.AddRange(value);

    /// <summary>Writes a conformant RPC_SID: MaxCount(=sub count), Revision, count, 6-byte authority, sub-authorities.</summary>
    public void WriteSid(byte revision, byte[] identifierAuthority, uint[] subAuthorities)
    {
        WriteUInt32((uint)subAuthorities.Length); // conformant MaxCount
        WriteByte(revision);
        WriteByte((byte)subAuthorities.Length);
        WriteBytes(identifierAuthority);           // 6 bytes
        foreach (uint sub in subAuthorities)
        {
            WriteUInt32(sub);
        }
    }

    /// <summary>Writes a 20-byte RPC context handle (attributes + 16-byte UUID).</summary>
    public void WriteContextHandle(byte[] handle)
    {
        Align(4);
        _buffer.AddRange(handle.Length == 20 ? handle : new byte[20]);
    }

    /// <summary>Writes a top-level [ref,string] wide string (the pointee directly, no referent).</summary>
    public void WriteReferencedString(string value) => WriteConformantVaryingString(value);

    /// <summary>Writes a top-level [unique,string] wide string (referent, then pointee if present).</summary>
    public void WriteUniqueString(string? value)
    {
        if (value is null)
        {
            WriteReferent(false);
            return;
        }

        WriteReferent(true);
        WriteConformantVaryingString(value);
    }

    /// <summary>Writes an RPC_UNICODE_STRING header: Length + MaximumLength (bytes) + Buffer referent.</summary>
    public void WriteUnicodeStringHeader(string value)
    {
        WriteUInt16((ushort)(value.Length * 2)); // Length (bytes, no NUL)
        WriteUInt16((ushort)(value.Length * 2)); // MaximumLength
        WriteReferent(true);                      // Buffer pointer
    }

    /// <summary>Writes an RPC_UNICODE_STRING Buffer (conformant-varying, exact chars, no NUL terminator).</summary>
    public void WriteUnicodeStringBuffer(string value)
    {
        WriteUInt32((uint)value.Length); // MaxCount
        WriteUInt32(0);                  // Offset
        WriteUInt32((uint)value.Length); // ActualCount
        _buffer.AddRange(Encoding.Unicode.GetBytes(value));
        Align(4);
    }

    /// <summary>
    /// Writes an RRP_UNICODE_STRING (MS-RRP) passed as an input argument: a
    /// NUL-terminated wide string where Length == MaximumLength count the NUL,
    /// followed inline by its conformant-varying buffer (also NUL-terminated).
    /// </summary>
    public void WriteRrpUnicodeString(string value)
    {
        uint count = (uint)(value.Length + 1); // characters incl. the NUL terminator
        WriteUInt16((ushort)(count * 2));       // Length (bytes)
        WriteUInt16((ushort)(count * 2));       // MaximumLength (bytes)
        WriteReferent(true);                     // Buffer pointer
        WriteUInt32(count);                      // MaxCount
        WriteUInt32(0);                          // Offset
        WriteUInt32(count);                      // ActualCount
        _buffer.AddRange(Encoding.Unicode.GetBytes(value + "\0"));
        Align(4);
    }

    /// <summary>Writes a conformant-varying wide string (max/offset/actual + UTF-16LE incl. terminator).</summary>
    public void WriteConformantVaryingString(string value)
    {
        string terminated = value + "\0";
        uint count = (uint)terminated.Length;
        WriteUInt32(count); // MaxCount
        WriteUInt32(0);     // Offset
        WriteUInt32(count); // ActualCount
        _buffer.AddRange(Encoding.Unicode.GetBytes(terminated));
        Align(4);
    }

    public byte[] ToArray() => _buffer.ToArray();
}
