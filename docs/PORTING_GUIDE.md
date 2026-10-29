# Porting guide: impacket (Python) → NetPacket (.NET)

This is the mechanical recipe for porting impacket structures and examples. It
assumes you have the impacket source open alongside this repo. Read
[`../CLAUDE.md`](../CLAUDE.md) first for scope and architecture.

## The two patterns (pick one per structure)

| If the impacket structure is… | Use | Example in this repo |
| --- | --- | --- |
| A fixed, sequential list of fields | **Declarative** `[Field]` properties | `SmbHeader`, `NetBiosSessionHeader` |
| Cross-referenced by offsets/pointers, or has conditional/variable layout the base class can't express | **Manual override** of `PackInto`/`Unpack` | `NtlmNegotiate` |

When in doubt, start declarative; drop to manual override only for the fields
that need it (you can mix: a mostly-declarative structure can override just
`PackInto`/`Unpack` and call the base where it helps).

## impacket format code → `FieldKind` / CLR type

impacket declares fields as `('Name', 'format')`. Map the format like this:

| impacket format | `FieldKind` | CLR property type | Notes |
| --- | --- | --- | --- |
| `'B'` | `UInt8` | `byte` | |
| `'b'` | `Int8` | `sbyte` | |
| `'<H'` | `UInt16` | `ushort` | set structure `ByteOrder` = `Little` |
| `'>H'` | `UInt16` | `ushort` | structure `ByteOrder` = `Big` |
| `'<h'` | `Int16` | `short` | |
| `'<L'` / `'<I'` | `UInt32` | `uint` | |
| `'<l'` / `'<i'` | `Int32` | `int` | |
| `'<Q'` | `UInt64` | `ulong` | |
| `'<q'` | `Int64` | `long` | |
| `':'` | `Bytes` (no `Length`/`LengthFrom`) | `byte[]` | consumes the rest of the buffer |
| `'nts'` fixed blob, e.g. `'8s'` | `Bytes` with `Length = 8` | `byte[]` | fixed-size byte field |
| `'z'` | `AsciiZ` | `string` | NUL-terminated ASCII |
| `'u'` | `UnicodeZ` | `string` | NUL-terminated UTF-16LE |
| length-prefixed blob (`'_-Field'` / `len` refs) | see **Length references** below | | |
| nested `Structure` | `Structure` | that `NetStructure` type | |

Endianness is **per structure**, not per field, on the declarative path: set
`public override ByteOrder ByteOrder => ByteOrder.Little;` (or `Big`). If a single
structure genuinely mixes endianness across multi-byte fields, port it with the
manual-override pattern.

### Length references

impacket frequently pairs a length field with a data field. Port both:

- The **data** field (`byte[]`) gets `[Field(n, FieldKind.Bytes, LengthFrom = "LenField")]`.
  At unpack time its length is read from `LenField` (which must have a lower
  `Order` so it is already populated).
- The **length** field (numeric) gets `[Field(m, FieldKind.UInt16, LengthOf = "DataField")]`.
  At pack time its value is auto-computed from `DataField`'s byte length, so you
  never set it by hand.

```csharp
[Field(0, FieldKind.UInt16, LengthOf = "Data")]
public ushort DataLength { get; set; }

[Field(1, FieldKind.Bytes, LengthFrom = "DataLength")]
public byte[] Data { get; set; } = Array.Empty<byte>();
```

If the length and offset scheme is more complex (NTLM security buffers, NDR
pointers), use the manual-override pattern instead — see `NtlmNegotiate`.

## Step-by-step: porting a structure

1. **Locate** the impacket class (e.g. `impacket/smb.py` → `class SMBHeader`).
2. **Create** `src/NetPacket.Protocols.<Area>/<Name>.cs`, one type per file,
   namespace `NetPacket.Protocols.<Area>`.
3. **Choose a pattern** from the table above.
4. **Map the fields** in order using the format table. Keep impacket's field
   names (PascalCase them). Give each `[Field]` a unique ascending `Order`.
5. **Initialize** `byte[]` and `string` properties (`= Array.Empty<byte>()`,
   `= string.Empty`) and set fixed defaults (signatures, version constants).
6. **Document** the type with an XML-doc comment citing the impacket origin,
   e.g. `/// Port of impacket's smb.SMB.SMBHeader.`
7. **Test** in `tests/`: a round-trip test always; a known-bytes test whenever
   you have reference bytes (from a capture or from running impacket in the lab).
8. **Track** it in [`PORTING_STATUS.md`](PORTING_STATUS.md).

## Step-by-step: porting an example (impacket `examples/`)

1. Read the impacket example (e.g. `examples/smbclient.py`).
2. Add a command to `src/NetPacket.Examples/Program.cs` (a `case`, or a dedicated
   class as it grows). Cite the impacket filename in a comment.
3. Keep behavior observable: print what is sent/received; offer a hex-dump mode;
   target lab hosts only. Do **not** add evasion/obfuscation (see `CLAUDE.md`).
4. Wire the structures you ported into the example.
5. Track it in [`PORTING_STATUS.md`](PORTING_STATUS.md).

## Idiom cheatsheet (Python → C#)

| impacket / Python | NetPacket / C# |
| --- | --- |
| `s = SMBHeader()` | `var s = new SmbHeader();` |
| `s['Command'] = 0x72` | `s.Command = 0x72;` |
| `data = s.getData()` | `byte[] data = s.Pack();` |
| `s.fromString(buf)` | `s.Unpack(buf);` |
| `struct.pack('<H', x)` | `writer.WriteUInt16(x);` |
| `struct.unpack('<H', b)[0]` | `reader.ReadUInt16();` |
| `b'\xffSMB'` | `new byte[] { 0xFF, (byte)'S', (byte)'M', (byte)'B' }` |
| ASCII `str.encode()` | `Encoding.ASCII.GetBytes(s)` |
| UTF-16LE `str.encode('utf-16le')` | `Encoding.Unicode.GetBytes(s)` |

## Verifying wire compatibility

The whole point is matching bytes. For each port:

- **Round-trip**: `Unpack(Pack())` reproduces the field values.
- **Known-bytes**: assert `Pack()` equals bytes captured from a real exchange or
  produced by stock impacket.
- **Capture diff**: run the NetPacket example and the impacket original against
  the same lab host; capture both with `tcpdump`/`tshark`; diff the payloads.
  Record notable differences in `PORTING_STATUS.md` — those differences are the
  behavior-analysis output this project exists to produce.
