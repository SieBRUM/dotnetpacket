# CLAUDE.md — NetPacket

Guidance for Claude (and humans) working in this repository. Read this before
making changes.

## What this project is

**NetPacket** is a .NET 8 port of [impacket](https://github.com/fortra/impacket)
— its protocol structures, client implementations, and `examples/` scripts —
built so that a **Security Operations Center (SOC)** can study the *behavior* of
these protocols on the wire from a non-Python runtime.

### Why port it to .NET

The SOC that owns this repo currently detects impacket largely by **fingerprinting
Python/impacket-specific artifacts over the wire** (field orderings, default
values, timing, string quirks). Fingerprints are brittle: a reimplementation in
another language produces the same *protocol* but different *fingerprints*. By
reimplementing impacket's protocol behavior in .NET and running it in a closed
lab, the team can:

- Capture and diff the wire traffic of the .NET port against stock impacket, so
  detections key on **protocol behavior** rather than runtime-specific strings.
- Build and validate **behavioral** detections (sequences, state machines, RPC
  call patterns) that survive a tool being rewritten in another language.
- Generate labelled traffic for tuning SIEM/EDR rules without relying only on
  event logs and signatures.

### Scope and intended use — read this

This code is for **authorized, closed-lab use by the SOC that owns it**:
defensive research, detection engineering, and behavior analysis against systems
the team is explicitly authorized to test. It is not for use against systems
without authorization.

Practical consequences for how we build it:

- **Lab-first.** Examples target lab hosts and print/observe wire bytes. Default
  to behavior that is observable and inspectable (hex dumps, pcaps, verbose
  logging) rather than silent operation.
- **No evasion features.** The goal is to make this traffic *easier* to study and
  detect, not harder. Do not add obfuscation, anti-analysis, traffic shaping to
  dodge sensors, or anything whose only purpose is to defeat detection. If a
  behavior exists in impacket and is relevant to detection, port it faithfully
  and document it — but do not invent new evasion on top.
- **Faithful, documented ports.** Each ported piece should cite the impacket
  source it came from (module + class) so traffic diffs are explainable.
- **Realism is a hard requirement.** Traffic must look like a legitimate modern
  Windows/.NET client (e.g. SMB2/3, not SMB1; real capability sets and negotiate
  contexts), not like a tool or a minimal demo. Read **`docs/REALISM.md`** before
  porting anything that goes on the wire.
- If a requested change would turn this from a detection-research tool into
  something whose main value is attacking un-authorized targets, stop and raise
  it with the repo owner rather than implementing it.

## Repository layout

```
NetPacket.sln
Directory.Build.props              # shared TFM / lang / nullable settings
src/
  NetPacket.Core/                  # FOUNDATION: binary (de)serialization engine
    ByteOrder.cs                   #   endianness enum
    Buffers/ByteReader.cs          #   cursor-based reader (LE/BE, strings, blobs)
    Buffers/ByteWriter.cs          #   growable writer (LE/BE, strings, blobs)
    Structure/FieldKind.cs         #   wire field kinds (mirrors impacket formats)
    Structure/FieldAttribute.cs    #   declarative field metadata
    Structure/NetStructure.cs      #   base class: declarative pack/unpack + override hook
    Hex.cs                         #   hex-dump helper for lab output
  NetPacket.Transport/             # sockets: SMB Direct TCP / NetBIOS framing
    DirectTcpTransport.cs          #   4-byte length-framed messages over TCP
  NetPacket.Protocols.Smb/         # SMB1 (legacy) + SMB2/3 (realistic transport)
    SmbHeader.cs                   #   SMBv1 header  (impacket smb.SMB.SMBHeader)
    NetBiosSessionHeader.cs        #   NBSS header   (big-endian example)
    Smb2/Smb2Constants.cs          #   SMB2 commands, dialects, caps, context types
    Smb2/Smb2Header.cs             #   SMB2 64-byte header (declarative)
    Smb2/Smb2NegotiateRequest.cs   #   SMB2 NEGOTIATE + 3.1.1 contexts (realistic)
    Smb2/Smb2NegotiateResponse.cs  #   SMB2 NEGOTIATE response parser
    Smb2/Smb2SessionSetup.cs       #   SMB2 SESSION_SETUP request/response
    Smb2/Smb2TreeConnect.cs        #   SMB2 TREE_CONNECT request/response
    Smb2/Smb2Create.cs             #   SMB2 CREATE request/response (open a file)
    Smb2/Smb2ReadClose.cs          #   SMB2 READ + CLOSE request/response
    Smb2/Smb2QueryDirectory.cs     #   SMB2 QUERY_DIRECTORY (dir listing)
    Smb2/Smb2Write.cs              #   SMB2 WRITE request/response
    Smb2/Smb2Ioctl.cs              #   SMB2 IOCTL + FSCTL codes (pipe transceive)
    Smb2/Smb2Flags.cs              #   header/session/share flag + enum coverage
    Smb2/Smb2CreateConstants.cs    #   access mask, disposition, options, file attributes
    Smb2/Smb2Crypto.cs             #   preauth integrity, SP800-108 KDF, AES-CMAC signing
    Smb2/Smb2Client.cs             #   full session: NEGOTIATE..SESSION_SETUP..TREE_CONNECT..READ/WRITE/IOCTL
  NetPacket.Protocols.Dcerpc/      # DCERPC (MS-RPCE) over SMB named pipes
    DcerpcConstants.cs             #   PDU types, flags, NDR syntax, well-known interfaces
    DcerpcHeader.cs                #   16-byte common PDU header
    DcerpcBind.cs / DcerpcBindAck.cs #  BIND / BIND_ACK
    DcerpcRequest.cs               #   REQUEST / RESPONSE / FAULT PDUs
    Ndr/NdrWriter.cs / NdrReader.cs #  NDR marshalling (alignment, referents, handles, strings)
    Srvsvc.cs                      #   srvsvc NetrShareEnum + NetrServerGetInfo
    Wkssvc.cs                      #   wkssvc NetrWkstaGetInfo (host/OS recon)
    Lsarpc.cs                      #   lsarpc policy open + account domain/SID (RPC_UNICODE_STRING, RPC_SID)
    Lsat.cs                        #   lsat LsarLookupSids (SID->name) + LsarLookupNames (name->SID)
    Samr.cs                        #   samr connect/enum/lookup/open + per-user QueryInfo (samrdump)
    Svcctl.cs                      #   svcctl SCM/service control (psexec surface, lab-only)
    DcerpcPipe.cs                  #   ncacn_np transport (open pipe on IPC$, transceive, bind, call)
  NetPacket.Protocols.Ntlm/        # NTLM + SPNEGO (functional auth path)
    Ntlm.cs / NtlmFlags.cs         #   NTLMSSP constants, flags, AV ids
    SecurityBuffer.cs              #   NTLM len/maxlen/offset buffer
    NtlmNegotiate.cs               #   NTLMSSP NEGOTIATE (reference structure)
    NtlmChallenge.cs               #   NTLMSSP CHALLENGE (Type 2) parser
    AvPairs.cs                     #   target-info AV_PAIR list
    NtlmCrypto.cs                  #   MD4/HMAC-MD5/RC4/NTOWFv2/NTLMv2/GSS signing
    NtlmClient.cs                  #   Type 1 / Type 3 builder (NTLMv2 + MIC)
    Spnego.cs                      #   GSS/SPNEGO wrapping (System.Formats.Asn1)
  NetPacket.Examples/              # CLI, the impacket examples/ equivalent
    Program.cs                     #   command dispatcher + sample commands
tests/
  NetPacket.Core.Tests/            # xUnit tests (round-trip + known-bytes)
docs/
  REALISM.md                       # REQUIRED READING: make traffic look like a real client
  PORTING_GUIDE.md                 # the mechanical impacket -> .NET recipe
  PORTING_STATUS.md                # tracker: what's ported, what's next
  WIRE_DIFF.md                     # NetPacket vs impacket fingerprint diff (the research output)
tools/
  fingerprint.sh                   # extract SMB2/NTLM fingerprint fields from a capture (for diffing)
```

## Build & test

> Requires the .NET 8 SDK and (first build) NuGet access. The build, the test
> suite, and the live `smb2-negotiate` / `smb2-login` (NTLMv2) against a Samba
> server have all been verified; see `docs/PORTING_STATUS.md` for the record.

```bash
dotnet restore
dotnet build -c Release
dotnet test
dotnet run --project src/NetPacket.Examples -- smb2-negotiate <lab-host>
dotnet run --project src/NetPacket.Examples -- smb2-login <lab-host> <user> <password> [domain]
dotnet run --project src/NetPacket.Examples -- smb2-connect <lab-host> <share> <user> <password> [domain]
dotnet run --project src/NetPacket.Examples -- smb2-cat <lab-host> <share> <path> <user> <password> [domain]
dotnet run --project src/NetPacket.Examples -- smb2-ls <lab-host> <share> <user> <password> [path] [domain]
dotnet run --project src/NetPacket.Examples -- dcerpc-bind <lab-host> <user> <password> [interface] [domain]
dotnet run --project src/NetPacket.Examples -- rpc-shares <lab-host> <user> <password> [domain]
dotnet run --project src/NetPacket.Examples -- rpc-svcctl <lab-host> <user> <password> [domain]
dotnet run --project src/NetPacket.Examples -- rpc-hostinfo <lab-host> <user> <password> [domain]
dotnet run --project src/NetPacket.Examples -- rpc-lsa <lab-host> <user> <password> [domain]
dotnet run --project src/NetPacket.Examples -- rpc-lookupsid <lab-host> <user> <password> [domain]
dotnet run --project src/NetPacket.Examples -- rpc-enumusers <lab-host> <user> <password> [domain]
dotnet run --project src/NetPacket.Examples -- rpc-lookupnames <lab-host> <user> <password> [names]
```

If `dotnet` is missing, install the .NET 8 SDK from
https://dotnet.microsoft.com/download (or your distro's package). `dotnet test`
pulls xUnit from NuGet, so the first build needs network access to nuget.org.

## Architecture: the (de)serialization engine

Everything hangs off `NetPacket.Core`. Two building blocks and two porting
patterns — learn these and the rest of the port is mechanical.

### `ByteReader` / `ByteWriter`

Cursor-based binary I/O with explicit endianness. Integers, raw byte blobs,
null-terminated ASCII (`z`) and UTF-16LE (`u`) strings. These are the escape
hatch: any structure can be (de)serialized by hand with these, and the reader's
`Position` is settable so you can follow NTLM-style payload offsets.

### `NetStructure` — the base class

A port of impacket's `Structure`. It supports **two patterns**:

**1. Declarative (preferred for sequential layouts).** Decorate properties with
`[Field(order, kind, ...)]`; the base class packs/unpacks them in `Order`.
See `SmbHeader` and `NetBiosSessionHeader`. This is the pattern cheaper models
should use for the many straightforward structures.

```csharp
public sealed class SmbHeader : NetStructure
{
    public override ByteOrder ByteOrder => ByteOrder.Little;

    [Field(0, FieldKind.Bytes, Length = 4)]
    public byte[] Protocol { get; set; } = (byte[])Signature.Clone();

    [Field(1, FieldKind.UInt8)]  public byte Command { get; set; }
    [Field(2, FieldKind.UInt32)] public uint Status  { get; set; }
    // ...
}
```

**2. Manual override (for pointer/offset layouts).** Override `PackInto(ByteWriter)`
and `Unpack(ByteReader)` and drive the buffer directly. Use this when fields
reference each other by offset — NTLM, some DCERPC NDR, etc. See `NtlmNegotiate`.

Supported `FieldKind`s: `UInt8/Int8/UInt16/Int16/UInt32/Int32/UInt64/Int64`,
`Bytes` (fixed `Length`, or `LengthFrom` another field, or rest-of-buffer),
`AsciiZ`, `UnicodeZ`, and nested `Structure`. A numeric field can auto-fill a
length prefix with `LengthOf = "DataField"`.

Per-field endianness is intentionally **not** supported on the declarative path:
set the structure's `ByteOrder` (uniform), and if a structure genuinely mixes
endianness across multi-byte fields, use the manual-override pattern.

## How to port a new protocol structure (the common task)

1. Open the impacket source for the structure (e.g. `impacket/smb.py`,
   `impacket/dcerpc/v5/*`). Keep the Python `structure = (...)` tuple in view.
2. Create `src/NetPacket.Protocols.<Area>/<Name>.cs`, one structure per file.
3. If the layout is sequential, use the **declarative** pattern; map each
   impacket field to a `[Field]` property using the table in
   `docs/PORTING_GUIDE.md`. If it is offset/pointer-based, use **manual override**.
4. Add a round-trip test and, where you have reference bytes (from a capture or
   from impacket), a known-bytes test in `tests/`.
5. Add an XML-doc comment citing the impacket class you ported.
6. Tick it off in `docs/PORTING_STATUS.md`.

## How to port an example (impacket `examples/`)

Each impacket example becomes a command in `NetPacket.Examples` (a `case` in
`Program.cs`, or its own class as they grow). Keep output observable: print what
is sent/received, offer a hex-dump / pcap-friendly mode. Cite the impacket
example filename in a comment.

## Verifying wire compatibility (the whole point)

A port is only useful if its bytes match what the protocol requires. Verify by:

- **Round-trip tests**: `Pack()` then `Unpack()` must reproduce field values.
- **Known-bytes tests**: assert against bytes captured from a real exchange or
  produced by stock impacket in the lab.
- **Capture diffing**: run the .NET example and the impacket original against the
  same lab host, capture both (`tcpdump`/`tshark`), and diff. Differences are the
  research output — record notable ones in `docs/PORTING_STATUS.md`.

## Conventions

- One structure/class per file; filename matches the type.
- Namespaces follow folders: `NetPacket.Protocols.<Area>`.
- `Nullable` is enabled; initialize byte-array/string fields (`= new byte[n]`,
  `= string.Empty`) so packing never NREs.
- Favor `byte[]`/`ReadOnlySpan<byte>` over streams for structures.
- XML-doc every ported type with its impacket origin (`module.Class`).
- No secrets, credentials, or real target hostnames in code, tests, or commits —
  tests use lab/sample values.

## Commit / branch

- Development branch for this work: `claude/tender-johnson-706edv`.
- Small, reviewable commits; do not open a PR unless the owner asks.
