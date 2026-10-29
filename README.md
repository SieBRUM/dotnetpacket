# NetPacket

A .NET 8 port of [impacket](https://github.com/fortra/impacket) — protocol
structures, clients, and examples — for **SOC behavior analysis in a closed
lab**.

The goal is detection research: reimplementing impacket's protocol behavior on a
different runtime so the team can diff the wire traffic against stock impacket
and build detections that key on **behavior**, not brittle Python/impacket
fingerprints. See [`CLAUDE.md`](CLAUDE.md) for scope, intended use, and the full
developer guide, and [`docs/PORTING_GUIDE.md`](docs/PORTING_GUIDE.md) for the
porting recipe.

> **Authorized lab use only.** This is a defensive detection-engineering tool for
> use against systems the SOC is explicitly authorized to test. It deliberately
> contains no evasion/obfuscation features — the point is to make this traffic
> easier to study and detect. See the Scope section of `CLAUDE.md`.

## Quick start

```bash
dotnet build -c Release
dotnet test
dotnet run --project src/NetPacket.Examples -- smb-header
dotnet run --project src/NetPacket.Examples -- ntlm-negotiate
```

Requires the .NET 8 SDK and NuGet access on first build.

## Status

Foundation + two reference ports are in place:

- `NetPacket.Core` — the binary (de)serialization engine (`NetStructure`,
  `ByteReader`/`ByteWriter`).
- `NetPacket.Protocols.Smb` — SMBv1 header, NetBIOS Session header (declarative
  pattern).
- `NetPacket.Protocols.Ntlm` — NTLMSSP NEGOTIATE (manual-override pattern).

Everything else is tracked in [`docs/PORTING_STATUS.md`](docs/PORTING_STATUS.md).
