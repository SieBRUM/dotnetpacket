<div align="center">

# NetPacket

**A .NET 8 port of [impacket](https://github.com/fortra/impacket) for SOC detection research.**

Reimplement impacket's protocol *behavior* on a different runtime, then diff the wire
traffic — so detections key on **behavior**, not brittle Python/impacket fingerprints.

[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?logo=dotnet&logoColor=white)](https://dotnet.microsoft.com/)
[![Tests](https://img.shields.io/badge/tests-67%20passing-success)](tests/)
[![Scope](https://img.shields.io/badge/use-authorized%20lab%20only-critical)](CLAUDE.md)
[![No evasion](https://img.shields.io/badge/evasion-none%20by%20design-informational)](docs/REALISM.md)

</div>

---

> [!WARNING]
> **Authorized lab use only.** NetPacket is a defensive detection-engineering tool for
> use against systems the SOC is explicitly authorized to test. It deliberately contains
> **no evasion or obfuscation** — the whole point is to make this traffic *easier* to
> study and detect. See the Scope section of [`CLAUDE.md`](CLAUDE.md).

## Why this exists

Most impacket detections fingerprint **Python/impacket-specific artifacts** on the wire —
field orderings, default values, string quirks. Those break the moment the same protocol
is spoken by a different implementation. NetPacket reimplements impacket's protocol
behavior as a realistic, modern-Windows-style .NET client so a SOC can:

- **Diff** NetPacket traffic against stock impacket (and, ideally, real Windows) to see
  which detections are keyed on the *runtime* rather than the *protocol*.
- Build **behavioral** detections (call sequences, state machines, RPC patterns) that
  survive a tool being rewritten in another language.
- Generate labelled lab traffic for tuning SIEM/EDR rules.

Every ported structure cites the impacket class it came from, so each wire diff is
explainable.

## What works

A realistic, **signed**, modern-Windows-style client — SMB 3.1.1 with negotiate contexts,
NTLMv2 + SPNEGO, AES-CMAC signing — validated end-to-end against Samba.

### SMB2/3
`NEGOTIATE` · NTLMv2 `SESSION_SETUP` (SPNEGO + MIC) · message signing (SP800-108 KDF +
AES-CMAC) · `TREE_CONNECT` · `CREATE` · `READ` · `WRITE` · `CLOSE` · `QUERY_DIRECTORY` ·
`QUERY_INFO` · `IOCTL`

### DCERPC over named pipes (ncacn_np)
A `BIND` + NDR engine, with an **NTLMSSP-authenticated bind** offering per-PDU packet
integrity (sign) and privacy (seal) — the signed/sealed channel a modern Windows RPC
client negotiates by default — and these interfaces:

| Interface | Calls | Behavior |
| --- | --- | --- |
| **srvsvc** | NetrShareEnum, NetrServerGetInfo | share + server recon |
| **wkssvc** | NetrWkstaGetInfo | host / OS recon |
| **lsarpc** | LsarOpenPolicy2, LsarQueryInformationPolicy | domain name + SID |
| **lsat** | LsarLookupSids, LsarLookupNames | SID ↔ name resolution |
| **samr** | Connect, Enumerate\*, LookupDomain, OpenDomain/User, QueryInformationUser2 | `samrdump` user enumeration + detail |
| **svcctl** | OpenSCManager, CreateService, … | service-control (`psexec`) signature — lab/benign |
| **winreg** | OpenHKLM, BaseRegGetVersion, BaseRegOpenKey, BaseRegCloseKey | remote-registry (`reg.py`) recon |

## Quick start

```bash
dotnet build -c Release
dotnet test
dotnet run --project src/NetPacket.Examples          # list all example commands
```

Each example targets a lab host you are authorized to test:

```bash
dotnet run --project src/NetPacket.Examples -- smb2-login    <host> <user> <pass> [domain]
dotnet run --project src/NetPacket.Examples -- smb2-ls       <host> <share> <user> <pass> [path]
dotnet run --project src/NetPacket.Examples -- smb2-cat      <host> <share> <path> <user> <pass>
dotnet run --project src/NetPacket.Examples -- rpc-shares    <host> <user> <pass> [domain]
dotnet run --project src/NetPacket.Examples -- rpc-enumusers <host> <user> <pass> [domain]
dotnet run --project src/NetPacket.Examples -- rpc-lookupsid <host> <user> <pass> [domain]
dotnet run --project src/NetPacket.Examples -- rpc-reg       <host> <user> <pass> [subkey]
```

Requires the .NET 8 SDK and NuGet access on first build.

## The research loop

1. Run a NetPacket example **and** stock impacket against the *same* lab host, capturing
   both: `tcpdump -w out.pcap 'tcp port 445'`.
2. Extract the fingerprint fields with [`tools/fingerprint.sh`](tools/fingerprint.sh) and
   diff them.
3. Record notable differences in [`docs/WIRE_DIFF.md`](docs/WIRE_DIFF.md).

> **Example.** Stock impacket's SMB2 `NEGOTIATE` advertises `Capabilities=0x40`, a single
> AES-128-CCM cipher, and sends no NTLM version block. NetPacket (like Windows) advertises
> `0x6f`, offers GCM+CCM, and sends a version block. A detection keyed on the impacket
> values misses **both** NetPacket and real Windows — exactly the brittleness this project
> exists to surface.

## Documentation

| Doc | What's in it |
| --- | --- |
| [`CLAUDE.md`](CLAUDE.md) | Scope, full repo layout, the (de)serialization engine, how to port a structure |
| [`docs/REALISM.md`](docs/REALISM.md) | **Required reading** — the rules for making traffic look like a real client |
| [`docs/PORTING_GUIDE.md`](docs/PORTING_GUIDE.md) | The mechanical impacket → .NET recipe |
| [`docs/PORTING_STATUS.md`](docs/PORTING_STATUS.md) | What's ported, what's validated, what's next |
| [`docs/WIRE_DIFF.md`](docs/WIRE_DIFF.md) | The recorded NetPacket-vs-impacket fingerprint diff (the research output) |

## License & use

A defensive research tool for authorized, closed-lab use by the SOC that owns it. Not for
use against systems without authorization. See [`CLAUDE.md`](CLAUDE.md) for the full scope
statement.
