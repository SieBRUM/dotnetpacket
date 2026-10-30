# NetPacket

A .NET 8 port of [impacket](https://github.com/fortra/impacket) — protocol
structures, a working SMB2/3 + DCERPC client, and example commands — built for
**SOC behavior analysis in a closed lab**.

The goal is detection research: reimplementing impacket's protocol *behavior* on
a different runtime so the team can diff the wire traffic against stock impacket
(and a real Windows client) and build detections that key on **behavior**, not
brittle Python/impacket fingerprints. See [`CLAUDE.md`](CLAUDE.md) for scope and
the developer guide, [`docs/REALISM.md`](docs/REALISM.md) for the realism rules,
and [`docs/WIRE_DIFF.md`](docs/WIRE_DIFF.md) for the recorded NetPacket-vs-impacket
fingerprint diff.

> **Authorized lab use only.** A defensive detection-engineering tool for use
> against systems the SOC is explicitly authorized to test. It deliberately
> contains **no evasion/obfuscation** — the point is to make this traffic easier
> to study and detect. See the Scope section of `CLAUDE.md`.

## What works

A realistic, signed, modern-Windows-style client (SMB 3.1.1 with negotiate
contexts, NTLMv2 + SPNEGO, AES-CMAC signing), validated end-to-end against Samba:

**SMB2/3** — NEGOTIATE, NTLMv2 SESSION_SETUP (SPNEGO + MIC), message signing
(SP800-108 KDF + AES-CMAC), TREE_CONNECT, CREATE, READ, WRITE, CLOSE,
QUERY_DIRECTORY, QUERY_INFO, IOCTL.

**DCERPC over named pipes (ncacn_np)** — BIND + an NDR engine, with these
interfaces/calls:

| Interface | Calls | Behavior |
| --- | --- | --- |
| srvsvc | NetrShareEnum, NetrServerGetInfo | share + server recon |
| wkssvc | NetrWkstaGetInfo | host/OS recon |
| lsarpc | LsarOpenPolicy2, LsarQueryInformationPolicy | domain name + SID |
| lsat | LsarLookupSids, LsarLookupNames | SID ↔ name resolution |
| samr | Connect, Enumerate*, LookupDomain, OpenDomain/User, QueryInformationUser2 | `samrdump` user enumeration + detail |
| svcctl | OpenSCManager, CreateService, … | service-control (`psexec`) signature — lab/benign |

## Quick start

```bash
dotnet build -c Release
dotnet test
dotnet run --project src/NetPacket.Examples          # list all example commands
```

Example commands (each targets a lab host you are authorized to test):

```bash
dotnet run --project src/NetPacket.Examples -- smb2-login   <host> <user> <pass> [domain]
dotnet run --project src/NetPacket.Examples -- smb2-ls      <host> <share> <user> <pass> [path]
dotnet run --project src/NetPacket.Examples -- smb2-cat     <host> <share> <path> <user> <pass>
dotnet run --project src/NetPacket.Examples -- rpc-shares   <host> <user> <pass> [domain]
dotnet run --project src/NetPacket.Examples -- rpc-enumusers <host> <user> <pass> [domain]
dotnet run --project src/NetPacket.Examples -- rpc-lookupsid <host> <user> <pass> [domain]
```

Requires the .NET 8 SDK and NuGet access on first build.

## The research loop

1. Run a NetPacket example and stock impacket against the **same** lab host,
   capturing both (`tcpdump -w out.pcap 'tcp port 445'`).
2. Extract the fingerprint fields with [`tools/fingerprint.sh`](tools/fingerprint.sh)
   and diff them.
3. Record notable differences in [`docs/WIRE_DIFF.md`](docs/WIRE_DIFF.md).

For example, stock impacket's SMB2 NEGOTIATE advertises `Capabilities=0x40` and a
single AES-128-CCM cipher and sends no NTLM version block; NetPacket (like
Windows) advertises `0x6f`, offers GCM+CCM, and sends a version block. A
detection keyed on the impacket values misses both NetPacket and real Windows —
which is exactly the brittleness this project exists to surface.

## Repository layout & porting guide

See [`CLAUDE.md`](CLAUDE.md) for the full layout and architecture,
[`docs/PORTING_GUIDE.md`](docs/PORTING_GUIDE.md) for the mechanical impacket→.NET
recipe, and [`docs/PORTING_STATUS.md`](docs/PORTING_STATUS.md) for what is ported,
what is validated, and what remains.
