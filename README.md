<div align="center">

# DotNetPacket

### impacket, but it speaks C# and doesn't trip the same wires.

**A .NET 8 port of [impacket](https://github.com/fortra/impacket) — its protocol structures, clients, and `examples/` — for SOC detection engineering.**

Same protocol *behavior* on a different runtime, so your detections key on **what the traffic does**, not on the Python-shaped fingerprints impacket happens to leave behind.

[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?logo=dotnet&logoColor=white)](https://dotnet.microsoft.com/)
[![CI](https://github.com/SieBRUM/dotnetpacket/actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-202%20passing-success)](tests/)
[![Release](https://img.shields.io/github/v/release/SieBRUM/dotnetpacket?include_prereleases&sort=semver)](../../releases)
[![Scope](https://img.shields.io/badge/use-authorized%20lab%20only-critical)](CLAUDE.md)
[![Evasion](https://img.shields.io/badge/evasion-none%20by%20design-informational)](docs/REALISM.md)

</div>

---

> [!WARNING]
> **Authorized, closed-lab use only.** DotNetPacket is a *defensive* detection-engineering tool,
> for systems the SOC that owns it is explicitly authorized to test. It deliberately contains
> **no evasion, no obfuscation, no anti-analysis** — the entire point is to make this traffic
> *easier* to study and detect. If that's not what you're here for, you're holding it wrong.
> See the Scope section of [`CLAUDE.md`](CLAUDE.md).

## Why this thing exists

Here's the uncomfortable truth about a lot of "impacket detections": they don't detect the
*attack*, they detect **Python**. Field orderings. Default capability flags. A hardcoded
`2015-07-15` timestamp in a scheduled task. The literal string `Server: BaseHTTP/0.6 Python/3.13`
bolted onto a relay server. Rewrite the same tool in another language and every one of those
signatures evaporates — while the attack keeps working perfectly.

DotNetPacket *is* that rewrite. It re-implements impacket's protocol behavior as a realistic,
modern-Windows-style .NET client and runs it in a closed lab, so a SOC can:

- **Diff** DotNetPacket against stock impacket (and ideally real Windows) and find every
  detection that was secretly keyed on the runtime instead of the protocol.
- Build **behavioral** detections — call sequences, state machines, RPC patterns — that
  survive a tool being ported to a new language.
- Generate clean, labelled lab traffic for tuning SIEM/EDR rules.

Every ported structure cites the impacket class it came from, so every wire diff is explainable.

## The twist: same behavior, different fingerprint

This is the part that matters, so it gets its own section.

A **protocol structure** (an SMB2 header, an NDR stub, a Kerberos ASN.1 blob, an MS-DTYP
security descriptor) is dictated by the protocol — DotNetPacket reproduces it **byte-faithfully**,
because that's what makes a wire diff meaningful.

A **tool payload** (a command line, a scheduled-task XML template, a hardcoded service name, a
server banner) was *invented by the tool author*. A real reimplementation would never reproduce
those by accident — so DotNetPacket **deliberately diverges** on them, keeping the behavior
identical. Not to hide. To *prove the point*: that a brittle string rule misses the rewrite while
a behavioral rule still fires. Every divergence is documented and pinned by a test.

A few of the fingerprints that already differ (full table in [`docs/WIRE_DIFF.md`](docs/WIRE_DIFF.md)):

| Surface | Stock impacket leaves… | DotNetPacket sends… |
| --- | --- | --- |
| HTTP relay `Server:` banner | `BaseHTTP/0.6 Python/3.x` 😬 | `Microsoft-IIS/10.0` |
| SMB2 `NEGOTIATE` capabilities | `0x40`, single AES-128-CCM, no NTLM version | `0x6f`, GCM+CCM, real Win10 version block |
| atexec task XML | `StartBoundary 2015-07-15T20:35:13.2757294` | a different, valid boundary — no 2015 tell |
| smbexec service binPath | `%COMSPEC% /Q /c … __output_… .bat` | `cmd.exe /c … %TEMP%\<rand>.cmd` |
| DCERPC NDR padding | `0xAB` / `0xBF` filler | zero-fill (like Windows/MIDL) |

> A rule matching `Capabilities==0x40` or `StartBoundary>2015-07-15…` isn't catching an attacker —
> it's catching a specific build of a specific tool, and it misses DotNetPacket **and real Windows**.
> That's the brittleness this project exists to surface.

## What's in the box

A realistic, **signed**, modern-Windows-style stack, validated end-to-end against a Samba AD DC:

- **SMB 2/3** — `NEGOTIATE` with 3.1.1 negotiate contexts, NTLMv2 `SESSION_SETUP` (SPNEGO + MIC),
  SP800-108 KDF + AES-CMAC message signing, `TREE_CONNECT`, `CREATE/READ/WRITE/CLOSE`,
  `QUERY_DIRECTORY`, `QUERY_INFO`, `SET_INFO`, `IOCTL`.
- **DCERPC** (MS-RPCE) over both named pipes (`ncacn_np`) and TCP (`ncacn_ip_tcp`), with
  NTLMSSP-authenticated **sign & seal**, an NDR marshaller, and clients for `srvsvc`, `wkssvc`,
  `lsarpc`, `lsat`, `samr`, `svcctl`, `winreg`, `tsch`, `mgmt`, `epm`.
- **LDAP** (RFC 4511) — bind (simple + GSS-SPNEGO NTLM), search with the full filter grammar,
  add/modify/delete, and the `LDAP_SERVER_SD_FLAGS` control.
- **Kerberos v5** — AS-REQ/AS-REP (with and without pre-auth), TGS-REQ/TGS-REP, RC4-HMAC,
  AS-REP-roast and Kerberoast hash formatting.
- **NTLM / SPNEGO**, **TDS** (MS-TDS pre-login), **GPP**, **LAPS**, and an **ntlmrelayx** relay
  server (SMB→SMB, HTTP→SMB, SMB→LDAP) — lab-only, owner-authorized.

Full, per-call status lives in [`docs/PORTING_STATUS.md`](docs/PORTING_STATUS.md).

## Install

Grab a self-contained binary from [**Releases**](../../releases) (no .NET runtime required) —
built for Windows, Linux, and macOS on x64 and arm64 — or build it yourself:

```bash
dotnet build -c Release
dotnet test                                     # 188 tests
dotnet run --project src/DotNetPacket.Examples  # list every command
```

Needs the .NET 8 SDK and NuGet access on first build. Prefer the one-liner form? Every command below
is `dotnet run --project src/DotNetPacket.Examples -- <command> …` (or `DotNetPacket.Examples <command> …`
from a release build).

## Usage

> Common conventions: `[domain]` is the short NetBIOS name (e.g. `LAB`); `<domain-fqdn>` is the
> DNS name (e.g. `lab.local`); `[port]` defaults sensibly per protocol (445 SMB, 389 LDAP, 88
> Kerberos). The first positional `<host>` is the target (and the DC) — a name or an IP, so there's
> no separate `-dc-ip`/`-target-ip`. Anything in `[brackets]` is optional. 🧪 = lab-only exec
> primitive. 🎯 = owner-authorized offensive module.

### Global options (impacket-style)

These work with **any** command and can appear anywhere on the line, just like impacket:

| Option | impacket | What it does |
| --- | --- | --- |
| `-hashes [LMHASH]:NTHASH` | `-hashes` | **Pass-the-hash** — authenticate with the NT hash instead of a password (only NTHASH is used for NTLMv2). The password argument becomes a placeholder. Covers every NTLM path: SMB, DCERPC-over-SMB, and the SMB-based examples. |
| `-no-pass` | `-no-pass` | Don't use a password (pair with `-hashes`). |
| `-proxy <url>` | *(proxychains)* | Route **all** TCP through a proxy: `socks5://[user:pass@]host:port`, `socks4a://host:port`, `socks4://host:port`, or `http://[user:pass@]host:port`. The target hostname is handed to the proxy so it resolves on the far side of a pivot. |

```bash
# Pass-the-hash (no password needed; the "x" is just a placeholder)
dotnetpacket smbexec dc01.lab.local x 'whoami' C$ LAB -hashes :ac8d0d3c9858659864b8493a51050efd

# Everything through a SOCKS5 pivot (BloodHound-style), by hostname so DNS resolves on the far side
dotnetpacket rpc-samrdump dc01.lab.local alice 'Passw0rd!' LAB -proxy socks5://127.0.0.1:1080
```

> **Deferred (honest about parity):** Kerberos-from-ccache (`-k`) and `-aesKey` are not ported — the
> Kerberos layer is RC4-only with no ccache. LDAP commands use a simple bind, so `-hashes` applies to
> the NTLM/SMB paths (where pass-the-hash belongs), not to LDAP simple bind.

### Works with Proxynator 🔀

DotNetPacket is built to run cleanly through **[Proxynator](https://github.com/SieBRUM/proxynator)**
(force any app's traffic through a SOCKS/HTTP proxy or a pivot) — the way you'd run NetExec or
impacket behind a C2's SOCKS server. Two ways:

- **Transparent (Proxynator's kernel modes `windivert`/`ebpf`) — no flags needed.** DotNetPacket
  makes ordinary TCP `connect()`s **by hostname through the system resolver**, so Proxynator's
  capture and remote-DNS fake-IP handling just work. Add a Proxynator rule for `DotNetPacket.Examples`
  (or `netpacket`) → your pivot, and go.
- **Explicit `-proxy socks5://…`** points DotNetPacket straight at any SOCKS/HTTP proxy with no
  redirector at all.

Why it fits what AD tooling needs (per Proxynator's own [AD guide](https://github.com/SieBRUM/proxynator/blob/main/docs/guides/active-directory.md)):

| Requirement | DotNetPacket |
| --- | --- |
| **SOCKS, not HTTP** (SMB/LDAP/Kerberos/MSRPC are raw TCP) | ✅ all protocols are plain TCP |
| **Connect by name** so the far side resolves it | ✅ connects to the hostname via the system resolver (and `-proxy` passes the name to the proxy) |
| **Everything over TCP** (pivots can't do UDP) | ✅ incl. **Kerberos over TCP/88** — no UDP, so no UDP-fallback retry |
| **DC discovery / internal names** | ✅ give the DC's name or IP as `<host>`; Proxynator's remote DNS + `remoteServer` handle SRV |
| **Loopback isn't redirected** | lab targets are loopback (not proxied); real targets are not — as expected |

### SMB2/3 — files, shares, and credential-less recon

| Command | Parameters | impacket | Does |
| --- | --- | --- | --- |
| `smb2-negotiate` | `<host> [port]` | — | SMB2 NEGOTIATE, dump both directions |
| `smb2-login` | `<host> <user> <pass> [domain] [port]` | — | NTLMv2 SESSION_SETUP |
| `smb2-connect` | `<host> <share> <user> <pass> [domain] [port]` | — | signed TREE_CONNECT |
| `smb2-cat` | `<host> <share> <path> <user> <pass> [domain] [port]` | `smbclient` | read a file (CREATE/READ/CLOSE) |
| `smb2-ls` | `<host> <share> <user> <pass> [path] [domain] [port]` | `smbclient` | directory listing |
| `smb2-info` | `<host> <share> <user> <pass> [domain] [port]` | — | volume / filesystem info |
| `smb-attrib` / `smb-attrib-set` | `<host> <share> <path> <user> <pass> [attrs] [domain]` | `attrib.py` | read / set DOS attributes |
| `smb-ntlminfo` | `<host> [port]` | `DumpNTLMInfo.py` | host/OS/DNS names from the NTLM handshake — **no creds** |
| `gpp-passwords` | `<host> <user> <pass> [domain] [share] [port]` | `Get-GPPPassword.py` | crawl SYSVOL, decrypt GPP `cpassword` |

### DCERPC recon — srvsvc · wkssvc · lsarpc · lsat · samr · winreg

| Command | Parameters | impacket | Does |
| --- | --- | --- | --- |
| `dcerpc-bind` | `<host> <user> <pass> [iface] [domain]` | — | bind a named-pipe interface over IPC$ |
| `rpc-shares` / `rpc-shares-sealed` | `<host> <user> <pass> [seal\|sign] [domain]` | `srvsvc` | share enum (plain / signed+sealed) |
| `rpc-hostinfo` / `rpc-srvinfo` | `<host> <user> <pass> [domain]` | `srvsvc`/`wkssvc` | host, OS, and server-tunable recon |
| `rpc-services` / `rpc-svcconfig` / `rpc-svcstatus` | `<host> <user> <pass> [service] [domain]` | `services.py` | service enum / config / live status |
| `rpc-lsa` / `rpc-privs` / `rpc-accountrights` | `<host> <user> <pass> [sid] [domain]` | `lsarpc` | policy, SID, privilege & rights enum |
| `rpc-lookupsid` / `rpc-lookupsid2` / `rpc-lookupnames[2]` | `<host> <user> <pass> [names] [domain]` | `lookupsid.py` | SID ↔ name resolution |
| `lookupsid` | `<host> <user> <pass> [maxRid=1100] [domain] [port]` | `lookupsid.py` | **RID cycling** — enumerate accounts with no directory read |
| `rpc-enumusers` / `rpc-enumgroups` / `rpc-samrdump` | `<host> <user> <pass> [domain]` | `samrdump.py` | SAMR user/group dump + policy |
| `rpc-userinfo` / `rpc-dispinfo` / `rpc-dispgroups` / `rpc-domaininfo` / `rpc-aliasmem` | `<host> <user> <pass> [target] [domain]` | `samrdump.py` | per-user / display / domain / alias detail |
| `rpc-passpol` | `<host> <user> <pass> [domain]` | `samrdump.py` | domain password policy |
| `rpc-reg` / `rpc-regquery` / `rpc-regenum` / `rpc-regkeys` | `<host> <user> <pass> [subkey] [value] [domain]` | `reg.py` | remote-registry read/enum |
| `rpc-dump` / `rpc-dump-tcp` | `<host> [user] [pass] [domain]` | `rpcdump.py` | registered-interface enumeration |
| `rpc-getarch` / `rpc-epm-map` / `rpc-samr-tcp` | `<host> [iface\|user…]` | `getArch.py`/epm | arch probe · ept_map · sealed SAMR over TCP |

### AD / LDAP

| Command | Parameters | impacket | Does |
| --- | --- | --- | --- |
| `get-adcomputers` | `<host> <user> <pass> <domain-fqdn> [port]` | `GetADComputers.py` | LDAP search for computer objects |
| `get-adusers` | `<host> <user> <pass> <domain-fqdn> [all] [port]` | `GetADUsers.py` | LDAP search for user accounts |
| `get-laps` | `<host> <user> <pass> <domain-fqdn> [computer] [port]` | `GetLAPSPassword.py` | read LAPS passwords from LDAP |
| `find-delegation` | `<host> <user> <pass> <domain-fqdn> [target-user] [port]` | `findDelegation.py` | unconstrained / constrained / protocol-transition / **RBCD** |
| `ldap-signing` | `<host> <domain> [port]` | `CheckLDAPStatus` | does the DC require LDAP signing? |

### Kerberos

| Command | Parameters | impacket | Does |
| --- | --- | --- | --- |
| `get-npusers` | `<host> <user> <pass> <domain-fqdn> [target-user] [port]` | `GetNPUsers.py` | AS-REP roast (accounts without pre-auth) |
| `kerb-tgt` | `<host> <user> <pass> <domain-fqdn> [port]` | `getTGT.py` | request a TGT (RC4 PA-ENC-TIMESTAMP) |
| `get-userspns` | `<host> <user> <pass> <domain-fqdn> [target-user] [port]` | `GetUserSPNs.py` | Kerberoast SPN accounts |
| `rpc-changepw` | `<host> <user> <oldpass> <newpass> [domain] [port]` | `changepasswd.py` | change your own password (SAMR) |

### ACL / delegation / account edits 🧪

| Command | Parameters | impacket | Does |
| --- | --- | --- | --- |
| `dacledit` | `<read\|write\|remove\|backup\|restore> <host> <user> <pass> <domain-fqdn> <target> [principal] [rights] [ace-type] [file]` | `dacledit.py` | read / edit an object's DACL |
| `owneredit` | `<read\|write> <host> <user> <pass> <domain-fqdn> <target> [new-owner]` | `owneredit.py` | read / set an object's owner |
| `rbcd` | `<read\|write\|remove\|flush> <host> <user> <pass> <domain-fqdn> <delegate-to> [delegate-from]` | `rbcd.py` | resource-based constrained delegation |
| `badsuccessor` | `<search\|add\|delete\|modify> <host> <user> <pass> <domain-fqdn> [dmsa] [ou] [target]` | `badsuccessor.py` | dMSA "BadSuccessor" (Server 2025) |
| `rpc-addcomputer` | `<host> <user> <pass> <computer-name> [domain] [port]` | `addcomputer.py` | create + delete a machine account |

### Execution 🧪

| Command | Parameters | impacket | Does |
| --- | --- | --- | --- |
| `smbexec` | `<host> <user> <pass> <command> [share=C$] [domain] [port]` | `smbexec.py` | command exec via a one-shot svcctl service |
| `atexec` | `<host> <user> <pass> <command> [domain] [port]` | `atexec.py` | command exec via the Task Scheduler |
| `rpc-svcctl` | `<host> <user> <pass> [domain] [port]` | `psexec`-ish | benign service-create/delete signature demo |

### NTLM relay 🎯 — `ntlmrelayx`, owner-authorized, loopback-bound

| Command | Parameters | impacket | Does |
| --- | --- | --- | --- |
| `ntlmrelayx` | `<target> [listen-port] [victim-user victim-pass [domain]]` | `ntlmrelayx.py` | SMB→SMB NTLM relay core + NetNTLMv2 capture |
| `ntlmrelayx-http` | `<target> [listen-port] [victim-user victim-pass [domain]]` | `ntlmrelayx.py` | HTTP→SMB relay (coerces `WWW-Authenticate: NTLM`) |
| `ntlmrelayx-ldap` | `<dc-host> <listen-port> <victim-user> <victim-pass> <domain-fqdn>` | `ntlmrelayx.py` | SMB→LDAP relay (`ldapattack`) |

### Misc

| Command | Parameters | impacket | Does |
| --- | --- | --- | --- |
| `mssql-cbt` | `<host> [port]` | `checkMSSQLStatus.py` | TDS PRELOGIN encryption posture (channel-binding precondition) |
| `smb-header` / `ntlm-negotiate` | — | — | build + hex-dump a reference structure |

## The research loop

1. Run a DotNetPacket command **and** stock impacket against the *same* lab host, capturing both:
   `dumpcap -i lo -f 'tcp port 445' -w out.pcap`.
2. Extract the fingerprint fields with [`tools/fingerprint.sh`](tools/fingerprint.sh) and diff them.
3. Record what differs — and, crucially, what *doesn't* — in [`docs/WIRE_DIFF.md`](docs/WIRE_DIFF.md).
   The behavioral invariants that survive the diff are your durable detections.

Need a target? [`tools/lab-addc.sh`](tools/lab-addc.sh) stands up a throwaway, loopback-bound
Samba AD DC (`up` / `down` / `status` / `destroy`) and prints the credentials to use.

## Documentation

| Doc | What's in it |
| --- | --- |
| [`CLAUDE.md`](CLAUDE.md) | Scope, full repo layout, the (de)serialization engine, how to port a structure |
| [`docs/REALISM.md`](docs/REALISM.md) | **Required reading** — the rules for looking like a real client |
| [`docs/PORTING_GUIDE.md`](docs/PORTING_GUIDE.md) | The mechanical impacket → .NET recipe |
| [`docs/PORTING_STATUS.md`](docs/PORTING_STATUS.md) | What's ported, what's validated, what's next |
| [`docs/WIRE_DIFF.md`](docs/WIRE_DIFF.md) | The recorded DotNetPacket-vs-impacket fingerprint diff — **the research output** |

## Scope & license

A defensive research tool for authorized, closed-lab use by the SOC that owns it. **Not** for use
against systems you aren't explicitly authorized to test. No evasion features, by design and on
principle. See [`CLAUDE.md`](CLAUDE.md) for the full scope statement.

<div align="center"><sub>Built for detection engineers who are tired of detecting Python.</sub></div>
