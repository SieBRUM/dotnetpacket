<div align="center">

# DotNetPacket

### impacket, rewritten in C#.

**A .NET 8 port of [impacket](https://github.com/fortra/impacket) — its protocol structures, clients, and `examples/` scripts — as a single self-contained binary for Windows, Linux, and macOS.**

SMB2/3 · DCERPC (MSRPC) · LDAP · Kerberos · NTLM/SPNEGO · TDS · DCSync · Kerberoasting · S4U · NTLM relay — no Python, no dependencies, one executable.

[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?logo=dotnet&logoColor=white)](https://dotnet.microsoft.com/)
[![CI](https://github.com/SieBRUM/dotnetpacket/actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-260%20passing-success)](tests/)
[![Release](https://img.shields.io/github/v/release/SieBRUM/dotnetpacket?include_prereleases&sort=semver)](../../releases)

</div>

---

> [!NOTE]
> For authorized engagements and research only — pentests, red-team ops, CTFs, and lab work on
> systems you have permission to test. You are responsible for staying in scope.

## What it is

DotNetPacket re-implements impacket's protocol stack and its `examples/` scripts in C#, so you get
impacket's AD tradecraft as **one self-contained native binary** — nothing to `pip install`, no
Python on disk, drops cleanly onto a Windows host or runs from your Linux box. The wire protocols are
built to match a real modern-Windows client (SMB 2/3 with 3.1.1 negotiate contexts, proper signing,
real capability sets), and every ported structure cites the impacket class it came from.

A side effect worth knowing: because it's a ground-up .NET rewrite, it does **not** carry impacket's
Python-shaped artifacts — the default capability flags, field orderings, hardcoded task timestamps,
`Server: BaseHTTP/… Python/…` banners and other tool-specific strings that signature-based rules
love to key on. Same protocol behavior, different fingerprint. The per-call differences are catalogued
in [`docs/WIRE_DIFF.md`](docs/WIRE_DIFF.md).

## Features

A realistic, **signed**, modern-Windows-style stack, validated end-to-end against a Samba AD DC:

- **SMB 2/3** — `NEGOTIATE` with 3.1.1 negotiate contexts, NTLMv2 `SESSION_SETUP` (SPNEGO + MIC),
  SP800-108 KDF + AES-CMAC message signing, `TREE_CONNECT`, `CREATE/READ/WRITE/CLOSE`,
  `QUERY_DIRECTORY`, `QUERY_INFO`, `SET_INFO`, `IOCTL`.
- **DCERPC** (MSRPC) over both named pipes (`ncacn_np`) and TCP (`ncacn_ip_tcp`), with
  NTLMSSP-authenticated **sign & seal**, an NDR marshaller, and clients for `srvsvc`, `wkssvc`,
  `lsarpc`, `lsat`, `samr`, `svcctl`, `winreg`, `tsch`, `mgmt`, `epm`, `drsuapi`.
- **LDAP** (RFC 4511) — bind (simple + GSS-SPNEGO NTLM + sealed Kerberos), the full search filter
  grammar, add/modify/delete, and the `LDAP_SERVER_SD_FLAGS` control.
- **Kerberos v5** — AS-REQ/AS-REP (with and without pre-auth), TGS-REQ/TGS-REP, **RC4-HMAC and
  AES128/256-CTS-HMAC-SHA1-96** (RFC 3962, byte-exact vs impacket + RFC vectors), AP-REQ/AP-REP SMB
  login (`-k`, AES-256 by default), **sealed GSS-SPNEGO LDAP binds**, **S4U2self/S4U2proxy**
  constrained delegation, AS-REP-roast / Kerberoast hash output, MIT **ccache** read/write, and a
  **PAC** parser + signature verifier.
- **NTLM / SPNEGO**, **TDS** (MS-TDS pre-login), **GPP** cpassword, **LAPS**, and an **ntlmrelayx**
  relay server (SMB→SMB, HTTP→SMB, SMB→LDAP).

Full, per-call status is in [`docs/PORTING_STATUS.md`](docs/PORTING_STATUS.md).

## Install

Grab a self-contained binary from [**Releases**](../../releases) (no .NET runtime required) —
built for Windows, Linux, and macOS on x64 and arm64 — or build it yourself:

```bash
dotnet build -c Release
dotnet test
dotnet run --project src/DotNetPacket.Examples    # list every command
```

Needs the .NET 8 SDK and NuGet access on first build. Every command below is
`dotnetpacket <command> …` from a release build (or
`dotnet run --project src/DotNetPacket.Examples -- <command> …` from source).

## Usage

> `[domain]` is the short NetBIOS name (e.g. `LAB`); `<domain-fqdn>` is the DNS name (e.g.
> `lab.local`); `[port]` defaults sensibly per protocol (445 SMB, 389 LDAP, 88 Kerberos). The first
> positional `<host>` is the target (and the DC) — a name or an IP. Anything in `[brackets]` is
> optional.

### Credentials & global options (impacket-style)

Credentials can be given as positional `<user> <pass>` args **or** as an impacket-style target string
in the host slot — `[[domain/]username[:password]@]host` — in which case the separate user/pass
positionals are dropped. With the target form, when you authenticate with a ticket or a hash **no
password is required** (no placeholder):

```bash
# password, in the target
dotnetpacket rpc-samrdump 'LAB/alice:Passw0rd!@dc01.lab.local'
# pass-the-hash — no password at all
dotnetpacket dcsync 'lab.local/alice@dc01.lab.local' Administrator LAB -hashes :ac8d0d3c9858659864b8493a51050efd
# Kerberos from a ccache
KRB5CCNAME=alice.ccache dotnetpacket get-adusers 'lab.local/alice@dc01.lab.local' -k
```

> The target-string form (and password-free auth) currently covers the core auth commands
> — `smb2-login`, `rpc-samrdump`, `get-adusers`, `dcsync` — and is rolling out to the rest. The legacy
> `<host> <user> <pass> [domain]` positional form still works on **every** command, and `-hashes` /
> `-k` / `-aesKey` apply to all of them (with a placeholder in the password slot until a command gains
> the target form).

These flags work with **any** command and can appear anywhere on the line, like impacket:

| Option | What it does |
| --- | --- |
| `-hashes [LM]:NT` | **Pass-the-hash** — authenticate with the NT hash (only NTHASH is used for NTLMv2). No password needed. |
| `-no-pass` | Don't use/ask for a password (pair with `-k` / a ccache). |
| `-k` | **Kerberos** — AP-REQ instead of NTLM. With a password the KDC's etypes are probed and the strongest used (**AES-256 by default**). Loads a TGT from `-ccache`/`KRB5CCNAME` if present. |
| `-aesKey <hex>` | **Overpass-the-hash** with a 128/256-bit AES Kerberos key (implies `-k`). |
| `-ccache <file>` | Use a cached TGT (MIT ccache v4); also read from `KRB5CCNAME`. |
| `-save-ccache <file>` | Write the obtained ticket to a ccache (`kerb-tgt`, `get-st`) — reusable by `klist` / impacket. |
| `-dc-ip <ip>` | KDC address for `-k` (defaults to the host). |
| `-target-ip <ip>` | Connect here while using the host arg as the SPN/logical name (SPN host ≠ reachable address). |
| `-proxy <url>` | Route **all** TCP through a proxy: `socks5://[user:pass@]host:port`, `socks4a://…`, `socks4://…`, `http://[user:pass@]host:port`. The target hostname is handed to the proxy so it resolves on the far side of a pivot. |

> **`-k` covers both SMB and LDAP.** For SMB it performs a real AP-REQ login (AS → service ticket for
> `cifs/<host>` → AP-REQ → `SESSION_SETUP`), AES-256 by default, signing keyed on the AP-REP acceptor
> subkey ([MS-KILE] 3.1.1.2) so privileged calls actually authorize. For the LDAP tools it does a
> GSS-SPNEGO bind for `ldap/<host>` and then **seals** every PDU (AES CFX for a password/`-aesKey`
> ticket, RC4 for `-hashes`), as a modern DC requires. The AES128/256-CTS-HMAC-SHA1-96 crypto is
> byte-exact against impacket and the RFC 3962 vectors.

### Pivoting / Proxynator 🔀

Runs cleanly behind a SOCKS/HTTP pivot — the way you'd run NetExec or impacket behind a C2's SOCKS
server — either with `-proxy socks5://…` or transparently through
**[Proxynator](https://github.com/SieBRUM/proxynator)**'s kernel modes (add a rule for
`DotNetPacket.Examples`/`netpacket` → your pivot, no flags). Everything is plain TCP, including
**Kerberos over TCP/88** (no UDP fallback), and connections are made **by hostname** so remote DNS
resolves on the far side of the pivot.

### SMB2/3 — files, shares, recon

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
| `kerb-tgt` | `<host> <user> <pass> <domain-fqdn> [port]` | `getTGT.py` | request a TGT (probes the KDC; AES-256 PA-ENC-TIMESTAMP by default, RC4 fallback) |
| `get-userspns` | `<host> <user> <pass> <domain-fqdn> [target-user] [port]` | `GetUserSPNs.py` | Kerberoast SPN accounts |
| `get-st` | `<dc-host> <service-user> <pass> <domain-fqdn> <impersonate> <target-spn> [port]` | `getST.py` | S4U2self + S4U2proxy — a constrained-delegation ticket impersonating a user |
| `getpac` | `<dc-host> <service-user> <domain-fqdn> <impersonate> <service-key-hex> [krbtgt-key-hex] [port]` | `getPac.py` | S4U2self, decrypt the ticket, parse the **PAC** (RID, groups, ExtraSids) and verify its SERVER/KDC signatures |
| `rpc-changepw` | `<host> <user> <oldpass> <newpass> [domain] [port]` | `changepasswd.py` | change a password (SAMR) |

### Credential dumping — DCSync

| Command | Parameters | impacket | Does |
| --- | --- | --- | --- |
| `dcsync` | `<dc-host> <user> <pass> <domain-fqdn> <target-user> [netbios] [epm-port]` | `secretsdump.py` | replicate one account via DRSUAPI (`DsGetNCChanges` / `EXOP_REPL_OBJ`): NT hash + Kerberos keys (aes256/aes128/des) + cleartext |
| `dcsync-all` | `<dc-host> <user> <pass> <domain-fqdn> [netbios] [epm-port]` | `secretsdump.py` | enumerate every account (SAMR) and DCSync each by SID — the whole-domain dump |
| `dcsync-k` | `<dc-host> <user> <pass> <domain-fqdn> <target-user> <dc-fqdn> [netbios] [epm-port]` | `secretsdump.py -k` | DCSync authenticated with Kerberos (DCE-style GSS sealed DRSUAPI bind) |
| `dcsync-all-k` | `<dc-host> <user> <pass> <domain-fqdn> <dc-fqdn> [netbios] [epm-port]` | `secretsdump.py -k` | whole-domain DCSync over Kerberos — one `host/<dc-fqdn>` ticket seals the SAMR enum and the DRSUAPI replication |

### ACL / delegation / account edits

| Command | Parameters | impacket | Does |
| --- | --- | --- | --- |
| `dacledit` | `<read\|write\|remove\|backup\|restore> <host> <user> <pass> <domain-fqdn> <target> [principal] [rights] [ace-type] [file]` | `dacledit.py` | read / edit an object's DACL (e.g. grant **DCSync**) |
| `owneredit` | `<read\|write> <host> <user> <pass> <domain-fqdn> <target> [new-owner]` | `owneredit.py` | read / set an object's owner |
| `rbcd` | `<read\|write\|remove\|flush> <host> <user> <pass> <domain-fqdn> <delegate-to> [delegate-from]` | `rbcd.py` | resource-based constrained delegation |
| `badsuccessor` | `<search\|add\|delete\|modify> <host> <user> <pass> <domain-fqdn> [dmsa] [ou] [target]` | `badsuccessor.py` | dMSA "BadSuccessor" (Server 2025) |
| `rpc-addcomputer` | `<host> <user> <pass> <computer-name> [domain] [port]` | `addcomputer.py` | create + delete a machine account |

### Execution

| Command | Parameters | impacket | Does |
| --- | --- | --- | --- |
| `smbexec` | `<host> <user> <pass> <command> [share=C$] [domain] [port]` | `smbexec.py` | command exec via a one-shot svcctl service |
| `atexec` | `<host> <user> <pass> <command> [domain] [port]` | `atexec.py` | command exec via the Task Scheduler |
| `rpc-svcctl` | `<host> <user> <pass> [domain] [port]` | `psexec`-ish | service create/start/delete |

### NTLM relay

| Command | Parameters | impacket | Does |
| --- | --- | --- | --- |
| `ntlmrelayx` | `<target> [listen-port] [victim-user victim-pass [domain]]` | `ntlmrelayx.py` | SMB→SMB NTLM relay + NetNTLMv2 capture |
| `ntlmrelayx-http` | `<target> [listen-port] [victim-user victim-pass [domain]]` | `ntlmrelayx.py` | HTTP→SMB relay (coerces `WWW-Authenticate: NTLM`) |
| `ntlmrelayx-ldap` | `<dc-host> <listen-port> <victim-user> <victim-pass> <domain-fqdn>` | `ntlmrelayx.py` | SMB→LDAP relay (`ldapattack`) |

### Misc

| Command | Parameters | impacket | Does |
| --- | --- | --- | --- |
| `mssql-cbt` | `<host> [port]` | `checkMSSQLStatus.py` | TDS PRELOGIN encryption posture (channel-binding precondition) |
| `smb-header` / `ntlm-negotiate` | — | — | build + hex-dump a reference structure |

## Need a target?

[`tools/lab-addc.sh`](tools/lab-addc.sh) stands up a throwaway, loopback-bound Samba AD DC
(`up` / `down` / `status` / `destroy`) and prints the credentials to use.

## Documentation

| Doc | What's in it |
| --- | --- |
| [`CLAUDE.md`](CLAUDE.md) | Project scope, full repo layout, the (de)serialization engine, how to port a structure |
| [`docs/PORTING_STATUS.md`](docs/PORTING_STATUS.md) | What's ported, what's validated, what's next |
| [`docs/WIRE_DIFF.md`](docs/WIRE_DIFF.md) | The per-call DotNetPacket-vs-impacket wire/fingerprint differences |
| [`docs/REALISM.md`](docs/REALISM.md) | The rules for making traffic look like a real client |
| [`docs/PORTING_GUIDE.md`](docs/PORTING_GUIDE.md) | The mechanical impacket → .NET recipe |

## License & scope

A faithful impacket reimplementation for authorized security testing and research. Don't point it at
anything you don't have written permission to test. Project scope and conventions are in
[`CLAUDE.md`](CLAUDE.md).
