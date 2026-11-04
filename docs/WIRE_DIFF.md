# Wire diff: DotNetPacket vs. stock impacket

This is the research output the project exists to produce (see `CLAUDE.md` →
"Capture diffing"): running the .NET port and stock impacket against the **same**
lab server and diffing the wire fields a SOC fingerprints on. Where they differ,
a fingerprint-based detection is keying on a **runtime artifact**, not on protocol
behavior — exactly the brittleness this project studies.

## How to reproduce

Capture each client against the same host, then extract and diff the fields with
`tools/fingerprint.sh`:

```bash
tcpdump -i <iface> -w netpacket.pcap 'tcp port 445' &
dotnet run --project src/DotNetPacket.Examples -- smb2-login <host> <user> <pass> <domain>
# then, stock impacket against the same host:
tcpdump -i <iface> -w impacket.pcap 'tcp port 445' &
python3 -c "from impacket.smbconnection import SMBConnection as C; \
            c=C('<host>','<host>',sess_port=445); c.login('<user>','<pass>','<domain>')"

tools/fingerprint.sh netpacket.pcap
tools/fingerprint.sh impacket.pcap   # diff the two outputs
```

Add a third capture of a **real Windows client** doing the same operation to see
which side actually matches Windows (that capture needs a Windows host, which the
current lab does not have — see the caveat at the end).

## Findings (lab: Samba 4.19, 2026-10-30)

### SMB2 NEGOTIATE request

| Field | DotNetPacket (.NET) | stock impacket | Note |
| --- | --- | --- | --- |
| Capabilities | `0x0000006f` (DFS, LEASING, LARGE_MTU, MULTI_CHANNEL, DIRECTORY_LEASING, ENCRYPTION) | `0x00000040` (ENCRYPTION only) | **Strong impacket tell.** A real Win10/11 client advertises ~`0x6f`; impacket advertises only ENCRYPTION. |
| Encryption ciphers | AES-128-GCM **and** AES-128-CCM | AES-128-CCM **only** | Windows offers GCM+CCM; impacket offers CCM only. |
| Dialects | 2.0.2 … 3.1.1 | 2.0.2 … 3.1.1 | same |
| Preauth integrity | SHA-512 | SHA-512 | same |
| ClientGuid | random per connection | random per process | neither is a stable machine GUID (both differ from a domain-joined Windows host) |

### NTLMSSP (inside SESSION_SETUP)

| Field | DotNetPacket (.NET) | stock impacket | Note |
| --- | --- | --- | --- |
| Type 1 NegotiateFlags | `0xa2888215` | `0xe0888235` | different sets; impacket sets SEAL + KEY_EXCH, DotNetPacket is signing-oriented |
| Type 1 **Version block** | `10.0.19041` (NTLM rev 15) | **absent** | **Strong impacket tell.** A real Windows client always sends the OS version; impacket omits it entirely. |
| Type 3 Version block | `10.0.19041` | absent | same |
| Type 3 MIC | present | present | both send a MIC |

## Findings (lab: Samba AD DC, 2026-10-31)

These cover the DCERPC paths added since: authenticated sign/seal, DCERPC over
TCP (`ncacn_ip_tcp`), and the endpoint mapper. Captured with `rpc-samr-tcp` /
`rpc-epm-map` vs impacket's `hept_map` + a sealed samr bind, against the same
Samba AD DC (`tools/lab-addc.sh`).

### DCERPC authenticated BIND — NTLMSSP over RPC (sign/seal)

| Field | DotNetPacket (.NET) | stock impacket | Note |
| --- | --- | --- | --- |
| Type 1 NegotiateFlags | `0xe2888235` | `0xe0888235` | differ only in `NEGOTIATE_VERSION` (`0x02000000`) |
| Type 1 / Type 3 Version block | `10.0.19041` (NTLM rev 15) | **absent** | **impacket tell**, same as on the SMB path: impacket sends no OS version; a real Windows client does. |
| SEAL + KEY_EXCH | set | set | both negotiate key exchange and sealing |
| Sealed REQUEST layout | sign whole PDU minus verifier; seal stub only; auth pad `0xBB` | identical | **durable behavioral signal** — the NTLM2 "sign-all / seal-data" shape is the same in both runtimes |

### Endpoint mapper `ept_map` request (ncacn_ip_tcp:135)

| Field | DotNetPacket (.NET) | stock impacket | Note |
| --- | --- | --- | --- |
| Protocol tower (5 floors, 75-byte octet string) | identical | identical | interface UUID + NDR + RPC-CO + TCP + IP floors are byte-for-byte the same |
| `obj` referent id | `0x00020000` (first pointer; later pointers `+4`) | `0x00000001` | DotNetPacket assigns referents sequentially from `0x00020000` incrementing by 4, the MIDL / Windows scheme; impacket uses its own numbering. Both non-null; server accepts either. |
| NDR conformant-struct pad fill | `0x00` | `0xAB` | **impacket tell.** impacket fills NDR alignment padding with `0xAA/0xBB`-family bytes; DotNetPacket zero-fills (closer to Windows). |
| `max_towers` requested | `1` | `4` | cosmetic request-size difference |

### Endpoint mapper `ept_map` response (server-side tell)

| Field | value on Samba DC | on Windows | Note |
| --- | --- | --- | --- |
| Returned tower host floor (IP) | `0.0.0.0` | the server's actual address | A **server** fingerprint (not a client one): Samba's mapper returns `0.0.0.0`, Windows returns the real IP. Useful for telling the responder apart, independent of the client. |

## What this means for detections

- A rule matching SMB2 NEGOTIATE **Capabilities == `0x40`** or **a single
  AES-128-CCM cipher** is fingerprinting *impacket's defaults*, not attacker
  behavior. It would **miss** DotNetPacket — and, more importantly, miss a real
  Windows client or any reimplementation that mirrors Windows.
- A rule matching **"NTLMSSP NEGOTIATE with no Version field"** is likewise an
  impacket (and some other tool) artifact. DotNetPacket includes the Version block,
  so it evades that rule by *looking more like Windows* — not by evasion tricks.
- The durable signal is **behavioral**: the sequence NEGOTIATE → SESSION_SETUP
  (NTLMv2) → TREE_CONNECT(IPC$) → BIND(svcctl) → CreateServiceW is the same
  whether the client is Python or .NET. Detections keyed on that call sequence and
  its state machine survive a tool being rewritten; detections keyed on the fields
  above do not.
- A rule keying on **`0xAA`/`0xBB` NDR padding bytes** in DCERPC stubs is an
  impacket marshaller artifact — DotNetPacket zero-fills (as Windows tends to), so
  that rule misses it. Likewise **"NTLMSSP on the RPC auth trailer with no Version
  field"** is the same impacket tell as on the SMB path.
- Over TCP the durable signal is again the **sequence**: EPM `ept_map` on port 135
  → connect to the returned dynamic port → authenticated BIND → the interface's
  calls. That mapper→dynamic-port→bind flow is identical for impacket, DotNetPacket,
  and Windows; the per-field tells above (version block, pad fill, referent ids) are
  what separate the runtimes, and they do **not** separate DotNetPacket from Windows.

## NDR request-marshalling choices (anti-fingerprint pass, 2026-11)

A deliberate pass to make request-side NDR look like a Windows client rather than
either impacket *or* a DotNetPacket-specific shape:

| Choice | DotNetPacket | impacket | Windows (MIDL) | Status |
| --- | --- | --- | --- | --- |
| Referent ids | sequential `0x00020000` + 4 per pointer | heap/randomish request ids | sequential `0x00020000` + 4 | **matched to Windows.** Previously a single constant `0x00020000` for every pointer — a DotNetPacket-only tell that also aliased distinct pointers. Now distinct and MIDL-style. |
| NDR alignment pad fill | `0x00` | `0xAA`/`0xBB` | `0x00` | matched to Windows (see above). |
| `LsarLookupSids2` / `LsarLookupNames2` ClientRevision | `2` | `1` | `2` | matched to Windows. impacket's `hLsarLookupSids2`/`hLsarLookupNames2` default ClientRevision to 1 (pre-Win2003); a modern Windows client sends 2, so DotNetPacket sends 2. |

Calls with **no** request-side discretion (fully determined by the handle + inputs, so
nothing to fingerprint and nothing to revisit): `LsarEnumerateAccountRights` (opnum 36) —
the request is the policy handle plus the account SID marshalled as an embedded conformant
RPC_SID, with no referent pointers, no pre-sized out-buffers, and no option/revision fields.
DotNetPacket's bytes here are identical to impacket's and to what Windows must send.
`LsarLookupPrivilegeValue` (opnum 31) and `LsarLookupPrivilegeName` (opnum 32) are the same:
the request is the policy handle plus either a privilege name (an RPC_UNICODE_STRING, exact-count
buffer, no NUL — Length/MaxLength 32, MaxCount/ActualCount 16 for `SeDebugPrivilege`, matching
impacket byte-for-byte) or a LUID. The only per-field difference from impacket is the string's
referent id (impacket's heap-ish value vs DotNetPacket's sequential `0x00020000`), already covered
by the referent-id row above — i.e. a point where DotNetPacket matches Windows/MIDL, not impacket.

### Pending a Windows capture (currently ≈ impacket; revisit)

These request-side *discretionary* values were taken from impacket / reg.exe
convention while decoding the protocol. They are protocol-valid and the server
accepts them, but I can't prove they match a **real Windows client** without a
capture, and changing them blindly risks the server rejecting the call. They are
left close to impacket **on purpose** and flagged here to revisit when we get a
Windows capture as the third column:

- **`BaseRegEnumKey` `lpClassIn` = 64 spaces, `lpNameIn` buffer = 1024 bytes.** Taken
  from impacket's `hBaseRegEnumKey`. Real `reg.exe`/`RegEnumKeyExW` may send a
  different class hint (possibly NULL) or a different buffer size. Left as-is because
  a wrong pre-size can make the server truncate or fault.
- **`BaseRegEnumValue` / `BaseRegQueryValue` pre-allocated buffer sizes** (256 / 512
  bytes, then grow on `ERROR_MORE_DATA`). The two-call grow pattern itself is
  protocol-driven and Windows-like; the exact first-guess size is a discretionary
  value copied from impacket/reg.exe convention.
- **`SamrQueryDisplayInformation` `EntryCount` / `PreferredMaximumLength` = `0xFFFFFFFF`.** Taken
  from impacket's `hSamrQueryDisplayInformation` defaults — the "return as much as fits" sentinels,
  which make the DC return the whole display list in one call. A real Windows admin tool typically
  pages with a bounded `PreferredMaximumLength` and `SamrGetDisplayEnumerationIndex`. The paging
  *loop* DotNetPacket implements (resume from the last Index on STATUS_MORE_ENTRIES) is Windows-like
  and protocol-driven; the one-shot `0xFFFFFFFF` first request is the discretionary bit left ≈ impacket
  until a Windows capture shows a real page size.
- **`LsarLookupPrivilegeDisplayName` `ClientLanguage` / `ClientSystemDefaultLanguage` = `0x0409` (en-US).**
  The call takes the caller's preferred and system-default LANGIDs; impacket has no helper/default,
  so DotNetPacket sends en-US. A real Windows client sends its actual locale (and the server's
  `LanguageReturned` echoes what it could supply). Protocol-valid and the server returns English
  regardless on this lab; revisit if a Windows capture shows a different default locale.
- **samr open-handle `DesiredAccess` = `MAXIMUM_ALLOWED` (`0x02000000`).** All the samr open
  calls (SamrConnect, SamrOpenDomain, SamrOpenUser, SamrOpenAlias) request MAXIMUM_ALLOWED, taken
  from impacket convention. It is protocol-valid and the server grants whatever the caller is
  entitled to, but a real Windows admin tool often requests a *specific* access mask (e.g.
  ALIAS_LIST_MEMBERS `0x0004` for a members read) rather than MAXIMUM_ALLOWED. Left ≈ impacket
  across all the opens for consistency; revisit when a Windows capture shows the real masks.
- **`SamrLookupNamesInDomain` / `SamrLookupIdsInDomain` array `MaxCount` = 1000.** This
  one is **IDL-mandated** (`size_is(1000)`) — every client including Windows sends
  1000, so it is *not* a fingerprint. Noted here only to record that it was checked.
- **Conformant-varying string NUL handling.** DotNetPacket appends and counts a NUL
  terminator for `[string]` buffers (as Windows does for NUL-counted strings) but
  sends exact-count (no-NUL) buffers for the samr name arrays (matching what the
  server returned in captures). Believed correct per MS-DTYP; revisit if a Windows
  capture shows otherwise.

## Caveat

These diffs are DotNetPacket vs. impacket. The realism target is a **real Windows
client**, which this lab cannot capture. DotNetPacket was built to match documented
Windows behavior (full capability set, GCM+CCM, NTLM version block), so where it
differs from impacket it is generally *closer* to Windows — but confirming that
requires a Windows capture to add as the third column. Known remaining gaps where
DotNetPacket itself still differs from Windows are tracked in `PORTING_STATUS.md`
(NTLM KEY_EXCH/sealing, SMB2 CREATE create-contexts, stable ClientGuid).
