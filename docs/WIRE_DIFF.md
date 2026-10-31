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
| `obj` referent id | `0x00020000` | `0x00000001` | different NDR referent-numbering scheme (both non-null; server accepts either) |
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

## Caveat

These diffs are DotNetPacket vs. impacket. The realism target is a **real Windows
client**, which this lab cannot capture. DotNetPacket was built to match documented
Windows behavior (full capability set, GCM+CCM, NTLM version block), so where it
differs from impacket it is generally *closer* to Windows — but confirming that
requires a Windows capture to add as the third column. Known remaining gaps where
DotNetPacket itself still differs from Windows are tracked in `PORTING_STATUS.md`
(NTLM KEY_EXCH/sealing, SMB2 CREATE create-contexts, stable ClientGuid).
