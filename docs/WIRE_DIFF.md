# Wire diff: DotNetPacket vs. stock impacket

This is the research output the project exists to produce (see `CLAUDE.md` →
"Capture diffing"): running the .NET port and stock impacket against the **same**
lab server and diffing the wire fields a SOC fingerprints on. Where they differ,
a fingerprint-based detection is keying on a **runtime artifact**, not on protocol
behavior — exactly the brittleness this project studies.

The realism target, though, is a real domain-joined **Windows** client, which the
Samba lab cannot produce — so the entries below are two-column (DotNetPacket vs
impacket) until a Windows capture lands. To capture that third column, follow
`WINDOWS_CAPTURE.md`; its findings resolve the **"Pending a Windows capture"**
section near the end of this file.

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

### DumpNTLMInfo credential-less recon (`smb-ntlminfo`, SMB2 path) — 2026-11-05

Both tools pull the same host facts from the server's NTLM CHALLENGE (NetBIOS name `VM`,
domain `LAB`, DNS `lab.local` / `vm.lab.local`, OS `Windows NT 6.1 Build 0`) and both get
`Null Session = True`. The difference is entirely in *our* request shape:

| Field | DotNetPacket (`smb-ntlminfo`) | stock impacket (`DumpNTLMInfo.py`) | Note |
| --- | --- | --- | --- |
| SMB2 NEGOTIATE dialects offered | 2.0.2, 2.1, 3.0, 3.0.2, **3.1.1** (+ 3.1.1 negotiate contexts) | 2.0.2, 2.1, 3.0 + an SMB2 **wildcard (`0x02ff`)** probe | **impacket tell.** Its custom `SMB2Negotiate` hardcodes a dialect list capped at 3.0, so the DC selects **SMB 3.0**; DotNetPacket offers the full modern set and the DC selects **SMB 3.1.1**, like a real Win10/11 client. |
| Negotiated dialect (result) | **3.1.1** | **3.0** | direct consequence of the row above — a rule keying on "NTLM-recon that lands on SMB 3.0 with a `0x02ff` wildcard offer" catches impacket, not DotNetPacket or a real client. |
| Null-session AUTHENTICATE (Type 3) | NT response empty, LM `00`, user NULL, `NEGOTIATE_ANONYMOUS` | NT response empty, LM `00`, user NULL | **same** — a true anonymous bind looks identical in both (and in Windows); the anonymous shape is not a usable tell. |
| SMBv1 probe | one SMB1 NEGOTIATE offering only `NT LM 0.12` | same | both detect SMBv1 the same way (server answered → enabled). |

The takeaway mirrors the other SMB findings: the **host-disclosure result is identical**
(it comes from the server), while impacket's **limited dialect offer** is the fingerprint —
and DotNetPacket diverges from it by looking *more* like Windows, not by evasion.

### Get-GPPPassword SYSVOL crawl (`gpp-passwords`) — 2026-11-05

Both tools authenticate, crawl the share for `*.xml`, and decrypt any `cpassword` with the
same published GPP key — recovering byte-identical plaintext (`Passw0rd!Lab` from a planted
Groups.xml). The decryption is offline and identical; the wire difference is the transport:

| Aspect | DotNetPacket (`gpp-passwords`) | stock impacket (`Get-GPPPassword.py`) | Note |
| --- | --- | --- | --- |
| SMB3 encryption of the crawl | **off** — all 112 SMB2 messages cleartext (signed) | **on** — 168 `SMB2_TRANSFORM` (encrypted) messages; tree/filenames opaque to tshark | **Biggest difference.** impacket encrypts the whole SYSVOL crawl, so a network sensor cannot see which files are read or that a cpassword crossed the wire. Ours is observable by design (lab-first) — and reflects the known SMB3-encryption gap (tracked in PORTING_STATUS). A *real* Windows client would encrypt when the server offers it, so here impacket is closer to Windows; the SOC should treat the cleartext crawl as a lab convenience, not the on-wire truth. |
| Negotiated dialect | SMB 3.1.1 | SMB 3.1.1 | same (unlike DumpNTLMInfo, this path uses the full modern negotiate in both) |
| Pre-crawl `srvsvc` share enumeration | not sent | `list_shares()` (NetrShareEnum over IPC$) before crawling | cosmetic recon step impacket prints; not part of the GPP read itself |
| Directory walk | BFS QUERY_DIRECTORY from the share root, READ each `*.xml` | BFS `listPath` + `getFile` (streamed, no mount) | same behavioral shape |
| cpassword decryption | AES-256-CBC, published key, zero IV, offline | identical | the key is public (MS14-025); not a secret and not on the wire |

The durable detection signal here is **behavioral and partly host/endpoint-side**: an
authenticated client doing a recursive SYSVOL walk that opens GPP `*.xml` files. On the wire
that is only visible when the session is unencrypted; against an encrypting client (impacket
or Windows) the network sees an SMB3 session to SYSVOL and little else, so GPP-cpassword
detection leans on SYSVOL file-access auditing / the file content at rest rather than payload
inspection.

### GetADComputers LDAP search (`get-adcomputers`) — 2026-11-05

No stock-impacket diff was possible here: this Samba lab **rejects impacket's NTLM-over-LDAP
bind with `data 52e`** (SMB NTLMv2 with the same credentials succeeds — an environment quirk,
not an impacket bug), so impacket never reaches the search. DotNetPacket binds **simple** over
389 (the lab was set to `ldap server require strong auth = no` to allow it) and the SearchRequest
was instead validated against Wireshark's LDAP dissector:

| Aspect | DotNetPacket (`get-adcomputers`) | Note |
| --- | --- | --- |
| Bind | simple bind, UPN `user@domain`, password in `simple [0]` | lab path. A real/default DC requires sign/seal or LDAPS; impacket uses NTLM-sealed bind (deferred here, and un-validatable on this lab). The *search* that follows is identical regardless of bind. |
| SearchRequest | base `dc=lab,dc=local`, scope wholeSubtree, deref never, filter `(&(objectCategory=computer)(objectClass=computer))`, attrs sAMAccountName/dNSHostName/operatingSystem/operatingSystemVersion | Wireshark decodes it exactly as intended; the BER (context-tagged `and [0]` of two `equalityMatch [3]`, attrs as `SEQUENCE OF OCTET STRING`) is what any RFC-4511 encoder — impacket's `ldapasn1` included — emits for this filter. |
| Paging | none (unpaged) | impacket sends a `SimplePagedResultsControl(size=100)`; ours omits it. On a large directory this is a visible difference (no `1.2.840.113556.1.4.319` control, single result set). Tracked as deferred. |

The durable detection signal is the **search shape**: an authenticated client doing a subtree
search for `(&(objectCategory=computer)(objectClass=computer))` returning OS/DNS attributes —
identical whatever the bind or runtime. Visible on the wire only for an unencrypted bind (ours);
an NTLM-sealed or LDAPS bind (impacket / a real client) hides the filter and results, pushing
detection to LDAP server-side query logging.

### GetADUsers LDAP search (`get-adusers`) — 2026-11-06

Same bind situation as GetADComputers (simple bind; impacket's NTLM LDAP bind fails `data 52e`
on this lab), so the diff is again at the search layer, and again validated by hand + Wireshark +
server acceptance rather than an impacket capture. Two filters, both accepted by the DC
(searchResDone resultCode 0):

| Mode | Filter sent | Note |
| --- | --- | --- |
| default | `(&(sAMAccountName=*)(mail=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))` | mirrors impacket — present + `not [2]` + `extensibleMatch [9]` (matchingRule `1.2.840.113556.1.4.803`, type `userAccountControl`, value `2`). Note Wireshark's LDAP dissector hits a recursion-depth assertion on the extensibleMatch and won't render it, but the raw BER is exactly the MatchingRuleAssertion and the server honours it. |
| `all` | `(&(sAMAccountName=*)(objectCategory=user))` | lists every user object. |

Attributes requested (both): `sAMAccountName`, `pwdLastSet`, `mail`, `lastLogon` — identical to
impacket. The only cosmetic nit: impacket's default filter string literally spells
`UserAccountControl`; LDAP attribute names are case-insensitive, so the chosen case is not a
usable fingerprint. Detection takeaway is the same as GetADComputers: the durable signal is the
**user-enumeration search shape**, visible only when the bind is unencrypted.

### GetLAPSPassword LDAP search (`get-laps`) — 2026-11-06

Same simple-bind lab path as the other LDAP examples. The LAPS search filter
`(&(objectCategory=computer)(|(msLAPS-EncryptedPassword=*)(ms-MCS-AdmPwd=*)(msLAPS-Password=*)))`
and the six LAPS attributes are identical to impacket; the DC accepted the search (searchResDone
resultCode 0) and returned nothing (Samba carries no LAPS schema). Wireshark confirmed the nested
`and`/`or`/`present` structure. The one deliberate divergence is at the decrypt layer, not the
wire: impacket decrypts `msLAPS-EncryptedPassword` (DPAPI-NG / MS-GKDI), while this port observes
and reports the blob but does not decrypt it (deferred). The cleartext paths (ms-Mcs-AdmPwd,
msLAPS-Password JSON) are read directly, identically to impacket. Detection signal: a client
searching computer objects for LAPS attributes — visible on the wire only for an unencrypted bind.

### GetNPUsers AS-REP roast (`get-npusers`) — 2026-11-06

The new Kerberos path. The LDAP discovery half is the usual simple-bind + extensible-match
search; the diff of interest is the **AS-REQ** we put on TCP/88. Wireshark decodes it identically
to what impacket sends:

| Field | DotNetPacket AS-REQ | Note |
| --- | --- | --- |
| kdc-options | `50800000` (forwardable + proxiable + renewable) | byte-identical to impacket's GetNPUsers |
| pa-data | single `PA-PAC-REQUEST` (include-pac TRUE) | same |
| etype | `[23]` (RC4-HMAC) first, AES256/128 on `KDC_ERR_ETYPE_NOSUPP` | same two-step as impacket |
| cname / sname / realm | `roastme` / `krbtgt/LAB.LOCAL` / `LAB.LOCAL`, NT-PRINCIPAL | same |

Both tools get the **same** reply from this lab: `KRB-ERROR KDC_ERR_PREAUTH_REQUIRED` — the
Samba 4.19 KDC does not honour `UF_DONT_REQUIRE_PREAUTH`, so no pre-auth-less AS-REP is produced
here for either runtime (a real Windows DC would return the roastable AS-REP). The detection
signal is the **AS-REQ with no encrypted pre-auth for a TGT** — identical on the wire whatever the
runtime; the roast hash only appears when the target DC actually allows it. A real Windows capture
would add the AS-REP side as the third column.

### getTGT AS exchange with pre-auth (`kerb-tgt`) — 2026-11-06

The TGT foundation. Our AS-REQ carries a PA-ENC-TIMESTAMP (RC4-HMAC) + PA-PAC-REQUEST, same as
impacket's getTGT; Wireshark decodes it as `krb-as-req` with both pa-data, and the KDC returns a
`krb-as-rep`. Both DotNetPacket and impacket obtain a TGT for the same account, and the recovered
RC4 session key decrypts cleanly. The RC4-HMAC crypto (string-to-key, encrypt/decrypt, key-usage
mapping) is **byte-for-byte identical to impacket's `_RC4`** (known-answer tests), so there is no
client fingerprint to distinguish the runtimes here — the diff, when a Windows capture lands, will
be the **etype choice** (we request RC4; a modern Windows client prefers AES256) and the pa-data
ordering, not the crypto. Detection signal: an AS-REQ with PA-ENC-TIMESTAMP for a TGT — normal
Kerberos, so detection keys on context (volume, source), not the bytes.

### GetUserSPNs Kerberoast (`get-userspns`) — 2026-11-06

A rare case where **DotNetPacket is more correct than impacket, and it shows on the wire.** Both
build a TGS-REQ whose PA-TGS-REQ wraps an AP-REQ (the TGT + an authenticator). The difference is
the **authenticator checksum over the KDC-REQ-BODY**:

| | DotNetPacket (`get-userspns`) | stock impacket (`GetUserSPNs.py`) |
| --- | --- | --- |
| TGS authenticator `cksum [3]` | **present** — HMAC-MD5 (cksumtype -138) over the req-body, key usage 6, per RFC 4120 5.5.1 | **absent** — impacket omits it |
| Result on this Samba 4.19 (Heimdal) KDC | service ticket returned; `$krb5tgs$` hash produced and verified to crack to the service password | `KRB_AP_ERR_INAPP_CKSUM` (error 50) — **fails to roast** |

Against real Windows AD impacket's omission is tolerated, which is why it normally works; the
stricter Heimdal KDC rejects it. DotNetPacket includes the checksum a real Windows client sends,
so it is both RFC-correct and succeeds here. Everything else matches: kdc-options `40810010`,
sname as the SPN (NT-SRV-INST), RC4 etype, and the `$krb5tgs$` format (incl. the `:`→`~` in the
SPN) is byte-compatible with impacket's. Detection signal: a flurry of TGS-REQs for many SPNs from
one client — behavioral, independent of the checksum nuance.

### Kerberos SMB login with AES-256 (`-k`) — 2026-11-16

The headline parity feature: `-k` now authenticates to SMB with **AES-256** (impacket's default),
not just RC4. Capture: `dotnetpacket-kerberos-aes256.pcap`. The full exchange on the wire matches a
modern Windows/impacket client:

| Stage | DotNetPacket (`-k`, password) | Note |
| --- | --- | --- |
| AS probe | AS-REQ etype `[18, 17, 23]`, no pre-auth | same list + order impacket offers (AES-256 first) |
| KDC reply | `KDC_ERR_PREAUTH_REQUIRED` + PA-ETYPE-INFO2 (etype 18, salt `LAB.LOCALAdministrator`) | we read the salt from here, as impacket does |
| AS-REQ #2 | PA-ENC-TIMESTAMP encrypted **aes256-cts-hmac-sha1-96**, etype `[18]` | key = RFC 3962 string-to-key(password, salt, 4096) |
| TGS-REQ | AP-REQ authenticator + req-body checksum both **AES** (enc usage 7, cksumtype 16 usage 6) | etype-driven by the TGT session key |
| AP-REQ | SPNEGO(MS KRB5) `[APPLICATION 0]{krb5-OID, 0x0001, AP-REQ}`, authenticator usage 11, `mutual-required` | byte-structure unit-tested |
| AP-REP | server returns `krb-ap-rep`; we decrypt EncAPRepPart (usage 12) → **acceptor subkey** | the SMB session key under AES |
| SESSION_SETUP | single round → **STATUS_SUCCESS**; signing key = KDF(AP-REP subkey) | signed `srvsvc` then succeeds |

**The subtle, important finding.** Authenticating is not enough: the first AES attempt reached
`STATUS_SUCCESS` but every *signed* follow-up (TREE_CONNECT, the `srvsvc` pipe) was rejected, and
Samba logged **`Bad SMB2 (sign_algo_id=1) signature for message`**. The earlier RC4 `-k` work had
mis-attributed this to "Samba RC4 PAC hardening" — but AES failed *identically*, which ruled that
out. The real cause is [MS-KILE] 3.1.1.2: when the client requests **mutual authentication** (we do),
the GSS/SMB session key is the **subkey in the server's AP-REP**, not the ticket session key — and
*for AES the two differ* (for RC4 they happen to coincide, which is why RC4 "looked" authenticated).
Keying SMB signing on the recovered AP-REP subkey fixes authorization for **both** RC4 and AES; a
signed `srvsvc NetrShareEnum` now returns the share list, matching an NTLM admin session.

**Crypto fidelity.** The aes128/aes256-cts-hmac-sha1-96 profiles (`AesCtsCrypto`) are verified
**byte-for-byte against stock impacket** (encrypt + keyed-checksum known-answer tests with a fixed
confounder) and against the **RFC 3962 Appendix B** string-to-key vectors; n-fold matches the MIT
krb5 reference (note: the widely-copied `be07…` n-fold value for `"012345678"` is wrong — MIT and
impacket both produce `a928a426e3e36b30`). So there is no client crypto fingerprint separating the
runtimes on the AES path. Detection signal: ordinary Kerberos — AS/TGS/AP-REQ sequences and volume,
not bytes.

### Sealed Kerberos LDAP (`-k` for the LDAP tools) — 2026-11-16

Extends `-k` to the LDAP half of the tool (GetADUsers, GetADComputers, findDelegation, …). Capture:
`dotnetpacket-ldap-kerberos-sealed.pcap`. The SASL GSS-SPNEGO bind rides in the clear; afterwards
every LDAP PDU is GSS-wrapped and Wireshark labels them **"SASL GSS-API Privacy"** (confidentiality):

| Stage | DotNetPacket (`-k`) | Note |
| --- | --- | --- |
| bind | `bindRequest` SASL `GSS-SPNEGO`, mechToken = SPNEGO(MS KRB5) AP-REQ for `ldap/<host>` | AES-256 ticket |
| bind resp | `bindResponse success`, serverSaslCreds = SPNEGO(accept-completed **+ AP-REP**) | mutual auth |
| search+ | each PDU = `[4-byte len][CFX Wrap 0x0504 header][sealed ciphertext]`, key usage 24/22 | AES CFX, RFC 4121 |

**The research finding (and a real divergence from impacket).** A Kerberos bind authenticates fine,
but the DC then *seals* the channel, and the seal key is where implementations differ. impacket's
native `ldap.py` sends a **non-mutual** AP-REQ (empty ap-options) and seals with the **ticket session
key**; real Windows AD tolerates this. This Samba 4.19 DC does **not**: it accepts the bind, then
`FIN`s the first sealed search with no reply (the CFX Wrap header's AcceptorSubkey flag is set, but no
acceptor subkey exists). Per **[MS-KILE] 3.1.1.2** the GSS context key for a mutual exchange is the
**AP-REP acceptor subkey**. DotNetPacket therefore requests **mutual auth**, recovers the acceptor
subkey from the AP-REP in the bind's SASL creds, and seals with it — which is both MS-KILE-correct and
accepted by Samba. (We could not cross-check with impacket's own LDAP `-k` here: impacket omits the
TGS authenticator checksum, so its `getKerberosTGS` fails against this Heimdal KDC before it ever
binds — the same `KRB_AP_ERR_INAPP_CKSUM` quirk documented under Kerberoast above.)

**Crypto fidelity.** Both wrap profiles (`KerberosGssContext`) are byte-for-byte equal to impacket
(fixed-confounder known-answer tests): the AES CFX Wrap (`GSSAPI_AES256.GSS_Wrap_LDAP`) and the RC4-HMAC
Wrap (`GSSAPI_RC4.GSS_Wrap_LDAP`, RFC 1964 — the MechIndepToken GSS framing, the `key ^ 0xF0` seal key,
the RC4-encrypted sequence/confounder). So LDAP `-k` now completes the matrix: password/`-aesKey` seal
with AES, `-hashes` (overpass-the-hash) seals with RC4 — the RC4 path validated live (`-k -hashes` →
sealed `get-adusers`). Detection signal: a Kerberos LDAP bind followed by GSS-API-Privacy traffic on
389 — LDAP a sensor can no longer read in clear; the tell is the bind + the switch to sealed buffers,
not the (encrypted) contents. (RC4-sealed LDAP is itself a weak-crypto signal on a modern network.)

### S4U / constrained delegation (`get-st`) — 2026-11-16

The abuse half of delegation (findDelegation finds the targets; `get-st` uses them). Capture:
`dotnetpacket-s4u.pcap`. A service account's TGT drives two back-to-back TGS-REQs that are highly
distinctive on the wire:

| TGS-REQ | What makes it an S4U request | DotNetPacket |
| --- | --- | --- |
| **S4U2self** | a 2nd pa-data **PA-FOR-USER (129)** naming another user, sname = the service itself (NT-UNKNOWN), kdc-options `40810000` | matches getST |
| → reply | the returned ticket's **cname is now the impersonated user** | — |
| **S4U2proxy** | **PA-PAC-OPTIONS (167)** RBCD flag `10000000`, kdc-options `40830000` (adds **cname-in-addl-tkt**), an **additional-ticket** (the S4U2self ticket), sname = the target SPN | matches getST |

The one subtlety worth recording: the **PA-FOR-USER checksum is always KERB_CHECKSUM_HMAC_MD5
(cksumtype -138), keyed with the TGT session key at key usage 17 — even when the TGT is AES-256**
(MS-SFU 2.2.1). So an all-AES exchange still carries one HMAC-MD5 checksum here; DotNetPacket computes
it exactly as impacket's `_HMACMD5.checksum` does (byte-for-byte known-answer test). Everything else
(authenticator usage 7, req-body checksum usage 6) is the normal etype. Detection signal: the
PA-FOR-USER / PA-PAC-OPTIONS pa-data and the additional-ticket + cname-in-addl-tkt option in a TGS-REQ
— a strong behavioral marker of S4U, independent of the runtime; the impersonated cname appearing in a
ticket the requester did not authenticate as is the tell.

Lab note: this Samba 4.19 restricts `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD) writes to SYSTEM,
so the scenario was set up with **classic** constrained delegation (`msDS-AllowedToDelegateTo` + the
`TRUSTED_TO_AUTH_FOR_DELEGATION` UAC flag). The request still carries the PA-PAC-OPTIONS RBCD flag,
as impacket's getST sends it unconditionally.

### ccache (`KRB5CCNAME`) — off the wire, 2026-11-17

No wire fingerprint: the MIT ccache is a local file, not a protocol. It earns a line here only because
it is the **interop substrate for this whole document** — the way to feed the *same* ticket to
DotNetPacket and to stock impacket so their on-wire behavior can be diffed. `-k` now loads a TGT from
`-ccache` / `KRB5CCNAME` exactly as impacket does (so a ticket obtained once drives many tools), and
`kerb-tgt -save-ccache` emits a ccache that impacket reads back intact (`describeTicket.py`: correct
session key, principals and the `0x50e10000` flag set). The only behavior change on the wire is a
*negative* one — with a loaded TGT the AS exchange simply does not happen, which is itself a useful
detection note (a Kerberos service access with no preceding AS-REQ from that client = a cached/replayed
or injected ticket).

### secretsdump DCSync (DRSUAPI replication) (`dcsync`) — 2026-11-17

The highest-value detection target in this whole port: replicating an account's secrets out of a DC
with the directory replication service, the way a second DC would — [MS-DRSR] `IDL_DRSGetNCChanges`
with `ulExtendedOp = EXOP_REPL_OBJ`. DotNetPacket drives the full sealed sequence over ncacn_ip_tcp:
`DsBind(0) → DsGetDomainControllerInfo(16) → DsCrackNames(12) → DsGetNCChanges(3) → DsUnbind(1)`,
and Wireshark decodes every request as a valid DRSUAPI operation.

**The behavioral signature (the whole point).** DCSync's tell is not a string — it is *who* is
replicating. A `DsGetNCChanges` from a source IP that is **not a domain controller** (not in the
DC's own replication topology / not a member of `Domain Controllers`) is the classic detection, and
on a well-run network it fires regardless of the tool's language or TLS/seal state. Secondary tells
in the same flow: the `DsBind` carries a `DRS_EXTENSIONS_INT` with `dwExtCaps = 0xFFFFFFFF` and the
`GETCHGREQ_V8`/`GETCHGREPLY_V6` capability bits a replication partner advertises; the `DsCrackNames`
immediately before resolves the single victim account (`DS_NT4_ACCOUNT_NAME → DS_UNIQUE_ID_NAME`);
and `cMaxObjects = 1` + `EXOP_REPL_OBJ` marks a *single-object* pull (secretsdump's `-just-dc-user`),
distinct from a full-domain sync. DotNetPacket emits all of these faithfully.

**Sealed on the wire, like the real thing.** The bind negotiates NTLMSSP **packet privacy**, so the
`DsGetNCChanges` request stub and the reply (the ENCRYPTED_PAYLOAD-wrapped hashes) are encrypted —
a sensor sees the opnum/sequence and the non-DC source, not the cleartext attributes. This matches
real DCSync; detection keys on behavior, not payload bytes.

**Request marshalling vs impacket.** Byte-for-byte identical to impacket's `DRSGetNCChanges` V8 stub
*except* the two already-documented, Windows-matching divergences (see *NDR request-marshalling
choices*): sequential MIDL referent ids (vs impacket's heap-ish ids) and `0x00` NDR alignment pad
(vs impacket's `0xAB`/`0xEE` filler — the V8 struct is 8-aligned because it carries `hyper` fields).
Verified against impacket's own `getData()` for identical inputs (`scratchpad/cmp_req.py`). One
deliberate protocol choice differs from a naive impacket port: DotNetPacket sends an **empty request
prefix map** and the **canonical well-known ATTRTYP ids** (unicodePwd `0x9005A`, …) rather than a
MakeAttid-built custom prefix table — Samba rejects a custom remote prefixMap and silently returns
zero objects, while the empty-map/canonical-attid form is what both Samba and Windows DCs resolve via
their own base schema. (`PrefixTable.MakeAttid` is still ported and unit-tested for fidelity.)

**Crypto.** The recovered secrets prove correctness: Administrator decrypts to the known NT hash
`ac8d0d3c9858659864b8493a51050efd` (RID 500). Two layers, both ported faithfully from impacket:
`MD5(DCERPC seal session key ‖ salt) → RC4 → CRC-32` (ENCRYPTED_PAYLOAD) then per-RID single-DES
(MS-SAMR). No divergence here — the bytes must match or the hash is wrong.

**Kerberos keys (supplementalCredentials).** DCSync also returns the directory's *stored* Kerberos
keys, which `dcsync` decrypts and prints after the hash line — the aes256-cts/aes128-cts/des-cbc-md5
keys from the `Primary:Kerberos-Newer-Keys` property of the MS-SAMR USER_PROPERTIES blob (and the
cleartext password where one is stored). A second correctness oracle: Administrator's replicated
AES-256/AES-128 keys match the keys derived independently from the known password + salt via PBKDF2.
These keys are reusable for pass-the-key (Silver/Golden tickets) without cracking, so pulling them is
the same high-value, non-DC-source detection as pulling the hashes — same sealed GetNCChanges, nothing
extra on the wire (supplementalCredentials is just another attribute in the already-requested set).

### Whole-domain DCSync (`dcsync-all`) — 2026-11-17

The default secretsdump behavior: dump *every* account, not one named target. impacket does this by
**enumerating the accounts first (SAMR/LDAP) and then DCSync'ing each one individually** with
`EXOP_REPL_OBJ` — it does not issue a single whole-NC replication. `dcsync-all` mirrors that exactly:
a sealed SAMR `SamrEnumerateUsersInDomain` to list the RIDs, then one `DsGetNCChanges` per account
addressed **by SID** (impacket's `DRSGetNCChangesSid`), which skips the per-account `DsCrackNames`.

**Detection signature.** The tell is a *burst* of `DsGetNCChanges` / `EXOP_REPL_OBJ` requests from one
non-DC source in quick succession (one per principal), optionally preceded by a SAMR enumeration from the
same host — a stronger, noisier version of the single-object DCSync signature. All sealed at packet
privacy, as before; detection keys on the call pattern and source, not payload.

**Fragmentation is normal here, and is a wire characteristic worth noting.** A DC's GetNCChanges reply
for an account with `supplementalCredentials` exceeds the DCERPC fragment size, so the reply comes back
as PFC_FIRST_FRAG … PFC_LAST_FRAG across several PDUs (visible in the capture as `cn_flags` 0x01 then
0x02, versus 0x03 for a single-PDU reply). DotNetPacket reassembles these the way any conformant client
must — read until PFC_LAST_FRAG, unseal/verify each fragment independently (sign/seal is per-PDU), then
concatenate. No divergence from impacket or Windows on the wire; the fragment boundaries are the server's
choice, not the client's.

### Kerberos (-k) DCSync — DCE-style GSS-authenticated DRSUAPI (`dcsync-k`) — 2026-11-17

DCSync authenticated with a Kerberos ticket instead of NTLM (`secretsdump -k`). The DCERPC bind uses
RPC_C_AUTHN_GSS_NEGOTIATE with the Microsoft DCE-style three-leg handshake — distinct from the single-leg
NTLM bind and a strong behavioral signal in itself:

`AS-REQ/AS-REP` (or a cached TGT) → `TGS-REQ/TGS-REP` for `host/<dc-fqdn>` → `BIND` (GSS AP-REQ,
ap-options mutual-required, GSS checksum flags incl. **DCE_STYLE 0x1000**) → `BIND_ACK` (AP-REP) →
`ALTER_CONTEXT` (the client's mutual-auth completion AP-REP + SPNEGO mechListMIC) → `ALTER_CONTEXT_RESP`
→ sealed `DsGetNCChanges`. Per-PDU protection is RFC 4121 AES CFX `GSS_Wrap` (the acceptor subkey from the
AP-REP), the same CFX machinery as the sealed Kerberos LDAP bind but with the DCERPC token split (sealed
stub in the PDU, 16-byte header + rotated front slice in the auth verifier).

**Detection.** Two tells stack on the EXOP_REPL_OBJ-from-a-non-DC signature: the replication is now
preceded by a Kerberos service-ticket request for the DC's `host/` SPN, and the DCERPC bind is a
DCE-style GSS-NEGOTIATE three-leg exchange (BIND→ALTER_CONTEXT) rather than NTLM. A `host/<dc>` TGS
followed by a sealed DRSUAPI replication from a workstation is a crisp DCSync-over-Kerberos pattern.

**vs impacket (a real divergence worth recording).** impacket's `getKerberosType3` sends **no**
SPNEGO mechListMIC in the ALTER_CONTEXT. Against Samba 4.19.5's strict SPNEGO that leaves the context
accept-incomplete and the first sealed request faults `nca_s_proto_error`; DotNetPacket sends the client
mechListMIC (a GSS MIC over the offered MS-KRB5 MechTypeList) and completes the bind. Doing so surfaced
two impacket bugs that are latent because real DCs don't require the mechListMIC: its
`GSSAPI_AES.GSS_GetMIC` adds a `_calculateMICPad` that is wrong for a CFX MIC token (a correct MIC
checksums `data || header` with no pad), and the MIC must be over the MS-KRB5 OID (`1.2.840.48018.1.2.2`)
as offered, not the canonical KRB5 OID. DotNetPacket emits the RFC-correct, Samba-accepted form.

### addcomputer SAMR machine-account creation (`rpc-addcomputer`) — 2026-11-06

The first **write**. The SAMR stub rides the sealed SAMR-over-SMB pipe, so the request is encrypted
on the wire (SMB3 + NTLMSSP seal) — not readable from a capture, same as the other sealed RPC
calls. What a sensor sees is the sealed DCERPC to `\samr` and the SMB3 session; the detectable
event is behavioral: a client calling **SamrCreateUser2InDomain** with AccountType
WORKSTATION_TRUST_ACCOUNT (0x80). DotNetPacket's request NDR matches impacket's
`hSamrCreateUser2InDomain` (name as an RPC_UNICODE_STRING with **no trailing NUL**, AccountType 0x80,
DesiredAccess MAXIMUM_ALLOWED), validated by the DC accepting it and by a pinned known-bytes test.
Difference from impacket: impacket follows the create with SamrSetPasswordInternal4New + an enable
and leaves a usable account; this port creates then immediately **deletes** (lab hygiene), so the
on-wire sequence is CreateUser2 → DeleteUser rather than CreateUser2 → SetInformationUser2(×2).
The password-set is deferred (see PORTING_STATUS).

### attrib DOS-attribute query/set (`smb-attrib`) — 2026-11-06

Benign SMB2. The query is SMB2 QUERY_INFO FileBasicInformation; the set is SMB2 SET_INFO
FileBasicInformation with the four timestamps 0 ("unchanged") and the new FileAttributes. The
SET_INFO body matches impacket's (StructureSize 0x21, InfoType File, class 4, BufferOffset 0x60,
40-byte FILE_BASIC_INFORMATION) and the DC applied it (ReadOnly+Hidden round-tripped). This rides
the ordinary signed SMB2 session (not encrypted here), so the fields are visible on the wire; no
client-fingerprint divergence from impacket on this call.

### smbexec svcctl command exec (`smbexec`) — 2026-11-12  (deliberate signature divergence)

Remote command execution via a one-shot svcctl service (psexec-without-RemComSvc). This is the one
example where byte-for-byte fidelity would be **wrong**: smbexec's service binary path is a
heavily-signatured tool IOC, not a protocol structure. A genuine reimplementation in another
language would not reproduce impacket's exact command string, so DotNetPacket keeps the **behaviour**
and diverges on the **surface tokens** — the "same behaviour, different fingerprint" this whole
project exists to produce. (Not evasion: a fixed, documented alternative construction, no
obfuscation/encoding/per-call dodging.)

| Token | impacket `RemoteShell.execute_remote` | DotNetPacket `SmbExecCommand` |
| --- | --- | --- |
| interpreter | `%COMSPEC% /Q /c` | `cmd.exe /c` |
| temp script | `%SYSTEMROOT%\<r8>.bat` | `%TEMP%\<r16>.cmd` |
| output file | `__output_<r8>` | `<r16>` (no fixed prefix) |
| random names | 8 chars, `string.ascii_letters` (letters only) | 10/16 chars, **alphanumeric** |
| service name | `<r8>` letters | `<r10>` alphanumeric |

impacket binPath:
`%COMSPEC% /Q /c echo <cmd> ^> \\%COMPUTERNAME%\<share>\__output_<r8> 2^>^&1 > %SYSTEMROOT%\<r8>.bat & %COMSPEC% /Q /c %SYSTEMROOT%\<r8>.bat & del %SYSTEMROOT%\<r8>.bat`

DotNetPacket binPath (observed in `dotnetpacket-smbexec.pcap`, frame 47):
`cmd.exe /c echo <cmd> ^> \\%COMPUTERNAME%\<share>\<r16> 2^>^&1 > %TEMP%\<r16>.cmd & cmd.exe /c %TEMP%\<r16>.cmd & del %TEMP%\<r16>.cmd`

**Behavioural invariants a detection should key on instead** (these survive the rewrite and match
both tools): a `svcctl` `RCreateServiceW` (opnum 12) with `dwStartType=SERVICE_DEMAND_START`, whose
binary path drives a command interpreter that echoes a redirecting line into a throwaway script,
runs it, and redirects output (`2>&1`) to a file on a readable share; the service is started (and
times out — it is not a real service) and **deleted within seconds** on the same handle. A SIGMA-style
rule matching the *literal* `%COMSPEC% /Q /c`, `__output_`, or the `.bat` under `%SYSTEMROOT%` will
**miss this port** — which is the measurable result the lab is meant to demonstrate.

**On the wire (lab):** Samba's svcctl does not implement service creation, so both DotNetPacket **and
stock impacket smbexec** get DCERPC fault `0x1C010002` (`nca_s_op_rng_error`) on the CreateServiceW.
DotNetPacket's CreateServiceW rides a cleartext+signed pipe, so its binPath is fully visible in the
capture (frame 47) — service name `RDY8tkW8MR`, the DotNetPacket-flavoured binPath above, none of
impacket's tokens. **impacket's own binPath is not visible on the wire here** because impacket
encrypts the pipe (SMB3 transform — the separately-documented SMB3-encryption gap), so its string is
referenced from source/oracle, not its capture; that impacket encrypts while this port is observable
is itself part of the diff. End-to-end execution + the output-file grab need a Windows target. The
`SERVER`-mode local SMB server, the semi-interactive shell, and the powershell `-Enc` encoder are not
ported. The CreateServiceW stub itself also carries the already-documented NDR referent-id / pad
choices (see the NDR section below).

### atexec Task Scheduler exec (`atexec`) — 2026-11-06, divergence pass 2026-11-13

Remote command execution via MS-TSCH (`\atsvc`). Samba doesn't implement the service, so this
can't run end-to-end on the lab — the `\atsvc` open returns STATUS_OBJECT_NAME_NOT_FOUND (visible
in the capture; the detectable behavior on this target is just a client *attempting* to open
`\atsvc`). The request encoding was validated against the **impacket tsch encoder** instead of a
server.

**Deliberate signature divergence (2026-11-13).** The task XML and the command line are heavily-
signatured tool IOCs (not protocol structures), so — like smbexec — the behaviour is kept and the
signaturable constants diverge from impacket. A brittle rule matching impacket's famous
`StartBoundary>2015-07-15T20:35:13.2757294`, `P3D`, or the `/C … > %windir%\Temp\….tmp 2>&1`
command will **miss this port**; a behavioural detection (a **hidden LocalSystem task created, run,
and deleted within seconds whose action spawns a command interpreter that redirects output to a Temp
file**) still catches it.

| Token | impacket `atexec.py` | DotNetPacket |
| --- | --- | --- |
| task `StartBoundary` | `2015-07-15T20:35:13.2757294` | `2019-05-02T14:00:00` |
| `ExecutionTimeLimit` | `P3D` | `PT72H` |
| `Priority` | `7` | `5` |
| trailing whitespace after `</Task>` | present (8 spaces) | none |
| command | `cmd.exe /C <cmd> > %windir%\Temp\<r8>.tmp 2>&1` | `cmd.exe /c <cmd> 1> %SystemRoot%\Temp\<r12>.log 2>&1` |
| temp name | 8 `ascii_letters`, `.tmp` | 12 alphanumeric, `.log` |
| task vs output name | **same** 8-letter name reused | **independent** random names |

The schema element order is unchanged so Windows Task Scheduler still accepts the XML; the divergence
is pinned by unit tests (impacket's IOC constants absent, behaviour present) since the XML never
reaches the wire on Samba.

For SchRpcRegisterTask / Run / Delete / GetLastRunInfo the stubs match impacket's
structure byte-for-byte except:

| Field | DotNetPacket | impacket |
| --- | --- | --- |
| LPWSTR/pointer referent ids | `0x00020000`+ (MIDL/Windows sequential) | random per-process |
| NDR alignment pad fill | `0x00` | `0xAB` / `0xBF` |
| trailing align after the last string | present (we always align) | omitted |

All three are the project's existing, documented anti-fingerprint / Windows-faithful choices, not
new divergences. The task XML (hidden task, LocalSystem, run-on-demand, `cmd.exe /C … > tmp 2>&1`)
is a verbatim port of impacket's template. The durable detection signal is behavioral: an `\atsvc`
bind + SchRpcRegisterTask → SchRpcRun → SchRpcDelete burst — identical in shape whatever the
runtime; a Windows capture would add the on-wire third column.

### changepasswd SAMR self-service password change (`rpc-changepw`) — 2026-11-06

Benign SAMR over the sealed pipe. SamrUnicodeChangePasswordUser2 carries the new password
RC4-encrypted under the old NT hash and the old NT hash DES-encrypted under the new NT hash — all
**deterministic for fixed passwords** (no random salt), so the crypto buffers are byte-identical to
impacket's (NT hashes, SamEncryptNTLMHash all match). The request is sealed on the wire, so a
sensor sees the sealed `\samr` call, not the fields; the server validated the old-password proof
and the new password (it returned STATUS_PASSWORD_RESTRICTION under the default 1-day min password
age, then succeeded once that was relaxed). The NDR framing differs from impacket only in the
documented referent-id scheme and zero pad-fill; total request length is identical (616 bytes).

### badsuccessor dMSA / LDAP writes (`badsuccessor`) — 2026-11-08

Adds the LDAP write path (AddRequest [APP 8], ModifyRequest [APP 6], DelRequest [APP 10]) over the
same simple-bind connection, plus an MS-DTYP security-descriptor parser/builder. All validated
against the lab: Add/Modify/Delete of a real OU return result 0; the SD parser reads Samba's real
OU `nTSecurityDescriptor`s; and the SID binary + the `msDS-GroupMSAMembership` SD this tool builds
are **byte-for-byte identical to impacket's** (same DACL-first self-relative layout, Control 0x8004,
ACE masks 0x000F01FF + GenericAll). The dMSA object create cannot complete on Samba (no Server-2025
schema), but the DC parses the AddRequest and rejects it on the object class, confirming the wire
encoding. Detection signal: the `search` path is read-only LDAP; the attack itself is an LDAP
**add** of an `msDS-DelegatedManagedServiceAccount` with `msDS-ManagedAccountPrecededByLink` set —
a high-signal write a SOC can key on, identical on the wire whatever the runtime.

### ntlmrelayx SMB→LDAP relay / ldapattack (`ntlmrelayx-ldap`) — 2026-11-12

Relays the victim's NTLM to the DC's LDAP as a GSS-SPNEGO SASL bind, the highest-impact ntlmrelayx
chain (a relayed LDAP bind as a privileged user enables RBCD writes, machine-account creation, DCSync
grants, …). The wire sequence against the lab DC:

- `bindRequest(1)` NTLMSSP_NEGOTIATE (the relayed victim Type 1) → `bindResponse(1) saslBindInProgress`
  NTLMSSP_CHALLENGE (the DC's Type 2, relayed back to the victim).
- `bindRequest(2)` NTLMSSP_AUTH, `User: LAB\Administrator` (the relayed victim Type 3) →
  `bindResponse(2) success`. **The relay is now authenticated to LDAP as the victim.**
- The follow-on `searchRequest(3)` over `dc=lab,dc=local` is answered with a **TCP RST** from the DC.

**The mitigation on the wire:** the bind succeeds, but the NTLM bind negotiated signing/sealing and the
DC enforces LDAP integrity on *operations*. The relay holds no session key, so it cannot seal the
search, and the DC resets it. This is exactly why LDAP signing + channel binding (LDAPS/EPA) is the
defence against LDAP relay: the authentication relays, but the session is unusable for the actual
attack. The port reproduces both halves — the successful relayed bind and the reset operation — and
reports the reset as the mitigation rather than swallowing it. (A DC without signing, or an LDAPS
target, would let the post-bind writes through; that case is tracked in PORTING_STATUS.) The relay
reuses the same `IRelayTarget` bridge as the SMB and HTTP servers, so the inbound victim side is
unchanged and the cross-session challenge-reuse signal still holds.

### ntlmrelayx HTTP→SMB relay (`ntlmrelayx-http`) — 2026-11-10

The second relay server and a new inbound protocol surface: HTTP NTLM (the coerced-auth vector behind
PetitPotam/PrinterBug over HTTP/WebDAV). The victim side is plain HTTP/1.1 with connection-oriented
NTLM: GET → `401 WWW-Authenticate: NTLM` → GET `Authorization: NTLM <b64 Type1>` →
`401 WWW-Authenticate: NTLM <b64 Type2>` → GET `Authorization: NTLM <b64 Type3>` → `200`. Unlike SMB,
HTTP carries **bare base64 NTLMSSP** (no SPNEGO), so the server decodes the tokens straight from the
header and the outbound `IRelayTarget` re-wraps them in SPNEGO for the SMB target. The detection signal
is identical to the SMB relay and now spans two *different* protocols: in the lab capture the same
server challenge (`e594e3ca950f30bb`) appears in the HTTP victim session (:8081) and the SMB target
session (:445) at the same instant.

- **The MIC is the mitigation, shown on the wire.** A bare-HTTP victim does not (and cannot) carry a
  SPNEGO mechListMIC, and the relay cannot forge one because it never holds the session key. So the
  relay only succeeds when the victim's Type 3 does **not** assert an NTLM MIC (the MsvAvFlags MIC
  bit): with `IncludeMic=true` the Samba target answers `STATUS_MORE_PROCESSING_REQUIRED` (it still
  wants a MIC-backed SPNEGO completion); with `IncludeMic=false` — realistic for bare HTTP NTLM — it
  answers `STATUS_SUCCESS`. This is exactly why enabling MIC/EPA enforcement breaks cross-protocol
  relay, and the port reproduces both outcomes faithfully rather than hiding the failing one.
- **Server realism tell:** the HTTP server returns a `Server: Microsoft-IIS/10.0` banner (as impacket
  mimics) and minimal headers; a SOC can profile the response shape, but the durable signal remains the
  cross-session challenge reuse, not the banner.

### ntlmrelayx SMB→SMB relay (`ntlmrelayx`) — 2026-11-09

The first *server* in the port, and the single highest-signal relay artifact a SOC can key on. The
relay server speaks SMB2 to a victim and bridges the NTLM SPNEGO handshake to a target SMB server:

- **Victim session:** victim→server NEGOTIATE; server answers SMB 2.1 with an SPNEGO NegTokenInit
  advertising NTLMSSP. Victim→server SESSION_SETUP #1 carries NTLM Type 1; server→victim returns a
  NegTokenResp (negState=accept-incomplete) wrapping a **challenge it did not generate**. Victim→
  server SESSION_SETUP #2 carries the Type 3 the victim computed against that challenge.
- **Target session (concurrent):** server→target NEGOTIATE; server→target SESSION_SETUP #1 forwards
  the victim's Type 1; target→server returns its real Type 2 challenge — the one the server handed the
  victim. Server→target SESSION_SETUP #2 forwards the victim's Type 3; target returns SUCCESS.

**The detection signal** is the challenge correlation: the identical 8-byte NTLM server challenge
appears in two different TCP connections at nearly the same instant (one inbound from the victim, one
outbound to the target). In the lab capture both the victim session (:4455) and the target session
(:445) carry server challenge `1f51fcab07af7d21`. This correlation is *runtime-independent* — it holds
whether the relay is impacket, this .NET port, or anything else — which is exactly why it is a durable
behavioral detection rather than a tool fingerprint. A SOC can also key on the server side looking
"off": here the relay downgrades to SMB 2.1 and presents a freshly-generated ServerGuid with a minimal
NEGOTIATE (no 3.1.1 negotiate contexts), because it holds no session key and cannot complete 3.1.1
preauth/signing — a realism gap worth noting as its own tell (documented, not hidden; CLAUDE.md forbids
closing such gaps with evasion). The victim's AUTHENTICATE is also harvested as a NetNTLMv2 hashcat
line (`NtlmAuthenticate` + `NetNtlmv2.Format`, byte-identical to impacket's `outputToJohnFormat`) — not
a wire artifact but the offline-crackable output every operator collects; the hash binds the victim's
user/domain to the relayed (target's) challenge. Scope: SMB→SMB core only; the other relay servers,
attack modules and SOCKS reuse are deferred (PORTING_STATUS).

### rbcd delegation read/edit (`rbcd`) — 2026-11-08

The third SD-editing LDAP tool, but with a telling wire difference from dacledit/owneredit: the
security descriptor lives in a **plain attribute** (`msDS-AllowedToActOnBehalfOfOtherIdentity`), not
`nTSecurityDescriptor`, so the modify carries **no SD-flags control** at all. On the wire it is a bare
`modifyReplace` of that attribute with a self-relative SD value. When the attribute is absent the tool
builds impacket's `create_empty_sd()` (Control 0x8004, owner `S-1-5-32-544`, empty DACL) and appends
one ALLOW ACE (mask `0xF01FF`) for the delegate-from SID — our bytes are identical to impacket's
`getData()` (known-bytes tests). Detection signal: an LDAP **modifyReplace of
msDS-AllowedToActOnBehalfOfOtherIdentity** on a computer object, with a value that decodes to an SD
whose DACL names the attacker SID — a clean, language-independent RBCD marker; the follow-on attack is
a Kerberos S4U2Proxy, out of this tool's scope. Lab note: Samba refuses the write over LDAP (result
19, "can only be modified as system"), so the read/parse path was validated live against an attribute
set through the system path with impacket's exact bytes, and the write bytes against impacket's
encoder; same simple-bind-over-389 divergence as the other LDAP ports.

### owneredit owner read/set (`owneredit`) — 2026-11-08

The owner-attribute sibling of dacledit, and it reuses the same `NtSecurityDescriptor` model and
SD-flags control — only the flag differs: **sdflags=0x01** (OWNER_SECURITY_INFORMATION), control value
`30 03 02 01 01`. The DC then returns/accepts an **owner-only** descriptor (Control 0x8001,
OffsetOwner=20, group/sacl/dacl offsets 0), so the write re-serializes just a 20-byte header + the new
OwnerSid. Our parse of that owner-only SD and the re-serialized write SD are byte-identical to
impacket's `getData()`, verified by a known-bytes test and live against the DC (owner changed, then
read back). Detection signal: a **modifyReplace of nTSecurityDescriptor carrying the OWNER SD-flags
control (0x01)** — distinct from dacledit's DACL control (0x04) and a clean behavioral marker for a
take-ownership step, identical on the wire whatever the runtime. Same one intentional divergence as the
other LDAP ports: a simple bind over 389 in the lab vs. ldap3's NTLM/Kerberos bind.

### dacledit DACL read/edit (`dacledit`) — 2026-11-08

Reuses the badsuccessor LDAP write path but adds two things with real on-wire signature:

- **The LDAP_SERVER_SD_FLAGS control.** Both the `read` search and the `write`/`remove` modify carry
  an LDAPMessage-level `controls [0]` holding OID `1.2.840.113556.1.4.801` with controlValue
  `30 03 02 01 04` (SEQUENCE { INTEGER 0x04 } = DACL_SECURITY_INFORMATION) and **no criticality**
  (left at DEFAULT FALSE). This is **byte-identical to ldap3's `security_descriptor_control(sdflags=0x04)`**,
  which stock dacledit uses — verified by capturing both and by a known-bytes test. The control makes
  the DC return/replace only the DACL (owner/group/sacl offsets 0), which is why our round-trip never
  has to reproduce those parts.
- **The re-serialized security descriptor.** Our `NtSecurityDescriptor.GetData()` reproduces impacket
  `ldaptypes.SR_SECURITY_DESCRIPTOR.getData()` exactly: self-relative body order Sacl, Dacl, Owner,
  Group; `NtAce.Serialize()` mirrors impacket's `ACE.getData()` including its AceSize recompute and
  4-byte alignment, and re-emits SIDs minimally (dropping any trailing pad the DC included). A real
  50-ACE DACL parses and re-serializes identically; appending a DCSync pair (two object ACEs with
  CONTROL_ACCESS mask and GUIDs `1131f6aa…`/`1131f6ad…`) produces exactly impacket's bytes.

Detection signal: a `write` is an LDAP **modifyReplace of nTSecurityDescriptor carrying the SD-flags
control** — a high-signal, runtime-independent artifact. The added ACEs themselves (e.g. the DCSync
GUID pair, or a FullControl `0x000F01FF` allow ACE for a non-admin principal) are the payload a SOC
keys on, identical on the wire whatever language emits them. One intentional divergence from impacket
is inherited from our LDAP stack and already documented above: the bind is a **simple bind over 389**
(lab), where stock dacledit uses ldap3's NTLM/Kerberos bind — the SD-flags control and the SD bytes
are identical regardless.

### checkMSSQLStatus TDS PRELOGIN (`mssql-cbt`) — 2026-11-08

First non-SMB, non-DCERPC protocol in the port: MS-TDS over TCP/1433. The example sends a single
PRELOGIN (option table + VERSION/ENCRYPTION/INSTANCE/THREADID) and reads back the server's
`ENCRYPTION` byte to judge whether TLS — and therefore channel binding / Extended Protection — can be
enforced. The PRELOGIN payload our `TdsPreLogin.Build` emits is **byte-for-byte identical to stock
impacket's `tds.TDS_PRELOGIN`** (verified against the impacket encoder as a byte-oracle and pinned by
a known-bytes test): same option offsets, the same advertised client VERSION `08 00 01 55 00 00`
(8.0.341), INSTANCE `"MSSQLServer\0"`, and the THREADID packed little-endian. A live loopback capture
dissects in Wireshark as a clean *TDS7 pre-login message*, so on the wire this looks like a legitimate
TDS client, not a minimal probe.

- **No discretionary fields.** Unlike the DCERPC paths, PRELOGIN has no NDR referent ids or pad bytes
  to choose, so there is nothing here to diverge from impacket on; the bytes are fully determined by
  the option layout. The only per-run variable is THREADID (we seed it from the process id, as
  impacket seeds it from the client PID) — not a stable fingerprint either way.
- **Deferred (documented, not a divergence):** impacket's `checkMSSQLStatus` goes on to attempt two
  full LOGIN7/SSPI logins — one offering channel-binding, one without — to observe which the server
  accepts, which is the actual CBT-enforcement verdict. We implement only the PRELOGIN
  encryption-posture leg (`ENCRYPT_REQ` ⇒ TLS forced ⇒ CBT can be enforced). The LOGIN7 leg needs the
  full TDS login record + NTLM-over-TDS SSPI token plumbing and a live SQL Server to validate; it is
  tracked for a later pass. A SOC keying on PRELOGIN alone already sees the encryption negotiation.
- **Validation ceiling:** the lab has no SQL Server, so the end-to-end posture read was exercised
  against a loopback TDS responder that answers `ENCRYPT_REQ`; our client reported it correctly.
  Capturing against a real MSSQL instance (and the Windows `sqlcmd`/.NET `SqlClient` PRELOGIN as the
  third column) is the remaining diff work.

## Signature-divergence audit (2026-11-15)

A full sweep of `src/` for places where DotNetPacket could accidentally carry an
impacket/Python fingerprint or copy a tool-specific IOC verbatim. Verdict: the
protocol *structures* stay faithful (that is the protocol), but every *tool payload*
and *runtime fingerprint* either already diverges or was made to. Summary:

| Surface | impacket / Python tell | DotNetPacket | Verdict |
| --- | --- | --- | --- |
| smbexec service binPath | `%COMSPEC% /Q /c echo … 2^>^&1 … \__output_… .bat` | `cmd.exe /c … %TEMP%\<r16>.cmd`, alphanumeric names | diverged (2026-11-12) |
| atexec task XML / command | `StartBoundary 2015-07-15T20:35:13.2757294`, `P3D`, `/C … %windir%\Temp\<r8>.tmp` | `2019-05-02T14:00:00`, `PT72H`, `cmd.exe /c … %SystemRoot%\Temp\<r12>.log` | diverged (2026-11-13) |
| **HTTP relay `Server:` banner** | **`BaseHTTP/0.6 Python/3.x`** (stdlib default — a blatant Python/impacket tell) | `Microsoft-IIS/10.0` | already realistic + divergent |
| NTLM `VERSION` block | impacket default `0.0.0` rev `0x0F` (or absent) | `10.0.19041` rev `0x0F` (a real Win10 build) | already realistic + divergent |
| SMB2 `ClientGuid` | random per run | random per run (16 bytes) | non-fixed (no shared IOC) |
| NTLM `Workstation` | tool-set or empty | the real .NET host NetBIOS name (what Windows sends) | realistic (observable by design) |
| svcctl demo service name | n/a (impacket psexec drops RemComSvc) | `DotNetPacketLab` — our *own* benign, branded, self-deleting marker | intentionally non-impacket |
| NDR referent ids / pad fill | random ids, `0xAB`/`0xBF` pad | MIDL-style `0x00020000+`, zero pad | diverged (anti-fingerprint pass) |
| hashcat/john formats (`$krb5*$`, NetNTLMv2) | format is the *consumer contract* | identical (must match hashcat) | faithful by necessity |
| GPP AES key, MS-DTYP SD/ACE/SID bytes, NDR stubs, Kerberos ASN.1 | protocol-mandated bytes | identical | faithful by necessity |

Rule of thumb applied everywhere: **a wire *structure* dictated by the protocol stays
byte-faithful; a *payload* the tool author invented (command lines, script/task templates,
hardcoded names, dates, banners) gets a fixed, documented divergence** — same behaviour,
different fingerprint. Not evasion: nothing here obfuscates, encodes, or dodges per-call;
the goal is to let a SOC prove a brittle string rule misses a reimplementation while a
behavioural rule still fires. Each divergence is pinned by a test asserting impacket's
tokens are absent and the behaviour is present.

### Kerberos (-k) SMB authentication — 2026-11-16

`-k` swaps the whole SMB auth fingerprint from NTLM to Kerberos: instead of NTLMv2 SESSION_SETUP
rounds, the wire shows AS-REQ/REP → TGS-REQ/REP (service ticket for `cifs/<host>`) → a single
SESSION_SETUP carrying SPNEGO(**MS KRB5** mechType) wrapping a GSS `[APPLICATION 0]` AP-REQ (standard
KRB5 OID, TOK_ID 0x0001). That is the durable behavioural signal — a detection keyed on NTLMSSP in
SESSION_SETUP misses a Kerberos login entirely; one keyed on "SMB SESSION_SETUP with a Kerberos
AP-REQ" catches it regardless of the client runtime. The AP-REQ authenticator carries the RFC-1964
GSS checksum (type 0x8003) with impacket's SMB flag word **minus `GSS_C_DCE_STYLE`**: with DCE_STYLE
(impacket's value, aimed at Windows) Samba returns `accept-incomplete` and demands a second SPNEGO
leg, so DotNetPacket omits it and completes in one round, which Samba answers STATUS_SUCCESS.

**Enctype divergence:** DotNetPacket's Kerberos is **RC4-HMAC**; impacket defaults to **AES256**. Both
produce a valid AP-REQ, but the ticket etype differs on the wire (a defender can see RC4 vs AES in the
AS-REP/TGS-REP). On modern Samba the RC4 session authenticates (non-guest, signed) but the PAC groups
are not applied to the token, so privileged shares/RPC return ACCESS_DENIED — Samba's RC4 hardening,
and the reason AES is the remaining parity work.

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
