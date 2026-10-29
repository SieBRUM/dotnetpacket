# Porting status

Tracker for the impacket → NetPacket port. Tick items as they land, add rows as
you discover more. Keep it honest: "done" means ported **and** tested.

Legend: `[x]` done · `[~]` in progress · `[ ]` not started

## Foundation (`NetPacket.Core`)

- [x] `ByteOrder`
- [x] `ByteReader` / `ByteWriter` (ints, blobs, ASCIIZ/UnicodeZ, seekable)
- [x] `FieldKind`, `FieldAttribute`
- [x] `NetStructure` (declarative + manual-override)
- [x] `Hex` dump helper
- [ ] Bit-field support (impacket `'B=...'` bit packing) — add when first needed
- [ ] NDR primitives for DCERPC (alignment, referents) — large; design before porting

## Transport (`NetPacket.Transport`)

- [x] `DirectTcpTransport` — SMB Direct TCP / NetBIOS 4-byte message framing
- [ ] Async variants / cancellation (add if a scenario needs it)

## Protocol structures

### SMB / NetBIOS (`NetPacket.Protocols.Smb`)

- [x] `Smb2Header` (SMB2/3, 64-byte) — impacket `smb3structs.SMB2Packet`
- [x] `Smb2NegotiateRequest` (+ 3.1.1 preauth & encryption contexts) — realistic Win10/11 defaults
- [x] `Smb2NegotiateResponse` (parse: dialect, caps, SPNEGO buffer)
- [x] `Smb2Client.Negotiate` — live NEGOTIATE over `DirectTcpTransport`
- [x] `SmbHeader` (SMBv1, legacy) — impacket `smb.SMB.SMBHeader`
- [x] `NetBiosSessionHeader` — RFC 1002 (16-bit length simplification)
- [ ] SMB 3.1.1 negotiate contexts: compression, netname, signing (see REALISM.md) — close the gap to a real client
- [x] SMB2 SESSION_SETUP request/response + two-round NTLMv2 login (`Smb2Client.Login`)
- [x] SMB2 signing — 3.1.1 preauth integrity + SP800-108 KDF + AES-CMAC (`Smb2Crypto`)
- [x] SMB2 TREE_CONNECT / TREE_DISCONNECT, signed (`Smb2Client.TreeConnect`)
- [x] Comprehensive flag/enum coverage (`Smb2Flags.cs`, `Smb2CreateConstants.cs`:
      header/session/share flags, access mask, create disposition/options, file attributes)
- [x] SMB2 CREATE / READ / CLOSE (+ `Smb2Client.ReadFile`), signed
- [x] SMB2 WRITE (`Smb2Client.Write`), signed
- [x] SMB2 IOCTL + FSCTL_PIPE_TRANSCEIVE (`Smb2Client.Ioctl`), signed; async STATUS_PENDING handled
- [ ] SMB2 QUERY_DIRECTORY, QUERY_INFO
- [ ] CREATE contexts (DHnQ / MxAc / QFid) — Windows sends them (realism gap)
- [ ] SMB 2.x / 3.0.x signing variants (HMAC-SHA256 / 3.0 KDF) — only 3.1.1 implemented
- [ ] SMB1 command parameter/data blocks — only if studying legacy/SMB1 traffic

### NTLM (`NetPacket.Protocols.Ntlm`)

- [x] `Ntlm` constants, `SecurityBuffer`, `NtlmNegotiateFlags`, `NtlmAvId`
- [x] `NtlmNegotiate` (reference structure) — impacket `ntlm.NTLMAuthNegotiate`
- [x] `NtlmChallenge` parser (Type 2) — impacket `ntlm.NTLMAuthChallenge`
- [x] `AvPairs` — target-info AV_PAIR list parse/rebuild
- [x] `NtlmCrypto` — MD4, HMAC-MD5, RC4, NTOWFv2, NTLMv2 response, GSS signing (KATs + MS-NLMP vector)
- [x] `NtlmClient` — Type 1/Type 3 with Windows-like flags, version, NTLMv2, MIC
- [x] `Spnego` — GSS/SPNEGO NegTokenInit/NegTokenResp + mechListMIC (System.Formats.Asn1)
- [ ] NEGOTIATE_KEY_EXCH + sealed GSS signing (realism gap — see REALISM.md / notes below)
- [ ] NTLM signing/sealing of subsequent SMB2 messages

### DCERPC (`NetPacket.Protocols.Dcerpc`)

- [x] `DcerpcHeader` (16-byte common PDU header) — impacket `rpcrt.MSRPCHeader`
- [x] `DcerpcBind` / `DcerpcBindAck` (PDU types, presentation context, result)
- [x] ncacn_np transport (`DcerpcPipe`): open pipe on IPC$, FSCTL_PIPE_TRANSCEIVE
- [x] Well-known interfaces: srvsvc, wkssvc, lsarpc, samr, svcctl
- [x] REQUEST / RESPONSE / FAULT PDUs (`DcerpcRequest` / `DcerpcResponse`, `DcerpcPipe.Call`)
- [x] NDR encode/decode basics (`NdrWriter` / `NdrReader`): alignment, unique
      referents, conformant-varying strings
- [x] srvsvc `NetrShareEnum` level 1 (share enumeration) — `Srvsvc.NetrShareEnum`
- [x] NDR context handles (20-byte) + top-level [ref]/[unique] strings (`NdrWriter`/`NdrReader`)
- [x] svcctl (`Svcctl`): OpenSCManagerW, OpenServiceW, CreateServiceW, StartServiceW,
      DeleteService, CloseServiceHandle — the psexec service-control surface
- [x] Level-union → struct → deferred unique-string-pointer NDR (host-info parsers)
- [x] wkssvc `NetrWkstaGetInfo` (level 100) + srvsvc `NetrServerGetInfo` (level 101) — host/OS recon
- [x] NDR `RPC_UNICODE_STRING`, `RPC_SID`, enum-switched union (lsarpc parser)
- [x] lsarpc `LsarOpenPolicy2` + `LsarQueryInformationPolicy` (account domain + SID) — `Lsarpc`
- [x] NDR conformant arrays of structs (SID array in; referenced-domains + translated-names out)
- [x] lsat `LsarLookupSids` (SID -> domain\name, the lookupsid behavior) — `Lsat`
- [x] samr enumeration (`Samr`): Connect, EnumerateDomains, LookupDomain, OpenDomain,
      EnumerateUsersInDomain, CloseHandle — the samrdump / enumdomusers behavior
- [ ] Fuller NDR: [v1_enum], multi-level pointers, lsat LsarLookupNames (name -> SID)
- [ ] More calls: samr group/alias enum, SamrQueryInformationUser
- [ ] DCERPC auth (sign/seal via NTLMSSP) for authenticated-RPC realism
- [ ] ncacn_ip_tcp transport (DCERPC directly over TCP/135 + dynamic ports)

### Kerberos (`NetPacket.Protocols.Krb5` — not created yet)

- [ ] ASN.1 helper strategy (decide: library vs. hand-rolled) before porting
- [ ] AS-REQ / AS-REP, TGS-REQ / TGS-REP

## Examples (`NetPacket.Examples`)

- [x] `smb-header` — demo: build + hex-dump an SMBv1 header
- [x] `ntlm-negotiate` — demo: build + hex-dump an NTLMSSP NEGOTIATE
- [x] `smb2-negotiate <host> [port]` — live SMB2 NEGOTIATE, dumps both directions
- [x] `smb2-login <host> <user> <password> [domain] [port]` — live NTLMv2 SESSION_SETUP
- [x] `smb2-connect <host> <share> <user> <password> [domain] [port]` — signed TREE_CONNECT
- [x] `smb2-cat <host> <share> <path> <user> <password> [domain] [port]` — read a file (CREATE/READ/CLOSE)
- [x] `dcerpc-bind <host> <user> <password> [interface] [domain] [port]` — DCERPC bind over IPC$
- [x] `rpc-shares <host> <user> <password> [domain] [port]` — srvsvc NetrShareEnum (share recon)
- [x] `rpc-svcctl <host> <user> <password> [domain] [port]` — svcctl service-control (psexec signature, lab/benign)
- [x] `rpc-hostinfo <host> <user> <password> [domain] [port]` — wkssvc/srvsvc host & OS recon
- [x] `rpc-lsa <host> <user> <password> [domain] [port]` — lsarpc account domain + SID
- [x] `rpc-lookupsid <host> <user> <password> [domain] [port]` — lsat SID->name (lookupsid)
- [x] `rpc-enumusers <host> <user> <password> [domain] [port]` — samr domain user enumeration
- [ ] Port of `examples/smbclient.py`
- [ ] Port of `examples/rpcdump.py`
- [ ] Port of `examples/rpcdump.py`
- [ ] (others — add as prioritized by the SOC's detection needs)

## Wire-compatibility notes

Record notable differences found when diffing NetPacket vs. stock impacket
captures here (what differs, why, and whether it is detection-relevant).

- **2026-10-29 — SMB2 NEGOTIATE validated against Samba 4.19 (SMB2-only).**
  `smb2-negotiate` negotiated SMB 3.1.1 successfully. Wireshark/tshark (`-O smb2`)
  dissects the request as a clean `Negotiate Protocol Request` with no malformed
  fields: StructureSize 0x24, 5 dialects (2.0.2–3.1.1), SecurityMode signing
  enabled, Capabilities 0x6f fully decoded, and both negotiate contexts parsed
  (Preauth Integrity SHA-512 + 32-byte salt; Encryption AES-128-GCM/CCM). tshark
  computes the Preauth Hash, confirming byte-perfect layout.
  - _Realism gaps vs. a real Win10/11 client:_ (1) only 2 of ~5 negotiate
    contexts sent — missing compression, netname, signing; (2) ClientGuid is
    random per connection rather than a stable machine GUID; (3) CreditCharge /
    CreditRequest are 0 on NEGOTIATE — confirm against a real client capture.
    None are malformed, but each is a potential discriminator worth closing or
    studying.
- **2026-10-29 — NTLMv2 SMB2 SESSION_SETUP validated against Samba 4.19.**
  `smb2-login` completes the two-round handshake and the server returns
  STATUS_SUCCESS / SPNEGO `negResult: accept-completed`; a wrong password returns
  STATUS_LOGON_FAILURE, confirming real credential validation. tshark dissects
  the exchange as a normal NTLMSSP NEGOTIATE/CHALLENGE/AUTHENTICATE with the
  client mechListMIC accepted.
  - _Realism gaps vs. a real Win10/11 client:_ (1) NEGOTIATE_KEY_EXCH is not set
    and GSS signing is unsealed — a real client sets key exchange and RC4-seals
    the signature; dropping it keeps the mechListMIC deterministic but is a
    discriminator. (2) The AUTHENTICATE target info does not add the
    MsvAvChannelBindings / MsvAvTargetName pairs Windows includes. (3) NTLM
    negotiate flags are a fixed set — confirm against a real client capture.
- **2026-10-29 — Signed SMB2 TREE_CONNECT validated against Samba (signing
  mandatory).** With `server signing = mandatory`, `smb2-connect` reaches
  `\\host\public`: SMB 3.1.1 preauth-integrity hash + SP800-108 KDF
  (`"SMBSigningKey\0"` + 0x00 separator — the double-NUL form) + AES-CMAC produce
  a signature Samba accepts (STATUS_SUCCESS), and the client verifies the
  server's signed responses (ServerSig OK). A wrong key is rejected with
  STATUS_ACCESS_DENIED ("Bad SMB2 signature" in the server log). tshark shows
  the Tree Connect as a normal signed SMB2 PDU.
  - _Implementation note:_ only the SMB 3.1.1 signing path is implemented
    (AES-CMAC). SMB 2.x (HMAC-SHA256) and 3.0.x (different KDF label/context)
    are not yet covered.
- **2026-10-29 — Signed file read (CREATE/READ/CLOSE) validated against Samba.**
  `smb2-cat` reads `\\host\public\readme.txt` end to end: signed CREATE opens the
  file (FileId + EndOfFile returned), signed READ returns the 59 bytes, signed
  CLOSE succeeds — all STATUS_SUCCESS, content byte-exact. tshark shows normal
  signed Create/Read/Close PDUs (Filename, FileId, Read Length all correct).
  - _Realism gap:_ CREATE sends no create contexts; Windows sends DHnQ (durable
    handle), MxAc (maximal access query), and QFid. Adding them is the next step
    toward a Windows-identical open.
- **2026-10-29 — DCERPC BIND over SMB named pipe validated against Samba.**
  `dcerpc-bind` connects IPC$, opens the pipe (CREATE), and binds via
  FSCTL_PIPE_TRANSCEIVE (IOCTL). srvsvc/wkssvc/lsarpc/svcctl all return BIND_ACK
  with result = acceptance; tshark dissects a clean Bind (abstract syntax +
  NDR v2 transfer syntax) and Bind_ack. The server answers the transceive with an
  async STATUS_PENDING interim first, which the client skips before reading the
  real reply. This is the transport every impacket DCE/RPC example sits on; a
  real call still needs the NDR layer + REQUEST/RESPONSE PDUs.
- **2026-10-29 — srvsvc NetrShareEnum (share recon) validated against Samba.**
  `rpc-shares` binds srvsvc and calls NetrShareEnum (opnum 15, level 1) with an
  NDR REQUEST stub, parses the NDR RESPONSE, and lists the real shares: `public`
  (DiskTree) and `IPC$` (Ipc, special, remark "IPC Service (NetPacket Lab)").
  tshark dissects it as `Operation: NetShareEnumAll (15)`, Level 1, TotalEntries 2.
  This is the first end-to-end impacket-style RPC call. NDR coverage is still
  minimal (referents + conformant-varying strings); richer calls need structs,
  scalar arrays, and non-string pointers.
- **2026-10-29 — svcctl service-control (psexec signature) exercised against Samba.**
  `rpc-svcctl` binds svcctl, opens the SCM (ALL_ACCESS -> ERROR_ACCESS_DENIED for a
  non-admin user; CONNECT -> ERROR_SUCCESS, a valid 20-byte context handle), then
  issues a benign CreateServiceW (cmd.exe echoing a lab marker) and closes the
  handle. tshark shows OpenSCManagerW / CreateServiceW / CloseServiceHandle with
  the service name + binary path intact. Context-handle in/out is validated by the
  SCM open+close round-trip.
  - _Behavioral artifact:_ Samba answers CreateServiceW (opnum 12) with DCERPC
    fault `nca_op_rng_error` (0x1c010002) — it does not implement remote service
    creation. impacket hits the same wall, confirming our stub is well-formed; the
    request-side signature matches a real psexec create. Against real Windows the
    call would instead proceed or return ERROR_ACCESS_DENIED — a server-type
    discriminator worth recording.
  - _Scope:_ lab/benign only. The example never leaves a service behind (it deletes
    on the success path, which Samba never reaches).
- **2026-10-29 — Host/OS recon (wkssvc + srvsvc GetInfo) validated against Samba.**
  `rpc-hostinfo` reads wkssvc NetrWkstaGetInfo(100) -> ComputerName LABSRV,
  Domain WORKGROUP, OS 6.1 (platform 500), and srvsvc NetrServerGetInfo(101) ->
  Name LABSRV, type 0x00809a03, comment "NetPacket Lab" — all matching the lab
  server config. Exercises the level-union -> struct -> deferred unique-string NDR
  decode path. (Samba reports itself as OS 6.1; real Windows reports its true
  build — an OS-version recon signal the SOC can diff.)
- **2026-10-29 — lsarpc account-domain + SID recon validated against Samba.**
  `rpc-lsa` does LsarOpenPolicy2 (MAXIMUM_ALLOWED) then LsarQueryInformationPolicy
  (opnum 7, PolicyAccountDomainInformation) -> domain LABSRV, SID
  S-1-5-21-2786383041-2443124272-643774106. Exercises RPC_UNICODE_STRING, RPC_SID
  (conformant), and a 4-byte-tag union. The byte layout was taken from an impacket
  capture and is pinned by a known-bytes test. Note: Samba implements opnum 7
  (QueryInformationPolicy) but not opnum 46 (QueryInformationPolicy2) — impacket's
  Policy2 call faults here, so we use opnum 7.
- **2026-10-29 — lsat LsarLookupSids (SID->name) validated against Samba.**
  `rpc-lookupsid` resolves well-known SIDs and account-domain RIDs:
  S-1-5-32-544 -> BUILTIN\Administrators (Alias), S-1-5-32-545 -> BUILTIN\Users,
  S-1-1-0 -> Everyone, S-1-5-18 -> NT Authority\SYSTEM, <domainSid>-501 ->
  LABSRV\nobody, -513 -> LABSRV\None; 500/512 come back unresolved on this
  standalone server. Exercises array-of-structs NDR both ways (input SID array;
  output referenced-domain list + translated-names array with enum16 Use + pad).
  Byte layout taken from an impacket capture; parser covered by a synthetic
  round-trip test and the live run.
- **2026-10-29 — samr domain user enumeration validated against Samba.**
  `rpc-enumusers` runs the full chain: SamrConnect -> EnumerateDomainsInSamServer
  (LABSRV, Builtin) -> LookupDomainInSamServer(LABSRV) -> domain SID
  S-1-5-21-2786383041-2443124272-643774106 -> OpenDomain -> EnumerateUsersInDomain
  -> RID 1000 labuser. Threads server/domain context handles through five calls and
  re-marshals the looked-up SID into OpenDomain. The two enumerate calls share one
  SAMPR_RID_ENUMERATION parser; covered by a synthetic round-trip test and the live run.