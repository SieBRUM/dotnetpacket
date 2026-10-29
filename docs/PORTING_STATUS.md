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
- [ ] NDR type system (alignment, pointers/referents, conformant arrays, strings)
- [ ] REQUEST / RESPONSE PDUs + a first real call (e.g. srvsvc NetrShareEnum)
- [ ] DCERPC auth (sign/seal via NTLMSSP / gss) for authenticated-RPC realism
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
- [ ] Port of `examples/smbclient.py`
- [ ] Port of `examples/rpcdump.py` / srvsvc share enumeration (needs NDR + REQUEST/RESPONSE)
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
