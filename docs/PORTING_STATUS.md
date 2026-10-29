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
- [ ] SMB2 SESSION_SETUP request/response (carries NTLM/SPNEGO) — next realism milestone
- [ ] SMB2 TREE_CONNECT, CREATE, READ, WRITE, CLOSE
- [ ] SMB2 signing (needed once authenticated)
- [ ] SMB1 command parameter/data blocks — only if studying legacy/SMB1 traffic

### NTLM (`NetPacket.Protocols.Ntlm`)

- [x] `Ntlm` constants, `SecurityBuffer`
- [x] `NtlmNegotiate` — impacket `ntlm.NTLMAuthNegotiate`
- [ ] `NtlmChallenge` — impacket `ntlm.NTLMAuthChallenge` (same security-buffer pattern)
- [ ] `NtlmAuthenticate` — impacket `ntlm.NTLMAuthChallengeResponse`
- [ ] AV_PAIR / target-info structures
- [ ] NTLMv2 response computation

### DCERPC (`NetPacket.Protocols.Dcerpc` — not created yet)

- [ ] MSRPC header — impacket `dcerpc/v5/rpcrt.py` `MSRPCHeader`
- [ ] Bind / BindAck / Request / Response PDUs
- [ ] Transport (ncacn_np over SMB, ncacn_ip_tcp)

### Kerberos (`NetPacket.Protocols.Krb5` — not created yet)

- [ ] ASN.1 helper strategy (decide: library vs. hand-rolled) before porting
- [ ] AS-REQ / AS-REP, TGS-REQ / TGS-REP

## Examples (`NetPacket.Examples`)

- [x] `smb-header` — demo: build + hex-dump an SMBv1 header
- [x] `ntlm-negotiate` — demo: build + hex-dump an NTLMSSP NEGOTIATE
- [x] `smb2-negotiate <host> [port]` — live SMB2 NEGOTIATE, dumps both directions
- [ ] Port of `examples/smbclient.py`
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
