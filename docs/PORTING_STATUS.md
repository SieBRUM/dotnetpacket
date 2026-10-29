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

## Protocol structures

### SMB / NetBIOS (`NetPacket.Protocols.Smb`)

- [x] `SmbHeader` (SMBv1) — impacket `smb.SMB.SMBHeader`
- [x] `NetBiosSessionHeader` — RFC 1002 (16-bit length simplification)
- [ ] SMB1 command parameter/data blocks (Negotiate, SessionSetup, TreeConnect, …)
- [ ] SMB2/3 header — impacket `smb3structs.SMB2Packet`
- [ ] SMB2/3 command structures

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
- [ ] Port of `examples/smbclient.py`
- [ ] Port of `examples/rpcdump.py`
- [ ] (others — add as prioritized by the SOC's detection needs)

## Wire-compatibility notes

Record notable differences found when diffing NetPacket vs. stock impacket
captures here (what differs, why, and whether it is detection-relevant).

- _none recorded yet_
