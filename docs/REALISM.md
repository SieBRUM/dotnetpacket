# Realism doctrine

The research goal of DotNetPacket is to emit traffic that looks like a **legitimate,
modern Windows / .NET client** performing the same operation — *not* like impacket,
and *not* like a minimal protocol demo. Detections built against realistic traffic
generalize; detections built against tool quirks are brittle (that brittleness is
the exact problem this project exists to study).

Treat this as a hard requirement when porting anything that goes on the wire.

## Principles

1. **Speak the dialects a real client speaks.**
   Modern Windows does not use SMB1 — SMB1 traffic is itself an anomaly on a
   current network. Prefer SMB2/3. When offering SMB 3.1.1, send the negotiate
   contexts a real client sends (see below); offering 3.1.1 *without* contexts is
   a tell.

2. **Populate client fields the way Windows does, not with library defaults.**
   impacket and other tools ship recognizable constant values (client GUIDs,
   capability flags, workstation names). Fill these to match a real client:
   - **ClientGuid**: real clients use a *stable per-machine* GUID. DotNetPacket
     defaults to a random 16 bytes per connection, which is fine for isolated
     lab runs but is itself a (weak) signal. For sustained realism, set a stable
     GUID per simulated host and reuse it.
   - **Capabilities / SecurityMode**: use the set a real Windows workstation
     advertises (DFS, LEASING, LARGE_MTU, MULTI_CHANNEL, DIRECTORY_LEASING,
     ENCRYPTION; signing enabled). Don't invent combinations.
   - **Names / domains**: use plausible lab hostnames and casing, not `WORKGROUP`
     placeholders or tool defaults, unless that is what you are testing.

3. **Order and sizes match the spec exactly.**
   Field order, structure sizes (including SMB2's "+1" `StructureSize` quirk),
   padding, and 8-byte alignment of negotiate contexts must match MS-SMB2. A
   capture that is one pad byte off is a fingerprint.

4. **Sequence and pacing look like a session, not a script.**
   MessageId increments, credit request/charge values, and the request/response
   cadence should resemble a real client's. Avoid firing structurally valid but
   behaviorally odd sequences unless that is the thing under study.

5. **No evasion.** Realism here means *indistinguishable from a normal client*,
   never *engineered to defeat a sensor*. If a change's purpose is to dodge
   detection rather than to faithfully mimic a legitimate client, it does not
   belong here (see `CLAUDE.md`).

## SMB 3.1.1 negotiate contexts — the realistic set

A current Windows 10/11 client sends these negotiate contexts on the SMB2
NEGOTIATE request (MS-SMB2 2.2.3.1), 8-byte aligned, in roughly this order:

| Context | Type | Notes | In DotNetPacket |
| --- | --- | --- | --- |
| Preauth Integrity Capabilities | 0x0001 | SHA-512, 32-byte random salt | **implemented** |
| Encryption Capabilities | 0x0002 | AES-128-GCM, AES-128-CCM (Win11 adds AES-256) | **implemented** |
| Compression Capabilities | 0x0003 | LZ77, LZ77+Huffman, pattern-v1 | TODO |
| Netname Negotiate Context Id | 0x0005 | the server name the client dialed, as UTF-16LE | TODO |
| Signing Capabilities | 0x0008 | AES-128-GMAC, AES-128-CMAC | TODO |

`Smb2NegotiateRequest` sends Preauth + Encryption today. Adding the remaining
three (tracked in `PORTING_STATUS.md`) closes the gap to a real Win10/11 client —
do it before using the negotiate as a realism baseline for research.

## Authentication & signing realism

- NTLMv2 inside SPNEGO is implemented with a Windows-like flag set, a version
  block, the server's echoed target info, a message MIC, and the SPNEGO
  mechListMIC. SMB 3.1.1 message signing (preauth integrity + SP800-108 KDF +
  AES-CMAC) is implemented and validated against a signing-mandatory server.
- Remaining auth realism gaps (each a potential discriminator): NTLM
  `NEGOTIATE_KEY_EXCH` + RC4-sealed GSS signing is not done (dropped to keep the
  mechListMIC deterministic); the AUTHENTICATE target info omits Windows'
  `MsvAvChannelBindings` / `MsvAvTargetName` pairs; and Kerberos is not offered
  (a domain-joined Windows client prefers Kerberos over NTLM — NTLM-only is itself
  a signal in an AD environment).

## How to check realism

For any ported exchange, capture it and compare against a real client:

```bash
# capture the lab exchange
tcpdump -i any -w capture.pcap 'tcp port 445'

# inspect what actually went on the wire
tshark -r capture.pcap -O smb2
```

Then diff against a capture of a genuine Windows client doing the same thing.
Record differences (and whether they are detection-relevant) in the
"Wire-compatibility notes" section of `PORTING_STATUS.md`. Those diffs are the
research output.
