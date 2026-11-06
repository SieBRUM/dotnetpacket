# WINDOWS_CAPTURE.md — capturing a real Windows client for the third column

`WIRE_DIFF.md` compares **DotNetPacket vs stock impacket**. The realism target,
though, is a **real domain-joined Windows client**, which the loopback Samba lab
cannot produce. This file is the step-by-step playbook for capturing that third
column: a clean PCAP from a domain-joined Windows machine in an AD lab, covering
the protocols the ported (and still-to-be-ported) examples exercise.

Capture to a lab you are authorized to test. Treat every secret below (hashes,
keytabs, keys) as lab-only and **never commit them**.

## 0. The one insight that makes this easy

Almost every field we diff is a **client-side discretionary value in a cleartext
handshake**, not encrypted payload. You do **not** need to break encryption to
give us a useful capture:

- SMB2 **NEGOTIATE / SESSION_SETUP** are cleartext even when the session later
  encrypts → capabilities, dialects, negotiate contexts, NTLM flags + version
  block + MIC are all visible.
- **Kerberos** AS-REQ/AS-REP, TGS-REQ/TGS-REP, AP-REQ: the tickets inside are
  encrypted, but kdc-options, the etype list **and its ordering**, PA-DATA types
  and ordering, cname/sname, nonce and flags are cleartext — exactly the
  fingerprint surface for the Kerberos example family.
- **DCERPC** BIND / BIND_ACK / AUTH3 and the NTLMSSP Type 1/2/3 tokens are
  cleartext even when the stubs are sealed → auth level, context negotiation,
  pad bytes and referent ids on unsealed calls.

So a plain capture already fills most of the third column. Decryption (section 5)
is optional and only needed to verify *result parsing*.

## 1. Prepare the Windows client (once)

Run elevated PowerShell on the client. These stop the NIC from mangling the
capture and clear caches so each exchange is captured from its real start.

```powershell
# 1a. Disable offloads on the capture NIC (replace -Name with your adapter).
#     Offloads produce oversized/garbled segments and bad checksums in captures.
Get-NetAdapter
Disable-NetAdapterLso  -Name "Ethernet"
Disable-NetAdapterRsc  -Name "Ethernet"
# Checksum / large-send offload (if the above left any on):
Set-NetAdapterAdvancedProperty -Name "Ethernet" -DisplayName "*Offload*" -DisplayValue "Disabled" -ErrorAction SilentlyContinue

# 1b. Record environment metadata (save the output alongside the PCAP).
winver                      # note the exact build
ipconfig /all               # client IP, DNS, domain
klist                       # current tickets
whoami /user                # account name + SID
```

Re-enable the offloads when you are done (`Enable-NetAdapterLso` / `...Rsc`).

## 2. Pick a capture tool

Any of these works; all produce pcap/pcapng Wireshark can read.

- **Wireshark + Npcap** (install Npcap in "WinPcap API-compatible" mode). Best for
  interactive, labelled captures.
- **`pktmon`** (built in, no install):
  ```cmd
  pktmon start --capture --pkt-size 0 --file-name cap.etl
  pktmon stop
  pktmon etl2pcap cap.etl --out cap.pcapng
  ```
- **`dumpcap`** (ships with Wireshark), good for scripted/ring-buffer captures:
  ```cmd
  dumpcap -i <N> -s 0 -b filesize:102400 -w scenario.pcapng
  ```

Always use **full snaplen** (`-s 0` / `--pkt-size 0`). Never truncate — we need
full payloads.

## 3. Capture discipline

1. **Capture on the client NIC facing the DC.** The client is what we imitate.
2. **One scenario per file**, named for the scenario (`smb.pcapng`,
   `kerberos-ldap.pcapng`, `rpc-wmi.pcapng`). Small, labelled captures beat one
   huge file.
3. **Start the capture before the action, from a cold state**, so each TCP
   connection's handshake is in the file:
   ```cmd
   klist purge            :: fresh AS-REQ / TGS-REQ next time
   ```
   and restart the tool / open a new connection so you get a fresh SMB NEGOTIATE,
   LDAP bind, or RPC BIND rather than a reused one.
4. **No capture-side drops**: use a ring buffer, watch the dropped-packet counter,
   capture to local disk with room to spare.
5. **Keep a short index**: for each file, jot `tool + version`, the exact command,
   the timestamp, and (if one file holds several) the frame ranges per scenario.

## 4. Scenarios to run (these cover the whole example roadmap)

Run these as the normal/admin flows a real client produces. The right column is
the DotNetPacket example(s) each one gives a third column for.

| Scenario (run on the Windows client) | Protocol captured | Feeds example(s) |
| --- | --- | --- |
| Boot, log a user in, `gpupdate /force` | Kerberos AS/TGS, LDAP bind, SMB3 to SYSVOL, DNS | `machine_role`, GPP/LAPS SYSVOL path, baseline |
| `Get-ADUser -Filter *`, `Get-ADComputer -Filter *` (RSAT) | LDAP search: real filters, attributes, **paged control 1.2.840.113556.1.4.319** | `get-adusers`, `get-adcomputers`, `samrdump` |
| `net user /domain`, `net group /domain` | LDAP + SAMR | `samrdump`, `rpc-enum*` |
| **`ldp.exe`**: connect → bind → search | LDAP **sign/seal or LDAPS bind** (the bind Samba refuses) | all LDAP examples' bind path |
| `klist get <spn>` or access a service by SPN | **TGS-REQ / TGS-REP** | `GetUserSPNs` (kerberoast) |
| Log on an account flagged "do not require preauth" | **AS-REP** without preauth | `GetNPUsers` (AS-REP roast) |
| `sc.exe \\host query` | svcctl (DCERPC) | `services`, `psexec`, `smbexec` |
| `reg query \\host\HKLM\SOFTWARE\...` | winreg (MS-RRP) | `reg`, `registry-read` (fills the reg buffer-size "pending" items) |
| `schtasks /query /s host` | atsvc (DCERPC) | `atexec` |
| `Get-WmiObject -ComputerName host Win32_OperatingSystem` | DCOM / WMI | `wmiexec`, `wmiquery`, `dcomexec` |
| Sysinternals **PsExec** to a host | svcctl CreateService + SMB3 | `psexec`, `smbexec` |
| SSMS / `sqlcmd` to a lab SQL Server (if present) | TDS pre-login + auth | `checkMSSQLStatus`, `mssqlclient` |
| Read a LAPS password via the LAPS PowerShell module (if configured) | `msLAPS-EncryptedPassword` + **DPAPI-NG / MS-GKDI GetKey RPC** | `get-laps` (the deferred v2 decrypt) |

If you only have time for three: **boot+`gpupdate`**, **RSAT `Get-ADUser`/`Get-ADComputer`**,
and **`ldp.exe`**. Those alone fill most of the pending column and de-risk the
Kerberos + LDAP examples coming next.

## 5. (Optional) unlock encrypted payloads

Only needed to verify result *parsing*; skip for pure fingerprinting. Collect for
the **lab** account and keep them out of the repo:

- The account's **NT hash and/or AES keys**, or a **keytab** → Wireshark decrypts
  Kerberos, SMB3, and NTLM-sealed DCERPC (Edit → Preferences → Protocols → KRB5 /
  SMB2, and the NTLMSSP secret).
- A run **forced to RC4** for that account makes NT-hash decryption trivial — but
  **also** do a normal (AES default) run so we still see the real default etype
  ordering (that ordering is itself a fingerprint).
- Native-Windows LDAPS (schannel) ignores `SSLKEYLOGFILE`, so LDAPS stays opaque
  without keys. Prefer capturing **LDAP + Kerberos sign/seal** and supplying the
  Kerberos key, or rely on the cleartext GSS-SPNEGO tokens for the fingerprint.

## 6. Hand-off checklist

For each capture, provide:

- [ ] The `.pcapng` (full snaplen, offloads were disabled, 0 drops).
- [ ] `winver` build, and the tool + version used.
- [ ] The exact command(s) and timestamps; frame-range index if multiple scenarios.
- [ ] `ipconfig /all`, `klist`, account name/SID, domain FQDN.
- [ ] (Optional) the decryption secrets from section 5, delivered **out of band**,
      never committed.

Once a capture lands, add its findings as the third column in `WIRE_DIFF.md` and
resolve the matching entries under **"Pending a Windows capture"**.
