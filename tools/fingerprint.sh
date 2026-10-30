#!/usr/bin/env bash
#
# fingerprint.sh — extract the SMB2 / NTLMSSP fields a SOC commonly fingerprints
# on, from a capture file. Run it over captures of different clients (NetPacket,
# stock impacket, a real Windows host) and diff the outputs to see which fields
# a fingerprint-based detection is actually keying on.
#
# Usage:  tools/fingerprint.sh <capture.pcap>
#
# Requires tshark (Wireshark CLI). Capture a client with, e.g.:
#   tcpdump -i <iface> -w out.pcap 'tcp port 445'
#
set -euo pipefail

pcap="${1:?usage: fingerprint.sh <capture.pcap>}"

req='smb2.cmd==0 && smb2.flags.response==0'

echo "# Fingerprint for: $pcap"
echo
echo "## SMB2 NEGOTIATE request"
echo "SecurityMode : $(tshark -r "$pcap" -Y "$req" -T fields -e smb2.sec_mode 2>/dev/null | head -1)"
echo "Capabilities : $(tshark -r "$pcap" -Y "$req" -T fields -e smb2.capabilities 2>/dev/null | head -1)"
echo "ClientGuid   : $(tshark -r "$pcap" -Y "$req" -T fields -e smb2.client_guid 2>/dev/null | head -1)"
echo "Dialects     : $(tshark -r "$pcap" -Y "$req" -T fields -e smb2.dialect 2>/dev/null | head -1)"
echo "Ciphers      : $(tshark -r "$pcap" -Y "$req" -O smb2 2>/dev/null | grep -i 'CipherId:' | sed 's/^ *//' | paste -sd', ' -)"
echo "Contexts     : $(tshark -r "$pcap" -Y "$req" -T fields -e smb2.negotiate_context.count 2>/dev/null | head -1)"

echo
echo "## NTLMSSP"
echo "Type1 Flags  : $(tshark -r "$pcap" -Y 'ntlmssp.messagetype==1' -T fields -e ntlmssp.negotiateflags 2>/dev/null | head -1)"
echo "Type1 Version: $(tshark -r "$pcap" -Y 'ntlmssp.messagetype==1' -T fields \
    -e ntlmssp.version.major -e ntlmssp.version.minor -e ntlmssp.version.build_number \
    -e ntlmssp.version.ntlm_current_revision 2>/dev/null | head -1)"
echo "Type3 Flags  : $(tshark -r "$pcap" -Y 'ntlmssp.messagetype==3' -T fields -e ntlmssp.negotiateflags 2>/dev/null | head -1)"
echo "Type3 Version: $(tshark -r "$pcap" -Y 'ntlmssp.messagetype==3' -T fields \
    -e ntlmssp.version.major -e ntlmssp.version.minor -e ntlmssp.version.build_number 2>/dev/null | head -1)"
