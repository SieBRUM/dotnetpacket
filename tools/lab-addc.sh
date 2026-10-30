#!/usr/bin/env bash
#
# lab-addc.sh — stand up a throwaway Samba Active Directory Domain Controller
# for validating DotNetPacket against a richer RPC surface than a standalone
# file server offers: an endpoint mapper on TCP/135 (ept_map / ncacn_ip_tcp),
# dynamic-port services, admin-only calls, and a real AD password policy.
#
# LAB USE ONLY. This provisions an ephemeral DC bound to loopback. The admin
# password below is a throwaway sample for a disposable lab, not a secret —
# override it with ADDC_ADMINPASS. Do not point DotNetPacket at anything you
# are not authorized to test (see CLAUDE.md, "Scope and intended use").
#
# Usage:
#   tools/lab-addc.sh up        # provision (if needed) and start the DC
#   tools/lab-addc.sh down      # stop the DC daemon
#   tools/lab-addc.sh status    # show daemon + listening ports
#   tools/lab-addc.sh destroy   # stop and delete the provisioned directory
#
# Configurable via environment:
#   ADDC_REALM      (default LAB.LOCAL)
#   ADDC_DOMAIN     (default LAB)
#   ADDC_ADMINPASS  (default LabAdm1n!Pass — throwaway lab credential)
#   ADDC_TARGETDIR  (default /tmp/samba-ad)
#   ADDC_IP         (default 127.0.0.1 — the interface the DC binds to)
#
set -euo pipefail

REALM="${ADDC_REALM:-LAB.LOCAL}"
DOMAIN="${ADDC_DOMAIN:-LAB}"
ADMINPASS="${ADDC_ADMINPASS:-LabAdm1n!Pass}"
TARGETDIR="${ADDC_TARGETDIR:-/tmp/samba-ad}"
BIND_IP="${ADDC_IP:-127.0.0.1}"
SMBCONF="$TARGETDIR/etc/smb.conf"

log() { printf '[lab-addc] %s\n' "$*" >&2; }
die() { printf '[lab-addc] ERROR: %s\n' "$*" >&2; exit 1; }

# samba-tool's Python extensions (ldb/samba) are built for one specific CPython
# minor version, which may not be the default `python3`. Find the interpreter
# whose version matches the compiled ldb module and use it to run samba-tool.
find_samba_python() {
    local so ver py
    so=$(ls /usr/lib/python3/dist-packages/ldb.cpython-3*-*.so 2>/dev/null | head -1) \
        || die "python3-samba/ldb not installed (apt-get install samba samba-ad-provision python3-samba)"
    ver=$(basename "$so" | sed -E 's/.*cpython-3([0-9]+)-.*/3.\1/')   # e.g. cpython-312 -> 3.12
    py="python${ver}"
    command -v "$py" >/dev/null 2>&1 || py="python3"
    "$py" -c 'import ldb, samba' 2>/dev/null || die "no Python interpreter can import the samba modules (tried $py)"
    echo "$py"
}

ensure_winbind() {
    # An AD DC runs winbindd as an internal service; if the binary is absent the
    # whole daemon aborts on start. Install it if we can.
    if [[ ! -x /usr/sbin/winbindd ]]; then
        log "winbindd missing — installing the winbind package"
        apt-get install -y winbind >/dev/null 2>&1 || die "could not install winbind (needs apt + network)"
    fi
}

stop_standalone_smbd() {
    # A standalone file-server smbd would hold port 445; the AD DC runs its own.
    if pgrep -f 'smbd -D' >/dev/null 2>&1 && ! pgrep -x samba >/dev/null 2>&1; then
        log "stopping standalone smbd to free port 445"
        pkill -f 'smbd -D' || true
        sleep 2
    fi
}

provision() {
    [[ -f "$SMBCONF" ]] && { log "already provisioned at $TARGETDIR"; return; }
    local py; py=$(find_samba_python)
    log "provisioning AD DC: realm=$REALM domain=$DOMAIN -> $TARGETDIR (using $py)"
    rm -rf "$TARGETDIR"
    "$py" /usr/bin/samba-tool domain provision \
        --realm="$REALM" --domain="$DOMAIN" --server-role=dc \
        --dns-backend=SAMBA_INTERNAL --adminpass="$ADMINPASS" \
        --targetdir="$TARGETDIR" >/dev/null \
        || die "provision failed"

    # Bind to the chosen (IPv4) interface only; the default tries to bind IPv6
    # too, which fails in containers without IPv6 and aborts startup.
    if ! grep -q 'bind interfaces only' "$SMBCONF"; then
        "$py" - "$SMBCONF" "$BIND_IP" <<'PY'
import sys
path, ip = sys.argv[1], sys.argv[2]
s = open(path).read()
s = s.replace("[global]", f"[global]\n\tinterfaces = {ip}\n\tbind interfaces only = yes", 1)
open(path, "w").write(s)
PY
        log "patched $SMBCONF to bind $BIND_IP only"
    fi
}

start() {
    if pgrep -x samba >/dev/null 2>&1; then
        log "AD DC already running"; return
    fi
    ensure_winbind
    stop_standalone_smbd
    provision
    log "starting samba AD DC daemon"
    /usr/sbin/samba -s "$SMBCONF" || die "samba daemon failed to start"

    # Wait for the endpoint mapper + SMB to come up.
    for _ in $(seq 1 20); do
        if (echo >"/dev/tcp/$BIND_IP/135") 2>/dev/null && (echo >"/dev/tcp/$BIND_IP/445") 2>/dev/null; then
            break
        fi
        sleep 1
    done
    status
    cat >&2 <<EOF
[lab-addc] ready. Connect DotNetPacket examples with:
    host=$BIND_IP  user=Administrator  password=$ADMINPASS  domain=$DOMAIN
  e.g.  dotnet run --project src/DotNetPacket.Examples -- rpc-epm-map $BIND_IP samr
        dotnet run --project src/DotNetPacket.Examples -- rpc-dump-tcp $BIND_IP
        dotnet run --project src/DotNetPacket.Examples -- rpc-passpol $BIND_IP Administrator '$ADMINPASS' $DOMAIN
EOF
}

stop() {
    if pgrep -x samba >/dev/null 2>&1; then
        log "stopping samba AD DC daemon"
        pkill -x samba || true
        sleep 2
    else
        log "AD DC not running"
    fi
}

status() {
    if pgrep -x samba >/dev/null 2>&1; then
        log "samba AD DC: RUNNING (pid $(pgrep -x samba | head -1))"
    else
        log "samba AD DC: stopped"
    fi
    local open=()
    for p in 135 445 389 88 464; do
        (echo >"/dev/tcp/$BIND_IP/$p") 2>/dev/null && open+=("$p")
    done
    log "listening on $BIND_IP: ${open[*]:-none}"
}

destroy() {
    stop
    log "removing $TARGETDIR"
    rm -rf "$TARGETDIR"
}

case "${1:-up}" in
    up|start) start ;;
    down|stop) stop ;;
    status) status ;;
    destroy) destroy ;;
    *) die "usage: $0 {up|down|status|destroy}" ;;
esac
