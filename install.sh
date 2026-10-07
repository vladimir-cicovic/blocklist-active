#!/bin/bash
# blocklist-active - installs nftables blocks (geo + attackers + proxy/Tor)
# with automatic refresh, verification before apply and rollback.
#
# Runs ON THE TARGET MACHINE as root. From a workstation use
# deploy/deploy.sh, deploy/Deploy-Blocklist.ps1 or ansible/site.yml.
#
#   ./install.sh --config blocklist.conf [options]
#
# Options:
#   --config FILE       configuration (required the first time; see blocklist.conf.example)
#   --force-config      overwrite an existing /etc/blocklist.conf
#   --hold-ip IP        address that passes every block during the installation
#                       (repeatable; defaults to the address of the SSH session)
#   --hold SECONDS      how long that address still passes AFTER the installation (30)
#   --rollback SECONDS  timer that disables the blocks unless confirmed (600)
#   --no-rollback       no safety net
#   --trust-hold-ip     add the --hold-ip addresses permanently to OWNER_IPS
#   --no-bootstrap      do not download lists now (existing ones are used, if any)
#   --no-packages       do not install packages
#   --no-backup         no daily configuration snapshot
#   --seed FILE         initial data: tar.gz with root/final and root/geoip/abuse/seen.txt
#   -h, --help
#
# Supported: Debian 12/13, Ubuntu 22.04/24.04/26.04, RHEL/AlmaLinux/Rocky/CentOS Stream 9/10,
# Fedora, Oracle Linux, Amazon Linux 2023, openSUSE, Arch (see README). Requires systemd.
set -euo pipefail

CONFIG=""
FORCE_CONFIG=0
HOLD=30
HOLD_IPS=""
ROLLBACK=600
TRUST_HOLD=0
BOOTSTRAP=1
PACKAGES=1
BACKUP=1
SEED=""
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="$(cat "$SRC/VERSION" 2>/dev/null || echo dev)"
INSTALL_WINDOW=3600   # how long the hold lasts WHILE the installation runs (the trap shortens it)

usage() { sed -n '2,27p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --config)        CONFIG="${2:?}"; shift 2 ;;
    --force-config)  FORCE_CONFIG=1; shift ;;
    --hold-ip)       HOLD_IPS="$HOLD_IPS ${2:?}"; shift 2 ;;
    --hold)          HOLD="${2:?}"; shift 2 ;;
    --rollback)      ROLLBACK="${2:?}"; shift 2 ;;
    --no-rollback)   ROLLBACK=0; shift ;;
    --trust-hold-ip) TRUST_HOLD=1; shift ;;
    --no-bootstrap)  BOOTSTRAP=0; shift ;;
    --no-packages)   PACKAGES=0; shift ;;
    --no-backup)     BACKUP=0; shift ;;
    --seed)          SEED="${2:?}"; shift 2 ;;
    -h|--help)       usage; exit 0 ;;
    *) echo "unknown argument: $1 (see --help)" >&2; exit 2 ;;
  esac
done
for n in "$HOLD" "$ROLLBACK"; do
  case "$n" in ''|*[!0-9]*) echo "--hold and --rollback must be a number of seconds" >&2; exit 2 ;; esac
done

if [ -t 1 ]; then B=$'\033[1m' G=$'\033[32m' Y=$'\033[33m' R=$'\033[31m' N=$'\033[0m'; else B='' G='' Y='' R='' N=''; fi
say()  { printf '\n%s== %s%s\n' "$B" "$*" "$N"; }
ok()   { printf '   %sOK%s %s\n' "$G" "$N" "$*"; }
warn() { printf '   %s!%s  %s\n' "$Y" "$N" "$*"; }
die()  { printf '\n%sERROR:%s %s\n' "$R" "$N" "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

say "blocklist-active $VERSION"
[ "$(id -u)" = 0 ] || die "must run as root (or through sudo)"
[ -d /run/systemd/system ] || die "systemd is not running - only distributions with systemd are supported"
[ -d "$SRC/files" ] || die "$SRC/files is missing - run from an unpacked kit"

# ---------- 0. distribution ----------
# shellcheck source=/dev/null
. /etc/os-release
OS_IDS=" ${ID:-} ${ID_LIKE:-} "
case "$OS_IDS" in
  *" debian "*|*" ubuntu "*)                           PM=apt ;;
  *" rhel "*|*" fedora "*|*" centos "*|*" amzn "*)     if have dnf; then PM=dnf; else PM=yum; fi ;;
  *" suse "*|*" opensuse "*|*" sles "*)                PM=zypper ;;
  *" arch "*)                                          PM=pacman ;;
  *) PM=unknown ;;
esac
ok "${PRETTY_NAME:-$ID} (packages: $PM)"

# ---------- 1. packages ----------
pkg_for() {   # command -> package on this distribution
  case "$PM:$1" in
    *:nft)            echo nftables ;;
    pacman:python3)   echo python ;;
    *:python3)        echo python3 ;;
    *:curl)           echo curl ;;
    apt:ss|apt:ip|zypper:ss|zypper:ip|pacman:ss|pacman:ip) echo iproute2 ;;
    *:ss|*:ip)        echo iproute ;;
    apt:logger)       echo bsdutils ;;
    zypper:logger)    echo util-linux-systemd ;;
    *:logger|*:flock) echo util-linux ;;
    *:sha256sum)      echo coreutils ;;
    apt:awk)          echo mawk ;;
    *:awk)            echo gawk ;;
    *:find)           echo findutils ;;
    *:cmp)            echo diffutils ;;
    *:tar)            echo tar ;;
    *:gzip)           echo gzip ;;
    *:hostname)       case "$PM" in pacman) echo inetutils ;; *) echo hostname ;; esac ;;
  esac
}
CMDS="nft python3 curl ss ip logger flock sha256sum awk find cmp tar gzip hostname"
ca_ok() {
  [ -s /etc/ssl/certs/ca-certificates.crt ] || [ -s /etc/pki/tls/certs/ca-bundle.crt ] || \
  [ -s /etc/ssl/ca-bundle.pem ] || [ -s /etc/ssl/cert.pem ]
}
if [ "$PACKAGES" = 1 ]; then
  say "Packages"
  need=""
  for c in $CMDS; do have "$c" || need="$need $(pkg_for "$c")"; done
  ca_ok || need="$need ca-certificates"
  # shellcheck disable=SC2086
  need=$(printf '%s\n' $need | sort -u | tr '\n' ' ')
  if [ -n "${need// /}" ]; then
    echo "   installing: $need"
    case "$PM" in
      # shellcheck disable=SC2086
      apt)    export DEBIAN_FRONTEND=noninteractive
              apt-get update -qq && apt-get install -y -qq --no-install-recommends $need >/dev/null ;;
      # shellcheck disable=SC2086
      dnf)    dnf -y -q install $need ;;
      # shellcheck disable=SC2086
      yum)    yum -y -q install $need ;;
      # shellcheck disable=SC2086
      zypper) zypper -n -q install --no-recommends $need ;;
      # shellcheck disable=SC2086
      pacman) pacman -Sy --noconfirm --needed $need ;;
      *)      die "unknown package manager - install manually: $need, then rerun with --no-packages" ;;
    esac || die "package installation failed:$need"
    ok "installed: $need"
  else
    ok "everything needed is already present"
  fi
fi
missing=""
for c in $CMDS; do have "$c" || missing="$missing $c"; done
[ -z "$missing" ] || die "missing commands:$missing"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 7) else 1)' \
  || die "Python >= 3.7 is required (found $(python3 -V 2>&1))"
NFT_VER=$(nft --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
ok "nftables $NFT_VER, $(python3 -V 2>&1)"
case "$NFT_VER" in 0.[0-8].*|0.9.[0-2]) warn "nftables $NFT_VER is old; tested from 1.0.2 upwards" ;; esac

# ---------- 2. configuration ----------
say "Configuration"
conf_set() {   # conf_set KEY VALUE - write or replace a line in /etc/blocklist.conf
  if grep -q "^$1=" /etc/blocklist.conf; then
    sed -i "s|^$1=.*|$1=\"$2\"|" /etc/blocklist.conf
  else
    printf '%s="%s"\n' "$1" "$2" >> /etc/blocklist.conf
  fi
}
if [ -n "$CONFIG" ] && [ "$(readlink -f "$CONFIG")" = /etc/blocklist.conf ]; then
  ok "using /etc/blocklist.conf"
elif [ -s /etc/blocklist.conf ] && [ "$FORCE_CONFIG" = 0 ]; then
  ok "/etc/blocklist.conf already exists, keeping it (--force-config to overwrite)"
  if [ -n "$CONFIG" ] && ! cmp -s "$CONFIG" /etc/blocklist.conf; then
    warn "--config $CONFIG differs from the existing file and was NOT applied"
  fi
else
  [ -n "$CONFIG" ] || die "the first installation needs --config FILE (see blocklist.conf.example)"
  [ -s "$CONFIG" ] || die "config $CONFIG does not exist or is empty"
  [ -s /etc/blocklist.conf ] && cp -a /etc/blocklist.conf "/etc/blocklist.conf.bak-$(date +%F-%H%M%S)"
  install -m 0600 "$CONFIG" /etc/blocklist.conf
  ok "installed /etc/blocklist.conf"
fi
chmod 0600 /etc/blocklist.conf   # may contain notification tokens
bash -n /etc/blocklist.conf || die "/etc/blocklist.conf has a syntax error"
# shellcheck source=/dev/null
SERVER_IPS="" OWNER_IPS="" SITE_URL="" SSH_PORT=""; . /etc/blocklist.conf
if [ -z "${SERVER_IPS// /}" ]; then
  SERVER_IPS=$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | sort -u | tr '\n' ' ' | sed 's/ $//')
  [ -n "$SERVER_IPS" ] || die "SERVER_IPS is empty and cannot be detected - set it in the config"
  conf_set SERVER_IPS "$SERVER_IPS"
  warn "SERVER_IPS was not set - detected and written: $SERVER_IPS"
  warn "  behind NAT (AWS, GCP...) also add the PUBLIC address of the server"
fi
[ -n "$SITE_URL" ] || warn "SITE_URL is not set - the site check after apply is skipped"

# address the installation comes from: argument, SSH session, then parent processes (sudo clears env)
detect_client() {
  local v="${SSH_CONNECTION:-${SSH_CLIENT:-}}" pid=$$ i
  if [ -z "$v" ]; then
    for i in 1 2 3 4 5 6 7 8 9 10; do
      pid=$(awk '{print $4}' "/proc/$pid/stat" 2>/dev/null) || break
      [ -n "$pid" ] && [ "$pid" -gt 1 ] || break
      v=$(tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null | sed -n 's/^SSH_CONNECTION=//p;s/^SSH_CLIENT=//p' | head -1)
      [ -n "$v" ] && break
    done
  fi
  echo "${v%% *}"
}
if [ -z "${HOLD_IPS// /}" ]; then
  c=$(detect_client)
  [ -n "$c" ] && HOLD_IPS="$c"
fi
HOLD4=""
for ip in $HOLD_IPS; do
  case "$ip" in *:*) ok "address $ip is IPv6 - blocks are IPv4 only, no hold needed" ;;
                  *)  HOLD4="$HOLD4 $ip" ;; esac
done
HOLD4="${HOLD4# }"
if [ "$TRUST_HOLD" = 1 ] && [ -n "$HOLD4" ]; then
  for ip in $HOLD4; do
    case " $OWNER_IPS " in *" $ip "*) ;; *) OWNER_IPS="${OWNER_IPS:+$OWNER_IPS }$ip" ;; esac
  done
  conf_set OWNER_IPS "$OWNER_IPS"
  ok "OWNER_IPS extended: $HOLD4"
fi

# ---------- 3. files ----------
say "Scripts and systemd units"
inst() { install -D -m "$1" "$SRC/files/$2" "/$2"; }
inst 0644 usr/local/lib/blocklist/common.sh
printf '%s\n' "$VERSION" > /usr/local/lib/blocklist/VERSION
for f in blocklist blocklist-update.sh blocklist-health.sh blocklist-backup.sh certbot-canary.sh; do
  inst 0755 "usr/local/sbin/$f"
done
mkdir -p /root/geoip/zones /root/geoip/proxy /root/geoip/abuse /root/geoip/crawlers
for f in "$SRC"/files/root/geoip/*.py; do install -m 0755 "$f" /root/geoip/; done
rm -rf /root/geoip/__pycache__
[ -s /root/geoip/crawlers/allow.txt ] || inst 0644 root/geoip/crawlers/allow.txt
for u in "$SRC"/files/etc/systemd/system/*; do install -m 0644 "$u" /etc/systemd/system/; done
if [ -d /etc/update-motd.d ]; then
  inst 0755 etc/update-motd.d/99-blocklist-status
  rm -f /etc/profile.d/blocklist-status.sh
else
  inst 0644 etc/profile.d/blocklist-status.sh
fi
if [ -d /etc/letsencrypt ] || have certbot; then
  inst 0755 etc/letsencrypt/renewal-hooks/pre/00-blocklist-off.sh
  inst 0755 etc/letsencrypt/renewal-hooks/post/99-blocklist-on.sh
  # the 1.x hooks do the same thing - they must not run twice
  for old in /etc/letsencrypt/renewal-hooks/pre/00-nft-off.sh /etc/letsencrypt/renewal-hooks/post/99-nft-on.sh; do
    [ -f "$old" ] && grep -q 'nft' "$old" && rm -f "$old" && ok "removed the old hook $(basename "$old")"
  done
  if have nginx && ! grep -lqs 'reload nginx' /etc/letsencrypt/renewal-hooks/deploy/* 2>/dev/null; then
    inst 0755 etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
    ok "deploy hook: reload nginx after renewal"
  fi
  ok "Let's Encrypt hooks installed"
fi
ok "installed into /usr/local/sbin, /usr/local/lib/blocklist, /root/geoip, /etc/systemd/system"

# shellcheck source=/dev/null
. /usr/local/lib/blocklist/common.sh
mkdir -p "$STATE" "$NFT_DIR"

# ---------- 4. upgrade from older versions ----------
for nc in /etc/nftables.conf /etc/sysconfig/nftables.conf; do
  if [ -f "$nc" ] && grep -qE 'nftables\.d/(geoblock|abuseblock|proxyblock)\.nft' "$nc"; then
    cp -a "$nc" "$nc.bak-blocklist-$(date +%F-%H%M%S)"
    sed -i -E '/nftables\.d\/(geoblock|abuseblock|proxyblock)\.nft/d' "$nc"
    ok "$nc: include lines removed (blocklist.service loads the tables now)"
  fi
done
# Legacy names: real file, unit and set names that version 1.x created on existing
# servers. They are matched verbatim so an upgrade can remove them.
LEGACY_UNITS="bekap-konfiguracije.timer bekap-konfiguracije.service bekap-failed.service"
LEGACY_FILES="/usr/local/sbin/bekap-konfiguracije.sh /root/geoip/konfig.py $STATE/last-good.nft $STATE/bekap $STATE/bekap-error"
LEGACY_BACKUP_DIR=/var/backups/konfiguracija
LEGACY_SETS='dozvoljeni|bijela|napadaci'
for u in $LEGACY_UNITS; do
  if [ -e "/etc/systemd/system/$u" ]; then
    systemctl disable --now "$u" >/dev/null 2>&1 || true
    rm -f "/etc/systemd/system/$u"
    ok "removed the 1.x unit $u (replaced by blocklist-backup)"
  fi
done
# shellcheck disable=SC2086
rm -f $LEGACY_FILES
if [ -d "$LEGACY_BACKUP_DIR" ]; then
  warn "1.x snapshots in $LEGACY_BACKUP_DIR are no longer rotated;"
  warn "  new ones go to /var/backups/server-config - delete the old directory when no longer needed"
fi

# ---------- 5. initial data ----------
[ -n "$SEED" ] || SEED="$SRC/seed/seed.tar.gz"
if [ -f "$SEED" ]; then
  say "Initial data"
  tmp=$(mktemp -d)
  tar xzf "$SEED" -C "$tmp"
  if [ ! -s "$FINAL" ] && [ -s "$tmp/root/final" ]; then
    cp "$tmp/root/final" "$FINAL"; ok "$FINAL seeded ($(wc -l < "$FINAL") lines)"
  fi
  if [ ! -s /root/geoip/abuse/seen.txt ] && [ -s "$tmp/root/geoip/abuse/seen.txt" ]; then
    cp "$tmp/root/geoip/abuse/seen.txt" /root/geoip/abuse/seen.txt
    ok "seen.txt seeded ($(wc -l < /root/geoip/abuse/seen.txt) addresses)"
  fi
  rm -rf "$tmp"
fi

for t in $TABLES; do
  [ -s "$NFT_DIR/$t.nft" ] || echo "# not generated yet" > "$NFT_DIR/$t.nft"
done

# ---------- 6. hold the address the installation comes from ----------
say "Holding the installer's address"
systemctl daemon-reload
bl_guard_ensure || die "the guard table cannot be created (is nftables working?)"
finish_hold() {
  local rc=$? ip
  for ip in $HOLD4; do
    if bl_hold_set "$ip" "$HOLD" 2>/dev/null; then
      if [ "$HOLD" -gt 0 ]; then echo "   $ip passes the blocks for another ${HOLD}s"
      else echo "   hold released for $ip"; fi
    fi
  done
  exit $rc
}
if [ -n "$HOLD4" ]; then
  for ip in $HOLD4; do
    bl_hold_set "$ip" "$INSTALL_WINDOW" || die "cannot hold $ip"
    ok "$ip passes every block until the installation ends + ${HOLD}s"
  done
  trap finish_hold EXIT
else
  warn "the installer's address is unknown (not an SSH session) - no hold; use --hold-ip"
fi

# ---------- 7. safety net ----------
rm -f "$STATE/disabled"
systemctl enable blocklist.service >/dev/null 2>&1 || true
if [ "$ROLLBACK" -gt 0 ]; then
  say "Safety net"
  /usr/local/sbin/blocklist arm-rollback "$ROLLBACK"
  ok "unless confirmed within ${ROLLBACK}s, the blocks get disabled (blocklist confirm)"
fi

# ---------- 8. lists ----------
needs_regen=0
for t in $TABLES; do
  if ! bl_file_ok "$NFT_DIR/$t.nft" || ! grep -q 'meta mark &' "$NFT_DIR/$t.nft" \
     || grep -qE "set ($LEGACY_SETS) " "$NFT_DIR/$t.nft"; then
    needs_regen=1
  fi
done
if [ "$BOOTSTRAP" = 1 ]; then
  say "First list load (download, verify, apply) - a few minutes"
  /usr/local/sbin/blocklist-update.sh all || die "list load failed - see /var/lib/blocklist/last-error and last-verify"
  ok "lists loaded and verified"
elif [ "$needs_regen" = 1 ] && [ -n "$(ls -A /root/geoip/zones 2>/dev/null)" ]; then
  say "Regenerating from local data (no download)"
  /usr/local/sbin/blocklist-update.sh rebuild || die "rebuild failed - see /var/lib/blocklist/last-error"
  ok "lists regenerated"
elif [ "$needs_regen" = 1 ]; then
  warn "no lists on disk - run: blocklist update all"
else
  /usr/local/sbin/blocklist load && ok "existing lists loaded"
fi
systemctl start blocklist.service >/dev/null 2>&1 || true

# ---------- 9. timers ----------
say "Timers"
units="blocklist-update@abuse.timer blocklist-update@geo.timer blocklist-update@proxy.timer blocklist-health.timer"
[ "$BACKUP" = 1 ] && units="$units blocklist-backup.timer"
if have certbot; then units="$units certbot-canary.timer"
else systemctl disable --now certbot-canary.timer >/dev/null 2>&1 || true; fi
for u in $units; do
  if systemctl enable --now "$u" >/dev/null 2>&1; then ok "$u"; else warn "$u was not enabled"; fi
done
if [ "$BACKUP" = 0 ]; then systemctl disable --now blocklist-backup.timer >/dev/null 2>&1 || true; fi
if [ "$BACKUP" = 1 ]; then
  if /usr/local/sbin/blocklist-backup.sh >/dev/null 2>&1; then ok "first configuration snapshot taken"
  else warn "first snapshot failed - see /var/lib/blocklist/backup-error"; fi
fi
/usr/local/sbin/blocklist-health.sh >/dev/null 2>&1 || true

# ---------- 10. report ----------
say "Status"
for t in $GUARD $TABLES; do
  if nft list table inet "$t" >/dev/null 2>&1; then ok "table inet $t loaded"
  else warn "table inet $t is NOT loaded"; fi
done
if bl_site_check; then ok "site: ${SITE_URL:-not set} -> $BL_SITE_CODE"
else warn "site $SITE_URL returns $BL_SITE_CODE"; fi
for ip in $HOLD4; do
  if out=$(/usr/local/sbin/blocklist check "$ip" 2>&1 | grep -v HELD); then
    ok "$out"
  else
    printf '\n   %s!!! %s%s\n' "$R" "$out" "$N"
    printf '   %s    Once the hold expires (%ss), new connections from that address will be dropped.%s\n' "$R" "$HOLD" "$N"
    printf '   %s    Add it to OWNER_IPS (or use --trust-hold-ip) and run: blocklist update rebuild%s\n' "$R" "$N"
  fi
done

if [ "$ROLLBACK" -gt 0 ]; then
  cat <<EOF

  +----------------------------------------------------------------+
  |  CONFIRM ACCESS                                                |
  |                                                                |
  |  Wait ${HOLD}s for the hold to expire, open a NEW SSH connection
  |  and, if it works, confirm:                                    |
  |                                                                |
  |      blocklist confirm                                         |
  |                                                                |
  |  Without confirmation the blocks disable themselves in ${ROLLBACK}s.
  +----------------------------------------------------------------+
EOF
fi
echo
exit 0
