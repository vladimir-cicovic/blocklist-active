#!/bin/bash
# blocklist-backup.sh - daily on-host snapshot of the server configuration, with rotation.
#
# This is NOT a replacement for an off-host backup - if the disk dies, so do the
# snapshots. It protects against the more common case: a bad configuration change.
# The archive may contain the private TLS key (/etc/letsencrypt), hence 700/600.
#
# Extra paths (for example site content) go into BACKUP_EXTRA in /etc/blocklist.conf.
#
# Usage: blocklist-backup.sh [--keep N] [--dest DIR]
set -u
BL_TAG=blocklist-backup
# shellcheck source=/dev/null
. /usr/local/lib/blocklist/common.sh

DEST=/var/backups/server-config
DEST_DEFAULT=$DEST
KEEP="$BACKUP_KEEP"

while [ $# -gt 0 ]; do
  case "$1" in
    --keep) KEEP="${2:?}"; shift 2 ;;
    --dest) DEST="${2:?}"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

mkdir -p "$DEST" "$STATE"
chmod 700 "$DEST"

# state is written ONLY for the real backup - a trial run with --dest must not change the MOTD
is_real() { [ "$DEST" = "$DEST_DEFAULT" ]; }

fail() {
  bl_log "ERROR: $*"
  is_real && echo "$(date '+%F %T') backup failed: $*" > "$STATE/backup-error"
  exit 1
}

STAMP=$(date +%F-%H%M)
ARCHIVE="$DEST/config-$STAMP.tar.gz"

# ---------- metadata ----------
META=$(mktemp -d) || fail "cannot create a temporary directory"
trap 'rm -rf "$META"' EXIT
{
  echo "# Taken: $(date '+%F %T %Z')"
  echo "# Host: $(hostname) / $(hostname -I 2>/dev/null | awk '{print $1}')"
  echo "# blocklist $BL_VERSION"
  echo
  grep PRETTY /etc/os-release; uname -r
  bl_have nginx && nginx -v 2>&1
  bl_have openssl && openssl version
  nft --version
} > "$META/system.txt" 2>&1
bl_have nginx && nginx -V > "$META/nginx-build.txt" 2>&1
if bl_have dpkg; then dpkg --get-selections > "$META/packages.txt" 2>&1
elif bl_have rpm; then rpm -qa | sort > "$META/packages.txt" 2>&1; fi
systemctl list-unit-files --state=enabled --no-pager > "$META/enabled-units.txt" 2>&1
ss -tulpn > "$META/ports.txt" 2>&1
bl_have certbot && certbot certificates > "$META/certificates.txt" 2>&1
nft list tables > "$META/nft-tables.txt" 2>&1

# ---------- paths (without the leading slash) ----------
PATHS=""
add_path() { local p="${1#/}"; [ -e "/$p" ] && PATHS="$PATHS $p"; return 0; }
for p in \
    etc/blocklist.conf \
    etc/nftables.conf \
    etc/nftables.d \
    etc/sysconfig/nftables.conf \
    etc/nginx \
    etc/apache2 \
    etc/httpd \
    etc/letsencrypt \
    etc/ssh/sshd_config \
    etc/ssh/sshd_config.d \
    etc/sysctl.d \
    etc/apt/sources.list.d \
    etc/apt/preferences.d \
    etc/update-motd.d/99-blocklist-status \
    usr/local/lib/blocklist \
    usr/local/sbin/blocklist \
    usr/local/sbin/blocklist-update.sh \
    usr/local/sbin/blocklist-health.sh \
    usr/local/sbin/blocklist-backup.sh \
    usr/local/sbin/certbot-canary.sh \
    root/geoip \
    root/final \
    var/lib/blocklist ; do
  add_path "$p"
done
for f in /etc/systemd/system/blocklist*.service /etc/systemd/system/blocklist*.timer \
         /etc/systemd/system/certbot-canary.*; do
  [ -e "$f" ] && add_path "$f"
done
for p in $BACKUP_EXTRA; do add_path "$p"; done
[ -n "$PATHS" ] || fail "no path to back up"

# ---------- archive ----------
# shellcheck disable=SC2086
tar czf "$ARCHIVE.part" \
    --exclude='var/www/htmly/cache/*' \
    --exclude='var/lib/blocklist/staging' \
    -C / $PATHS -C "$META" . 2>/dev/null || fail "tar failed"
mv "$ARCHIVE.part" "$ARCHIVE"
chmod 600 "$ARCHIVE"

# ---------- make sure the archive is not an empty shell ----------
LISTING=$(mktemp)
tar tzf "$ARCHIVE" > "$LISTING" 2>/dev/null || { rm -f "$LISTING"; fail "the archive cannot be read"; }
N=$(wc -l < "$LISTING")
MISSING=""
for must in etc/blocklist.conf ./system.txt; do
  grep -qx "$must" "$LISTING" || MISSING="$MISSING $must"
done
rm -f "$LISTING"
[ -n "$MISSING" ] && fail "missing from the archive:$MISSING"
[ "$N" -lt 10 ] && fail "the archive has only $N entries - suspiciously few"

# ---------- rotation ----------
REMOVED=0
# shellcheck disable=SC2012
for old in $(ls -t "$DEST"/config-*.tar.gz 2>/dev/null | tail -n +$((KEEP + 1))); do
  rm -f "$old" && REMOVED=$((REMOVED + 1))
done

SIZE=$(du -h "$ARCHIVE" | cut -f1)
if is_real; then
  rm -f "$STATE/backup-error"
  {
    echo "time=\"$(date '+%F %T')\""
    echo "archive=\"$ARCHIVE\""
    echo "size=\"$SIZE\""
    echo "items=$N"
    echo "total_snapshots=$(find "$DEST" -maxdepth 1 -name 'config-*.tar.gz' | wc -l)"
  } > "$STATE/backup"
fi
bl_log "OK: $ARCHIVE ($SIZE, $N entries), old snapshots removed: $REMOVED"
exit 0
