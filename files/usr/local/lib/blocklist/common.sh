# shellcheck shell=bash
# /usr/local/lib/blocklist/common.sh - shared functions for every blocklist script.
# Sourced, never executed directly.
#
# Architecture in short:
#   inet blocklist_guard  priority -20  'hold' set (addresses with an expiry) -> marks the packet
#   inet geoblock         priority -10  countries          (all ports)
#   inet abuseblock       priority  -7  attackers          (all ports)
#   inet proxyblock       priority  -5  proxy / Tor        (tcp 80/443 only)
# Every blocking table accepts marked packets BEFORE its drop rule, so an address
# in the 'hold' set passes all three. All tables use policy accept - this is a
# filter, not a firewall, and it never touches other tables (Docker, firewalld, ufw).

BL_LIB=/usr/local/lib/blocklist
BL_VERSION="$(cat "$BL_LIB/VERSION" 2>/dev/null || echo dev)"
CONF="${BLOCKLIST_CONF:-/etc/blocklist.conf}"
GEOIP="${BLOCKLIST_HOME:-/root/geoip}"
NFT_DIR="${BLOCKLIST_NFT_DIR:-/etc/nftables.d}"
FINAL="${BLOCKLIST_FINAL:-/root/final}"
STATE=/var/lib/blocklist
LOCK=/run/blocklist.lock
TABLES="geoblock abuseblock proxyblock"
GUARD=blocklist_guard

# ---------- defaults (the config file overrides them) ----------
SITE_URL=""
SSH_PORT=""
SERVER_IPS=""
OWNER_IPS=""
COUNTRIES="ir ru cn br co bg ro sc"
WHITELIST_CC="ba"
GUARD_MARK="0x08000000"
LIST_CACHE_DIR=""
LIST_CACHE_MAX_AGE=82800
NOTIFY_NTFY_URL=""
NOTIFY_TELEGRAM_TOKEN=""
NOTIFY_TELEGRAM_CHAT=""
NOTIFY_EMAIL=""
BACKUP_EXTRA=""
BACKUP_KEEP=14
STALE_DAYS=3

# shellcheck source=/dev/null
[ -r "$CONF" ] && . "$CONF"
GUARD_MARK=$(printf '0x%08x' "$GUARD_MARK" 2>/dev/null || echo 0x08000000)
BL_TAG="${BL_TAG:-blocklist}"

bl_log() {
  logger -t "$BL_TAG" -- "$*" 2>/dev/null
  printf '%s %s\n' "$(date '+%F %T')" "$*"
}

bl_have() { command -v "$1" >/dev/null 2>&1; }

bl_is_ipv4() {
  local IFS=. o
  # shellcheck disable=SC2086
  set -- $1
  [ $# = 4 ] || return 1
  for o in "$@"; do
    case "$o" in ''|*[!0-9]*) return 1 ;; esac
    [ "$o" -le 255 ] || return 1
  done
  return 0
}

# ---------- locking: one update/load at a time ----------
bl_lock() {   # bl_lock -w SECONDS | -n
  exec 9>"$LOCK" || return 1
  flock "$@" 9
}
bl_unlock() { exec 9>&- 2>/dev/null || true; }

# ---------- off-host notifications (all optional) ----------
bl_notify() {   # bl_notify TITLE MESSAGE
  local title="$1" msg="$2" host
  host=$(hostname -f 2>/dev/null || hostname)
  if [ -n "$NOTIFY_NTFY_URL" ]; then
    curl -fsS -m 15 -H "Title: blocklist $host: $title" -d "$msg" "$NOTIFY_NTFY_URL" >/dev/null 2>&1 \
      || logger -t blocklist "notification (ntfy) was not sent"
  fi
  if [ -n "$NOTIFY_TELEGRAM_TOKEN" ] && [ -n "$NOTIFY_TELEGRAM_CHAT" ]; then
    curl -fsS -m 15 "https://api.telegram.org/bot${NOTIFY_TELEGRAM_TOKEN}/sendMessage" \
      --data-urlencode "chat_id=$NOTIFY_TELEGRAM_CHAT" \
      --data-urlencode "text=[$host] $title: $msg" >/dev/null 2>&1 \
      || logger -t blocklist "notification (telegram) was not sent"
  fi
  if [ -n "$NOTIFY_EMAIL" ]; then
    if bl_have mail; then
      printf '%s\n' "$msg" | mail -s "blocklist $host: $title" "$NOTIFY_EMAIL" 2>/dev/null
    elif bl_have sendmail; then
      printf 'To: %s\nSubject: blocklist %s: %s\n\n%s\n' "$NOTIFY_EMAIL" "$host" "$title" "$msg" | sendmail -t 2>/dev/null
    else
      logger -t blocklist "NOTIFY_EMAIL is set, but neither mail nor sendmail is installed"
    fi
  fi
  return 0
}

# ---------- downloads with an optional cache (tests, mirrors, offline networks) ----------
bl_fetch() {   # bl_fetch URL OUTPUT [SECONDS]  -> 0 only if OUTPUT was replaced with non-empty content
  local url="$1" out="$2" t="${3:-120}" key="" c="" age
  if [ -n "$LIST_CACHE_DIR" ]; then
    key=$(printf '%s' "$url" | sha256sum | cut -c1-24)
    c="$LIST_CACHE_DIR/$key"
    if [ -s "$c" ]; then
      age=$(( $(date +%s) - $(stat -c %Y "$c") ))
      if [ "$age" -lt "$LIST_CACHE_MAX_AGE" ]; then
        cp "$c" "$out.part" && mv -f "$out.part" "$out" && return 0
      fi
    fi
  fi
  if curl -sSfL --retry 2 --retry-delay 3 -m "$t" -o "$out.part" "$url" 2>/dev/null && [ -s "$out.part" ]; then
    mv -f "$out.part" "$out"
    if [ -n "$c" ]; then
      mkdir -p "$LIST_CACHE_DIR" && cp "$out" "$c.tmp.$$" && mv -f "$c.tmp.$$" "$c"
    fi
    return 0
  fi
  rm -f "$out.part"
  return 1
}

# ---------- site check: follows redirects, expects 2xx at the end ----------
BL_SITE_CODE=""
bl_site_check() {
  BL_SITE_CODE="not_set"
  [ -n "$SITE_URL" ] || return 0
  local i
  for i in 1 2 3; do
    BL_SITE_CODE=$(curl -sS -o /dev/null -L --max-redirs 5 -m 20 -w '%{http_code}' "$SITE_URL" 2>/dev/null)
    case "$BL_SITE_CODE" in 2??) return 0 ;; esac
    [ "$i" -lt 3 ] && sleep 3
  done
  return 1
}

# ---------- SSH port: config, then ssh.socket, then sshd -T ----------
bl_ssh_port() {
  if [ -n "$SSH_PORT" ]; then echo "$SSH_PORT"; return; fi
  local p=""
  if systemctl is-active --quiet ssh.socket 2>/dev/null; then
    p=$(systemctl show ssh.socket -p Listen --value 2>/dev/null | grep -oE ':[0-9]+ ' | head -1 | tr -d ': ')
  fi
  [ -n "$p" ] || p=$(sshd -T 2>/dev/null | awk '$1=="port"{print $2; exit}')
  echo "${p:-22}"
}

# ---------- guard table and held addresses ----------
bl_guard_def() {
  cat <<EOF
table inet $GUARD {
	set hold {
		type ipv4_addr
		flags timeout
		comment "temporarily held addresses (installation, administration)"
	}

	chain input {
		type filter hook input priority -20; policy accept;
		ip saddr @hold meta mark set meta mark | $GUARD_MARK counter comment "blocklist hold"
	}
}
EOF
}

bl_guard_ok() {
  nft list chain inet "$GUARD" input 2>/dev/null | grep -q "meta mark | $GUARD_MARK"
}

bl_guard_ensure() {
  bl_guard_ok && return 0
  nft delete table inet "$GUARD" 2>/dev/null
  bl_guard_def | nft -f -
}

bl_hold_set() {   # bl_hold_set IP SECONDS   (0 = remove)
  local ip="$1" sec="$2"
  bl_is_ipv4 "$ip" || return 1
  bl_guard_ensure || return 1
  # on older kernels 'add' does not change the expiry of an existing element,
  # so: add (if missing), delete, add again with the new expiry
  nft add element inet "$GUARD" hold "{ $ip timeout 1s }" 2>/dev/null
  nft delete element inet "$GUARD" hold "{ $ip }" 2>/dev/null
  if [ "$sec" -gt 0 ]; then
    nft add element inet "$GUARD" hold "{ $ip timeout ${sec}s }"
  fi
}

# ---------- loading tables from files ----------
bl_file_ok() { [ -s "$1" ] && grep -q '^table inet ' "$1"; }

bl_record_loaded() {
  mkdir -p "$STATE"
  (cd "$NFT_DIR" && sha256sum geoblock.nft abuseblock.nft proxyblock.nft 2>/dev/null) > "$STATE/loaded" || true
}

bl_load_tables() {   # bl_load_tables [DIR]  - DIR defaults to /etc/nftables.d
  local dir="${1:-$NFT_DIR}" t rc=0
  bl_guard_ensure || rc=1
  if [ -e "$STATE/disabled" ]; then
    for t in $TABLES; do nft delete table inet "$t" 2>/dev/null; done
    return $rc
  fi
  for t in $TABLES; do
    if bl_file_ok "$dir/$t.nft"; then
      nft -f "$dir/$t.nft" || rc=1
    else
      nft delete table inet "$t" 2>/dev/null
    fi
  done
  [ "$dir" = "$NFT_DIR" ] && bl_record_loaded
  return $rc
}

bl_unload_tables() {
  local t
  for t in $TABLES; do nft delete table inet "$t" 2>/dev/null; done
  return 0
}

bl_disable() {   # bl_disable REASON
  mkdir -p "$STATE"
  printf 'time="%s"\nreason="%s"\n' "$(date '+%F %T')" "$1" > "$STATE/disabled"
  bl_unload_tables
}

bl_in_set() { nft get element inet "$1" "$2" "{ $3 }" >/dev/null 2>&1; }

bl_count() {   # number of elements in a set (approximate - counts commas)
  nft list set inet "$1" "$2" 2>/dev/null | tr -cd ',' | wc -c
}
