#!/bin/bash
# blocklist-health.sh - health check every 6 hours.
# Tables loaded and identical to the files on disk, site up, SSH listening,
# certificate not about to expire, lists actually being refreshed. Whatever it
# can fix, it fixes; the rest goes to /var/lib/blocklist/health-error (MOTD)
# and out as a notification.
set -u
BL_TAG=blocklist-health
# shellcheck source=/dev/null
. /usr/local/lib/blocklist/common.sh
mkdir -p "$STATE"

problems=""
problem() { problems="${problems:+$problems; }$*"; bl_log "PROBLEM: $*"; }

cert_window_active() {
  [ -s "$STATE/cert-window" ] || return 1
  [ $(( $(date +%s) - $(cat "$STATE/cert-window") )) -lt 900 ]
}

# ---------- 1. tables ----------
if [ -e "$STATE/disabled" ]; then
  # shellcheck source=/dev/null
  why=$( . "$STATE/disabled"; echo "${reason:-?} since ${time:-?}" )
  problem "PROTECTION DISABLED ($why) - enable with: blocklist enable"
elif ! systemctl is-active --quiet blocklist.service; then
  problem "blocklist.service is not active - start it: systemctl start blocklist"
elif cert_window_active; then
  bl_log "certificate renewal in progress - skipping the table check"
else
  missing=""
  for t in $TABLES; do
    nft list table inet "$t" >/dev/null 2>&1 || missing="$missing $t"
  done
  drift=""
  if [ -s "$STATE/loaded" ] && ! (cd "$NFT_DIR" && sha256sum -c --quiet "$STATE/loaded" >/dev/null 2>&1); then
    drift=" (files on disk differ from the loaded ones)"
  fi
  bl_guard_ok || missing="$missing $GUARD"
  if [ -n "$missing$drift" ]; then
    if bl_lock -n; then
      bl_log "reloading from $NFT_DIR - missing:${missing:- nothing}$drift"
      bl_load_tables
      bl_unlock
      still=""
      for t in $TABLES; do
        nft list table inet "$t" >/dev/null 2>&1 || still="$still $t"
      done
      [ -n "$still" ] && problem "tables still missing:$still"
    else
      bl_log "update in progress - skipping the reload"
    fi
  fi
fi

# ---------- 2. site ----------
if ! bl_site_check; then
  problem "site $SITE_URL returns $BL_SITE_CODE"
fi

# ---------- 3. SSH ----------
port=$(bl_ssh_port)
if ! ss -tlnH "( sport = :$port )" 2>/dev/null | grep -q .; then
  problem "SSH is not listening on port $port"
fi

# ---------- 4. the lists are actually refreshed ----------
if [ -s "$STATE/last-success" ]; then
  # shellcheck source=/dev/null
  last=$( . "$STATE/last-success"; echo "${time:-}" )
  if [ -n "$last" ]; then
    age=$(( ( $(date +%s) - $(date -d "$last" +%s 2>/dev/null || date +%s) ) / 86400 ))
    [ "$age" -ge "$STALE_DAYS" ] && problem "lists have not been refreshed successfully for $age days (last $last)"
  fi
elif [ ! -e "$STATE/disabled" ]; then
  problem "lists have never been refreshed successfully - run: blocklist update all"
fi

# ---------- 5. rootkit scanner (only if installed) ----------
if [ -f /var/log/rkhunter.log ]; then
  RK=$(grep -c "^\[.*\] Warning:" /var/log/rkhunter.log 2>/dev/null)
  if [ "${RK:-0}" -gt 3 ]; then
    echo "$(date '+%F %T') rkhunter reported $RK warnings - /var/log/rkhunter.log" > "$STATE/rootkit-error"
  else
    rm -f "$STATE/rootkit-error"
  fi
fi

# ---------- 6. certificate ----------
EXP=""
if bl_have certbot; then
  EXP=$(certbot certificates 2>/dev/null | grep -oE 'VALID: [0-9]+ day' | grep -oE '[0-9]+' | sort -n | head -1)
  if [ -n "$EXP" ] && [ "$EXP" -lt 21 ]; then
    echo "$(date '+%F %T') certificate expires in $EXP days" > "$STATE/cert-error"
    problem "certificate expires in $EXP days"
  elif [ -n "$EXP" ] && [ -s "$STATE/cert-error" ] && grep -q 'expires' "$STATE/cert-error"; then
    rm -f "$STATE/cert-error"
  fi
fi

# ---------- 7. write the state ----------
if [ -n "$problems" ]; then
  prev=$(cut -d' ' -f3- "$STATE/health-error" 2>/dev/null)
  echo "$(date '+%F %T') $problems" > "$STATE/health-error"
  # notify only when the problem changes - not the same one every 6 hours
  [ "$prev" != "$problems" ] && bl_notify "problem" "$problems"
else
  if [ -s "$STATE/health-error" ]; then
    bl_notify "resolved" "the previous problem is gone"
  fi
  rm -f "$STATE/health-error"
fi

drops() { nft list chain inet "$1" input 2>/dev/null | grep 'drop' | grep -oE 'packets [0-9]+' | awk '{s+=$2} END{print s+0}'; }
{
  echo "time=\"$(date '+%F %T')\""
  echo "site=$BL_SITE_CODE"
  echo "cert_days=${EXP:-?}"
  echo "attackers=$(bl_count abuseblock attackers)"
  echo "dropped_geo=$(drops geoblock)"
  echo "dropped_attackers=$(drops abuseblock)"
  echo "dropped_proxy=$(drops proxyblock)"
} > "$STATE/health"
exit 0
