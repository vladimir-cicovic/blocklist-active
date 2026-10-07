#!/bin/bash
# blocklist-update.sh {geo|abuse|proxy|all|rebuild}
#
# Downloads the lists, generates the nftables files into a STAGING directory,
# VERIFIES them, applies them, checks the site and only then promotes them to
# /etc/nftables.d. If anything fails, the kernel gets back what is in
# /etc/nftables.d - a version that has already passed every check. Other tables
# (Docker, firewalld, ufw) are never touched: there is no 'flush ruleset'.
#
#   geo      country zones (ipdeny)                  - weekly
#   abuse    attackers: public lists + own logs      - daily
#   proxy    proxy and Tor lists                     - weekly
#   all      all three
#   rebuild  regenerate everything from local data, WITHOUT downloading
#            (after editing /etc/blocklist.conf)
set -u
MODE="${1:-all}"
case "$MODE" in
  geo|abuse|proxy|all|rebuild) ;;
  *) echo "usage: $0 {geo|abuse|proxy|all|rebuild}" >&2; exit 2 ;;
esac

BL_TAG=blocklist
# shellcheck source=/dev/null
. /usr/local/lib/blocklist/common.sh
mkdir -p "$STATE"

fail() {
  bl_log "ERROR: $*"
  echo "$(date '+%F %T') $*" > "$STATE/last-error"
  exit 1
}

[ "$(id -u)" = 0 ] || fail "root required"
bl_lock -w 1800 || fail "another update is running ($LOCK)"
[ -n "$SERVER_IPS" ] || fail "SERVER_IPS is not set in $CONF"

download() { [ "$MODE" = all ] || [ "$MODE" = "$1" ]; }
generate() { [ "$MODE" = all ] || [ "$MODE" = rebuild ] || [ "$MODE" = "$1" ]; }
py() { python3 "$GEOIP/$1" || fail "$1 failed"; }

STAGE="$STATE/staging"
rm -rf "$STAGE"
mkdir -p "$STAGE" "$NFT_DIR" "$GEOIP"/{zones,proxy,abuse,crawlers}
# tables that are not regenerated now enter verification as they are on disk
for t in $TABLES; do
  [ -f "$NFT_DIR/$t.nft" ] && cp -p "$NFT_DIR/$t.nft" "$STAGE/"
done
export BLOCKLIST_OUT="$STAGE"
FAILED_LISTS=""

# ---------- 1. country zones ----------
if download geo; then
  cd "$GEOIP" || fail "$GEOIP does not exist"
  bl_fetch https://www.ipdeny.com/ipblocks/data/countries/all-zones.tar.gz all-zones.tar.gz.new 300 \
    || fail "ipdeny.com is unreachable"
  rm -rf zones.new && mkdir zones.new
  tar xzf all-zones.tar.gz.new -C zones.new || { rm -rf zones.new all-zones.tar.gz.new; fail "zone archive is corrupt"; }
  for cc in $COUNTRIES $WHITELIST_CC; do
    [ -s "zones.new/$cc.zone" ] || { rm -rf zones.new; fail "zone '$cc' is missing or empty"; }
  done
  rm -rf zones.old
  [ -d zones ] && mv zones zones.old
  mv zones.new zones && rm -rf zones.old
  mv -f all-zones.tar.gz.new all-zones.tar.gz
  bl_log "country zones downloaded"
fi
generate geo && py gen-geoblock.py

# ---------- 2. proxy and Tor ----------
if download proxy; then
  cd "$GEOIP/proxy" || fail "$GEOIP/proxy does not exist"
  for l in proxylists_30d proxyrss_30d ri_web_proxies_30d sslproxies_30d socks_proxy_30d \
           xroxy_30d proxz_30d dm_tor et_tor; do
    bl_fetch "https://iplists.firehol.org/files/$l.ipset" "l_$l" 120 \
      || bl_fetch "https://iplists.firehol.org/files/$l.netset" "l_$l" 120 \
      || FAILED_LISTS="$FAILED_LISTS $l"
  done
  bl_fetch https://check.torproject.org/torbulkexitlist l_torbulkexit 60 || FAILED_LISTS="$FAILED_LISTS torbulkexit"
  bl_log "proxy lists downloaded"
fi
generate proxy && py build-proxy.py

# ---------- 3. attackers ----------
if download abuse; then
  # search engine ranges MUST be fresh - otherwise Googlebot may end up blocked
  cd "$GEOIP/crawlers" || fail "$GEOIP/crawlers does not exist"
  for u in "googlebot|https://developers.google.com/static/search/apis/ipranges/googlebot.json" \
           "bingbot|https://www.bing.com/toolbox/bingbot.json"; do
    n="${u%%|*}"; url="${u#*|}"
    if bl_fetch "$url" "$n.json.new" 60 && grep -q ipv4Prefix "$n.json.new"; then
      mv -f "$n.json.new" "$n.json"
    else
      rm -f "$n.json.new"; FAILED_LISTS="$FAILED_LISTS $n"
    fi
  done
  py crawlers-allow.py

  cd "$GEOIP/abuse" || fail "$GEOIP/abuse does not exist"
  for l in firehol_level1 firehol_level2 firehol_level3 spamhaus_drop spamhaus_edrop dshield \
           bruteforceblocker greensnow cybercrime blocklist_de blocklist_de_ssh blocklist_de_apache \
           blocklist_de_bruteforce blocklist_de_strongips firehol_webserver firehol_abusers_30d \
           botscout_30d stopforumspam_30d cleantalk_30d; do
    bl_fetch "https://iplists.firehol.org/files/$l.netset" "l_$l" 180 \
      || bl_fetch "https://iplists.firehol.org/files/$l.ipset" "l_$l" 180 \
      || FAILED_LISTS="$FAILED_LISTS $l"
  done
  # direct high-confidence sources (independent of the firehol mirror)
  for u in "et_compromised|https://rules.emergingthreats.net/blockrules/compromised-ips.txt" \
           "cins|https://cinsscore.com/list/ci-badguys.txt" \
           "spamhaus_drop_direct|https://www.spamhaus.org/drop/drop.txt"; do
    bl_fetch "${u#*|}" "l_${u%%|*}" 120 || FAILED_LISTS="$FAILED_LISTS ${u%%|*}"
  done
  # ThreatFox: confirmed IOCs, confidence 100 only
  if bl_fetch "https://threatfox.abuse.ch/export/csv/ip-port/recent/" n_threatfox 120; then
    if python3 - n_threatfox l_threatfox <<'PY'
import csv, sys
src, dst = sys.argv[1], sys.argv[2]
rows = set()
with open(src, errors='ignore') as fh:
    for l in csv.reader(fh, skipinitialspace=True):
        if len(l) > 9 and ':' in l[2] and l[9].strip() == '100':
            rows.add(l[2].split(':')[0].strip())
assert rows
with open(dst, 'w') as fh:
    fh.write('\n'.join(sorted(rows)) + '\n')
PY
    then :; else FAILED_LISTS="$FAILED_LISTS threatfox(format)"; fi
    rm -f n_threatfox
  else
    FAILED_LISTS="$FAILED_LISTS threatfox"
  fi
  # AbuseIPDB: only if a key exists (confidence >= 90)
  if [ -s "$GEOIP/abuseipdb.key" ]; then
    hdr=$(mktemp)
    printf 'Key: %s\nAccept: application/json\n' "$(tr -d ' \n' < "$GEOIP/abuseipdb.key")" > "$hdr"
    if curl -sSfL -m 120 -H @"$hdr" -o n_abuseipdb.json \
         "https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=90&limit=10000" 2>/dev/null; then
      python3 - n_abuseipdb.json l_abuseipdb <<'PY' || FAILED_LISTS="$FAILED_LISTS abuseipdb(format)"
import json, sys
d = json.load(open(sys.argv[1]))
assert d.get('data')
open(sys.argv[2], 'w').write('\n'.join(x['ipAddress'] for x in d['data'] if 'ipAddress' in x) + '\n')
PY
    else
      FAILED_LISTS="$FAILED_LISTS abuseipdb"
    fi
    rm -f "$hdr" n_abuseipdb.json
  fi
  rm -f n_*
  bl_log "attacker lists downloaded"
fi
generate abuse && py build-abuse.py

[ -n "$FAILED_LISTS" ] && bl_log "WARNING: not refreshed (previous version is used):$FAILED_LISTS"

# ---------- 4. VERIFY before applying ----------
python3 "$GEOIP/verify-lists.py" "$STAGE" "$NFT_DIR" || fail "VERIFICATION FAILED - nothing was applied"
for t in $TABLES; do
  nft -c -f "$STAGE/$t.nft" || fail "syntax check failed: $t.nft - nothing was applied"
done

promote() {
  local t
  for t in $TABLES; do
    cp "$STAGE/$t.nft" "$NFT_DIR/.$t.nft.tmp" && mv -f "$NFT_DIR/.$t.nft.tmp" "$NFT_DIR/$t.nft"
  done
  [ -s "$FINAL.new" ] && mv -f "$FINAL.new" "$FINAL"
  rm -rf "$STAGE"
}

success() {   # success APPLIED SITE_CODE
  rm -f "$STATE/last-error"
  {
    echo "time=\"$(date '+%F %T')\""
    echo "mode=$MODE"
    echo "applied=$1"
    echo "geoblock=$(tr -cd , < "$NFT_DIR/geoblock.nft" 2>/dev/null | wc -c)"
    echo "attackers=$(bl_count abuseblock attackers)"
    echo "proxy=$(bl_count proxyblock proxy)"
    echo "site=$2"
    echo "stale_lists=\"${FAILED_LISTS# }\""
  } > "$STATE/last-success"
}

# ---------- 5. disabled? refresh the files, but do not apply ----------
if [ -e "$STATE/disabled" ]; then
  promote
  success no "-"
  bl_log "OK ($MODE): lists refreshed and verified, but NOT applied - protection is disabled (blocklist enable)"
  exit 0
fi

# ---------- 6. apply ----------
bl_guard_ensure || fail "the guard table cannot be created"
for t in $TABLES; do
  if ! nft -f "$STAGE/$t.nft"; then
    bl_load_tables "$NFT_DIR"
    fail "applying $t failed - lists from $NFT_DIR restored"
  fi
done

# ---------- 7. the site must still work ----------
sleep 2
if ! bl_site_check; then
  bl_load_tables "$NFT_DIR"
  fail "site $SITE_URL returned $BL_SITE_CODE after apply - previous lists restored"
fi
[ -z "$SITE_URL" ] && bl_log "SITE_URL is not set - site check skipped"

# ---------- 8. success: only now do the new lists become current ----------
promote
bl_record_loaded
success yes "$BL_SITE_CODE"
bl_log "OK ($MODE): lists applied and verified, site $BL_SITE_CODE"
exit 0
