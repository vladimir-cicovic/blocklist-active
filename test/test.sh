#!/bin/bash
# test/test.sh - runs INSIDE a test container, after install.sh.
# Checks that the protection does what it claims and, just as important, that
# the safety brakes actually brake.
# NO pipefail: "nft ... | grep -q" may return 141 (SIGPIPE) and fail falsely.
set -u
PASS=0; FAIL=0
t_ok()  { PASS=$((PASS+1)); printf '  PASS %s\n' "$*"; }
t_bad() { FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$*"; }
check() { if [ "$1" = 0 ]; then t_ok "$2"; else t_bad "$2"; fi; }
head1() { printf '\n-- %s\n' "$*"; }
T0=$(date +%s)

# shellcheck source=/dev/null
. /usr/local/lib/blocklist/common.sh
. /etc/os-release
echo "== ${PRETTY_NAME:-?} | kernel $(uname -r) | $(nft --version) | $(python3 -V 2>&1)"

blocked_by() { /usr/local/sbin/blocklist check "$1" >/dev/null 2>&1; [ $? = 1 ]; }
tables_cnt() { nft list tables 2>/dev/null | grep -cE 'inet (geoblock|abuseblock|proxyblock)$'; }

# a foreign table - it must survive everything the protection does (no 'flush ruleset')
nft add table inet foreign_test
nft add chain inet foreign_test c '{ type filter hook input priority 50; policy accept; }'

head1 "1. Tables loaded, correct priorities"
for pair in "blocklist_guard:-20" "geoblock:filter - 10" "abuseblock:filter - 7" "proxyblock:filter - 5"; do
  t="${pair%%:*}"; p="${pair#*:}"
  nft list chain inet "$t" input 2>/dev/null | grep -qE "priority ($p|${p//filter - /-});"
  check $? "inet $t, priority $p"
done
systemctl is-active --quiet blocklist.service; check $? "blocklist.service is active"
systemctl is-enabled --quiet blocklist.service; check $? "blocklist.service is enabled at boot"

head1 "2. The hold rule comes BEFORE the drop rule"
for t in $TABLES; do
  nft list chain inet "$t" input 2>/dev/null | awk '/meta mark &/{m=NR} /drop/ && !d {d=NR} END{exit !(m && d && m<d)}'
  check $? "$t: hold rule before drop"
done

head1 "3. Set sizes"
n_geo=0; for cc in $COUNTRIES; do n_geo=$(( n_geo + $(bl_count geoblock "cc_$cc") )); done
n_ab=$(bl_count abuseblock attackers); n_px=$(bl_count proxyblock proxy)
echo "     geo ~$n_geo | attackers ~$n_ab | proxy ~$n_px"
[ "$n_geo" -gt 20000 ]; check $? "geoblock > 20,000"
[ "$n_ab" -gt 20000 ];  check $? "abuseblock > 20,000"
[ "$n_px" -gt 15000 ];  check $? "proxyblock > 15,000"

head1 "4. Countries whose codes are nftables keywords (ge, lt)"
for cc in ge lt; do
  nft list set inet geoblock "cc_$cc" >/dev/null 2>&1; check $? "set cc_$cc exists"
done

head1 "5. Allowlist - none of these may be blocked"
for ip in $SERVER_IPS $OWNER_IPS 66.249.66.1 40.77.167.29 8.8.8.8 1.1.1.1; do
  if blocked_by "$ip"; then t_bad "$ip IS blocked"; else t_ok "$ip is not blocked"; fi
done
for cc in $WHITELIST_CC; do
  ip=$(grep -m1 -oE '^[0-9.]+' "$GEOIP/zones/$cc.zone")
  ip="${ip%.*}.$(( ${ip##*.} + 1 ))"
  if blocked_by "$ip"; then t_bad "$cc address $ip IS blocked"; else t_ok "$cc address $ip is not blocked (allowlist)"; fi
done

head1 "6. Blocking actually catches"
RU=$(grep -m1 -oE '^[0-9.]+' "$GEOIP/zones/ru.zone"); RU="${RU%.*}.$(( ${RU##*.} + 10 ))"
blocked_by "$RU"; check $? "Russian address $RU is blocked"
bl_in_set geoblock cc_ru "$RU"; check $? "$RU is in set cc_ru"

head1 "7. proxyblock must not touch SSH"
nft list chain inet proxyblock input | grep -q 'tcp dport { 80, 443 }'; check $? "proxy rule limited to tcp 80/443"
port=$(bl_ssh_port)
if nft list chain inet proxyblock input | grep -qE "dport.*\b$port\b"; then t_bad "proxyblock mentions SSH port $port"
else t_ok "proxyblock does not mention SSH port $port"; fi

head1 "8. Hold - real packets through a network namespace"
TESTIP=203.0.113.10
echo "$TESTIP" > "$GEOIP/abuse/l_ztest"
/usr/local/sbin/blocklist-update.sh rebuild >/tmp/rebuild1.log 2>&1
check $? "rebuild with the local list l_ztest"
ip netns del bltest 2>/dev/null; ip link del blv0 2>/dev/null
ip netns add bltest
ip link add blv0 type veth peer name blv1
ip link set blv1 netns bltest
ip addr add 203.0.113.1/24 dev blv0 && ip link set blv0 up
ip -n bltest addr add "$TESTIP/24" dev blv1
ip -n bltest addr add "$RU/32" dev blv1
ip -n bltest link set blv1 up && ip -n bltest link set lo up
ip route add "$RU/32" dev blv0
ip -n bltest route add default dev blv1 2>/dev/null
systemd-run --quiet --unit=bl-listener python3 -m http.server 18080 --bind 203.0.113.1
sleep 1
probe() {   # probe SOURCE_ADDRESS -> 0 if a TCP connection succeeds
  ip netns exec bltest python3 - "$1" <<'PY'
import socket, sys
try:
    socket.create_connection(("203.0.113.1", 18080), timeout=2, source_address=(sys.argv[1], 0)).close()
except OSError:
    sys.exit(1)
PY
}
for src in "$TESTIP:abuseblock" "$RU:geoblock"; do
  ip="${src%%:*}"; tbl="${src#*:}"
  probe "$ip"; [ $? = 1 ]; check $? "$ip ($tbl) dropped without a hold"
  /usr/local/sbin/blocklist hold "$ip" 6 >/dev/null
  probe "$ip"; check $? "$ip passes while held (hold 6s)"
  sleep 8
  probe "$ip"; [ $? = 1 ]; check $? "$ip dropped again once the hold expires"
done
cnt=$(nft list chain inet blocklist_guard input | grep -oE 'packets [0-9]+' | awk '{print $2}')
[ "${cnt:-0}" -gt 0 ]; check $? "the guard counter recorded held packets ($cnt)"
/usr/local/sbin/blocklist hold "$TESTIP" 300 >/dev/null
systemctl restart blocklist.service
bl_in_set blocklist_guard hold "$TESTIP"; check $? "a held address survives a blocklist.service restart"
/usr/local/sbin/blocklist release "$TESTIP" >/dev/null
bl_in_set blocklist_guard hold "$TESTIP"; [ $? = 1 ]; check $? "blocklist release ends the hold"
systemctl stop bl-listener 2>/dev/null; ip link del blv0 2>/dev/null; ip netns del bltest 2>/dev/null

head1 "9. A failed site check restores the previous lists"
before=$(stat -c %Y "$NFT_DIR/abuseblock.nft")
sed 's|^SITE_URL=.*|SITE_URL="http://bl-site/500"|' /etc/blocklist.conf > /tmp/bad.conf
BLOCKLIST_CONF=/tmp/bad.conf /usr/local/sbin/blocklist-update.sh rebuild >/tmp/rebuild-bad.log 2>&1
[ $? != 0 ]; check $? "the update with a site returning 500 FAILED"
grep -q 'previous lists restored' "$STATE/last-error"; check $? "last-error says the previous lists were restored"
[ "$(stat -c %Y "$NFT_DIR/abuseblock.nft")" = "$before" ]; check $? "/etc/nftables.d untouched (new lists were not promoted)"
[ "$(tables_cnt)" = 3 ]; check $? "all three tables still loaded"
/usr/local/sbin/blocklist-update.sh rebuild >/tmp/rebuild2.log 2>&1
check $? "the next update with a working site passes"
[ ! -e "$STATE/last-error" ]; check $? "last-error removed after success"

head1 "10. Brakes in verify-lists.py"
V=/tmp/verify; rm -rf $V; mkdir -p $V
vcopy() { cp "$NFT_DIR"/*.nft $V/; }
verify_fails() { python3 "$GEOIP/verify-lists.py" $V "$NFT_DIR" >/tmp/verify.out 2>&1; [ $? != 0 ] && grep -q "$1" /tmp/verify.out; }
srv=$(echo "$SERVER_IPS" | awk '{print $1}')
vcopy; sed -i "0,/elements = { /s//&$srv\/32, /" $V/proxyblock.nft
verify_fails "CRITICAL address $srv"; check $? "server IP injected into the proxy list - caught"
vcopy
python3 - $V/abuseblock.nft <<'PY'
import sys
p = sys.argv[1]; t = open(p).read()
i = t.index('set attackers {'); j = t.index('elements = { ', i) + len('elements = { ')
open(p, 'w').write(t[:j] + '66.249.66.0/24, ' + t[j:])
PY
verify_fails "search engine"; check $? "Googlebot range injected - caught"
vcopy; echo "# empty" > $V/proxyblock.nft
verify_fails "proxyblock"; check $? "silently truncated proxy list - caught"
vcopy; sed -i '/meta mark &/d' $V/geoblock.nft
verify_fails "hold rule"; check $? "table without the hold rule - caught"
python3 "$GEOIP/verify-lists.py" "$NFT_DIR" "$NFT_DIR" >/dev/null 2>&1; check $? "correct lists pass verification"

head1 "11. Let's Encrypt window (cert-pre / cert-post)"
/usr/local/sbin/blocklist hold 203.0.113.99 300 >/dev/null
/usr/local/sbin/blocklist cert-pre
nft list table inet abuseblock >/dev/null 2>&1; [ $? = 1 ]; check $? "cert-pre removed abuseblock"
nft list table inet proxyblock >/dev/null 2>&1; [ $? = 1 ]; check $? "cert-pre removed proxyblock"
nft list table inet geoblock >/dev/null 2>&1; check $? "geoblock stayed"
/usr/local/sbin/blocklist cert-post
[ "$(tables_cnt)" = 3 ]; check $? "cert-post restored all three tables"
bl_in_set blocklist_guard hold 203.0.113.99; check $? "held addresses survive the certbot window"
/usr/local/sbin/blocklist release 203.0.113.99 >/dev/null

head1 "12. Health check"
echo "# test drift" >> "$NFT_DIR/proxyblock.nft"
/usr/local/sbin/blocklist-health.sh >/tmp/health.out 2>&1
grep -q 'reloading' /tmp/health.out; check $? "disk/kernel difference detected and reloaded"
/usr/local/sbin/blocklist-health.sh >/tmp/health.out 2>&1
grep -q '^site=200' "$STATE/health"; check $? "health follows the redirect (302 -> 200)"
[ ! -s "$STATE/health-error" ]; check $? "no health-error"
[ -s "$STATE/health-error" ] && sed 's/^/     /' "$STATE/health-error"

head1 "13. Rollback timer and disabling"
/usr/local/sbin/blocklist arm-rollback 30
systemctl is-active --quiet blocklist-rollback.timer; check $? "rollback armed"
/usr/local/sbin/blocklist confirm >/dev/null
systemctl is-active --quiet blocklist-rollback.timer; [ $? != 0 ]; check $? "blocklist confirm stops it"
/usr/local/sbin/blocklist arm-rollback 4
GONE=""
for _ in $(seq 1 20); do sleep 1; [ "$(tables_cnt)" = 0 ] && { GONE=1; break; }; done
[ -n "$GONE" ]; check $? "the rollback removed the blocks"
[ -e "$STATE/disabled" ]; check $? "the rollback left the 'disabled' flag"
/usr/local/sbin/blocklist load
[ "$(tables_cnt)" = 0 ]; check $? "load respects 'disabled' (no new lockout)"
/usr/local/sbin/blocklist-health.sh >/dev/null 2>&1
grep -q 'DISABLED' "$STATE/health-error"; check $? "health reports the disabled protection"
[ "$(tables_cnt)" = 0 ]; check $? "health does NOT restore the blocks while disabled"
/usr/local/sbin/blocklist enable >/dev/null
[ "$(tables_cnt)" = 3 ] && [ ! -e "$STATE/disabled" ]; check $? "blocklist enable restored the blocks"

head1 "14. Timers"
for u in blocklist-update@abuse.timer blocklist-update@geo.timer blocklist-update@proxy.timer \
         blocklist-health.timer blocklist-backup.timer; do
  systemctl is-enabled --quiet "$u"; check $? "$u enabled"
done
if command -v certbot >/dev/null; then
  systemctl is-enabled --quiet certbot-canary.timer; check $? "certbot-canary enabled (certbot exists)"
else
  systemctl is-enabled --quiet certbot-canary.timer; [ $? != 0 ]; check $? "certbot-canary disabled (no certbot)"
fi

head1 "15. Backup, status, MOTD"
/usr/local/sbin/blocklist-backup.sh >/dev/null 2>&1; check $? "the backup works without nginx"
/usr/local/sbin/blocklist status >/tmp/status.out 2>&1; check $? "blocklist status works"
/usr/local/sbin/blocklist motd >/dev/null 2>&1; check $? "blocklist motd works"

head1 "16. The environment is not damaged"
nft list table inet foreign_test >/dev/null 2>&1; check $? "the foreign nft table survived every operation"
getent hosts bl-site >/dev/null 2>&1; check $? "Docker DNS (NAT rules inside the container) still works"
if grep -rlE 'vladimircicovic|teamred|172\.236\.203' /usr/local/sbin/blocklist* /usr/local/lib/blocklist /root/geoip/*.py >/dev/null 2>&1; then
  t_bad "production values are hard-coded in the scripts"
else t_ok "no hard-coded production values"; fi
nft delete table inet foreign_test

printf '\n== RESULT: %d passed, %d failed (%ss)\n' "$PASS" "$FAIL" "$(( $(date +%s) - T0 ))"
[ "$FAIL" = 0 ]
