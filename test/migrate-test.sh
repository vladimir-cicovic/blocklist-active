#!/bin/sh
# test/migrate-test.sh - upgrade from the 1.x kit to blocklist-active 2.0,
# the same path as on a production server: old kit installed, then the new install.sh on top.
#
#   OLD=/path/to/1.x-kit sh test/migrate-test.sh
#
# The old kit is not part of the repository (it comes from the server). Uses the
# image bl-test:debian-12 (build it with: sh test/matrix.sh up debian-12).
set -u
KIT=$(cd "$(dirname "$0")/.." && pwd)
OLD="${OLD:?set OLD=/path/to/1.x-kit}"
C=bl-migrate
RES="$KIT/test/results"; mkdir -p "$RES"
log() { printf '%s %s\n' "$(date '+%T')" "$*"; }

docker rm -f $C >/dev/null 2>&1
docker run -d --name $C --hostname $C --privileged --cgroupns=private --network blnet \
  --tmpfs /run --tmpfs /run/lock -v bl-cache:/var/cache/blocklist-src bl-test:debian-12 >/dev/null || exit 1
i=0; while [ $i -lt 60 ]; do
  case "$(docker exec $C systemctl is-system-running 2>/dev/null)" in running|degraded) break ;; esac
  i=$((i + 1)); sleep 1
done
IP=$(docker inspect -f '{{.NetworkSettings.Networks.blnet.IPAddress}}' $C)
log "container $C ($IP)"

docker cp "$OLD/." $C:/opt/old
T=/tmp/blkit-migrate.$$; rm -rf $T; mkdir -p $T
cp -r "$KIT/install.sh" "$KIT/uninstall.sh" "$KIT/VERSION" "$KIT/files" $T/
docker cp $T/. $C:/opt/kit; rm -rf $T
docker exec -i $C sh -c 'cat > /opt/old.conf' <<EOF
SITE_URL="http://bl-site/"
SSH_PORT="22"
SERVER_IPS="$IP"
OWNER_IPS="198.51.100.7"
COUNTRIES="ir ru cn br co bg ro sc"
WHITELIST_CC="ba"
EOF

log "1/3 old kit (1.x)"
docker exec $C sh -c 'apt-get update -qq && apt-get install -y -qq --no-install-recommends iproute2 ca-certificates >/dev/null'
docker exec $C bash /opt/old/install.sh --config /opt/old.conf --rollback 3600 >"$RES/migrate.old.log" 2>&1
log "   old install rc=$? (log: $RES/migrate.old.log)"
docker exec $C systemctl stop blocklist-rollback.timer 2>/dev/null

log "2/3 upgrade to 2.0 (the existing config is kept)"
docker exec $C bash /opt/kit/install.sh --no-bootstrap --hold-ip 203.0.113.77 --hold 5 --rollback 3600 \
  >"$RES/migrate.new.log" 2>&1
log "   new install rc=$? (log: $RES/migrate.new.log)"
docker exec $C /usr/local/sbin/blocklist confirm >/dev/null 2>&1

log "3/3 checks"
docker exec -i $C bash -s >"$RES/migrate.test.log" 2>&1 <<'EOF'
PASS=0; FAIL=0
check() { if [ "$1" = 0 ]; then PASS=$((PASS+1)); echo "  PASS $2"; else FAIL=$((FAIL+1)); echo "  FAIL $2"; fi; }
! grep -qE 'nftables\.d/(geoblock|abuseblock|proxyblock)' /etc/nftables.conf; check $? "include lines removed from /etc/nftables.conf"
ls /etc/nftables.conf.bak-blocklist-* >/dev/null 2>&1; check $? "original nftables.conf kept (.bak-blocklist-*)"
[ ! -e /etc/letsencrypt/renewal-hooks/pre/00-nft-off.sh ] && [ ! -e /etc/letsencrypt/renewal-hooks/post/99-nft-on.sh ]
check $? "old certbot hooks removed"
[ -x /etc/letsencrypt/renewal-hooks/pre/00-blocklist-off.sh ] && [ -x /etc/letsencrypt/renewal-hooks/post/99-blocklist-on.sh ]
check $? "new certbot hooks installed"
[ ! -e /var/lib/blocklist/last-good.nft ]; check $? "last-good.nft (1.x) removed"
ls /etc/systemd/system | grep -q '^bekap-'; [ $? = 1 ]; check $? "old backup units removed"
systemctl is-enabled --quiet blocklist-backup.timer; check $? "blocklist-backup.timer enabled"
[ ! -e /root/geoip/konfig.py ] && [ -e /root/geoip/config.py ]; check $? "konfig.py replaced by config.py"
grep -q 'SITE_URL="http://bl-site/"' /etc/blocklist.conf; check $? "existing /etc/blocklist.conf kept"
grep -q 'set cc_ru' /etc/nftables.d/geoblock.nft; check $? "geoblock regenerated with cc_ set names (rebuild, no download)"
grep -q 'set attackers' /etc/nftables.d/abuseblock.nft; check $? "abuseblock regenerated with English set names"
for t in geoblock abuseblock proxyblock; do
  grep -q 'meta mark &' /etc/nftables.d/$t.nft; check $? "$t.nft has the hold rule"
done
systemctl is-active --quiet blocklist.service; check $? "blocklist.service is active"
/usr/local/sbin/blocklist-update.sh abuse >/tmp/u.log 2>&1; check $? "the daily refresh (abuse) passes after the upgrade"
/usr/local/sbin/blocklist-health.sh >/dev/null 2>&1
grep -q '^site=200' /var/lib/blocklist/health && [ ! -s /var/lib/blocklist/health-error ]
check $? "health without problems"
echo "== RESULT: $PASS passed, $FAIL failed"
EOF
cat "$RES/migrate.test.log"

log "container restart (boot): nftables.service from 1.x, then blocklist.service"
docker restart $C >/dev/null
i=0; while [ $i -lt 60 ]; do
  case "$(docker exec $C systemctl is-system-running 2>/dev/null)" in running|degraded) break ;; esac
  i=$((i + 1)); sleep 1
done
n=$(docker exec $C nft list tables 2>/dev/null | grep -cE 'inet (blocklist_guard|geoblock|abuseblock|proxyblock)$')
if [ "$n" = 4 ]; then echo "  PASS all 4 tables loaded after boot"; else echo "  FAIL only $n of 4 tables loaded after boot"; fi
docker exec $C systemctl is-active blocklist.service
