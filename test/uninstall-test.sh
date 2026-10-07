#!/bin/sh
# test/uninstall-test.sh - removal, reinstall without download, --purge.
# Runs on the Docker host against a container already installed by test/matrix.sh:
#   sh test/uninstall-test.sh ubuntu-22.04
set -u
C="bl-${1:?usage: $0 DISTRO}"
docker exec -i "$C" bash -s <<'EOF'
PASS=0; FAIL=0
p() { if [ "$1" = 0 ]; then PASS=$((PASS+1)); echo "  PASS $2"; else FAIL=$((FAIL+1)); echo "  FAIL $2"; fi; }
cnt() { nft list tables 2>/dev/null | grep -cE 'inet (blocklist_guard|geoblock|abuseblock|proxyblock)$'; }

echo "== uninstall (without --purge)"
bash /opt/kit/uninstall.sh >/tmp/un.log 2>&1; p $? "uninstall.sh works"
[ "$(cnt)" = 0 ]; p $? "all 4 tables removed"
[ ! -e /usr/local/sbin/blocklist ] && [ ! -e /etc/systemd/system/blocklist.service ] && [ ! -d /usr/local/lib/blocklist ]
p $? "scripts, units and library removed"
! systemctl list-timers --all --no-pager | grep -q blocklist; p $? "no blocklist timers left"
[ -s /etc/blocklist.conf ] && [ -s /etc/nftables.d/abuseblock.nft ] && [ -d /root/geoip/zones ]; p $? "config and data kept"

echo "== reinstall without download (from local data)"
bash /opt/kit/install.sh --no-bootstrap --no-rollback --hold 0 >/tmp/re.log 2>&1; p $? "install.sh --no-bootstrap works"
[ "$(cnt)" = 4 ]; p $? "all 4 tables loaded again"
grep -q 'existing lists loaded\|lists regenerated' /tmp/re.log; p $? "local lists were used"

echo "== uninstall --purge"
bash /opt/kit/uninstall.sh --purge >/tmp/un2.log 2>&1; p $? "uninstall.sh --purge works"
[ ! -e /etc/blocklist.conf ] && [ ! -d /root/geoip ] && [ ! -d /var/lib/blocklist ] && [ ! -e /etc/nftables.d/abuseblock.nft ]
p $? "config and data deleted"
ls /var/backups/server-config/*.tar.gz >/dev/null 2>&1; p $? "configuration snapshots left untouched"
[ "$(cnt)" = 0 ]; p $? "no tables"
echo "== RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
EOF
