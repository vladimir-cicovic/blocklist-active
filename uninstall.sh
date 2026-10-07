#!/bin/bash
# Removes blocklist-active from the machine.
#
#   ./uninstall.sh            removes the blocks, timers and scripts; data and config stay
#   ./uninstall.sh --purge    also deletes /etc/blocklist.conf, /root/geoip, /var/lib/blocklist,
#                             the generated lists and /root/final
# Configuration snapshots in /var/backups/server-config are NEVER deleted automatically.
set -u
PURGE=0
[ "${1:-}" = --purge ] && PURGE=1
[ "$(id -u)" = 0 ] || { echo "root required" >&2; exit 1; }

# Legacy names: real unit and file names created by version 1.x on existing servers.
LEGACY_UNITS="bekap-konfiguracije.service bekap-konfiguracije.timer bekap-failed.service"
LEGACY_SCRIPT=/usr/local/sbin/bekap-konfiguracije.sh

echo "== stopping timers and services"
for u in blocklist-update@abuse.timer blocklist-update@geo.timer blocklist-update@proxy.timer \
         blocklist-health.timer certbot-canary.timer blocklist-backup.timer \
         blocklist-rollback.timer blocklist.service $LEGACY_UNITS; do
  systemctl disable --now "$u" >/dev/null 2>&1 || true
done
systemctl reset-failed 'blocklist*' >/dev/null 2>&1 || true

echo "== removing the nftables tables"
for t in geoblock abuseblock proxyblock blocklist_guard; do
  nft delete table inet "$t" 2>/dev/null && echo "   inet $t"
done

echo "== removing scripts and units"
rm -f /etc/systemd/system/blocklist.service /etc/systemd/system/blocklist-update@.service \
      /etc/systemd/system/blocklist-update@abuse.timer /etc/systemd/system/blocklist-update@geo.timer \
      /etc/systemd/system/blocklist-update@proxy.timer /etc/systemd/system/blocklist-failed@.service \
      /etc/systemd/system/blocklist-health.service /etc/systemd/system/blocklist-health.timer \
      /etc/systemd/system/certbot-canary.service /etc/systemd/system/certbot-canary.timer \
      /etc/systemd/system/blocklist-backup.service /etc/systemd/system/blocklist-backup.timer \
      /etc/systemd/system/blocklist-backup-failed.service
for u in $LEGACY_UNITS; do rm -f "/etc/systemd/system/$u"; done
rm -f /usr/local/sbin/blocklist /usr/local/sbin/blocklist-update.sh /usr/local/sbin/blocklist-health.sh \
      /usr/local/sbin/blocklist-backup.sh /usr/local/sbin/certbot-canary.sh "$LEGACY_SCRIPT"
rm -rf /usr/local/lib/blocklist
rm -f /etc/update-motd.d/99-blocklist-status /etc/profile.d/blocklist-status.sh
rm -f /etc/letsencrypt/renewal-hooks/pre/00-blocklist-off.sh /etc/letsencrypt/renewal-hooks/post/99-blocklist-on.sh
# the nginx deploy hook stays - certificate renewal needs it with or without blocks
systemctl daemon-reload

if [ "$PURGE" = 1 ]; then
  echo "== deleting data and configuration (--purge)"
  rm -rf /root/geoip /var/lib/blocklist
  rm -f /etc/blocklist.conf /root/final /root/final.new
  rm -f /etc/nftables.d/geoblock.nft /etc/nftables.d/abuseblock.nft /etc/nftables.d/proxyblock.nft
  rmdir /etc/nftables.d 2>/dev/null || true
else
  echo "== data kept: /etc/blocklist.conf /root/geoip /var/lib/blocklist /etc/nftables.d (--purge deletes them)"
fi
[ -d /var/backups/server-config ] && echo "== configuration snapshots stay in /var/backups/server-config"
echo "done."
