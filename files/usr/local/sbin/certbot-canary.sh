#!/bin/bash
# certbot-canary.sh - weekly certificate renewal dry run.
# It also runs the renewal hooks, so it proves that removing and restoring the
# blocks works. A broken renewal shows up weeks before the certificate expires.
set -u
BL_TAG=certbot-canary
# shellcheck source=/dev/null
. /usr/local/lib/blocklist/common.sh
mkdir -p "$STATE"

if ! bl_have certbot; then
  bl_log "certbot is not installed - nothing to check"
  exit 0
fi
if certbot renew --dry-run > "$STATE/certbot-canary.log" 2>&1; then
  bl_log "renewal dry run OK"
  grep -q 'DRY RUN' "$STATE/cert-error" 2>/dev/null && rm -f "$STATE/cert-error"
  exit 0
fi
echo "$(date '+%F %T') CERTIFICATE RENEWAL DRY RUN FAILED - $STATE/certbot-canary.log" > "$STATE/cert-error"
bl_log "RENEWAL DRY RUN FAILED"
bl_notify "certificate" "renewal dry run (certbot renew --dry-run) failed"
exit 1
