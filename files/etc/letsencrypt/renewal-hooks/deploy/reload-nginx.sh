#!/bin/sh
# nginx keeps the certificate in memory; without a reload the renewal has no effect.
if systemctl is-active --quiet nginx; then
  exec systemctl reload nginx
fi
