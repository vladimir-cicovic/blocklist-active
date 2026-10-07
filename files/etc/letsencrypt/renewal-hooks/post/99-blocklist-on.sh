#!/bin/sh
# Restores the blocks after renewal (runs even when the renewal fails).
# Loads from /etc/nftables.d - the same, already verified lists.
exec /usr/local/sbin/blocklist cert-post
