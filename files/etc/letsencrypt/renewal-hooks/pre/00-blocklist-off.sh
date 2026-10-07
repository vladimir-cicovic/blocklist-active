#!/bin/sh
# Let's Encrypt validates the HTTP-01 challenge from addresses it does NOT publish.
# If one of them is on the attacker or proxy list, the renewal fails silently and
# the certificate expires. So these two tables are removed for the few seconds
# of validation. Geo blocks stay. The post hook restores them even if renewal fails.
exec /usr/local/sbin/blocklist cert-pre
