#!/usr/bin/env python3
"""Would an address be blocked, and by which table. Called by 'blocklist check'.

Reads the current lists from /etc/nftables.d (the same ones the kernel holds -
the health check makes sure of that). One pass for all addresses: every
'nft get element' call loads the whole ruleset (~1.5 s), so checking through
the kernel would take tens of seconds per address.

Usage: check-ip.py IP [IP...]    exit 1 if at least one address is blocked
"""
import ipaddress
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config  # noqa: E402

ips = sys.argv[1:]
for ip in ips:
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        sys.exit(f'not an IPv4 address: {ip}')

idx = {}
for table in ('geoblock', 'abuseblock', 'proxyblock'):
    r = config.read_sets(f'{config.LIVE}/{table}.nft')
    idx[table] = {k: config.Intervals(v) for k, v in (r[0] if r else {}).items()}

rc = 0
for ip in ips:
    hits, notes = [], []
    geo = idx['geoblock']
    if 'allowed' in geo and geo['allowed'].contains(ip):
        notes.append('allowlisted country (geoblock.allowed)')
    else:
        hits += [f'geoblock:{k[3:]}' for k, v in geo.items() if k.startswith('cc_') and v.contains(ip)]
    ab = idx['abuseblock']
    if 'allowlist' in ab and ab['allowlist'].contains(ip):
        notes.append('attacker allowlist (abuseblock.allowlist)')
    elif 'attackers' in ab and ab['attackers'].contains(ip):
        hits.append('abuseblock:attackers')
    px = idx['proxyblock']
    if 'proxy' in px and px['proxy'].contains(ip):
        hits.append('proxyblock:proxy(tcp/80,443)')
    if hits:
        rc = 1
        print(f'{ip}: BLOCKED -> {" ".join(hits)}')
    elif notes:
        print(f'{ip}: not blocked ({"; ".join(notes)})')
    else:
        print(f'{ip}: not blocked')
sys.exit(rc)
