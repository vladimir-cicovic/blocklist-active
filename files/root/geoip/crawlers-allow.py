#!/usr/bin/env python3
"""Extracts the IPv4 prefixes of search engine crawlers (googlebot.json,
bingbot.json) into allow.txt. Keeps the old allow.txt when the result looks
suspiciously small."""
import glob
import ipaddress
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config  # noqa: E402

DIR = f'{config.HOME}/crawlers'
out = set()
for path in glob.glob(f'{DIR}/*.json'):
    try:
        with open(path) as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        continue
    for p in data.get('prefixes', []):
        v = p.get('ipv4Prefix') or p.get('ipv4prefix')
        if v:
            try:
                out.add(str(ipaddress.ip_network(v, strict=False)))
            except ValueError:
                pass

previous = 0
if os.path.exists(config.ALLOW):
    with open(config.ALLOW) as fh:
        previous = sum(1 for line in fh if line.strip())
if len(out) < max(20, previous // 2):
    print(f'crawlers-allow: SUSPICIOUSLY few prefixes ({len(out)}, previously {previous}) - keeping the old allow.txt')
    sys.exit(0 if previous else 1)
with open(config.ALLOW + '.tmp', 'w') as fh:
    fh.write('\n'.join(sorted(out, key=lambda s: ipaddress.ip_network(s))) + '\n')
os.replace(config.ALLOW + '.tmp', config.ALLOW)
print(f'crawlers-allow: {len(out)} prefixes')
