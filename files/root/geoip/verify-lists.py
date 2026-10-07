#!/usr/bin/env python3
"""Checks the generated nft files BEFORE they are applied.

Usage: verify-lists.py [DIR_TO_CHECK] [CURRENT_DIR]
  both default to /etc/nftables.d (BLOCKLIST_OUT / BLOCKLIST_NFT_DIR)
A non-zero exit means nothing may be applied.

Checks:
  - all three files exist and were not silently truncated (MIN_*, and >= MIN_RATIO of current)
  - every table has the hold rule before its drop rule
  - the server, the owner, Googlebot, Bingbot and public DNS are not blocked
  - no search engine prefix and no allowlisted country range is blocked
  - the allowlists exist
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config  # noqa: E402

DIR = sys.argv[1] if len(sys.argv) > 1 else config.OUT
LIVE = sys.argv[2] if len(sys.argv) > 2 else config.LIVE
TABLES = ('geoblock', 'abuseblock', 'proxyblock')
BLOCKING_SET = {'abuseblock': 'attackers', 'proxyblock': 'proxy'}
errors = []


def count(table, sets):
    if table == 'geoblock':
        return sum(len(v) for k, v in sets.items() if k != 'allowed')
    return len(sets.get(BLOCKING_SET[table], []))


parsed = {}
for table in TABLES:
    r = config.read_sets(f'{DIR}/{table}.nft')
    if r is None:
        errors.append(f'{table}: {DIR}/{table}.nft does not exist')
        parsed[table] = ({}, '')
    else:
        parsed[table] = r

# --- 1. sizes: absolute minimum and comparison with the current lists ---
for table in TABLES:
    sets, txt = parsed[table]
    n = count(table, sets)
    if n < config.MINIMUM[table]:
        errors.append(f'{table}: only {n} intervals, expected >= {config.MINIMUM[table]}')
    if os.path.realpath(DIR) != os.path.realpath(LIVE):
        r = config.read_sets(f'{LIVE}/{table}.nft')
        if r:
            current = count(table, r[0])
            if current and n < current * config.MIN_RATIO:
                errors.append(f'{table}: {n} intervals while {current} are current - '
                              f'a drop of more than {int((1 - config.MIN_RATIO) * 100)}% (silently truncated list?)')

# --- 2. the hold rule must exist and come before the drop rule ---
rule = config.guard_rule().split(' comment')[0]
for table in TABLES:
    txt = parsed[table][1]
    if not txt:
        continue
    i, j = txt.find(rule), txt.find(' drop')
    if i < 0:
        errors.append(f'{table}: missing the hold rule ({rule})')
    elif j >= 0 and i > j:
        errors.append(f'{table}: the hold rule comes AFTER the drop rule')

# --- 3. the allowlist must not be blocked ---
allow = config.networks(config.ALLOW)
if len(allow) < 20:
    errors.append(f'allow.txt has only {len(allow)} prefixes - search engine ranges are broken')
allowed_zones = []
for cc in config.CC_ALLOW:
    allowed_zones += config.networks(f'{config.HOME}/zones/{cc}.zone')
CRITICAL = config.critical()

for table, key in BLOCKING_SET.items():
    nets = parsed[table][0].get(key, [])
    if not nets:
        continue
    idx = config.Intervals(nets)
    for ip in CRITICAL:
        if idx.contains(ip):
            errors.append(f'{table}: CRITICAL address {ip} is blocked')
    hits = [str(a) for a in allow if idx.overlaps(a)]
    if hits:
        errors.append(f'{table}: blocks {len(hits)} search engine prefixes, e.g. {hits[:3]}')
    zone_hits = sum(1 for b in allowed_zones if idx.overlaps(b))
    if zone_hits:
        errors.append(f'{table}: blocks {zone_hits} ranges of allowlisted countries ({" ".join(config.CC_ALLOW)})')

geo = parsed['geoblock'][0]
if geo:
    allowed = config.Intervals(geo.get('allowed', []))
    for name, nets in geo.items():
        if name == 'allowed' or not nets:
            continue
        idx = config.Intervals(nets)
        for ip in config.SERVER_IPS + config.OWNER_IPS:
            if idx.contains(ip) and not allowed.contains(ip):
                errors.append(f'geoblock: address {ip} (server/owner) is in the blocked country {name}')

# --- 4. the allowlists exist ---
if config.CC_ALLOW and parsed['geoblock'][1] and not geo.get('allowed'):
    errors.append("geoblock: set 'allowed' is missing or empty")
if parsed['abuseblock'][1] and len(parsed['abuseblock'][0].get('allowlist', [])) < 20:
    errors.append("abuseblock: set 'allowlist' is missing or too small")

os.makedirs(config.STATE, exist_ok=True)
if errors:
    print('VERIFICATION FAILED:')
    for e in errors:
        print('  -', e)
    with open(f'{config.STATE}/last-verify', 'w') as fh:
        fh.write('FAILED\n' + '\n'.join(errors) + '\n')
    sys.exit(1)
print('verification: all good')
for table in TABLES:
    for k, v in parsed[table][0].items():
        print(f'  {table}.{k}: {len(v)} intervals')
with open(f'{config.STATE}/last-verify', 'w') as fh:
    fh.write('OK\n')
sys.exit(0)
