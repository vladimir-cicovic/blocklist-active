#!/usr/bin/env python3
"""Manual report: where the attacks come from (by country), from SSH and web logs.
Not part of the automation. Usage: python3 /root/geoip/classify.py"""
import bisect
import collections
import glob
import gzip
import ipaddress
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config  # noqa: E402

rows = []
for path in glob.glob(f'{config.HOME}/zones/*.zone'):
    cc = os.path.basename(path).split('.')[0].upper()
    for n in config.networks(path):
        rows.append((int(n.network_address), int(n.broadcast_address), cc))
rows.sort()
starts = [r[0] for r in rows]
print(f'  index: {len(rows)} CIDR blocks from {len(set(r[2] for r in rows))} countries')


def lookup(ip):
    try:
        v = int(ipaddress.IPv4Address(ip))
    except ValueError:
        return None
    i = bisect.bisect_right(starts, v) - 1
    return rows[i][2] if i >= 0 and v <= rows[i][1] else None


def read(patterns):
    for pattern in patterns:
        for path in glob.glob(pattern):
            opener = gzip.open if path.endswith('.gz') else open
            try:
                with opener(path, 'rb') as fh:
                    yield from fh
            except (OSError, EOFError):
                continue


ssh = collections.Counter()
pat = re.compile(rb'(?:Failed password|Invalid user).* from (\d{1,3}(?:\.\d{1,3}){3})')
for line in read(config.AUTH_LOGS):
    m = pat.search(line)
    if m:
        ssh[m.group(1).decode()] += 1

web = collections.Counter()
ip4 = re.compile(rb'^(\d{1,3}(?:\.\d{1,3}){3}) ')
for line in read(config.WEB_LOGS):
    m = ip4.match(line)
    if m:
        web[m.group(1).decode()] += 1

for name, counter in (('SSH BRUTE FORCE', ssh), ('WEB REQUESTS', web)):
    hits, ips, unknown = collections.Counter(), collections.defaultdict(set), 0
    for ip, n in counter.items():
        cc = lookup(ip)
        if cc is None:
            unknown += n
            continue
        hits[cc] += n
        ips[cc].add(ip)
    total = sum(hits.values()) + unknown
    print(f'\n== {name} - {total:,} records in total, {len(counter):,} IPs ==')
    if not total:
        continue
    print(f"  {'COUNTRY':<8}{'RECORDS':>12}{'SHARE':>8}{'IPs':>9}")
    for cc, n in hits.most_common(18):
        print(f'  {cc:<8}{n:>12,}{100 * n / total:>7.1f}%{len(ips[cc]):>9}')
    if unknown:
        print(f"  {'??':<8}{unknown:>12,}{100 * unknown / total:>7.1f}%")
