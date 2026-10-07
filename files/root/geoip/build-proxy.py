#!/usr/bin/env python3
"""Merges the accumulated proxy list (FINAL, /root/final) with fresh proxy/Tor
lists and generates proxyblock.nft. Blocks ONLY tcp 80/443 - on purpose, so
this list can never lock out SSH.

The extended list is written to FINAL.new; blocklist-update.sh promotes it only
after the new blocks pass every check.
"""
import glob
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config  # noqa: E402

config.validate()

SRCDIR = f'{config.HOME}/proxy'
OUT = f'{config.OUT}/proxyblock.nft'

nets, stats = set(), {}
if os.path.exists(config.FINAL):
    n0 = len(nets)
    nets.update(config.networks(config.FINAL))
    stats['final (accumulated)'] = len(nets) - n0
for path in sorted(glob.glob(f'{SRCDIR}/l_*')):
    n0 = len(nets)
    nets.update(config.networks(path))
    stats[os.path.basename(path)[2:]] = len(nets) - n0

safe = config.Intervals(config.safe_networks())
kept, dropped = [], []
for n in nets:
    (dropped if safe.overlaps(n) else kept).append(n)
collapsed = list(config.ipaddress.collapse_addresses(kept))

print('  SOURCES:')
for k, v in stats.items():
    print(f'    {v:>8,} new  {k}')
print('  -----------------------------')
print(f'    {len(nets):>8,} unique in total')
print(f'    {len(dropped):>8,} removed by the safety filter')
print(f'    {len(collapsed):>8,} after collapsing into CIDR intervals')

lines = config.header('proxyblock', 'Proxy / Tor / anonymizers. Blocks ONLY tcp 80/443',
                      'build-proxy.py')
lines += config.nft_set('proxy', collapsed, f'proxy/tor, {len(collapsed)} intervals')
lines += ['\tchain input {',
          '\t\ttype filter hook input priority -5; policy accept;',
          '\t\tct state established,related accept',
          '\t\tiif lo accept',
          '\t\t' + config.guard_rule(),
          '\t\tip saddr @proxy tcp dport { 80, 443 } counter drop',
          '\t}', '}']
config.write_atomic(OUT, lines)
print(f'  written: {OUT}')

with open(config.FINAL + '.new', 'w') as fh:
    for n in collapsed:
        fh.write((str(n.network_address) if n.prefixlen == 32 else str(n)) + '\n')
print(f'  extended list: {config.FINAL}.new ({len(collapsed)} lines)')
