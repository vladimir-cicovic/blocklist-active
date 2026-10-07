#!/usr/bin/env python3
"""Generates geoblock.nft from the ipdeny zones in <HOME>/zones.

Country sets are named cc_<code> (for example cc_ru): some country codes are
nftables keywords (ge, lt, gt, ne...) and break loading when used as set names.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config  # noqa: E402

config.validate()

allowed = []
for cc, _ in config.WHITELIST:
    allowed += config.zone(cc)
allowed_names = ', '.join(n for _, n in config.WHITELIST) or 'none'

lines = config.header('geoblock', 'Country blocking (policy accept - a filter, not a firewall)',
                      'gen-geoblock.py')
lines += config.nft_set('allowed', allowed, f'{allowed_names} - never block')

total = 0
for cc, name in config.COUNTRIES:
    nets = config.zone(cc)
    total += len(nets)
    lines += config.nft_set(f'cc_{cc}', nets, f'{name} ({len(nets)} blocks)')

lines += ['\tchain input {',
          '\t\ttype filter hook input priority -10; policy accept;',
          '',
          '\t\tct state established,related accept',
          '\t\tiif lo accept',
          '\t\t' + config.guard_rule(),
          '\t\tip saddr @allowed accept',
          '']
for cc, name in config.COUNTRIES:
    lines.append(f'\t\tip saddr @cc_{cc} counter drop comment "{name}"')
lines += ['\t}', '}']

out = f'{config.OUT}/geoblock.nft'
config.write_atomic(out, lines)
print(f'geoblock: {total} blocks from {len(config.COUNTRIES)} countries -> {out}')
