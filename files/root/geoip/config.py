#!/usr/bin/env python3
"""Shared configuration and helpers for the block list generators.

Reads /etc/blocklist.conf - the same file the shell scripts load with 'source',
so the server IP, the owner addresses and the country list are never hard-coded.

Paths can be redirected with environment variables (used by blocklist-update.sh
and by the tests):
  BLOCKLIST_CONF     configuration             (/etc/blocklist.conf)
  BLOCKLIST_HOME     working directory         (/root/geoip)
  BLOCKLIST_OUT      where generators write    (/etc/nftables.d)
  BLOCKLIST_NFT_DIR  currently valid lists     (/etc/nftables.d)
  BLOCKLIST_FINAL    accumulated proxy list    (/root/final)
"""
import bisect
import ipaddress
import os
import re
import shlex

CONF = os.environ.get('BLOCKLIST_CONF', '/etc/blocklist.conf')
HOME = os.environ.get('BLOCKLIST_HOME', '/root/geoip')
OUT = os.environ.get('BLOCKLIST_OUT', '/etc/nftables.d')
LIVE = os.environ.get('BLOCKLIST_NFT_DIR', '/etc/nftables.d')
FINAL = os.environ.get('BLOCKLIST_FINAL', '/root/final')
STATE = '/var/lib/blocklist'
ALLOW = f'{HOME}/crawlers/allow.txt'

# country name next to the code - only for comments in the nft files
NAMES = {
    'ir': 'Iran', 'ru': 'Russia', 'cn': 'China', 'br': 'Brazil',
    'co': 'Colombia', 'bg': 'Bulgaria', 'ro': 'Romania', 'sc': 'Seychelles',
    'ba': 'Bosnia and Herzegovina', 'rs': 'Serbia', 'hr': 'Croatia',
    'me': 'Montenegro', 'si': 'Slovenia', 'mk': 'North Macedonia',
    'ge': 'Georgia', 'lt': 'Lithuania', 'kp': 'North Korea', 'by': 'Belarus',
    'in': 'India', 'vn': 'Vietnam', 'id': 'Indonesia', 'tr': 'Turkey',
    'ua': 'Ukraine', 'se': 'Sweden', 'de': 'Germany', 'at': 'Austria',
    'nl': 'Netherlands', 'us': 'United States', 'gb': 'United Kingdom',
}

# private and reserved ranges - never blocked
PRIVATE = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8',
           '169.254.0.0/16', '0.0.0.0/8', '224.0.0.0/4', '240.0.0.0/4']

# Addresses that must NEVER end up on a block list: Googlebot, Bingbot, Google
# and Cloudflare DNS. Server and owner addresses from the config are added.
CONTROL = ['66.249.66.1', '40.77.167.29', '8.8.8.8', '1.1.1.1']


def _load(path=CONF):
    values = {}
    if not os.path.exists(path):
        return values
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, _, val = line.partition('=')
            key = key.strip()
            if not key.replace('_', '').isalnum():
                continue
            try:
                parts = shlex.split(val.strip(), comments=True)
            except ValueError:
                continue
            values[key] = parts[0] if parts else ''
    return values


_values = _load()


def _list(key, default=''):
    return [x for x in _values.get(key, default).replace(',', ' ').split() if x]


def _number(key, default):
    try:
        return type(default)(_values.get(key, default))
    except (TypeError, ValueError):
        return default


SITE_URL = _values.get('SITE_URL', '')
SERVER_IPS = _list('SERVER_IPS')
OWNER_IPS = _list('OWNER_IPS')
CC_BLOCK = [c.lower() for c in _list('COUNTRIES', 'ir ru cn br co bg ro sc')]
CC_ALLOW = [c.lower() for c in _list('WHITELIST_CC', 'ba')]
LIMIT_404 = _number('LIMIT_404', 50)
SEEN_DAYS = _number('SEEN_DAYS', 180)
MIN_RATIO = _number('MIN_RATIO', 0.5)
MINIMUM = {
    'geoblock': _number('MIN_GEO', 100),
    'abuseblock': _number('MIN_ABUSE', 20000),
    'proxyblock': _number('MIN_PROXY', 15000),
}
AUTH_LOGS = _list('AUTH_LOGS', '/var/log/auth.log* /var/log/secure*')
WEB_LOGS = _list('WEB_LOGS', '/var/log/nginx/*access*.log* '
                             '/var/log/apache2/*access*.log* /var/log/httpd/*access_log*')
try:
    GUARD_MARK = int(_values.get('GUARD_MARK', '0x08000000'), 0)
except ValueError:
    GUARD_MARK = 0x08000000

COUNTRIES = [(c, NAMES.get(c, c.upper())) for c in CC_BLOCK]
WHITELIST = [(c, NAMES.get(c, c.upper())) for c in CC_ALLOW]


def guard_rule():
    """Rule that accepts addresses from the 'hold' set (the guard table marks them)."""
    m = f'0x{GUARD_MARK:08x}'
    return f'meta mark & {m} == {m} accept comment "blocklist hold"'


def critical():
    """Everything verify-lists.py must confirm is not blocked."""
    return list(dict.fromkeys(OWNER_IPS + SERVER_IPS + CONTROL))


def validate():
    """Fail loudly when the config is incomplete - better than protecting the wrong server."""
    missing = [k for k, v in (('SERVER_IPS', SERVER_IPS), ('COUNTRIES', CC_BLOCK)) if not v]
    if missing:
        raise SystemExit(f"{CONF}: missing {', '.join(missing)}")
    for ip in SERVER_IPS + OWNER_IPS:
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            raise SystemExit(f"{CONF}: '{ip}' is not a valid IPv4 address")
    for cc in CC_BLOCK + CC_ALLOW:
        if not (len(cc) == 2 and cc.isalpha()):
            raise SystemExit(f"{CONF}: '{cc}' is not a two-letter country code")


def network(text):
    """CIDR or IP -> IPv4Network; None for IPv6, comments and garbage."""
    text = text.strip()
    # strip inline comments: "1.2.3.0/24 ; SBL123" (Spamhaus), "1.2.3.4 # note"
    for sep in (';', '#'):
        if sep in text:
            text = text.split(sep, 1)[0].strip()
    if not text or ':' in text:
        return None
    try:
        return ipaddress.IPv4Network(text, strict=False)
    except ValueError:
        return None


def networks(path):
    out = []
    try:
        with open(path, errors='ignore') as fh:
            for line in fh:
                n = network(line)
                if n is not None:
                    out.append(n)
    except OSError:
        pass
    return out


def zone(cc):
    """Networks of one country from its ipdeny zone; an empty zone is an error."""
    nets = networks(f'{HOME}/zones/{cc}.zone')
    if not nets:
        raise SystemExit(f'error: {HOME}/zones/{cc}.zone is missing or empty')
    return nets


def safe_networks():
    """Networks that must never be blocked (the allowlist)."""
    safe = []
    for cc in CC_ALLOW:
        safe += zone(cc)
    safe += networks(ALLOW)
    safe += [ipaddress.IPv4Network(x) for x in PRIVATE]
    safe += [ipaddress.IPv4Network(f'{ip}/32') for ip in SERVER_IPS + OWNER_IPS]
    return safe


class Intervals:
    """Merged, sorted, disjoint address intervals.

    Overlap lookups are O(log n) instead of O(n). Previously each of ~220,000
    networks was compared with each of ~600 safe ones - about 5 minutes of CPU
    on a 1 vCPU server.
    """

    def __init__(self, nets):
        self.starts, self.ends = [], []
        for a, b in sorted((int(n.network_address), int(n.broadcast_address)) for n in nets):
            if self.starts and a <= self.ends[-1] + 1:
                if b > self.ends[-1]:
                    self.ends[-1] = b
            else:
                self.starts.append(a)
                self.ends.append(b)

    def __len__(self):
        return len(self.starts)

    def overlaps(self, net):
        a, b = int(net.network_address), int(net.broadcast_address)
        i = bisect.bisect_right(self.starts, b) - 1
        return i >= 0 and self.ends[i] >= a

    def contains(self, ip):
        v = int(ipaddress.IPv4Address(ip))
        i = bisect.bisect_right(self.starts, v) - 1
        return i >= 0 and v <= self.ends[i]


def read_sets(path):
    """Parse a generated .nft file -> ({set_name: [networks]}, text); None if missing."""
    if not os.path.exists(path):
        return None
    with open(path) as fh:
        txt = fh.read()
    out = {}
    for m in re.finditer(r'^\tset (\w+) \{\n(.*?)^\t\}', txt, re.S | re.M):
        e = re.search(r'elements = \{(.*?)\}', m.group(2), re.S)
        out[m.group(1)] = [n for n in (network(x) for x in e.group(1).split(',')) if n] if e else []
    return out, txt


def nft_set(name, elements, comment):
    """Lines of one interval set; an empty set has no 'elements' line."""
    lines = [f'\tset {name} {{', '\t\ttype ipv4_addr', '\t\tflags interval', '\t\tauto-merge',
             f'\t\tcomment "{comment}"']
    if elements:
        lines.append('\t\telements = { ' + ', '.join(str(x) for x in elements) + ' }')
    lines += ['\t}', '']
    return lines


def header(table, description, generator):
    return ['#!/usr/sbin/nft -f',
            f'# {description}. GENERATED - do not edit by hand.',
            f'# Generator: {HOME}/{generator}',
            '',
            f'table inet {table}',
            f'delete table inet {table}',
            '',
            f'table inet {table} {{']


def write_atomic(path, lines):
    """Atomic write: never a half-written file."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + '.tmp'
    with open(tmp, 'w') as fh:
        fh.write('\n'.join(lines) + '\n')
    os.replace(tmp, path)
