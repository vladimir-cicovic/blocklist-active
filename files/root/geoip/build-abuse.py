#!/usr/bin/env python3
"""Builds the attacker set: own logs + high-confidence public lists.

Own logs:
  - SSH: failed logins, invalid users, preauth probes
    (auth.log / secure; when neither exists - journald, e.g. Debian 12+ without rsyslog)
  - web: requests for exploit paths (request path only, not referer or user
    agent) and the 404 rate (>= LIMIT_404 within 24 h from one address)
  - long-term memory: seen.txt keeps addresses for SEEN_DAYS days because logs rotate
Public lists: every <HOME>/abuse/l_* file. Add your own list as l_local.

The safety filter drops everything that touches the allowlist (WHITELIST_CC
countries, Googlebot/Bingbot, private ranges, the server, the owner).
"""
import collections
import datetime
import glob
import gzip
import os
import re
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config  # noqa: E402

config.validate()

SRC = f'{config.HOME}/abuse'
SEEN = f'{SRC}/seen.txt'
OUT = f'{config.OUT}/abuseblock.nft'

nets, stats = set(), {}


def add(text):
    n = config.network(text)
    if n is not None:
        nets.add(n)


def open_log(path):
    return gzip.open(path, 'rb') if path.endswith('.gz') else open(path, 'rb')


def log_lines(patterns):
    for pattern in patterns:
        for path in sorted(glob.glob(pattern)):
            try:
                with open_log(path) as fh:
                    for line in fh:
                        yield line
            except (OSError, EOFError):
                continue


def journal_ssh(days=14):
    """SSH messages from journald (OpenSSH 9.8+ logs as sshd-session)."""
    if not shutil.which('journalctl'):
        return []
    since = (datetime.datetime.now() - datetime.timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')
    try:
        r = subprocess.run(['journalctl', '--no-pager', '-q', '-o', 'cat', '--since', since,
                            'SYSLOG_IDENTIFIER=sshd', 'SYSLOG_IDENTIFIER=sshd-session'],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=300)
        return r.stdout.splitlines()
    except (OSError, subprocess.SubprocessError):
        return []


# --- 1. own logs: SSH ---
IP = rb'(\d{1,3}(?:\.\d{1,3}){3})'
ssh_patterns = [
    re.compile(rb'(?:Failed password|Invalid user).* from ' + IP),
    re.compile(rb'authentication failure.*rhost=' + IP),
    re.compile(rb'(?:Disconnected from|Connection closed by) (?:invalid user|authenticating user) \S+ '
               + IP + rb'.*\[preauth\]'),
]
n0 = len(nets)
have_files = any(glob.glob(p) for p in config.AUTH_LOGS)
source = log_lines(config.AUTH_LOGS) if have_files else journal_ssh()
for line in source:
    for p in ssh_patterns:
        m = p.search(line)
        if m:
            add(m.group(1).decode())
            break
stats['own log: SSH attackers' + ('' if have_files else ' (journald)')] = len(nets) - n0

# --- 2. own logs: web scanners ---
scan = re.compile(rb'(wp-login|wp-admin|wp-content|wp-includes|wp-json/wp/v2/users|xmlrpc\.php|'
                  rb'/\.(env|DS_Store)|/\.git/|/\.svn/|/\.hg/|/\.aws/|'
                  rb'/server-status|/server-info|/phpinfo|/actuator|'
                  rb'/composer\.json|/package\.json|'
                  rb'\.sql|/backup|\.bak|'
                  rb'/manager/html|/jmx-console|/axis2|/struts|/solr/admin|'
                  rb'/telescope|/_profiler|/_all_dbs|/v2/_catalog|'
                  rb'/console/|/debug/|author=\d+|'
                  rb'phpmyadmin|/adminer|/shell\.php|/c99|/r57|/alfa\.php|/wso\.php|/vendor/phpunit)', re.I)
# IP - user [time] "METHOD path PROTOCOL" status
record = re.compile(rb'^' + IP + rb' \S+ \S+ \[([^\]]+)\] "(?:[A-Z]+ )?([^" ]*)[^"]*" (\d{3}) ')
cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=24)
count404 = collections.Counter()
n0 = len(nets)
for line in log_lines(config.WEB_LOGS):
    m = record.match(line)
    if not m:
        continue
    ip, when, path, status = m.group(1).decode(), m.group(2), m.group(3), m.group(4)
    if scan.search(path):
        add(ip)
    if status == b'404':
        try:
            t = datetime.datetime.strptime(when.decode(), '%d/%b/%Y:%H:%M:%S %z')
        except ValueError:
            continue
        if t >= cutoff:
            count404[ip] += 1
n1 = len(nets)
for ip, c in count404.items():
    if c >= config.LIMIT_404:
        add(ip)
stats['own log: web scanners (paths)'] = n1 - n0
stats[f'own log: 404 rate (>={config.LIMIT_404}/24h)'] = len(nets) - n1

# --- 3. long-term memory of attackers ---
today = datetime.date.today()
oldest = today - datetime.timedelta(days=config.SEEN_DAYS)
remembered = {}
if os.path.exists(SEEN):
    with open(SEEN) as fh:
        for line in fh:
            line = line.strip()
            if '|' not in line:
                continue
            ip, d = line.rsplit('|', 1)
            try:
                dd = datetime.date.fromisoformat(d)
            except ValueError:
                continue
            if dd >= oldest:
                remembered[ip] = dd
for n in nets:
    if n.prefixlen == 32:
        remembered[str(n.network_address)] = today
n0 = len(nets)
for ip in remembered:
    add(ip)
stats['remembered earlier attackers'] = len(nets) - n0
os.makedirs(SRC, exist_ok=True)
with open(SEEN + '.tmp', 'w') as fh:
    for ip, d in sorted(remembered.items()):
        fh.write(f'{ip}|{d.isoformat()}\n')
os.replace(SEEN + '.tmp', SEEN)
print(f'    (long-term memory: {len(remembered):,} addresses, dropped older than {oldest})')

# --- 4. public lists and local lists (l_*) ---
for path in sorted(glob.glob(f'{SRC}/l_*')):
    n0 = len(nets)
    for n in config.networks(path):
        nets.add(n)
    stats[os.path.basename(path)[2:]] = len(nets) - n0

# --- 5. safety filter ---
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
print(f'    {len(dropped):>8,} REMOVED by the safety filter')
for d in sorted(str(x) for x in dropped)[:12]:
    print(f'        {d}')
print(f'    {len(collapsed):>8,} after collapsing')

allowlist = list(config.ipaddress.collapse_addresses(config.safe_networks()))
lines = config.header('abuseblock', 'Attackers: own logs + public lists. Blocks ALL ports',
                      'build-abuse.py')
lines += config.nft_set('allowlist', allowlist, 'allowlist: countries, search engines, private, server, owner')
lines += config.nft_set('attackers', collapsed, f'attackers, {len(collapsed)} intervals')
lines += ['\tchain input {',
          '\t\ttype filter hook input priority -7; policy accept;',
          '\t\tct state established,related accept',
          '\t\tiif lo accept',
          '\t\t' + config.guard_rule(),
          '\t\tip saddr @allowlist accept',
          '\t\tip saddr @attackers counter drop',
          '\t}', '}']
config.write_atomic(OUT, lines)
print(f'  written: {OUT}')
