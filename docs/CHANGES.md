# Changes since 1.x

Version 2.0.0 grew out of the private 1.x kit that has protected a production web server
since August 2026. The blocking logic is the same: the list sources, the allowlist and
the verification before apply. Everything that stood in the way of portability, and
everything an analysis of the production server or the tests exposed as a bug, has changed.

## Fixed bugs

| Problem in 1.x | Consequence | 2.0 |
|---|---|---|
| The site check required exactly `200` | a `SITE_URL` that redirects (302) failed every refresh; the lists on the production server stayed stale for 13 days | redirects are followed (`curl -L`), the final answer must be 2xx; 3 attempts |
| Generators wrote straight into `/etc/nftables.d` | after a failed apply the kernel was restored but the disk kept the new files; a reboot or the certbot hook then loaded an unverified version | generation goes to `/var/lib/blocklist/staging`; files become current only after verification, apply and the site check succeed |
| Restore used `nft flush ruleset` and a snapshot of the whole ruleset | it wiped other tables: Docker NAT, firewalld, ufw | only the kit's own tables are loaded and removed; restore = reload from `/etc/nftables.d` |
| `/etc/nftables.conf` with `flush ruleset` and `include` lines | the same as above; on RHEL that file is not even read | an own `blocklist.service` (oneshot); the distribution's nftables.conf is left alone |
| Country sets named after the code (`set ge`) | `ge`, `lt`, `gt`, `ne` are nftables keywords - Georgia, Lithuania, Guatemala and Niger broke loading | sets are named `cc_<code>` |
| `WHITELIST_CC` with more than one country | duplicate set name - loading failed | all countries in one set |
| Safety filter hard-coded to one country zone | `WHITELIST_CC` did not affect the attacker and proxy lists | every country from `WHITELIST_CC` is used |
| Rollback only deleted the tables | the health check restored them from the files within 6 hours - the lockout came back | rollback leaves a `disabled` flag; load, health and update respect it until `blocklist enable` |
| The backup required `etc/nginx/nginx.conf` | failed on servers without nginx | only the config and the metadata are required; extra paths go to `BACKUP_EXTRA` |
| Web scanners were matched against the whole log line | `.sql` or `/backup` in a referer or user agent meant a block | only the request path is matched |
| Only `/var/log/nginx/access.log*` was read | per-vhost logs never reached the analysis | `WEB_LOGS` (nginx, apache, httpd), configurable |
| SSH attacks only from `/var/log/auth.log` | no data on Debian 12+ without rsyslog and on RHEL (`/var/log/secure`) | `auth.log`, `secure`, then journald (`sshd`, `sshd-session`) |
| O(n*m) safety filter | ~5 min of CPU and 494 MB on a 1 vCPU server on every daily refresh | interval index, O(n log m) |
| `certbot-canary.service` with an inline `sh -c` | a systemd warning on every `daemon-reload` | `certbot-canary.sh` |
| The nginx deploy hook was missing from the kit | a fresh installation would not apply a renewed certificate | installed when nginx exists and no other deploy hook reloads it |
| Thresholds hard-coded in Python | changing them meant editing code | `MIN_*`, `MIN_RATIO`, `LIMIT_404`, `SEEN_DAYS`, `STALE_DAYS` in the config |
| No off-host notifications | the stale-list failure went unnoticed for 13 days | ntfy, Telegram, e-mail; health also reports lists not refreshed for `STALE_DAYS` days |
| `/etc/blocklist.conf` mode 0644 | notification tokens readable by everyone | 0600 |

## New

- **Address hold.** The `inet blocklist_guard` table (priority -20) has a `hold` set with a
  per-element timeout. An address in the set gets a packet mark, and every blocking table
  accepts marked packets before its drop rule. The installer automatically holds the
  address it is run from (SSH session, `--hold-ip`) for the whole installation plus
  `--hold` seconds (30). Manually: `blocklist hold IP [SECONDS]`.
- **`blocklist` command**: status, check, hold, release, confirm, disable, enable, load, update.
- **`blocklist-update.sh rebuild`**: regenerates everything from local data without
  downloading (after a config change).
- **Distributions**: Debian/Ubuntu (apt), RHEL family (dnf), openSUSE (zypper), Arch (pacman);
  only packages whose commands are missing get installed.
- **Delivery**: `deploy/deploy.sh`, `deploy/Deploy-Blocklist.ps1`, an Ansible role and a
  self-extracting `.run` (`build.sh`).
- **Test matrix**: `test/matrix.sh` (Docker with systemd), `test/test.sh` (real packets through
  a network namespace for the hold, deliberate faults for the brakes).
- **Download cache** (`LIST_CACHE_DIR`) for tests, mirrors or offline networks.
- **Local lists**: every `/root/geoip/abuse/l_*` file goes into the attacker list.
- **English everywhere**: code, messages, state files and set names
  (`attackers`, `allowlist`, `allowed`).

## Upgrading an existing installation (1.x -> 2.0)

Running `install.sh` on a 1.x machine:

1. keeps `/etc/blocklist.conf` (fix `SITE_URL` before or after),
2. removes the three `include` lines from `/etc/nftables.conf` (original kept as `.bak-blocklist-*`),
3. removes the old certbot hooks `00-nft-off.sh` / `99-nft-on.sh` and the unused `last-good.nft`,
4. replaces the old backup units with `blocklist-backup.service` / `.timer`; old snapshots stay
   where they were and are no longer rotated,
5. regenerates all three tables (the old files have no hold rule and use the old set names).

The update units and the data paths (`/root/geoip`, `/var/lib/blocklist`, `/etc/nftables.d`)
keep their names. Set names change (`ru` -> `cc_ru`, attacker and allowlist sets get English
names); adjust your own scripts if they use them.
