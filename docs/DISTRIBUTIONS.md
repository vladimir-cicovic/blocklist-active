# Distributions: test results and proposals

Tested on a Docker host (Docker 29.5.3, kernel 6.18.53, cgroup v2). Every distribution
runs as a container with a real systemd and sshd and without nftables or Python
preinstalled - the installer pulls them in. `test/test.sh` has 75 checks.

## Results

| Distribution | nftables | Python | Packages | Installed through | Test |
|---|---|---|---|---|---|
| Ubuntu 26.04 LTS | 1.1.6 | 3.14.4 | apt | `install.sh`, **PowerShell** | 75/75 |
| Ubuntu 24.04 LTS | 1.0.9 | 3.12.3 | apt | `install.sh`, **`.run`** | 75/75 |
| Ubuntu 22.04 LTS | 1.0.2 | 3.10.12 | apt | `install.sh` | 75/75 |
| Debian 13 (trixie) | 1.1.3 | 3.13.5 | apt | `install.sh`, **`deploy.sh`** | 75/75 |
| Debian 12 (bookworm) | 1.0.6 | 3.11.2 | apt | `install.sh`, **Ansible** | 75/75 |
| AlmaLinux 10.2 | 1.1.5 | 3.12.14 | dnf | `install.sh` | 75/75 |
| AlmaLinux 9.8 | 1.0.9 | 3.9.25 | dnf | `install.sh`, **Ansible** | 75/75 |
| Rocky Linux 9.8 | 1.0.9 | 3.9.25 | dnf | `install.sh` | 75/75 |
| CentOS Stream 10 | 1.1.5 | 3.12.14 | dnf | `install.sh` | 75/75 |
| Oracle Linux 9.8 | 1.0.9 | 3.9.25 | dnf | `install.sh` | 75/75 |
| Fedora 44 | 1.1.6 | 3.14.7 | dnf5 | `install.sh` | 75/75 |
| Amazon Linux 2023 | 1.0.4 | 3.9.25 | dnf | `install.sh` | 75/75 |
| openSUSE Leap 16.0 | 1.1.3 | 3.13.14 | zypper | `install.sh` | 75/75 |
| Arch Linux | 1.1.7 | 3.14.7 | pacman | `install.sh` | 75/75 |

Additional scenarios:

| Scenario | Result |
|---|---|
| Upgrade 1.x -> 2.0 (Debian 12, `test/migrate-test.sh`) | 17/17, all 4 tables loaded after a reboot |
| Second Ansible run (idempotency) | `changed=0` on both hosts |
| Removal, reinstall from local data, `--purge` (`test/uninstall-test.sh`) | 12/12 |
| `.run`: `--extract`, modified file | extracts; a 1-byte modification is rejected (SHA-256) |

### Found and fixed along the way

- **openSUSE**: `logger` is not in `util-linux` but in `util-linux-systemd`.
- **Fedora (test only)**: `systemd-resolved` inside a container cannot see Docker's DNS
  names, so the test site was unreachable. On a real server resolved works normally; the
  test images mask it.
- **Minimal images** (RHEL family) lack `awk`, `find`, `cmp`, `hostname`, `ip` - the
  installer now pulls them in when needed.
- **Ansible**: network facts need the `ip` command; the role installs iproute first.

### Test limitation

All containers share the host kernel (6.18). Kernel-dependent behaviour - for example
whether re-adding a set element changes its expiry (new since ~6.10) - is not covered on
older kernels (Debian 12: 6.1, RHEL 9: 5.14, Ubuntu 22.04: 5.15). The code handles both
cases (a hold is always deleted and added again). For full confidence: one real VM with
a RHEL 9 or Debian 12 kernel.

## Proposals for further testing

By importance:

| Distribution | Why | How |
|---|---|---|
| **RHEL 9 / 10** (the real one) | AlmaLinux, Rocky and Oracle are binary compatible and pass, but real RHEL needs a subscription (the free Developer subscription covers up to 16 systems). The UBI image has no nftables. | VM from the RHEL ISO, `subscription-manager register`, then `deploy.sh` |
| **Debian 12 / RHEL 9 on a VM** | older kernel (6.1 / 5.14) - checks the hold expiry behaviour | a VM, then `deploy.sh` |
| **Rocky Linux 10** | Rocky 9 passes; 10 is the same code base as AlmaLinux 10 | add to `test/matrix.sh` |
| **CentOS Stream 9** | Stream 10 passes; 9 is the base of RHEL 9.x | `quay.io/centos/centos:stream9` |
| **SLES 15 SP7 / SLES 16** | openSUSE Leap 16 passes; SLES needs a registration for packages | VM or SUSE BCI image + SUSEConnect |
| **Debian/Ubuntu on ARM64** | Raspberry Pi, Oracle Ampere, AWS Graviton - the scripts are architecture independent | `docker buildx` with `--platform linux/arm64` or a real ARM VPS |
| **Proxmox VE 9** | Debian 13 plus its own firewall (pve-firewall on nftables) - make sure the tables do not collide | Proxmox VM |
| **Server running Docker** | confirm that Docker NAT survives (tested inside a container) and document the FORWARD limitation | VM with Docker and a published port |
| **Server with firewalld enabled** | the RHEL default; the tables are independent, but `firewall-cmd --reload` is worth confirming | AlmaLinux VM with active firewalld |

Not worth the time:

- **Alpine** - OpenRC instead of systemd; it would need a separate variant with OpenRC services and cron.
- **Ubuntu 20.04, Debian 11, CentOS 7/8** - out of standard support; nftables and Python are too old or unmaintained.
- **Flatcar, Fedora CoreOS, NixOS** - immutable or declarative systems; `/usr/local` and
  package installation do not work the classic way.
