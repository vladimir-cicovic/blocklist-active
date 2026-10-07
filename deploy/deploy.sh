#!/bin/bash
# deploy/deploy.sh - installs blocklist-active on a remote machine over SSH.
# Works from Linux, macOS, WSL and Git Bash on Windows.
#
#   deploy/deploy.sh -t root@server -c configs/server.conf [options] [-- install.sh options]
#
#   -t, --target USER@HOST   target machine (required)
#   -p, --port PORT          SSH port (22)
#   -i, --identity FILE      SSH key
#   -c, --config FILE        blocklist.conf (required for the first installation)
#       --hold SECONDS       how long your address still passes AFTER the installation (30)
#       --rollback SECONDS   without confirmation the blocks get disabled after this (600)
#       --no-confirm         do not confirm automatically (rollback waits for a manual confirm)
#       --known-hosts MODE   StrictHostKeyChecking: accept-new (default), yes, no
#   -h, --help
#
# Flow:
#   1. connection probe; the address the server sees (SSH_CONNECTION) becomes --hold-ip
#   2. the kit and the config are copied to a temporary directory on the server
#   3. install.sh: your address passes every block while it runs + --hold seconds
#   4. waits for the hold to expire, then opens a NEW (non-multiplexed) SSH connection:
#      if it gets through, it confirms (blocklist confirm); if not, the rollback restores access
set -euo pipefail

TARGET="" PORT=22 IDENT="" CONFIG="" HOLD=30 ROLLBACK=600 CONFIRM=1 KH=accept-new
EXTRA=()
while [ $# -gt 0 ]; do
  case "$1" in
    -t|--target)   TARGET="${2:?}"; shift 2 ;;
    -p|--port)     PORT="${2:?}"; shift 2 ;;
    -i|--identity) IDENT="${2:?}"; shift 2 ;;
    -c|--config)   CONFIG="${2:?}"; shift 2 ;;
    --hold)        HOLD="${2:?}"; shift 2 ;;
    --rollback)    ROLLBACK="${2:?}"; shift 2 ;;
    --no-confirm)  CONFIRM=0; shift ;;
    --known-hosts) KH="${2:?}"; shift 2 ;;
    -h|--help)     sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    --)            shift; EXTRA=("$@"); break ;;
    *) echo "unknown argument: $1 (see --help)" >&2; exit 2 ;;
  esac
done
[ -n "$TARGET" ] || { echo "missing --target USER@HOST" >&2; exit 2; }
[ -z "$CONFIG" ] || [ -s "$CONFIG" ] || { echo "config $CONFIG does not exist" >&2; exit 2; }

KIT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
die() { printf '\n\033[31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

if grep -qU $'\r' "$KIT/install.sh" "$KIT/files/usr/local/lib/blocklist/common.sh"; then
  die "the scripts have Windows line endings (CRLF) - clone with .gitattributes (eol=lf) or: git config core.autocrlf false"
fi

SSH_OPTS=(-p "$PORT" -o BatchMode=yes -o ConnectTimeout=15 -o ServerAliveInterval=15
          -o "StrictHostKeyChecking=$KH")
SCP_OPTS=(-P "$PORT" -o BatchMode=yes -o ConnectTimeout=15 -o "StrictHostKeyChecking=$KH")
if [ -n "$IDENT" ]; then SSH_OPTS+=(-i "$IDENT"); SCP_OPTS+=(-i "$IDENT"); fi
# the confirmation MUST be a new TCP connection - a multiplexed one would pass even when blocked
FRESH=(-o ControlMaster=no -o ControlPath=none)

say "Connecting to $TARGET:$PORT"
probe=$(ssh "${SSH_OPTS[@]}" "$TARGET" 'echo "$SSH_CONNECTION"; id -u; command -v systemctl || echo no-systemd') \
  || die "SSH connection failed"
CLIENT=$(echo "$probe" | sed -n 1p | awk '{print $1}')
RUID=$(echo "$probe" | sed -n 2p)
echo "$probe" | grep -q no-systemd && die "the target has no systemd"
SUDO=""
[ "$RUID" = 0 ] || SUDO="sudo -n"
echo "   the server sees you as: ${CLIENT:-unknown}   user: $([ -z "$SUDO" ] && echo root || echo "uid $RUID, via sudo")"

say "Uploading the kit"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
items=(install.sh uninstall.sh VERSION blocklist.conf.example files)
[ -f "$KIT/seed/seed.tar.gz" ] && items+=(seed)
tar czf "$TMP/kit.tgz" -C "$KIT" "${items[@]}"
RD="/tmp/blocklist-deploy-$$-$RANDOM"
ssh "${SSH_OPTS[@]}" "$TARGET" "mkdir -m 700 $RD" || die "cannot create $RD on the server"
files=("$TMP/kit.tgz")
CFGARG=""
if [ -n "$CONFIG" ]; then
  cp "$CONFIG" "$TMP/blocklist.conf"; files+=("$TMP/blocklist.conf"); CFGARG="--config $RD/blocklist.conf"
fi
scp -q "${SCP_OPTS[@]}" "${files[@]}" "$TARGET:$RD/" || die "upload failed"
echo "   uploaded to $RD"

say "Installing"
HOLDARG=""
[ -n "$CLIENT" ] && HOLDARG="--hold-ip $CLIENT"
set +e
ssh "${SSH_OPTS[@]}" "$TARGET" \
  "cd $RD && tar xzf kit.tgz && $SUDO bash ./install.sh $CFGARG $HOLDARG --hold $HOLD --rollback $ROLLBACK ${EXTRA[*]:-}; rc=\$?; cd /; $SUDO rm -rf $RD; exit \$rc"
rc=$?
set -e
[ $rc = 0 ] || die "install.sh exited with code $rc (if the rollback is armed, the blocks disable themselves within ${ROLLBACK}s)"

if [ "$ROLLBACK" -gt 0 ] && [ "$CONFIRM" = 1 ]; then
  say "Confirming access"
  echo "   waiting $((HOLD + 2))s for the hold to expire, then opening a NEW SSH connection..."
  sleep $((HOLD + 2))
  ok=0
  for i in 1 2 3; do
    if ssh "${SSH_OPTS[@]}" "${FRESH[@]}" "$TARGET" "$SUDO /usr/local/sbin/blocklist confirm"; then ok=1; break; fi
    echo "   attempt $i failed, retrying in 5s"; sleep 5
  done
  if [ $ok = 0 ]; then
    die "A NEW SSH CONNECTION DOES NOT GET THROUGH - your address ($CLIENT) is probably blocked.
   The rollback disables the blocks at most ${ROLLBACK}s after the installation.
   Then: add the address to OWNER_IPS, run 'blocklist update rebuild' and 'blocklist enable'."
  fi
elif [ "$ROLLBACK" -gt 0 ]; then
  echo
  echo "   The rollback waits ${ROLLBACK}s for a confirmation. Confirm from a NEW connection:"
  echo "     ssh -p $PORT $TARGET '$SUDO blocklist confirm'"
fi

say "Status"
ssh "${SSH_OPTS[@]}" "${FRESH[@]}" "$TARGET" "$SUDO /usr/local/sbin/blocklist status" || true
