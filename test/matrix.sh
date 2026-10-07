#!/bin/sh
# test/matrix.sh - distribution test matrix on a Docker host (for example a VM).
# POSIX sh (works on Alpine/busybox too). Every "server" is a container with a real
# systemd; nftables rules stay inside the container's network namespace - the host is untouched.
#
#   test/matrix.sh run     [distro...]   up + install + test (default: the core matrix)
#   test/matrix.sh up      [distro...]   build the image and start the container (sshd on port 22xx)
#   test/matrix.sh install [distro...]   install.sh inside the container (docker exec)
#   test/matrix.sh test    [distro...]   test/test.sh inside the container
#   test/matrix.sh down    [distro...]   remove the containers
#   test/matrix.sh list
#
# EXTENDED=1 adds the extended matrix (Ubuntu 22.04, RHEL family, Fedora, Amazon, openSUSE, Arch).
# PARALLEL=N how many distributions at once (default 4).
set -u
KIT=$(cd "$(dirname "$0")/.." && pwd)
NET=blnet
SITE=bl-site
CACHE=bl-cache
RES="$KIT/test/results"
BLKIT="/tmp/blkit.$$"   # own directory - concurrent runs must not share it
trap 'rm -rf "$BLKIT"' EXIT
CORE="ubuntu-26.04 ubuntu-24.04 debian-12 debian-13"
EXT="ubuntu-22.04 almalinux-9 almalinux-10 rocky-9 centos-stream-10 fedora-44 oraclelinux-9 amazonlinux-2023 opensuse-leap-16 archlinux"
PARALLEL="${PARALLEL:-4}"
mkdir -p "$RES"

spec() {   # family image port
  case "$1" in
    ubuntu-26.04)      echo "deb ubuntu:26.04 2201" ;;
    ubuntu-24.04)      echo "deb ubuntu:24.04 2202" ;;
    debian-12)         echo "deb debian:12 2203" ;;
    debian-13)         echo "deb debian:13 2204" ;;
    ubuntu-22.04)      echo "deb ubuntu:22.04 2205" ;;
    almalinux-9)       echo "rpm almalinux:9 2211" ;;
    almalinux-10)      echo "rpm almalinux:10 2212" ;;
    rocky-9)           echo "rpm rockylinux/rockylinux:9 2213" ;;
    centos-stream-10)  echo "rpm quay.io/centos/centos:stream10 2214" ;;
    fedora-44)         echo "rpm fedora:44 2215" ;;
    oraclelinux-9)     echo "rpm oraclelinux:9 2216" ;;
    amazonlinux-2023)  echo "rpm amazonlinux:2023 2217" ;;
    opensuse-leap-16)  echo "suse opensuse/leap:16.0 2218" ;;
    archlinux)         echo "arch archlinux:latest 2219" ;;
    *) return 1 ;;
  esac
}

log() { printf '%s %s\n' "$(date '+%T')" "$*"; }

infra() {
  docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null
  docker volume inspect "$CACHE" >/dev/null 2>&1 || docker volume create "$CACHE" >/dev/null
  if ! docker ps --format '{{.Names}}' | grep -qx "$SITE"; then
    docker rm -f "$SITE" >/dev/null 2>&1
    docker run -d --name "$SITE" --network "$NET" --restart unless-stopped \
      -v "$KIT/test/fixtures/site.conf:/etc/nginx/conf.d/default.conf:ro" nginx:alpine >/dev/null
    log "test site $SITE started"
  fi
  # key for the tests (Ansible, deploy.sh) + user keys from test/.keys/*.pub
  mkdir -p "$KIT/test/.keys"
  [ -f "$KIT/test/.keys/bltest" ] || ssh-keygen -q -t ed25519 -N '' -C bltest -f "$KIT/test/.keys/bltest"
  cat "$KIT"/test/.keys/*.pub > "$KIT/test/.keys/authorized_keys"
  # only what goes to the server
  rm -rf "$BLKIT" && mkdir -p "$BLKIT"
  cp -r "$KIT/install.sh" "$KIT/uninstall.sh" "$KIT/VERSION" "$KIT/files" "$KIT/test" "$BLKIT/"
  rm -rf "$BLKIT/test/results" "$BLKIT/test/.keys"
}

up_one() {
  d=$1
  s=$(spec "$d") || { log "unknown distribution: $d"; return 1; }
  set -- $s
  fam=$1 base=$2 port=$3
  log "[$d] image ($base)"
  docker build -q -t "bl-test:$d" --build-arg "BASE=$base" -f "$KIT/test/docker/Dockerfile.$fam" \
    "$KIT/test/docker" >"$RES/$d.build.log" 2>&1 || { log "[$d] BUILD FAILED - $RES/$d.build.log"; return 1; }
  docker rm -f "bl-$d" >/dev/null 2>&1
  docker run -d --name "bl-$d" --hostname "bl-$d" --privileged --cgroupns=private \
    --network "$NET" --tmpfs /run --tmpfs /run/lock -v "$CACHE:/var/cache/blocklist-src" \
    -p "$port:22" "bl-test:$d" >/dev/null || { log "[$d] RUN FAILED"; return 1; }
  i=0
  while [ $i -lt 90 ]; do
    s=$(docker exec "bl-$d" systemctl is-system-running 2>/dev/null)
    case "$s" in running|degraded) break ;; esac
    i=$((i + 1)); sleep 1
  done
  docker cp "$KIT/test/.keys/authorized_keys" "bl-$d:/root/.ssh/authorized_keys"
  docker exec "bl-$d" sh -c 'chown root:root /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys'
  docker cp "$BLKIT/." "bl-$d:/opt/kit"
  log "[$d] up (systemd: ${s:-?}, ssh: port $port)"
}

install_one() {
  d=$1; t0=$(date +%s)
  docker cp "$BLKIT/." "bl-$d:/opt/kit"
  docker exec "bl-$d" bash /opt/kit/install.sh --config /opt/kit/test/fixtures/blocklist.conf.test \
    --hold-ip 203.0.113.77 --hold 5 --rollback 3600 >"$RES/$d.install.log" 2>&1
  rc=$?
  docker exec "bl-$d" /usr/local/sbin/blocklist confirm >>"$RES/$d.install.log" 2>&1
  echo "$rc $(( $(date +%s) - t0 ))" > "$RES/$d.install.rc"
  log "[$d] install rc=$rc ($(( $(date +%s) - t0 ))s)"
  return $rc
}

test_one() {
  d=$1; t0=$(date +%s)
  docker cp "$BLKIT/test/." "bl-$d:/opt/kit/test"
  docker exec "bl-$d" bash /opt/kit/test/test.sh >"$RES/$d.test.log" 2>&1
  rc=$?
  echo "$rc $(( $(date +%s) - t0 ))" > "$RES/$d.test.rc"
  log "[$d] test rc=$rc - $(tail -1 "$RES/$d.test.log")"
  return $rc
}

run_one() { up_one "$1" && install_one "$1" && test_one "$1"; }

parallel() {   # parallel FUNCTION distro...  (in groups of PARALLEL)
  f=$1; shift; n=0
  for d in "$@"; do
    "$f" "$d" &
    n=$((n + 1))
    if [ "$n" -ge "$PARALLEL" ]; then wait; n=0; fi
  done
  wait
}

summary() {
  printf '\n%-18s %-10s %-8s %-8s %s\n' DISTRIBUTION INSTALL TIME TEST RESULT
  for d in "$@"; do
    irc=$(cut -d' ' -f1 "$RES/$d.install.rc" 2>/dev/null || echo -)
    isec=$(cut -d' ' -f2 "$RES/$d.install.rc" 2>/dev/null || echo -)
    trc=$(cut -d' ' -f1 "$RES/$d.test.rc" 2>/dev/null || echo -)
    r=$(grep -h 'RESULT' "$RES/$d.test.log" 2>/dev/null | sed 's/== RESULT: //')
    printf '%-18s %-10s %-8s %-8s %s\n' "$d" "rc=$irc" "${isec}s" "rc=$trc" "${r:--}"
  done
}

cmd=${1:-run}; [ $# -gt 0 ] && shift
if [ $# -eq 0 ]; then
  set -- $CORE
  [ "${EXTENDED:-0}" = 1 ] && set -- $CORE $EXT
fi
case "$cmd" in
  list) echo "core:     $CORE"; echo "extended: $EXT" ;;
  up)      infra; parallel up_one "$@" ;;
  install) infra; parallel install_one "$@" ;;
  test)    infra; parallel test_one "$@"; summary "$@" ;;
  run)
    infra
    first=$1; shift
    run_one "$first"            # the first one alone - it fills the list cache for the others
    [ $# -gt 0 ] && parallel run_one "$@"
    summary "$first" "$@"
    ;;
  down)
    for d in "$@"; do docker rm -f "bl-$d" >/dev/null 2>&1 && log "[$d] removed"; done ;;
  *) sed -n '2,16p' "$0"; exit 2 ;;
esac
