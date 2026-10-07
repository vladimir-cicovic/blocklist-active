#!/bin/sh
# test/ansible-test.sh - runs ansible/site.yml from a control container on the blnet network,
# twice: the first run installs, the second must change nothing (idempotency).
#   test/ansible-test.sh [host...]     (default: all hosts from test/ansible/inventory.ini)
set -u
KIT=$(cd "$(dirname "$0")/.." && pwd)
LIMIT=""
[ $# -gt 0 ] && LIMIT="--limit $(echo "$*" | tr ' ' ',')"
docker run --rm --network blnet -v "$KIT:/kit:ro" -e ANSIBLE_FORCE_COLOR=0 alpine:3.24 sh -c "
  apk add -q ansible-core openssh-client >/dev/null &&
  mkdir -p /root/.ssh && cp /kit/test/.keys/bltest /root/.ssh/bltest && chmod 600 /root/.ssh/bltest &&
  cd /kit/ansible &&
  echo '===== FIRST RUN =====' &&
  ansible-playbook -i /kit/test/ansible/inventory.ini site.yml $LIMIT &&
  echo '===== SECOND RUN (expected changed=0) =====' &&
  ansible-playbook -i /kit/test/ansible/inventory.ini site.yml $LIMIT
"
