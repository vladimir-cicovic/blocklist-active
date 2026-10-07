#!/bin/bash
# build.sh - builds the distribution files in dist/:
#   blocklist-installer-<version>.run   self-extracting installer (one file to scp)
#   blocklist-kit-<version>.tar.gz      the same content as an archive (Ansible, manual use)
#   SHA256SUMS
#
#   ./build.sh [--with-seed]     --with-seed includes seed/seed.tar.gz (private data!)
set -euo pipefail
KIT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
V="$(cat "$KIT/VERSION")"
DIST="$KIT/dist"
WITH_SEED=0
[ "${1:-}" = --with-seed ] && WITH_SEED=1

if grep -rlIU $'\r' "$KIT/install.sh" "$KIT/uninstall.sh" "$KIT/files" >/dev/null 2>&1; then
  echo "ERROR: files with CRLF line endings:" >&2
  grep -rlIU $'\r' "$KIT/install.sh" "$KIT/uninstall.sh" "$KIT/files" >&2
  exit 1
fi
for f in "$KIT/install.sh" "$KIT/uninstall.sh" "$KIT"/files/usr/local/sbin/* "$KIT/files/usr/local/lib/blocklist/common.sh"; do
  bash -n "$f" || { echo "ERROR: syntax error in $f" >&2; exit 1; }
done

items=(install.sh uninstall.sh VERSION blocklist.conf.example files)
if [ "$WITH_SEED" = 1 ]; then
  [ -f "$KIT/seed/seed.tar.gz" ] || { echo "seed/seed.tar.gz does not exist" >&2; exit 1; }
  items+=(seed)
fi

mkdir -p "$DIST"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir "$TMP/blocklist-kit-$V"
cp -r "${items[@]/#/$KIT/}" "$TMP/blocklist-kit-$V/"
chmod 0755 "$TMP/blocklist-kit-$V"/install.sh "$TMP/blocklist-kit-$V"/uninstall.sh \
           "$TMP/blocklist-kit-$V"/files/usr/local/sbin/* "$TMP/blocklist-kit-$V"/files/root/geoip/*.py
find "$TMP/blocklist-kit-$V" -name __pycache__ -prune -exec rm -rf {} +

# archive for Ansible / manual use (with a top-level directory)
tar czf "$DIST/blocklist-kit-$V.tar.gz" --owner=0 --group=0 --numeric-owner -C "$TMP" "blocklist-kit-$V"
# payload for the .run (no top-level directory)
tar czf "$TMP/payload.tgz" --owner=0 --group=0 --numeric-owner -C "$TMP/blocklist-kit-$V" .
SUM=$(sha256sum "$TMP/payload.tgz" | cut -d' ' -f1)

RUN="$DIST/blocklist-installer-$V.run"
cat > "$RUN" <<EOF
#!/bin/sh
# blocklist-active $V - self-extracting installer
#
#   sh blocklist-installer-$V.run --config blocklist.conf [install.sh options]
#   sh blocklist-installer-$V.run --extract DIR      extract only
#   sh blocklist-installer-$V.run --help             install.sh options
#
# Run as root on the target machine. The payload is verified (SHA-256) before extraction.
PAYLOAD_SHA256=$SUM
EOF
cat >> "$RUN" <<'EOF'
ME="$0"
SKIP=$(sed -n '/^__PAYLOAD_BELOW__$/=' "$ME" | head -1)
[ -n "$SKIP" ] || { echo "corrupt installer file" >&2; exit 1; }
SKIP=$((SKIP + 1))
SUM=$(tail -n +"$SKIP" "$ME" | sha256sum | cut -d' ' -f1)
if [ "$SUM" != "$PAYLOAD_SHA256" ]; then
  echo "checksum mismatch - the file is corrupt or was modified" >&2
  exit 1
fi
if [ "${1:-}" = --extract ]; then
  D="${2:?usage: --extract DIR}"
  mkdir -p "$D" && tail -n +"$SKIP" "$ME" | tar xzf - -C "$D" && echo "extracted to $D"
  exit $?
fi
T=$(mktemp -d /tmp/blocklist-kit.XXXXXX) || exit 1
if ! tail -n +"$SKIP" "$ME" | tar xzf - -C "$T"; then
  rm -rf "$T"; echo "extraction failed" >&2; exit 1
fi
bash "$T/install.sh" "$@"
RC=$?
rm -rf "$T"
exit $RC
__PAYLOAD_BELOW__
EOF
cat "$TMP/payload.tgz" >> "$RUN"
chmod 0755 "$RUN"

(cd "$DIST" && sha256sum "blocklist-installer-$V.run" "blocklist-kit-$V.tar.gz" > SHA256SUMS)
ls -la "$DIST"
[ "$WITH_SEED" = 1 ] && echo "NOTE: the package contains the seed (addresses from your logs) - do not publish it"
exit 0
