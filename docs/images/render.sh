#!/bin/sh
# docs/images/render.sh - renders the Mermaid sources in docs/images/src to PNG.
# Needs Docker (any host). Usage: sh docs/images/render.sh
set -eu
DIR=$(cd "$(dirname "$0")" && pwd)
for src in "$DIR"/src/*.mmd; do
  name=$(basename "$src" .mmd)
  docker run --rm -u "$(id -u):$(id -g)" -v "$DIR:/data" minlag/mermaid-cli \
    -i "/data/src/$name.mmd" -o "/data/$name.png" -b white -s 2 -q
  echo "rendered $name.png"
done
