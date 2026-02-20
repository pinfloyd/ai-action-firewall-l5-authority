#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="$ROOT/out"

mkdir -p "$OUTDIR"

FIXED_MTIME="2020-01-01 00:00:00Z"

TAR_TMP="$OUTDIR/ZENODO_BUNDLE.tar"
TGZ="$OUTDIR/ZENODO_BUNDLE.tar.gz"
SHA="$OUTDIR/ZENODO_BUNDLE_SHA256.txt"

rm -f "$TAR_TMP" "$TGZ" "$SHA"

cd "$ROOT"

tar \
  --sort=name \
  --mtime="$FIXED_MTIME" \
  --owner=0 --group=0 --numeric-owner \
  --exclude="bundle/v1/ZENODO_BUNDLE_SHA256_EXPECTED.txt" \
  -cf "$TAR_TMP" \
  bundle/v1

gzip -n -9 -c "$TAR_TMP" > "$TGZ"
rm -f "$TAR_TMP"

sha256sum "$TGZ" | awk '{print $1"  ZENODO_BUNDLE.tar.gz"}' > "$SHA"

echo "TGZ=$TGZ"
echo "SHA256_FILE=$SHA"
cat "$SHA"