#!/usr/bin/env bash
set -euo pipefail

# repo root = two levels up from bundle/v1
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTDIR="$ROOT/out"

mkdir -p "$OUTDIR"

# Create a deterministic tar.gz from repo content (bundle inputs)
# We archive the minimal proof object directory: bundle/v1
# Determinism knobs: sort, fixed mtime, numeric owner/group, stable gzip
# NOTE: GNU tar + gzip on ubuntu-latest supports these flags.
FIXED_MTIME="2020-01-01 00:00:00Z"

# Build tar (not gz) first to control gzip determinism
TAR_TMP="$OUTDIR/ZENODO_BUNDLE.tar"
TGZ="$OUTDIR/ZENODO_BUNDLE.tar.gz"
SHA="$OUTDIR/ZENODO_BUNDLE_SHA256.txt"

rm -f "$TAR_TMP" "$TGZ" "$SHA"

# Ensure consistent file modes where possible (git checkout should already be stable)
# Archive relative paths for portability
cd "$ROOT"

tar --format=gnu \
  --sort=name \
  --mtime="$FIXED_MTIME" \
  --owner=0 --group=0 --numeric-owner \
  --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime \
  -cf "$TAR_TMP" \
  bundle/v1

# Deterministic gzip: -n (no name/time in header)
gzip -n -9 -c "$TAR_TMP" > "$TGZ"
rm -f "$TAR_TMP"

# sha256
sha256sum "$TGZ" | awk '{print $1"  ZENODO_BUNDLE.tar.gz"}' > "$SHA"

echo "TGZ=$TGZ"
echo "SHA256_FILE=$SHA"
cat "$SHA"