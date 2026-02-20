#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUNDLE="$ROOT/bundle/v1"
OUT="$ROOT/out"
TGZ="$OUT/ZENODO_BUNDLE.tar.gz"
SHA="$OUT/ZENODO_BUNDLE_SHA256.txt"

mkdir -p "$OUT"

# Stable locale (defensive)
export LC_ALL=C

cd "$BUNDLE"

# Explicit stable file list (relative to bundle/v1)
# NOTE: do NOT include ZENODO_BUNDLE_SHA256_EXPECTED.txt (that is a target, not part of bundle).
FILES=(
  "ANCHORS_README.txt"
  "AUTHORITY_ID.txt"
  "AUTHORITY_IMAGE_DIGEST.txt"
  "AUTHORITY_URL.txt"
  "build.sh"
  "executor_config.json"
  "FETCH_VPS_ANCHORS.ps1"
  "intent.json"
  "last_executor_response.json"
  "PACKAGE_BUNDLE.ps1"
  "PUBLIC_KEY_B64.txt"
  "PUBLIC_KEY_SHA256.txt"
  "REPLAY_REPORT_SHA256.txt"
  "REPLAY_REPORT.txt"
  "SHA256SUMS.txt"
  "signed_record.json"
  "SPEC_SIGNED_ADMISSION_RECORD_V1.md"
  "verifier_go.exe"
  "verifier.py"
  "anchors/ledger_root_20260220_14.txt"
  "anchors/ledger_root_20260220_14.txt.ots"
)

# Deterministic tar:
# - fixed mtime/uid/gid/mode
# - no xattrs/acls/selinux
# - stable order by feeding explicit list
# - gzip -n to remove timestamp
rm -f "$TGZ" "$SHA"

printf '%s\n' "${FILES[@]}" | tar \
  --format=gnu \
  --no-acls --no-xattrs --no-selinux \
  --numeric-owner --owner=0 --group=0 \
  --mode='u=rw,go=r' \
  --mtime='@0' --clamp-mtime \
  -cf - --files-from - | gzip -n > "$TGZ"

# Write sha256 (hex only)
sha256sum "$TGZ" | awk '{print $1}' > "$SHA"

echo "TGZ=$TGZ"
echo "TGZ_SHA256=$(cat "$SHA")"