#!/bin/sh
# Rebuilds the artifacts with the pinned solc image. With "check" it only
# compares the fresh output with the checked-in files.
set -eu

SOLC_IMAGE="ethereum/solc:0.8.28"
OPTIMIZE_RUNS=200
EVM_VERSION=paris

here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

docker run --rm --platform linux/amd64 \
  -v "$here":/src:ro -v "$tmp":/out "$SOLC_IMAGE" \
  --optimize --optimize-runs "$OPTIMIZE_RUNS" --evm-version "$EVM_VERSION" \
  --metadata-hash none --bin --bin-runtime --abi --overwrite \
  -o /out /src/EdictaPublish.sol >/dev/null

sha() { shasum -a 256 "$1" | cut -d' ' -f1; }

cp "$tmp/EdictaPublish.bin-runtime" "$tmp/runtime.hex"
cp "$tmp/EdictaPublish.bin" "$tmp/init.hex"
cp "$tmp/EdictaPublish.abi" "$tmp/EdictaPublish.abi.json"
cat > "$tmp/build.json" <<JSON
{
  "solc_image": "$SOLC_IMAGE",
  "solc_version": "0.8.28",
  "optimizer": true,
  "optimizer_runs": $OPTIMIZE_RUNS,
  "evm_version": "$EVM_VERSION",
  "metadata_hash": "none",
  "source_sha256": "$(sha "$here/EdictaPublish.sol")",
  "runtime_sha256": "$(sha "$tmp/runtime.hex")",
  "init_sha256": "$(sha "$tmp/init.hex")"
}
JSON

for f in runtime.hex init.hex EdictaPublish.abi.json build.json; do
  if [ "${1:-}" = "check" ]; then
    cmp "$tmp/$f" "$here/$f" || { echo "stale artifact: $f" >&2; exit 1; }
  else
    cp "$tmp/$f" "$here/$f"
  fi
done
