#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# Runs in the celestia-node image. edictad reads blobs and proofs through a
# bridge node, so the single-validator devnet needs one. The devnet is a
# private network: the bridge trusts the hash of block 1 that the validator
# serves, which is the only way to bootstrap a chain with no public peers.
# DEV ONLY: the RPC runs without authentication on the compose network.
set -euo pipefail

CHAIN_ID="${CELESTIA_CHAIN_ID:-edicta-dev-1}"
CORE_RPC="${CORE_RPC:-http://celestia:26657}"
CORE_HOST="${CORE_HOST:-celestia}"
STORE="${NODE_STORE:-/bridge-home}"

if [ "$CHAIN_ID" != "edicta-dev-1" ]; then
  echo "celestia-bridge: refusing chain id $CHAIN_ID: only edicta-dev-1 is a dev chain" >&2
  exit 1
fi

# The validator is healthy before this runs, but block 1 is served as soon as
# the first block is committed.
HASH=""
for _ in $(seq 1 60); do
  HASH="$(curl -sf "$CORE_RPC/block?height=1" | jq -r '.result.block_id.hash // empty' || true)"
  [ -n "$HASH" ] && break
  sleep 2
done
if [ -z "$HASH" ]; then
  echo "celestia-bridge: no block 1 hash from $CORE_RPC" >&2
  exit 1
fi

export CELESTIA_CUSTOM="$CHAIN_ID:$HASH"
if [ ! -f "$STORE/config.toml" ]; then
  celestia bridge init --p2p.network "$CHAIN_ID" --node.store "$STORE"
fi
exec celestia bridge start --p2p.network "$CHAIN_ID" --node.store "$STORE" \
  --core.ip "$CORE_HOST" --core.port 9090 \
  --rpc.addr 0.0.0.0 --rpc.skip-auth
