#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Runs in the ev-node-evm image: the single sequencer of the Eden dev chain.
# It needs the genesis hash that ev-reth computed from the dev chainspec, so it
# waits for ev-reth and reads block 0. The data availability layer is the
# in-memory local DA (eden-da), never Celestia.
# DEV ONLY: the sequencer passphrase below protects a key that exists only in
# this stack's volume.
set -eu

HOME_DIR="${EVM_HOME:-/root/.evm}"
RETH="${EDEN_RETH_HOST:-eden-reth}"
EV_CHAIN_ID="${EDEN_NODE_CHAIN_ID:-edicta-eden-dev}"
PASSFILE="$HOME_DIR/passphrase.txt"

mkdir -p "$HOME_DIR"
if [ ! -f "$PASSFILE" ]; then
  echo "dev-only-sequencer-passphrase" >"$PASSFILE"
  chmod 600 "$PASSFILE"
fi
if [ ! -f "$HOME_DIR/config/node_key.json" ]; then
  evm init --home "$HOME_DIR" --chain_id "$EV_CHAIN_ID" \
    --evnode.node.aggregator=true --evnode.signer.passphrase_file "$PASSFILE"
fi

HASH=""
i=0
while [ "$i" -lt 60 ]; do
  HASH="$(wget -qO- --header 'Content-Type: application/json' \
    --post-data '{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["0x0",false]}' \
    "http://$RETH:8545" 2>/dev/null | sed -n 's/.*"hash":"\(0x[0-9a-fA-F]\{64\}\)".*/\1/p' || true)"
  [ -n "$HASH" ] && break
  i=$((i + 1))
  sleep 2
done
if [ -z "$HASH" ]; then
  echo "eden-node: no genesis hash from $RETH" >&2
  exit 1
fi

export EVM_ENGINE_URL="http://$RETH:8551"
export EVM_ETH_URL="http://$RETH:8545"
export EVM_JWT_SECRET
EVM_JWT_SECRET="$(tr -d '\n' </dev-home/genesis/jwt.hex)"
export EVM_GENESIS_HASH="$HASH"
export EVM_BLOCK_TIME="${EDEN_BLOCK_TIME:-100ms}"
export EVM_SIGNER_PASSPHRASE="dev-only-sequencer-passphrase"
export DA_ADDRESS="http://${EDEN_DA_HOST:-eden-da}:7980"

# The image entrypoint adds the engine, DA and signer flags from the
# environment above and appends these.
exec /usr/bin/entrypoint.sh start \
  --evnode.rpc.address 0.0.0.0:7331 \
  --evnode.da.block_time 1s \
  --evnode.da.batching_strategy immediate \
  --evnode.p2p.listen_address /ip4/0.0.0.0/tcp/7676
