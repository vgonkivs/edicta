#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# One-shot, runs in the celestia-app image after genesis-init. Builds the
# genesis of a single-validator devnet (chain id edicta-dev-1) that funds the
# Recorder and the demo funder. DEV ONLY: the validator key lives in the test
# keyring of the celestia volume and is worthless outside this stack.
#
# Idempotent: an existing genesis is kept, so a restart reuses the chain.
set -eu

CHAIN_ID="${CELESTIA_CHAIN_ID:-edicta-dev-1}"
HOME_DIR="${CELESTIA_HOME:-/celestia-home}"
DEV_HOME="${DEV_HOME:-/dev-home}"
APPD="celestia-appd"
# The image entrypoint wraps the binary with a banner; call it directly.
KR="--keyring-backend test --home $HOME_DIR"

if [ "$CHAIN_ID" != "edicta-dev-1" ]; then
  echo "celestia-init: refusing chain id $CHAIN_ID: only edicta-dev-1 is a dev chain" >&2
  exit 1
fi
if [ -s "$HOME_DIR/config/genesis.json" ]; then
  echo "celestia-init: genesis exists, keeping it"
  exit 0
fi

# shellcheck disable=SC1091
. "$DEV_HOME/accounts.env"
: "${RECORDER_ADDRESS:?}" "${FUNDER_ADDRESS:?}"

$APPD init edicta-dev --chain-id "$CHAIN_ID" --home "$HOME_DIR" >/dev/null 2>&1
# shellcheck disable=SC2086
$APPD keys add validator $KR >/dev/null 2>&1
# shellcheck disable=SC2086
VALIDATOR="$($APPD keys show validator -a $KR)"

# utia: 1 TIA = 1,000,000 utia.
# shellcheck disable=SC2086
$APPD genesis add-genesis-account "$VALIDATOR" 10000000000000utia --home "$HOME_DIR"
$APPD genesis add-genesis-account "$RECORDER_ADDRESS" 1000000000utia --home "$HOME_DIR"
$APPD genesis add-genesis-account "$FUNDER_ADDRESS" 10000000utia --home "$HOME_DIR"
# shellcheck disable=SC2086
$APPD genesis gentx validator 5000000000utia --fees 1000utia --chain-id "$CHAIN_ID" $KR >/dev/null 2>&1
$APPD genesis collect-gentxs --home "$HOME_DIR" >/dev/null 2>&1
$APPD genesis validate --home "$HOME_DIR"

CFG="$HOME_DIR/config/config.toml"
APP="$HOME_DIR/config/app.toml"
# Listen on all interfaces of the compose network.
sed -i 's|^laddr = "tcp://127.0.0.1:26657"|laddr = "tcp://0.0.0.0:26657"|' "$CFG"
sed -i 's|^minimum-gas-prices = .*|minimum-gas-prices = "0.002utia"|' "$APP"
# edictad and the bridge node submit and read through the consensus gRPC
# endpoint, which the app leaves off and on localhost.
sed -i '/^\[grpc\]/,/^\[/ s|^enable = false|enable = true|' "$APP"
sed -i 's|^address = "localhost:9090"|address = "0.0.0.0:9090"|' "$APP"
sed -i 's|^address = "127.0.0.1:9090"|address = "0.0.0.0:9090"|' "$APP"
echo "celestia-init: genesis written for $CHAIN_ID"
