# Edicta on Celestia: running the live demo

This module holds the Celestia side of Edicta: the Recorder, the chain client
for the gate, the executor's transaction signer, the `edictad` daemon and the
`edicta-live` runner. The demo runs against any Celestia network you have
endpoints for (Mocha, mainnet, a local devnet). No network name, chain id or
endpoint is built in; they come from your configuration.

What the demo does: an agent watches a real TIA price. When it moves by the
threshold (100 basis points = 1% by default), the agent publishes its decision
as a blob BEFORE acting, the gate authorizes the exact action, a separate
executor account sends the transfer with the commitment hash as memo, and the
gate records a receipt. `edicta-live` prints the evidence and checks it.

Working directory: the commands use `go -C celestia ...`, so run them from the
repository root. Paths given to the program (`-config`, key files) are resolved
against your shell's current directory, not `celestia/`, so use absolute paths or
`~`. Replace every placeholder in
angle brackets. Never paste real keys or tokens into chat, logs or the repo.

## 1. Prerequisites

- A bridge node endpoint (JSON-RPC) and its auth token, if it needs one.
- A consensus node gRPC endpoint (and token, if it needs one).
- Two chain accounts in two separate `file` keyrings, both funded:
  the Recorder account (pays blob fees) and the executor account (the
  sender of the transfer). They must be different accounts.
- A namespace for the blobs: 29 bytes, 58 hex characters. Any value that is a
  valid user namespace will do; pick one and keep it.
- Go (the version in `go.mod`), and a place outside the repository for keys
  and tokens, for example `~/edicta-live/`.

## 2. Keys and funds

Create the two chain keys with any tool that writes a Cosmos SDK `file`
backend keyring. For example, with the network's CLI (check `--help` for the
exact flags of your version):

```
celestia-appd keys add recorder --keyring-backend file --keyring-dir ~/edicta-live/recorder-keyring
celestia-appd keys add sender   --keyring-backend file --keyring-dir ~/edicta-live/executor-keyring
```

Each keyring has its own passphrase. The keyring library prints a line
"Enter keyring passphrase" even when the passphrase comes from a file; it is
not a prompt and nothing is read from the terminal. A wrong passphrase file
fails with a clear error and never falls back to a prompt. Put each passphrase in a file with mode
0600 (`chmod 600`), or for the executor use `--executor-passphrase-prompt` to
type it without echo. Note the two addresses the tool prints.

Fund both addresses. On a public testnet use that network's faucet. On Mocha,
use the Mocha faucet (see the Celestia documentation for its current location)
and ask for coins for both addresses. Receivers of the demo transfer need no
funds. On a devnet, send from your genesis account. Keep the amounts small.

Create the Ed25519 keys (raw 32-byte seeds, mode 0600): one for the agent, one
for the executor's record request, one for the gate. Then print the public
keys, which go into the `edictad` config:

```
mkdir -p ~/edicta-live
for k in agent executor gate; do head -c 32 /dev/urandom > ~/edicta-live/$k.ed25519; chmod 600 ~/edicta-live/$k.ed25519; done
go -C celestia run ./cmd/edicta-live pubkey ~/edicta-live/agent.ed25519
go -C celestia run ./cmd/edicta-live pubkey ~/edicta-live/executor.ed25519
go -C celestia run ./cmd/edicta-live pubkey ~/edicta-live/gate.ed25519
```

Create a bearer-token file (any long random string, mode 0600) for the
edictad API. Keep a bridge node token, if it needs one, in its own file:

```
head -c 24 /dev/urandom | base64 > ~/edicta-live/api.token; chmod 600 ~/edicta-live/api.token
```

## 3. Configure and start edictad

Copy the example and edit it:

```
cp celestia/cmd/edictad/edictad.example.toml ~/edicta-live/edictad.toml
```

Set, at least: the bridge and consensus addresses (and `tls`), `recorder.namespace`,
the Recorder keyring directory, key name and passphrase file, the gate key file
(the `gate.ed25519` seed), the registry path, `gate.executor_keys` (the executor's
public key from step 2), and the token files. Write the agents file named by
`gate.allowlist_file`:

```
[[agents]]
agent_id = "demo-agent-1"
pubkey = "<agent public key, 64 hex characters>"
```

Check that the config parses (it prints paths only, never secrets), then start:

```
go -C celestia run ./cmd/edictad -config ~/edicta-live/edictad.toml -print-config
go -C celestia run ./cmd/edictad -config ~/edicta-live/edictad.toml
```

edictad refuses to start if the node fails the compatibility check, if a key
file is too permissive, or if the config has an unknown key. Leave it running.

## 4. Run edicta-live

Dry run first. It does everything except broadcast the transfer: it publishes
the blob (this spends a small Recorder fee), verifies inclusion, gets and
verifies the Authorization, and signs the transfer without sending it. It
does not record a receipt. The first reading becomes the baseline, so the run
waits for the price to move; for a first test lower the threshold.

```
go -C celestia run ./cmd/edicta-live \
  --api-url http://127.0.0.1:8080 --api-token-file ~/edicta-live/api.token \
  --gate-pubkey <gate public key, 64 hex> \
  --bridge-addr <bridge host:port> --bridge-tls --bridge-token-file <file> \
  --grpc-addr <consensus host:port> --grpc-tls \
  --agent-id demo-agent-1 --agent-key-file ~/edicta-live/agent.ed25519 \
  --gen-recipient-key ~/edicta-live/recipient.key \
  --executor-keyring-dir ~/edicta-live/executor-keyring --executor-key sender \
  --executor-passphrase-file <file> \
  --executor-ed25519-file ~/edicta-live/executor.ed25519 \
  --up-addr <destination if price rises> --up-amount 1000 \
  --down-addr <destination if price falls> --down-amount 1000 \
  --threshold-bp 5 --dry-run
```

Amounts are in base units (`utia`). `--gen-recipient-key` creates the key that
opens the published payload; keep that file. Use `--recipient kid=<64 hex X25519 public key>` instead
to seal to a key you already have. `--bridge-addr` takes `host:port` (the scheme follows `--bridge-tls`) or a full
`http://` or `https://` URL, which must agree with `--bridge-tls`. Drop `--bridge-tls`, `--grpc-tls` for a
local plaintext endpoint. The gRPC endpoint must present a certificate that
verifies against the system roots; one with a private or origin-only
certificate cannot be used with `--grpc-tls`. `--da` (blob by default) must equal the `da` of edictad's config. `--chain-id` and `--namespace` optionally pin what
the nodes and edictad report.

The default inclusion check is `self`: it trusts your own bridge node, which is
right only when you run both the submitter and the agent. For an independent
check use `--inclusion light` (with `--rpc-primary`, `--rpc-witness`,
`--trust-height`, `--trust-hash`, from providers of different operators) or
`--inclusion crosscheck` (two or more `--crosscheck-bridge`). Without
`--gate-pubkey` the gate key is learned from edictad and the run warns.

When the dry run is green, run for real: the same command without `--dry-run`
(and use a new `--gen-recipient-key` path, or `--recipient`, because the file
is never overwritten). To use the real 1% trigger leave `--threshold-bp` out
(default 100), and expect to wait for the price to move; `--timeout` (default
30m) and `--poll-interval` (default 30s) bound the wait. The price comes from
a public source: `--price-source coingecko|kraken` (`--asset`, `--quote`,
`--kraken-pair`). There is no fake price in the command. `--max-decisions`
(default 1) stops the run. The fee is derived at startup from the node's
`minimum_gas_price`: gas limit x price x `--fee-margin` (default 1.2), rounded
up, in base units. `--gas-limit` and `--fee` (non-zero) override it, and
`--max-fee` caps either; the run refuses a fee above the cap. `--json` prints JSON instead of text and
`--evidence-file <path>` also saves it.

`--indexer-lag-blocks` (default 3) is how many blocks past the timeout height
the status node may lag before a missing transaction counts as lost, and
`--confirm-delay` (default 2s, at most `--rebroadcast-every`) is the wait
before the second status query of that final check.

The run exits non-zero with a clear message on any failure. If the transfer
was signed but its inclusion could not be confirmed (timeout height or grace
passed, or the node rejected it), the run reports it was handed off to the
operator. Look the printed tx hash up on the chain, and never send the
transfer again by hand while it may still be included (until timeout_height):
no second transaction is ever built for the
decision.

## 5. Reading the evidence

On success the run prints, and re-checks before printing OK:

- `chain_id`, `namespace`, `blob height H` and its block time, the share
  commitment and the signer (the Recorder's address): the decision was
  published at H.
- `commitment_hash` and the agent public key: what the agent signed.
- The Authorization: hash, expiry and `verified: OK` under the gate key.
- The transfer: tx hash, `tx height` (must be above H), code 0 and the memo
  (must equal `commitment_hash`).
- The receipt: `verified: OK`, with the executor key.
- Look-up hints that name no explorer: query the tx hash on your chain with
  any explorer or node, and fetch the blob from a bridge node by height,
  namespace and share commitment.

The acceptance claim is: the blob is at height H, the transfer is included at a
height above H, its memo is the commitment hash, and both the Authorization
and the receipt verify.

## Tests

```
go -C celestia build ./... && go -C celestia vet ./... && go -C celestia test -race -count=1 ./...
go -C celestia test -tags integration ./cmd/edicta-live    # skips without the environment
```

The integration tests read endpoints and key files from `EDICTA_*` variables
(listed at the top of `cmd/edicta-live/integration_test.go`) and need
`EDICTA_LIVE_WRITE=1`, because they publish a blob and move funds. They script
the price move; the command itself never does.
