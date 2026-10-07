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

Each keyring has its own passphrase. It is read only from the passphrase file
or, for the executor, from `--executor-passphrase-prompt` (typed without echo);
nothing else prompts, even when stdin is a terminal. A wrong passphrase fails
with a clear error. Put each passphrase in a file with mode 0600
(`chmod 600`). Note the two addresses the tool prints.

Fund both addresses. On a public testnet use that network's faucet. On Mocha,
use the Mocha faucet (see the Celestia documentation for its current location)
and ask for coins for both addresses. Receivers of the demo transfer need no
funds. On a devnet, send from your genesis account. Keep the amounts small.

Funding by the demo (`railtx.Funder`) trusts the funding node you point it at.
It checks the node's answers for a send that did not show up, but it has no
second source: a node that lies about committed state could make it send one
extra transfer, at most the configured per-send maximum. Use your own node or
one you trust, and keep the amounts small.

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

### Data availability mode and the archive

`network.da` picks the one mode an instance serves: `"celestia_blob"` (da = 2,
the blob is on Celestia L1) or `"fibre"` (da = 1). The old value `"blob"` is
refused; write `"celestia_blob"`. A decision for the other mode is refused with
`ErrDANotAllowed`.

- `[archive]` is required in both modes. `dir` is the archive directory (one
  edictad per directory), `write_timeout_s` bounds every archive write (1..60,
  default 10) and `sweep_interval_s` how often a failed sweep is repeated (60..86400,
  default 600).
- `da = "fibre"` takes `network.fibre_chain_ids` (the chains whose payment
  promises are accepted, default `["mocha-5"]`) and the `[fibre]` table:
  `max_data_bytes`, `max_read_bytes`, `anchor_cache_bytes`, `lookup_timeout_s`,
  `assumed_lag_blocks`, `sample_every_s`, `canary_every_s` and `bridge_fallback`.
  Every key has a default and the example config shows them. With `celestia_blob`
  these keys must be absent or zero, so a half-switched file never starts. The Fibre
  app version is pinned: `min_app_version` and `max_app_version` are refused.
- With `da = "fibre"` the Recorder can be enabled too; see "Fibre Recorder" below.

The gate writes the decision (the envelope and the action bytes exactly as
presented) to the archive after the agent signature, the action type allowlist and the
action bytes have passed, and before it reads or marks the nonce. So only signed,
allowlisted decisions with their committed bytes reach the archive, and unsigned
input cannot fill it. The Authorization is archived after it is signed, and a
refusal after the decision was archived leaves a marker with the error name. At
start, a sweep copies Authorizations that are in the registry but not in the
archive (after a crash or an archive outage between the two writes). The sweep
before the listener has a 30 s budget; what it does not reach is finished in the
background, and a sweep that left work is repeated every `sweep_interval_s`.
Records the gate could not write after signing wait in a memory queue of 1024 for
the next sweep. At shutdown one last attempt writes what is still queued, bounded
by the shutdown context and by `write_timeout_s`; if the shutdown context ends
first, `Shutdown` returns its error. A record still queued at exit is repaired by the
sweep at the next start. A record that was dropped because the queue was full, or
that failed permanently, is repaired by the next tick of the running process. Both
repairs read the Authorization from the registry, so the record has no retention
inputs, because only the request that issued the Authorization has them. At most 64 archive calls run at once, and one more gets the
retryable 503.

If the archive is down, `POST /v0/authorize` answers 503 with `ErrArchiveUnavailable`
and `Retry-After: 5`, nothing is signed and the nonce stays unused, so the same
request succeeds once the archive is back. This also holds for a retry of a
decision that was already authorized: the archive write comes before the nonce
read, so while the archive is down that retry gets 503 as well, and gets the usual
409 with the stored Authorization afterwards. An archive write that fails after the
Authorization was signed does not change the 200; the sweep repairs the archive.

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

## Endpoints

Every read the gate makes at a height is checked: the answer must carry the
height that was asked for. A consensus endpoint must honour the
`x-cosmos-block-height` header, which is how the gate reads x/fibre retention at
the height of an anchor. At start, each endpoint runs a height canary and edictad
logs one line per endpoint (`consensus: height honoured`, `consensus:
height-ignoring, observations-only mode`, `consensus: height check
inconclusive, observations-only mode`, and the same for `bridge`), then exactly one
summary line:

```
INFO edictad: at-height reads da=fibre retention=direct
WARN edictad: at-height reads da=fibre retention=observations-only reason=...
INFO edictad: at-height reads da=celestia_blob retention=unused bridge=honoured
```

The endpoints verified as honouring the height as of 2026-10-05 are P-OPS
(`grpc-mocha.pops.one:9090`) and nodes.guru. The public QuickNode endpoint is
height-ignoring. An own node is the robust choice.

An endpoint that is height-ignoring does not stop the start. edictad then runs in
observations-only mode: the retention at a height is taken only from the gate's own
samples (the observer samples x/fibre every `sample_every_s` seconds and stores
them in the registry file). A decision whose anchor height those samples do not
cover fails with 503 `ErrRetentionUnavailable`, and so does every height after the observer
has stopped; the health status is then degraded.

With `da = "fibre"` the bridge is required: the anchor proof (the data availability
header and the namespace data of the block that holds the payment) is read from it
and verified against the consensus header, so a lying bridge gets a 503, never a
false anchor. Nothing else is trusted from it.

The bridge download fallback is off by default. With `fibre.bridge_fallback = true`
edictad enables it only after a capability probe passes: it runs in the background
after the listener is up (the fallback is off until then) and repeats every
`canary_every_s` until it passes. It downloads one
recent, anchored blob through the same bridge client and token, checks that the raw
answer has exactly the expected shape and recomputes the blob's commitment. A node
version, or any capability, written in the configuration is never accepted instead
(the version method of the node needs an admin token, which a gate must not hold).
A failed or inconclusive probe leaves the fallback off with a warning. Every blob
from the fallback is recomputed anyway, so the probe only finds an incompatible
bridge shortly after the start instead of when it is needed.

Submission by the Fibre Recorder goes only through a consensus node the operator
controls, which `recorder.own_node = true` asserts.

## Fibre Recorder

With `da = "fibre"` and `recorder.enabled = true` edictad publishes through the
Fibre Recorder. It submits only through the operator's own consensus node, which
`recorder.own_node = true` asserts and which is required: the same node is read to
confirm the anchor. The Fibre compatibility check runs before the signing client is
dialled, so a chain it refuses is refused before any key is used. Keys, with the
defaults that apply only to this mode:

- `own_node`: must be `true`.
- `escrow_margin_utia` (default 0): kept in the escrow on top of the cost of an
  upload. Set it to at least the cost of one upload for every drain slot (two), so
  a submit whose outcome is still unknown cannot leave a later one failing on
  chain and wasting its fee.
- `submit_timeout_s` (default 300, 1..600): bound of one submit. `/v0/publish` has
  its own deadline of `submit_timeout_s + 120` seconds, so the submit is not cut
  short by the 2 minute deadline of the other routes.
- `upload_drain_s` (default 120, 1..600): how long shard uploads may continue after
  the submit returns. Each publish holds one of two drain slots for that long, so
  throughput is at most two publishes per `upload_drain_s`; a third waits for a
  slot and answers `deadline` if none frees in time.
- `close_timeout_s` (default 150, 1..600, not below `upload_drain_s`): the bound of
  the wait for draining uploads at shutdown.

`recorder.max_blob_bytes` may not exceed `fibre.max_data_bytes`. With
`celestia_blob`, or with the Recorder disabled, these keys must be absent. At
shutdown edictad stops the HTTP server and waits for requests, then calls the
Recorder's `Close`, which waits for draining uploads up to `close_timeout_s` and
then cancels them, then closes the signing client and the registry. A `Close` error
is logged and returned and does not skip the rest. If requests are still running
when the shutdown context ends, they are cut off and the rest is closed anyway.
The daemon allows itself the longest request, `write_timeout_s` and
`close_timeout_s` plus 10 seconds, which is `submit_timeout_s + 120 +
write_timeout_s + close_timeout_s + 10` seconds with the defaults. Set the unit's
`TimeoutStopSec` above that, or the process manager kills the drain.

The Recorder never deposits or withdraws; an escrow below the cost of an upload
fails the publish with `recorder.ErrEscrowInsufficient` (see below).

## Fibre escrow

A Fibre upload is paid from the signer's escrow balance. The cost of one decision's
blob is

```
650000 + 45000 * ceil(upload_bytes / 262144)   utia
```

where `upload_bytes` is the size the upload is charged for, which is larger than
the payload length (`fibrecommit.UploadSize`). Fund the escrow with a `MsgDepositToEscrow`
transaction from the Recorder account. **UNVERIFIED until the live run:** the
command below has not been run against a network and its flags may differ.

```
celestia-appd tx fibre deposit-to-escrow <amount>utia --from <recorder key> \
  --node <consensus rpc> --chain-id <chain id>
```

The Recorder checks the escrow before it uploads. A balance below the cost fails
with `recorder.ErrEscrowInsufficient`, which names the missing amount, and nothing
is uploaded. Funding is never automatic: `AutoFund` is switched off in every client
Edicta builds, so the escrow only changes by a deposit you make. A withdrawal
takes effect after the x/fibre `withdrawal_delay`, 24 h by default but a governance
parameter that can be raised to 7 days; read the current value with
`celestia-appd query fibre params`.

The Recorder's `ErrClockSkew` and `ErrAnchorRejected` are reported to clients as the
generic internal error; the log names them.

An upload whose payment promise is handed to validators but never settled may still
be charged once, so a failed upload can cost one fee without creating an anchor.

## Tests

```
go -C celestia build ./... && go -C celestia vet ./... && go -C celestia test -race -count=1 ./...
go -C celestia test -tags integration ./cmd/edicta-live    # skips without the environment
```

The integration tests read endpoints and key files from `EDICTA_*` variables
(listed at the top of `cmd/edicta-live/integration_test.go`) and need
`EDICTA_LIVE_WRITE=1`, because they publish a blob and move funds. They script
the price move; the command itself never does.
