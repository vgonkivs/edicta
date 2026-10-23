# Operator guide: edictad

`edictad` is the gate (verify and authorize, never execute), the archive
writer and, optionally, a Recorder that publishes agents' payloads. It runs as
`edicta gate serve`. One
instance serves one data availability mode. This guide is the overview; the
full key reference with every default and range is in
[../services/gate/README.md](../services/gate/README.md), section "Configure and start edictad", and the commented
example in `services/gate/edictad.example.toml`. Spec:
`spec/decision-commitment-v1.md`, sections 8 (gate), 13 (fast mode), 18
(HTTP API) and 19 (archive).

## Run

```sh
make build
cp services/gate/edictad.example.toml /etc/edictad/edictad.toml   # then edit
bin/edicta gate serve -config /etc/edictad/edictad.toml -print-config      # parse only, prints no secrets
bin/edicta gate serve -config /etc/edictad/edictad.toml
```

`-config` takes either file format: the shared `edicta.toml` (next section)
or the legacy `edictad.toml` of the example above. `edictad` tells them apart
by the `[network]` table: `edicta.toml` names a Celestia network there
(`celestia = "mocha"`), the legacy file does not. Everything below describes
the legacy keys unless it says `edicta.toml`.

Unknown keys are refused (that is also what refuses an inline secret).
Secrets live in files named by `*_file` keys; key files must not be readable
by group or others.

API: `POST /v1/publish` (Recorder), `POST /v1/authorize`, `POST /v1/record`,
`GET /v1/health`, with bearer tokens from `http.authorize_token_file` and
`http.record_token_file`. Plain HTTP with tokens is refused on a non-loopback
address unless `http.allow_insecure` or TLS is set.

## Configuration at a glance

| Table | What it sets |
|---|---|
| `[network]` | `da` (`"celestia_blob"` or `"fibre"`; `"blob"` is refused), `chain_id` cross-check, app version bounds (blob only), `fibre_chain_ids` (Fibre only), the bridge and consensus gRPC endpoints |
| `[fibre]` | Fibre read limits, sampling and the bridge download fallback; must be absent with `celestia_blob` |
| `[archive]` | `dir` (required; one edictad per directory), `write_timeout_s`, `sweep_interval_s` |
| `[recorder]`, `[recorder.quota]` | the Recorder's namespace, keyring, key and quotas; Fibre submission keys; fast-mode keys (below) |
| `[gate]` | `gate_id`, `key_file`, `registry_path`, `action_types`, `allowlist_file` (agents), `executor_keys`, `anchor_verifier = "self"`, `reveal_on_execution` |
| `[gate.fast]` | fast mode (below) |
| `[policy]` | `mandate_file` |
| `[capture]` | execution result capture for bank-send receipts (below) |
| `[http]` | listener, TLS, token files |

## The shared configuration: `edicta.toml`

One file describes a self-hosted stack for every tool: `edicta init` writes
it, `edicta doctor` checks it, `edicta gate serve -config` serves it and
`edicta verify|replay --config` take their defaults from it. It lives in the
Edicta home, `$EDICTA_HOME` or else `~/.edicta`. Loading is strict: an
unknown key is an error (so an inline secret is too), and every secret is a
path to a file.

Print what `edictad` makes of it, without starting anything:

```sh
bin/edicta gate serve -config ~/.edicta/edicta.toml -print-config
```

### Sections

| Table | Keys (defaults in brackets) |
|---|---|
| `[network]` | `celestia` (preset name, required), `settlement` (preset or `"none"`, [`none`]), `mode` [`self-hosted`], `celestia_preset_version`, `settlement_preset_version` (written by `init`, used to report preset drift), `chain_id`, `bridge` and `consensus_grpc` (`addr`, `tls`), `comet_rpc` (list), `[network.evm]`: `chain_id`, `rpc` (list), `facilitator_url`, `facilitator_network`, `[network.evm.usdc]`: `address`, `name`, `version`. Every endpoint key the preset knows is filled from the preset when absent |
| `[agent]` | `id`, `key_file`, `recorder_url`, `gate_url` |
| `[gate]` | `gate_id`, `key_backend` [`file`], `key_file`, `registry_path`, `allowlist_file`, `mandate_file`, `action_types`, `executor_keys`, `listen` [`127.0.0.1:8080`], `fast_mode`, `sessions` |
| `[recorder]` | `keyring_dir`, `key_name`, `passphrase_file`, `namespace` (hex), `da` [`celestia_blob`], `max_blob_bytes` [1048576], `own_node`, `escrow_headroom_utia`, `blobs_per_day` [100] |
| `[publisher]` | a second Celestia account with its own `keyring_dir`, `key_name`, `passphrase_file`, `namespace`, `blobs_per_day` [100] |
| `[archive]` | `dir`, `url`, `mirror_urls` |
| `[signer]` | `listen` [`127.0.0.1:8402`], `pinned_gate_keys`, `payer_backend` [`file`], `payer_key_file`, `payer_address`, `pinned_chain_id` and `pinned_usdc` [the settlement preset's], `[signer.risk]`: `max_per_payment`, `max_per_hour` (USDC base units) |
| `[capture]` | `dir`, `comet_rpc`, `node_prune_window_blocks` [100000], `retry_every_s` [30] |
| `[verify]` | `headers_rpc`, `tx_rpc`, `checkpoint_rpc`, `cross_check_rpc`, `exclude_host` (lists where marked), `quorum` [1] |

Only the tables a tool needs have to be present. `gate.key_backend` and
`signer.payer_backend` accept only `file` in this build (`kms` and `cdp` are
refused as not available). `recorder.da = "fibre"` needs `recorder.own_node`
and the Fibre keys described under Recorder below. Paths are not resolved
against the home: `init` writes absolute paths.

A deployment that holds a real payer key runs the light standalone
`edicta-signer` binary, which links far fewer dependencies than `edicta`.
`edicta signer serve` runs the same service inside the full `edicta` binary
and is for development and demos.

### Presets

A preset fills the endpoints and constants of a network, so the file holds
only what you choose or change. This build has two:

| Key | Value | Fills |
|---|---|---|
| `network.celestia` | `mocha` | chain id `mocha-5`, a public bridge and consensus gRPC endpoint, CometBFT RPC list |
| `network.settlement` | `base-sepolia` | EVM chain id 84532, public RPC list, USDC token, facilitator URL and network |

`custom` takes no values from a preset (give every endpoint yourself);
`settlement = "none"` leaves out the EVM side. `celestia-mainnet` and `base`
are refused as not available in this build. The public endpoints of a preset
are rate-limited and shared: fine for a test, not for a gate you depend on.
When this binary carries a newer version of a preset than the one the file
was written against, `edicta doctor` reports the drift; the file itself is
never rewritten.

### Overriding a key: `--set`

`edicta doctor` and `edicta init` take `--set key=value` (repeatable) to
replace a single key without editing the file: `section.key` with a TOML
value on the right, a bare word being a string.

```sh
bin/edicta doctor --set network.bridge.tls=true \
  --set 'network.comet_rpc=["https://rpc.example.org"]'
```

`init` accepts only `network.*` keys, writes them into the new `edicta.toml`,
and refuses the keys that `--preset` or its own bookkeeping decide
(`network.celestia`, `network.settlement`, `network.mode`, the preset
versions, the EVM chain id and the USDC token). `doctor` accepts any key and
checks the result.

### `edicta gate serve -config edicta.toml`

`edictad` projects the file onto its own configuration: the gate keys and
paths, the archive directory, the mandate, the Recorder (blob or Fibre), the
capture table and the listener. The publish quota is not in the file; it is
derived from `recorder.blobs_per_day` (one 24th per hour, rounded up) and
`recorder.max_blob_bytes`. Not served by this build: `gate.fast_mode = true`
and `gate.sessions = true` are refused at start with "not available in this
build", and the `[agent]`, `[publisher]`, `[signer]` and `[verify]` tables are
not read by the daemon. The HTTP token files are not part of `edicta.toml`;
for the endpoints that need them, use the legacy file.

### `edicta verify|replay --config`

`verify` and `replay` read `edicta.toml` (`--config PATH`, else the one in the
home when it exists) and use it only for flags you did not pass: the archive
directory or URL, the gate key (from `signer.pinned_gate_keys`), excluded
hosts, and the `[verify]` sources. A flag on the command line always wins.
Checkpoint sources are used only when you chose neither `--trusted` nor
`--checkpoint`, so the file never overrides how you decided to trust the
chain. See [verifier.md](verifier.md).

## Checking the setup: `edicta doctor`

```sh
bin/edicta doctor [--config PATH] [--set key=value]... [--json]
```

`doctor` loads `edicta.toml` (default: the Edicta home), applies the presets,
and runs the checks below in this order. Each result is `ok`, `warn` or
`fail`, with the cause and, for the last two, the fix. `--json` prints the
same report as JSON. No secret and no endpoint path, token or query appears
in the output.

| Check | What it looks at |
|---|---|
| `config` | the file loads, has no unknown keys and passes the stateless checks; preset version drift |
| `endpoints` | every configured endpoint resolves and answers (DNS, TCP, TLS, HTTP) |
| `chain` | the bridge and consensus node are on the chain the preset names, the app version is in the pinned range, the head is moving and close to the local clock |
| `fibre` | with `recorder.da = "fibre"`: the chain has `x/fibre` and the escrow covers an upload |
| `fees` | the node's minimum gas price, and balances of the Recorder and publisher accounts that cover a day of `blobs_per_day` |
| `keyring` | each keyring opens with its passphrase file and holds the named key |
| `keydirs` | every directory holding a key or passphrase is yours and closed to others |
| `clock` | the local clock is within one second of the network time sources |
| `archive` | `archive.dir` is writable and does not overlap `capture.dir`; the archive URL and mirrors answer (a warning when not) |
| `gate` | the gate key (0600, 32 bytes), executor keys distinct from the gate and agent, the agent in the allowlist, the mandate verifies, is bound to this `gate_id`, covers the agent and is in force |
| `signer` | the payer key and address agree, the pins match the settlement preset, the pinned gate key is the local one; the signer service itself is reported as a warning because this build has none |
| `settlement` | the EVM RPC providers answer with the preset's chain id; one provider alone is a warning |
| `facilitator` | the facilitator lists the `exact` scheme on the configured network |
| `balances` | the payer holds USDC on the settlement chain (a warning when it holds none) |

A check for a part that is not configured passes with "not configured".

Exit codes: `0` no check failed (warnings allowed), `1` at least one check
failed (or the report could not be written), `4` misuse: bad flags, a
malformed `--set`, no home. A config that does not load runs only the
`config` check and exits `1`.

## Keys and home: permission rules

`edicta init` and `edicta doctor` enforce the same rules; a file or directory
that breaks one is refused, never silently fixed.

- Key and passphrase files are regular files, mode `0600`,
  never symlinks. A seed file is exactly 32 raw bytes. The payer key is 32 raw
  bytes or 64 hex characters.
- The home and every directory that holds a key (`keys/`, the keyring
  directories) are owned by you and not writable by group or others (`chmod
  700 DIR`). Symlinked components are followed only when owned by you or
  root; directories above the home must not be writable by others unless
  sticky.
- Files are created with exclusive create: an existing key is never
  overwritten. Platforms other than macOS and Linux are refused ("platform not
  supported") because ownership cannot be checked there.

## Keys

Four signing roles never overlap: the gate key (`gate.key_file`, 32 raw seed
bytes), agent keys (the allowlist), executor keys (`gate.executor_keys`, used
only for record requests), and the principal key of the mandate. All four
are Ed25519 except a principal that signs with Keplr or MetaMask. The gate
refuses to start when the principal key equals a gate, executor or agent
key. The Recorder's chain key is a secp256k1 Cosmos key in its own keyring,
never the executor's; in every mode (strict and fast, blob and Fibre) it
must also not be the principal's Keplr or MetaMask key, and edictad refuses
to start if it is.

The gate key is as sensitive as the rail credentials it guards: whoever holds
it can authorize any bytes. Executors pin its public key out of band, never
from `/v1/health`.

## Mandate

```toml
[policy]
mandate_file = "/etc/edictad/mandate.cbor"   # binary SignedMandate from edicta-principal sign --out
```

At start `edictad` verifies the mandate, checks it is bound to `gate.gate_id`,
logs its rendered text, and writes the mandate record and the genesis state
to the archive before it listens. A mandate needs `archive.dir`, and every
entry of `gate.action_types` needs a policy extractor; this build has one, for
`application/vnd.edicta.cosmos.bank-send.v0+cbor`. With a mandate, every
commitment must carry `mandate_ref` equal to the mandate's hash
(`ErrMandateRefMissing`, `ErrMandateMismatch` otherwise).

To replace it: the principal signs a higher `version` of the same
`mandate_id` (counters continue); put it in `mandate_file` and restart. The
gate refuses a lower version, the same version with another hash, a changed
asset scale, a switch between public and private mode within one counter,
and, in fast mode, a `fast_mode_max_delay` below `min_fast_slack_blocks + 1`.
See [principal.md](principal.md) and, for private mandates,
[private-mode.md](private-mode.md).

`gate.reveal_on_execution` lists action types whose salt the gate publishes
once a receipt names the executed transaction, under a private mandate. Only
types of a compiled profile with public execution are accepted (bank-send).

## Gate in fast mode (`[gate.fast]`)

Fast mode authorizes a pending payload reference on its archived anchor
intent, before the anchor lands, and states `mode = 2` and an
`anchor_deadline` in the Authorization.

```toml
[gate.fast]
enabled = true
own_node = true
intent_source = "archive"
pending_namespaces = ["<58 hex>"]
fast_window_blocks = 100          # 1..1000
max_h0_age_blocks = 10            # 1..fast_window_blocks-1
min_fast_slack_blocks = 3         # 1..100
min_promise_slack_seconds = 15    # 1..600, da = "fibre"
rebroadcast_intent = true         # da = "fibre" only; default true
```

Requirements, each refused at start otherwise:
- `archive.dir` and `[policy] mandate_file` (no mandate, no fast mode);
- `own_node = true`: the gate looks anchor txs up and broadcasts them through
  `network.consensus_grpc`, which must be your own node; a node that lies
  about mempool acceptance is equivalent to the gate lying;
- `intent_source = "archive"`, a non-empty `pending_namespaces`;
- `max_h0_age_blocks + min_fast_slack_blocks <= fast_window_blocks`;
- the mandate's `fast_mode_max_delay` at least `min_fast_slack_blocks + 1`.

The deadline is `h0 + min(fast_window_blocks, fast_mode_max_delay, the
promise height window for Fibre)`, lowered to the PayForBlobs timeout height
for `celestia_blob`. Core spec, section 13.3.

## Recorder

With `recorder.enabled = true` the gate also answers `POST /v1/publish`:
agents sign a publish request, the Recorder pays the blob fee from its
account and returns the payload reference. In `celestia_blob` mode it submits
a PayForBlobs; in `fibre` mode it uploads to Fibre and submits a
PayForFibre, only through your own consensus node (`recorder.own_node =
true`), paying from the account's escrow. The Recorder's key must not be the
mandate's principal in any mode (see Keys). Fibre keys and escrow:
[../services/gate/README.md](../services/gate/README.md), sections "Fibre Recorder"
and "Fibre escrow".

### Recorder in fast mode

The fast Recorder returns a pending reference as soon as the payload record
and the signed anchor intent are archived and your node accepted the anchor
tx; it writes the anchor evidence at `H` when the anchor lands.

```toml
[recorder]
# ... the usual Recorder keys
fast = true
fast_dedicated_account = true                   # required
fast_timeout_blocks = 100                       # celestia_blob only; default 100, 13..1000
# fibre only:
# fast_upload_addr = "<own node>:9090"          # must equal network.consensus_grpc.addr
# fast_escrow_headroom_utia = <n>               # at least one upload of max_blob_bytes
```

Refused at start (the message names the key):
- any of `fast_timeout_blocks`, `fast_dedicated_account`, `fast_upload_addr`,
  `fast_escrow_headroom_utia` without `recorder.fast = true`;
- `recorder.fast needs recorder.enabled`;
- `recorder.fast needs gate.fast.enabled`: the anchor txs go out through the
  node `[gate.fast] own_node` attests as yours, and only a fast gate accepts
  the pending references;
- `recorder.fast needs recorder.namespace in gate.fast.pending_namespaces`;
- `recorder.fast_dedicated_account must be true` (see below);
- `celestia_blob`: `fast_upload_addr` and `fast_escrow_headroom_utia` are
  refused; `fast_timeout_blocks` outside 13..1000, or not above
  `gate.fast.max_h0_age_blocks + gate.fast.min_fast_slack_blocks`, is refused;
- `fibre`: `fast_timeout_blocks` is refused (the promise height window bounds
  the anchor); `fast_upload_addr` is required and must equal
  `network.consensus_grpc.addr`, compared without scheme or case before
  anything is dialled; `fast_escrow_headroom_utia` below the cost of one
  upload of `recorder.max_blob_bytes` is refused, and the message names that
  cost;
- `fibre`: the anchor signer is not the account of the Fibre submitter
  (`recorder.key_name`, whose escrow pays the uploads); checked before the
  boot recovery starts;
- `fibre`: the own consensus node does not report the x/fibre promise window,
  promise timeout and withdrawal delay after 6 reads (waits of 1 to 16 s):
  `edictad: x/fibre params unreadable`, naming the node; once running, the
  Recorder keeps the last params it read, goes on with them when a later
  read fails, and warns once per failure streak;
- the Recorder key is the mandate's principal: `the recorder key is the
  mandate's <scheme> principal`. The secp256k1 key is compared, so a Keplr
  (ADR-036) principal with the same address and a MetaMask (EIP-712)
  principal with the Ethereum address of the same key are both refused. An
  injected anchor signer that cannot show its public key is refused against
  an EIP-712 principal, and a signer whose shown key is not its account's
  key is refused whatever the principal scheme.

**Dedicated Recorder account.** Create a fresh key for `recorder.key_name`
and use it for nothing else. The account must sign nothing but this
Recorder's anchor txs: no other process, no strict-mode Recorder, no
executor, no manual transaction, no wallet, and it must not be a principal
key. A signed and archived anchor tx is never signed again; another tx on the
account moves its sequence, the archived one goes stale
(`recorder.ErrIntentStale`, answered as 409; publish a new blob), and that
decision's anchor is then provably absent at its deadline.
`fast_dedicated_account = true` is your written attestation of this. The log
names only the account address:
`edictad: recorder fast mode on; this account must sign nothing else`.

**Escrow headroom sizing (fibre).** One upload costs
`650000 + 45000 * ceil(upload_bytes / 262144)` utia. Escrow reservations are
held in memory and lost on restart, while promises of the earlier process can
still be charged until they settle. Size `fast_escrow_headroom_utia` as the
maximum blob cost times the number of promises that may be unsettled at a
restart. The minimum accepted is one upload of `recorder.max_blob_bytes`;
start once with 0 and the refusal names the number. A smaller
`max_blob_bytes` lowers it. The headroom is added to `escrow_margin_utia`, so
each upload needs cost + margin + headroom in the escrow. The Recorder never
deposits; fund the escrow yourself.

**Boot recovery.** At start the fast Recorder follows again every anchor
intent of its account that an earlier process archived and whose anchor may
still land: it re-sends the archived bytes (never signs them again) and
writes the evidence when they land. It signs nothing new until this is done;
a publish meanwhile waits for it and fails, to be retried later, if the
recovery cannot finish yet. The recovery retries with a bounded backoff; an
archived intent that can never be followed is skipped with an error in the
log, and its sequence is not reused while its tx could still land. Publishing right after a restart can still collide with an
old intent that is in a mempool; that costs at most one stale blob, never a
second anchor for one blob.

While any intent is skipped, `/v1/health` reports status 2 until the next
restart. Inspect the record at the logged path, remove or repair it, and
restart; a record whose tx can no longer land is not listed again.

Other errors a fast Recorder answers, sticky per blob: `recorder.ErrAnchorExpired`
(409, the anchor did not land in its window) and `recorder.ErrAnchorTxRejected`
(502, the node refused the anchor tx).

**`anchor_missing`.** The gate's sweep logs `edictad: anchor_missing` for a
fast-mode Authorization with no anchor evidence 10 blocks past its deadline.
It is an alert only, and at-least-once: each entry is alerted at most once
per process, again after a restart. It changes no answer and no record.

A manual live checklist for fast mode on Mocha (both DA modes, a forced stale
sequence, a killed anchor and its absence proof, a restart while pending) is
in [mocha-checklist.md](mocha-checklist.md). It has not been run yet, so fast
mode has not run live.

## Execution result capture (`[capture]`)

For a rail whose result is proven through the chain's `last_results_hash`
(today the bank-send profile), the proof of a transaction's result lives on
nodes that prune it: the block results at the execution height `H_exec` and
the header at `H_exec + 1`. Once every node has pruned them, the result can
only be node-attested. The capture keeps that proof before it is lost:

```toml
[capture]
enabled = true
dir = "/var/lib/edictad/capture"       # neither inside nor containing archive.dir
comet_rpc = "http://127.0.0.1:26657"   # serves /tx, /block, /block_results, /header
node_prune_window_blocks = 100000      # how many blocks that node keeps; at least 100
retry_every_s = 30                     # default 30
```

When `POST /v1/record` returns a receipt for a decision of a captured action
type, the gate tracks its `rail_ref` and, once the block `H_exec + 1`
exists, stores under `(chain_id, H_exec)`: the protobuf headers at `H_exec`
and `H_exec + 1`, complete namespace proofs against `data_hash` of header
`H_exec` for the transaction namespaces (ordinary txs, blob txs, Fibre txs,
and the share that closes them), the transaction's result, its index in the
block and the Merkle path from that result to `last_results_hash`. The
headers, proofs and namespace proofs are shared by every capture of the
block. Before anything is stored the capture rebuilds the square of the
block's transactions and requires its data root to be `data_hash`, derives
the index from the proofs (ordinary txs come first in block order, then blob
txs, then Fibre txs, and their unit counts must add up to the block's
results), checks that the transaction at that index hashes to `rail_ref`,
that header `H_exec + 1` names header `H_exec` as its last block, and that
the results hash to its `last_results_hash`. Only blocks of app version 10
are captured. The headers must carry the gate's chain id, and at start
`edictad` reads the header at the `comet_rpc` node's head and refuses to
start unless its chain id is the gate's, so captures of two networks never
mix in one store. Capture is
idempotent: a retried Record, a second receipt at the same height and a
restart share one record per block, and the first record stays; a node
answer that disagrees with it is logged at error level once, and the
reference stays pending.

The store is a local directory next to the registry, outside the archive
format: verifiers do not read it, and nothing in it changes an answer.

Migration into the archive. When the archive store can hold execution
results, the gate moves every capture into the archive: at start, on every
archive sweep, and right after a capture. For each captured transaction it
builds one archive record (kind 19) under `exec/<chain_id>/<rail_ref hex>`,
checks it with the same rules a verifier applies (a record that fails is
refused and alerted, never written), writes it, reads it back, and only then
drops the capture. If the key already holds a record that is not equivalent
(someone else's bytes, or a corrupt one), the capture is kept, the conflict is
logged at error level once per reference and `/v1/health` reports degraded
while any conflict remains. Remedy: get another archive copy that holds the
right record and give it to verifiers with `--result-archive`. The gate does not overwrite the conflicting key. A
transaction whose record is already in the archive is not stored twice.

The store keeps a small `archived/` done-index of moved references so a
restart does not track them again as missing; verifiers never read it. Each
archive call of the move has its own timeout, `archive.write_timeout_s`; a
slow or hung archive delays only the move, never new captures, and the
capture stays in the store and is retried at the next sweep.

Retries and fallback. Pending captures are retried every `retry_every_s`.
The sweep (every `archive.sweep_interval_s`, and at start) reads the
registry and tracks every receipt of a captured type that has neither a
capture nor a pending entry, for example after a crash between the receipt
and the tracking.

Timeliness. Executors should call Record right after their transaction is
included. A Record that reaches the gate when a quarter of
`node_prune_window_blocks` has passed since `H_exec` is logged as a
warning. A capture still missing after half the window is logged at error
level (once per capture and process) and `/v1/health` reports degraded
until it is captured, the same alert as a skipped anchor intent. A capture
still missing when the whole window has passed (counted from `H_exec`, or
from the head at which the gate first saw the `rail_ref` while the
transaction was not found) can no longer succeed from that node: it is
logged at error level once ("capture is lost"), moved to `lost/` in the
capture directory, no longer retried or tracked again, and no longer keeps
`/v1/health` degraded. The thresholds follow the configured window, so set
it to what the node really keeps (`min-retain-blocks` and its results
pruning), not a guess. A pending file that does not decode is moved to
`quarantine/`, logged at error level once, and its reference is tracked
again by a Record retry or by the sweep after a restart.

## Startup refusals

`edictad` refuses to start, before it listens, when:
- the configuration has an unknown key, invalid TOML, or a value out of
  range (each message names the key);
- `network.da` is `"blob"` or unknown, or keys of the other mode are set
  (`[fibre]`, `fibre_chain_ids`, app version bounds with Fibre, Fibre
  Recorder keys with `celestia_blob`);
- a key file is readable by group or others, or a required file is missing;
- the node fails the compatibility check (app version, chain id, encodings),
  or Fibre is allowed and the chain has no reachable x/fibre;
- a mandate is configured without `archive.dir`, is bound to another
  `gate_id`, does not verify, has an action type without an extractor, uses
  a principal key that is also a gate, executor or agent key, or conflicts
  with the stored counter (lower version, same version other hash, changed
  scale or state salt, too many assets);
- fast mode is enabled without the archive, a mandate or `own_node`, or with
  inconsistent bounds (above);
- the Recorder's key is the mandate's principal, in any mode (compared as
  the same secp256k1 key under Keplr ADR-036 and MetaMask EIP-712);
- the Recorder's fast keys are inconsistent or its signer is not its
  account (above);
- `fibre` with fast mode: the x/fibre params (promise window, timeout,
  withdrawal delay) stay unreadable after 6 reads (above);
- `gate.reveal_on_execution` names a type not in `gate.action_types` or
  without a public-execution profile;
- `[capture]` keys are set without `capture.enabled`, or it is enabled
  without a captured type in `gate.action_types`, with `capture.dir`
  missing, equal to, inside or containing `archive.dir` (compared as
  absolute clean paths, and at start also with symlinks resolved),
  `comet_rpc` not an http(s) URL,
  `node_prune_window_blocks` outside 100..6000000 or `retry_every_s`
  outside 1..3600, or the `comet_rpc` node does not answer its head header
  or answers it with another chain id than the gate's.

Height reads: at start each endpoint runs a height canary; a
height-ignoring consensus endpoint does not stop the start but puts the gate
in observations-only mode for Fibre retention. See
[../services/gate/README.md](../services/gate/README.md), section "Endpoints".

## What is verified, what is not

The gate verifies, before it signs: the agent signature, the payload and its
DA commitment, the anchor (strict) or the anchor intent (fast), the exact
action bytes under the salted hash and an allowed type, time bounds against
retention, the unused nonce (marked durably in the same transaction as the
Authorization and the mandate counters), and the mandate verdict.

The gate does not: execute anything or hold rail credentials; check that an
executor enforces the Authorization; prove execution (a receipt is the
gate's record of what the executor reported); and, in fast mode, guarantee
that the anchor lands (it makes a missing anchor provable afterwards). Your
own consensus node is trusted for header time and, in fast mode, for mempool
acceptance.

## Eden signer: moving to one payer key per agent

`edicta-signer` refuses the old shared `payer_key_file` and `payer_address`
keys of a chain; each served agent now has its own `[[chain.payer]]` table
(see `services/signer/signer.example.toml`). A decision keeps the payer it
was reserved under. When that payer is no longer its agent's, a repeat sign
request and its Payment-Signature are refused (`signer.ErrPinMismatch`), so
an executed deposit stays in the escrow until its refund, which goes to the
old payer.

Before switching:

1. Drain: stop sending new decisions and let every decision in flight
   settle and get its Payment-Signature, with the old binary and
   configuration.
2. If one agent made all the decisions still in flight, the switch may go
   ahead without the drain: give that agent the old shared key as its
   `[[chain.payer]]`, and give the other agents new keys.

At start the signer logs one warning per decision in flight (reserved,
signed, executed without its Payment-Signature yet, or held for the
operator) whose stored payer is not its agent's payer now, with
`commitment_hash`, `agent`, `chain`, `stored_payer` and `configured_payer`.
The start goes on and other agents are not affected. Give `stored_payer`'s
key back to that agent and restart to release those decisions. Decisions
already recorded are not listed: their Payment-Signature request is refused
with the same reason.

## API error codes added in v1.1

`POST /v1/record` answers two cases with their own codes; before, they came
out as `edictaapi.ErrInternal` (500) and, for a rejected anchor, as a
retryable 425 `ErrAnchorNotFound`.

| Code | Status | Retry |
|---|---|---|
| `recorder.ErrAnchorRejected` | 502 | no: the node refused the anchor tx, the same input will be refused again |
| `recorder.ErrClockSkew` | 503 | yes: the gate's clock and the chain's disagree; check the gate's clock, then retry |
