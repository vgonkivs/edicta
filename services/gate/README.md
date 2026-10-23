# Edicta on Celestia: the `edictad` reference

The one-command demo and the manual `edicta-live` runner are examples:
[../../examples/tia-transfer/demo/README.md](../../examples/tia-transfer/demo/README.md) (`make demo`) and
[../../examples/tia-transfer/README.md](../../examples/tia-transfer/README.md). This page is the full `edictad` configuration reference. The user guides, including fast mode and mandates, are in [../../docs/](../../docs/README.md).

Setting up a stack from scratch: `edicta init` creates the keys, a starter mandate and `edicta.toml` in the Edicta home, and `edicta doctor` checks it. `edictad -config` accepts that `edicta.toml` as well as the `edictad.toml` described below. See [../../docs/quickstart.md](../../docs/quickstart.md) and the "The shared configuration" and "Checking the setup" parts of [../../docs/operator.md](../../docs/operator.md).

Everything here is Edicta wire version 1 (spec revision `v1.0`, tags `v1.0.0` and `v1.0.1`): `/v1/*` HTTP paths, `edicta/v1/*` tags, and a salted action hash whose 32-byte salt `edicta-live` carries from the agent to the gate and the executor.

This module holds the `edictad` daemon: the gate's HTTP service and its
wiring to the Celestia module (`celestia/`: the Recorder, the chain client
for the gate, the executor's transaction signer and `edicta-signer`). The
`edicta` command line is the `services/cli` module. No network name, chain id
or endpoint is built in; they come from your configuration.

## Configure and start edictad

Start from the commented example, `cmd/edictad/edictad.example.toml`. Check
that the config parses (it prints paths only, never secrets), then start it,
from the repository root:

```
go -C services/gate run ./cmd/edictad -config <absolute path>/edictad.toml -print-config
go -C services/gate run ./cmd/edictad -config <absolute path>/edictad.toml
```

edictad refuses to start if the node fails the compatibility check, if a key
file is too permissive, or if the config has an unknown key. A step-by-step
setup with keys, funds and an agents file is in
[../../examples/tia-transfer/README.md](../../examples/tia-transfer/README.md), section 3.

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

If the archive is down, `POST /v1/authorize` answers 503 with `ErrArchiveUnavailable`
and `Retry-After: 5`, nothing is signed and the nonce stays unused, so the same
request succeeds once the archive is back. This also holds for a retry of a
decision that was already authorized: the archive write comes before the nonce
read, so while the archive is down that retry gets 503 as well, and gets the usual
409 with the stored Authorization afterwards. An archive write that fails after the
Authorization was signed does not change the 200; the sweep repairs the archive.

### Spending policy (optional `[policy]`)

```toml
[policy]
mandate_file = "/etc/edictad/mandate.cbor"
```

`mandate_file` is a canonical SignedMandate that the principal signed for this
`gate.gate_id` (build it with `policy.SignMandate`; `policy.Render` gives the text to
show before signing). The principal key must not be a gate, executor or agent key. A
mandate needs `archive.dir`, and every entry of `gate.action_types` must have a policy
extractor; today that is only `application/vnd.edicta.cosmos.bank-send.v0+cbor`
(Celestia, utia). The decision age cap and the other limits are rules inside the mandate.

At start edictad verifies the mandate, logs its rendered text, and writes the mandate
record and the genesis closed set to the archive before it listens; a failed write
refuses the start. To replace a mandate, sign a higher `version` with the same
`mandate_id` (counters continue) and restart. Auditors verify with
`edicta-verify --principal ed25519:HEX|cosmos:BECH32|eth:0xHEX --require-policy`
(`--principal-key HEX` is the Ed25519-only form).

The principal builds and signs the mandate with `cmd/edicta-principal` (Ed25519,
Keplr or MetaMask; a private mandate encrypted to auditors); see
[../../docs/principal.md](../../docs/principal.md). With a mandate, every commitment must
carry `mandate_ref`, the mandate's hash, or the gate refuses it with
`ErrMandateRefMissing`. `edicta-live --mandate-hash <64 hex>` sets `mandate_ref` to the
mandate's hash; without it `edicta-live` runs only against a gate without `[policy]`.
The demo sets it through the SDK (`sdk.Config.MandateHash`).

`gate.reveal_on_execution` (optional) lists action types whose action salt the gate
publishes, under a private mandate, once a receipt names the executed transaction.
Only types of a compiled profile with public execution are accepted (the bank send).

### Fast mode (optional `[gate.fast]`)

Off by default. With it the gate authorizes a pending payload reference on its
archived anchor intent before the anchor lands, and the Authorization says `mode =
2` with an `anchor_deadline` height. It needs `archive.dir`, a mandate whose
`fast_mode_max_delay` is set, and `own_node = true`, because intents are looked up
and broadcast through `network.consensus_grpc`. The keys, their ranges and the
startup refusals: [../../docs/operator.md](../../docs/operator.md). The Recorder's own
fast-mode keys (`recorder.fast`, `fast_dedicated_account`, `fast_timeout_blocks`,
`fast_upload_addr`, `fast_escrow_headroom_utia`), the dedicated Recorder account and
the escrow headroom are described there too. `edicta-live --fast --mandate-hash <64
hex> --archive-url <archive URL>` signs the pending reference the fast Recorder
returns; `--mandate-hash` is required with `--fast`.

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
- `submit_timeout_s` (default 300, 1..600): bound of one submit. `/v1/publish` has
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
go -C services/gate build ./... && go -C services/gate vet ./... && go -C services/gate test -race -count=1 ./...
```
