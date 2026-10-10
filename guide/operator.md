# Operator guide: edictad

`edictad` is the gate (verify and authorize, never execute), the archive
writer and, optionally, a Recorder that publishes agents' payloads. One
instance serves one data availability mode. This guide is the overview; the
full key reference with every default and range is in
[../celestia/README.md](../celestia/README.md), section 3, and the commented
example in `celestia/cmd/edictad/edictad.example.toml`. Spec:
`spec/decision-commitment-v1.md`, sections 8 (gate), 13 (fast mode), 18
(HTTP API) and 19 (archive).

## Run

```sh
make build
cp celestia/cmd/edictad/edictad.example.toml /etc/edictad/edictad.toml   # then edit
celestia/bin/edictad -config /etc/edictad/edictad.toml -print-config      # parse only, prints no secrets
celestia/bin/edictad -config /etc/edictad/edictad.toml
```

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
| `[http]` | listener, TLS, token files |

## Keys

Four signing roles never overlap: the gate key (`gate.key_file`, 32 raw seed
bytes), agent keys (the allowlist), executor keys (`gate.executor_keys`, used
only for record requests), and the principal key of the mandate. All four
are Ed25519 except a principal that signs with Keplr or MetaMask. The gate
refuses to start when the principal key equals a gate, executor or agent
key. The Recorder's chain key is a secp256k1 Cosmos key in its own keyring,
never the executor's; in fast mode it must also not be the principal's Keplr
or MetaMask key, and edictad refuses to start if it is.

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
true`), paying from the account's escrow. Fibre keys and escrow:
[../celestia/README.md](../celestia/README.md), sections "Fibre Recorder"
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
- the Recorder's fast keys are inconsistent, its signer is not its account,
  or its key is the mandate's principal (above);
- `gate.reveal_on_execution` names a type not in `gate.action_types` or
  without a public-execution profile.

Height reads: at start each endpoint runs a height canary; a
height-ignoring consensus endpoint does not stop the start but puts the gate
in observations-only mode for Fibre retention. See
[../celestia/README.md](../celestia/README.md), section "Endpoints".

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
