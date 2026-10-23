# Verifier

The verifier re-checks an archived decision from the archive and from block
headers it ties to a header you trust. It prints a list of named checks and
one verdict. Spec: `spec/decision-commitment-v1.md`, section 20, and
`spec/policy-v1.md`, section 13.

## Commands

Build with `make build`:

```
bin/edicta verify|replay|absence <commitment_hash> [flags]
```

The hash may stand before, between or after the flags. The flags you do not
pass take their defaults from `edicta.toml` (`--config PATH`, or the file in
the Edicta home when it exists). `--no-config` reads no file: the run then
depends on its flags alone, and `--config` is refused.

- `verify`: every check of the decision.
- `replay`: the same, plus `retention_replay`, which recomputes the gate's
  retention decision (rule K2) from the inputs it archived. It takes no
  receipt and no execution check.
- `absence`: builds and archives the absence proofs of a fast-mode
  decision's window (below).

## Flags

Required: `--gate-key HEX` (the gate's Ed25519 public key; several separated
by commas) and exactly one of `--archive DIR` or `--archive-url URL` (a
read-only archive over HTTP). The archive is only read, never created,
locked or cleaned (`absence` writes proof records to `--archive DIR`).

Trust root, one of:

| Flags | Mode in the report |
|---|---|
| `--trusted FILE` | `file`: a JSON file `{"height": H, "hash": "<hex>", "header": "<hex protobuf header>", "headers": ["<hex>", ...]}`. Only the hash is trusted; the bundled headers are checked by the hash chain. |
| `--checkpoint HEIGHT:HASH --headers-rpc URL` | `explicit`: a hash you took out of band (an explorer page, your own node). |
| `--checkpoint-rpc URL ... --headers-rpc URL [--checkpoint-quorum N]` | `agreed`: the minimum latest height of the sources, its header read from every source and compared. `N` (default 1) distinct operators must agree. |

`--headers-rpc` is a CometBFT RPC that serves the headers between the
checkpoint and the heights the decision needs. It is untrusted: every header
is hash-linked to the checkpoint.

Hardening: `--cross-check URL` (repeatable) compares the trusted chain with
another source; `--exclude-host HOST` (repeatable) refuses a checkpoint,
cross-check or settlement source on a host you know is not independent, such
as the gate's own endpoint.

Execution: `--receipt FILE --tx-rpc URL [--tx-rpc URL ...] --check-execution`
checks the transaction the receipt names (inclusion against the trusted
chain, result code against `last_results_hash`, body against the committed
action). `--exec-chain-id ID` sets the chain id a revealed private bank send
is rebuilt for (default: the chain id of the trusted header at the reference
height).

Policy: `--principal ed25519:HEX|cosmos:BECH32|eth:0xHEX` (repeatable; the
principals you trust), `--principal-key HEX` (Ed25519 only, the older form),
`--require-policy` (you know the gate had a mandate: a missing verdict is
`unchecked`, not skipped), `--policy-full` (walk the verdict chain to genesis
and search for forks), `--max-walk-steps N` (default 10000; alias
`--policy-depth`), `--policy-evidence FILE` (repeatable; signed verdicts you
hold, for fork detection), `--auditor-key FILE` (repeatable; an X25519
private key in hex, mode 0600, that opens private records).

Eden settlement (`verify` only, needs `--receipt`): `--settlement` with
`--settlement-rpc URL` (repeatable, public Eden JSON-RPC) and/or
`--settlement-own-rpc URL` (repeatable, your own Eden node, asked first);
`--settlement-level L0|L1|L2` (default `L1`; with one source the report
then reaches at most `settlement_below_level`, so ask for `L0` to accept one
source's word), `--settlement-min-sources N` (default 2), `--settlement-confirm-depth N` (default 20 blocks),
`--settlement-da URL` (your own ev-node, report only). See below.

Fast mode: `--absence-source URL`, a bridge node JSON-RPC URL that serves
absence proofs; block results come from `--headers-rpc`.

Other: `--skew SECONDS` (default 30) and `--blob-retention SECONDS` (default
14400) must equal the gate's; `--timeout DURATION` (default 5m) bounds the
run; `--json` prints one JSON document (errors too, as `{"error": "..."}`).

`--result-archive DIR|URL` (repeatable, only with `--check-execution`): a
further archive copy, a directory or an `http(s)` URL, that the execution
check reads for archived execution results after the main archive (below).
A value given twice is a usage error.

Flags that would have no effect are refused, for example `--tx-rpc` without
`--check-execution`, or `--check-execution` without `--receipt` and
`--tx-rpc`.

## Example

```sh
bin/edicta verify <commitment hash> --gate-key <gate public key hex> \
  --archive ~/.edicta-demo/runs/<timestamp>/archive \
  --headers-rpc https://rpc-mocha.pops.one \
  --checkpoint <HEIGHT>:<HASH> \
  --receipt ~/.edicta-demo/runs/<timestamp>/receipt.cbor \
  --tx-rpc https://rpc-1.testnet.celestia.nodes.guru --check-execution \
  --principal-key <principal hex> --require-policy --policy-full
```

## Checks

| Check | Passes when |
|---|---|
| `decision` | the decision record is present and decodes |
| `envelope` | the signed commitment decodes strictly, validates, and the agent signature verifies |
| `action` | the action bytes and salt (from the decision record, a private record or a reveal) hash to the committed `action.hash` |
| `authorization` | the record state is `authorized`, the gate signature verifies, it matches the decision, and its `mode` matches the reference form (strict iff included, fast iff pending) with `h0 < anchor_deadline <= h0 + 1000` |
| `payload` | the archived blob hashes to the commitment and its DA commitment recomputes |
| `anchor` | the inclusion evidence verifies against the header at the reference height; in fast mode, against the header at the anchor height inside `[h0, anchor_deadline]` |
| `anchor_time` | the decision was signed after the anchor's block time (`T_ref`; header time at `h0` in fast mode) |
| `header_trust` | every needed header links to the trusted header |
| `receipt` | with `--receipt`: the gate-signed receipt belongs to this decision |
| `execution` | with `--check-execution`: the transaction is the committed action, in a trusted block above the anchor, with result code 0 |
| `retention_replay` | `replay` only: the gate's retention decision recomputes |
| `policy` | with a mandate: the allow verdict, the facts re-extracted from the action, the per-action rules and the state the gate signed. Required when `--require-policy` is set, when an allow verdict exists, when the commitment has `mandate_ref`, or when the Authorization is fast mode |

Each check is `pass`, `fail` or `unchecked`; a non-pass line carries a
reason, the source it blames and advice.

`gate_integrity` is a report field, not a check: `ok`, `violated` (the gate
signed verdicts that contradict each other), `not_checked`, or `unchecked`.
After `--policy-full` it is `ok` only if the walk reached genesis; a walk cut
by `--max-walk-steps` is `unchecked` with `policy_walk_truncated` and prints
"last N of M verdicts checked".

## Verdict and exit codes

First match wins: `invalid` if any check fails; `unchecked` if
`gate_integrity` is violated; `unchecked` if no decision record;
`not_authorized` if the decision is pending or rejected; `unchecked` if any
check is unchecked or a required check is missing; otherwise `valid`.

| Exit | Meaning |
|---|---|
| 0 | `valid` |
| 1 | `invalid`: a violation proven from verified data |
| 2 | `unchecked` (shown as INCONCLUSIVE by the demo): a source or input did not allow a result |
| 3 | `not_authorized`: pending or rejected at the gate |
| 4 | usage, configuration or I/O error: no verdict |
| 5 | `unchecked` with `gate_integrity` violated: the text starts with `GATE INTEGRITY VIOLATED (<reason>)` |

Precedence 4, 1, 5, 3, 2, 0: an invalid decision at an equivocating gate
exits 1.

The general rule: `invalid` is issued only about the decision or the action,
and only from verified data. Every source problem (archive, header source,
tx source, receipt file, disagreement between sources) gives at most
`unchecked`. A hostile source can never cause `valid` or `invalid`.

## Reasons

The full list (43 reasons, closed) with meaning and advice is in the core
spec, section 20.1.1, and the text output prints the meaning of each. The
ones you will meet most:

| Reason | What to do |
|---|---|
| `decision_unavailable`, `payload_unavailable`, `evidence_unavailable` | Another archive copy. `payload_unavailable` is an operator retention failure, not a verdict on the decision. |
| `source_corrupt` | Bytes from a source fail a check a genuine copy passes. Try another copy. |
| `no_trusted_header`, `header_above_checkpoint`, `header_not_linking`, `checkpoint_quorum` | Supply or refresh the trust root; another header source. |
| `header_disagreement` | Sources disagree with the trusted chain: a bad trusted header, a hostile source or a fork. Check the trusted header independently. |
| `blocked` | A check needed another check that did not pass; fix the named one. |
| `tx_not_found`, `tx_source_unavailable`, `result_unproven`, `code_unproven`, `height_unproven` | A tx source that serves `/tx?prove=true` and `/block_results`. |
| `policy_verdict_unavailable` | No allow verdict for a decision that needs one. |
| `policy_principal_untrusted` | Pin the principal with `--principal`, if it is the intended one. |
| `policy_private` | A private record no configured `--auditor-key` opens. |
| `policy_walk_truncated` | Raise `--max-walk-steps` above the target's seq. |
| `gate_equivocation`, `gate_signed_inconsistent_private_part` | The gate is at fault; the report attaches the signed evidence. Exit 5. |
| `anchor_pending` | Fast mode, your trusted header is too low for the evidence. Retry later or with a newer checkpoint. If the anchor evidence is in the archive and verifies at height `H`, a trusted header at or above `H` is enough for a pass (see "Presence and absence need different headers"); below `H` the report says `evidence ties at H; verdict needs a checkpoint >= H`. A header trust that cannot name its checkpoint height leaves `header_trust` unchecked (`no_trusted_header`). |
| `absence_unproven` | Fast mode, no anchor in the window and absence not proven. Run `edicta absence` or pass `--absence-source`. |
| `anchor_unpaid` | The anchor PFF was included with a non-zero result code: the payload was published, but `valid` requires a paid anchor (result code 0). An unpaid anchor is an operator funding failure, surfaced by the escrow alert; nothing to fix on the verifier side. The report names `unpaid_height`. It stays `unchecked` for good and is never `invalid`. Another archive copy or `--absence-source` only helps if a paid anchor may sit at a height not proven. |
| `unsupported_revision` | The commitment hashes to the reference, but its `payload_ref.da` is a value this verifier does not define (for now anything outside 1 and 2); the rest of that `payload_ref` is read as opaque. A later revision may define it, so this is not a verdict on the decision and never `invalid`. Use a verifier of a revision that defines this `da`; the gate keeps refusing such commitments. |

## Fast-mode decisions

For a decision with `mode = 2` the report adds `mode: fast`, `h0`,
`anchor_deadline`, `anchor_height` when the anchor landed, `publication`
(`anchored`, `failed` or `unknown`) and these assumptions for a valid one:

```
mode: fast. The gate authorized before the L1 anchor. The anchor landed at height H (window h0..deadline, in blocks).
Proven: payload bytes match the commitment; anchored on L1 no later than T_H (anchor inclusion proven); policy evaluated on T_ref (header h0).
Informational: anchor tx result: code 0, node-reported, not part of the claim   (da = 1 only)
Attested by the gate (not proven): the availability evidence was verified before the Authorization
  (Fibre: validators' custody certificate; celestia_blob: the signed anchor tx accepted by the gate's node).
```

"Anchored" means the inclusion of the anchor in block `H` of your trusted
chain is proven from the archived evidence: for `celestia_blob` the blob's
commitment proof against the data root, for Fibre the complete PayForFibre
namespace proof, the binding of the PFF to the reference and the
availability certificate. The anchor tx's result code is not part of that
claim. For every Fibre decision whose anchor proof verified, in both modes,
the report shows it as the JSON field `anchor_tx_result` and the text line
`Informational: anchor tx result: code 0, node-reported, not part of the
claim`; it is never listed under `assumptions`. A `celestia_blob` report
has neither.

The `policy` check is always required in fast mode: fast mode needs the
principal's consent, so without an allow verdict the decision is never
`valid`.

If the anchor never landed in `[h0, anchor_deadline]`, the decision is
`invalid` with `anchor` failing `anchor_absent`, but only once absence is
proven for every height of the window. The report then names the intent
signer, the account that signed the anchor tx, taken from chain data (for
`da = 2` it equals the agent-signed `payload_ref.signer`).

### Presence and absence need different headers

For a fast-mode decision whose archived anchor evidence verifies at height
`H` inside the window (`h0 <= H <= D`, `D` the `anchor_deadline`), the trusted
header file (or checkpoint) only has to reach `H` for `anchor` to pass. The
deadline `D` does not matter: the anchor is there. For any verdict that rests
on the anchor being absent (`absence`, `anchor_absent`, a missing or untied
evidence record) the trust must reach `D`, and `D + 1` when a Fibre result
code has to be proven from block results. A trusted header below `H` leaves
`anchor` at `anchor_pending`.

### Absence proofs

```sh
bin/edicta absence <commitment hash> --gate-key <gate key hex> \
  --archive <archive dir> --absence-source <bridge JSON-RPC URL> \
  --headers-rpc <CometBFT RPC> --checkpoint <HEIGHT>:<HASH>
```

It verifies the decision, then for every height of `[h0, anchor_deadline]`
fetches the block's data availability header and the namespace data from the
bridge, verifies them against the trusted chain, and writes each proof that
verifies to the archive (kind 14). An archived proof that does not verify is
replaced. It exits 0 when every height is proven and archived, 2 otherwise;
it refuses a decision that is not a pending reference with a verified
fast-mode Authorization. The trust root must reach `anchor_deadline`
(`anchor_deadline + 1` when a Fibre result code must be proven), so a
checkpoint taken after the deadline is needed.

Then `verify` reads the proofs from the archive. Instead of archiving, you can
pass `--absence-source` to `verify` directly.

What a proof shows: the header at `h` is on the trusted chain, the namespace
data is complete for that block (NMT completeness), and no anchor for this
blob is in it (Fibre: no PayForFibre for this commitment that succeeded,
proven against the block results). A source can withhold proofs
(`absence_unproven`), but cannot forge absence without breaking SHA-256 or
the NMT. Cost: a few MB for the default window of 100 blocks on Mocha.

## Archived execution results

The execution check needs the transaction's result proof, which nodes prune.
The gate keeps it for ordinary rail transactions as an archive record
(kind 19), stored under `exec/<chain_id>/<rail_ref hex>`: the headers at the
execution height and the next one, complete proofs of the transaction
namespaces, the result and its Merkle path to `last_results_hash`. With
`--check-execution` the verifier reads that key from the main archive first,
then from each `--result-archive` copy in order, and checks the record
against your trusted chain (the header trust must reach the execution height
plus one). A record that proves the transaction and its result is used
instead of a node; a forged or incomplete record is set aside and the next
copy, then the `--tx-rpc` nodes, are tried. An archived record can prove a
result, and a proven bad result or body gives `fail`; a record that cannot be
checked never causes `invalid`.

A decision with no record, for example one executed before the gate moved
its captures into the archive, falls back to the nodes. If they have pruned
the block the check is `unchecked`; point `--result-archive` at another copy
that holds the record.

An archive must answer a missing `exec/` key as absent: HTTP 404, or a
missing file. Any other answer is an archive fault and stops the run with
exit 4 and no verdict. The execution check reads an `exec/` key even for old
decisions that have none, so a store that answers 403 for missing keys (S3
without list permission on the bucket) now stops every `--check-execution`
run. Grant `s3:ListBucket` to the reading identity, or put a front end in
front of the bucket that maps a missing object to 404. Check with
`curl -I <archive url>/<any absent key>`: it must say 404.

## Eden settlement report

For an Eden escrow deposit (action type
`application/vnd.edicta.eden.escrow-deposit-tx.v1+cbor`), `--settlement`
adds the field `rail_settlement` (text lines `rail settlement ...`). It says
whether the transaction the receipt names is exactly the authorized deposit,
whether it is in an Eden block at the confirmation depth, and whether it
executed or reverted. It is printed beside the core report and **never
changes the verdict or the exit code**; tooling that wants to act on it reads
the field. The core `execution` check does not cover Eden
(`--check-execution` gives `unchecked`, `no_checker`).

```sh
bin/edicta verify <commitment hash> --gate-key <hex> --archive <dir> \
  --trusted <file> --receipt receipt.cbor --json \
  --settlement --settlement-rpc https://rpc.eden.gateway.fm/
```

`status` is one of:
- `violated` (`wrong_tx`): the bytes that hash to the signed `rail_ref` are
  not the authorized transaction. Only signed data proves this; no RPC can
  cause it.
- `pass` with `level` and `outcome` (`executed` or `reverted`).
- `unchecked` with a `reason`, for example `settlement_not_found`,
  `settlement_unconfirmed` (retry later), `settlement_disagree`,
  `settlement_below_level`, `malformed_rail_ref` (the receipt's `rail_ref` is
  not 64 lower-case hex characters).
- `not_run` with `blocked_on`: no receipt that passed, the decision is not
  authorized, or the action type has no settlement report (`no_checker`).

Levels, and what you trust at each:
- `L0`: one source's word (class `public-rpc`: the RPC operator; class
  `own-node`: your node, which re-executes the blocks, and the sequencer's
  ordering). Read the class on the `sources` lines.
- `L1`: at least `--settlement-min-sources` sources of different operators
  agree on the block, the index and the receipt. A source given as
  `OPERATOR=URL` (for example `gateway=https://rpc.eden.gateway.fm/`) names
  its operator; without a label its host stands in (`operator_label`
  `default` in the report), which cannot tell two hosts in front of one node
  apart. You trust that the operators do not collude.
- `L2`: in addition the block's transactions and receipts rebuild the roots
  of a header whose fields hash to the block hash. The header itself is
  attested by the `L1` sources. `block_number` and `block_time` come from
  that proven header; below `L2` they are the used source's word.

No level proves that the Eden block's data is in Celestia (`da_included` is
your ev-node's word), and the single sequencer can roll back blocks that
have not reached Celestia; a re-check then gives `unchecked`, never
`violated`. Two passing sources that disagree make the report `unchecked`
at any level, so one misbehaving source you configure can block it. Nothing
about the Eden transaction is archived: once the RPCs prune the block, a
re-check is `unchecked`. Source errors name the host, not the URL, so API
keys in a URL path or query do not reach the report.

## Assumptions

- Header trust is as good as your trust root. With `agreed` and quorum 1, one
  RPC operator colluding with the archive's writer can fake a whole chain;
  the report names that operator. Raise `--checkpoint-quorum`, add
  `--cross-check` from another operator, or take an explicit checkpoint from
  an independent source. Distinct host names are not distinct operators; the
  verifier counts a node id once.
- The archive is trusted for availability only; every record is re-checked.
  An archive that answers anything but 404 or a missing file for an absent
  object makes the run stop without a verdict (exit 4); configure it to
  answer 404.
- Ed25519, SHA-256 and more than 2/3 honest Celestia voting power.

## What is verified, what is not

Verified: the agent signed exactly this decision; the payload was published
and anchored at the stated height before the decision was signed (or, in
fast mode, by the deadline); the gate authorized exactly the committed
action bytes and type; the mandate allowed it and the gate's verdict chain
is consistent (with `--policy-full`); with `--check-execution`, that the
named transaction is the committed action, included above the anchor with
code 0.

Not verified: that the agent's inputs were true or its decision good; a
second execution of the same decision; allows a gate kept outside every
chain and every piece of evidence; the anchor-age rule P9 (gate clock);
in fast mode, the gate's claim that the availability evidence was checked
before it authorized (attested, not proven). In private mode without an
auditor key: the facts, the rules and the action content.
