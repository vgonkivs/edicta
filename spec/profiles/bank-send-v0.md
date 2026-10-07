# bank-send profile v0 (Cosmos MsgSend action, price-trigger context)

Edicta profile for a bank transfer on a Cosmos SDK chain, used by the demo in
`examples/tia-transfer`.

Status: revision `bank-send-v0-draft.6` (2026-10-07). Working draft, subject
to change. Built on the core spec `spec/decision-commitment-v0.md`, revision
`v0-draft.11`. Section 3.4 needs core `v0-draft.27` (core section 20). Section
numbers prefixed "core" refer to the core spec.

Keywords MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119. Items marked
`UNVERIFIED` are facts about Celestia or the Cosmos SDK that a Celestia
protocol engineer must confirm. Everything else is normative for this
profile.

Nothing in this profile names a network. Chain id, bech32 prefix and denom
are the chain's own values, discovered from the node (section 6); the
vectors use `mocha-4`, `celestia` and others only as examples.

## 0. Versioning

| Change | Rule |
|---|---|
| Editorial | No version change. |
| Any change to an encoding, a check or its outcome, while in draft | Bump `bank-send-v0-draft.N`, regenerate the profile vectors, record the change. |
| Any such change after freeze | New types (`...cosmos.bank-send.v1+cbor`, `...price-trigger.v1+cbor`). The version is in the type name, so the bodies carry no version field. |

Changes:

| Revision | Change | Vectors |
|---|---|---|
| `bank-send-v0-draft.1` | First draft. | Initial set. |
| `bank-send-v0-draft.2` | (1) The pinned chain has no transaction timeout timestamp (section 6), so the chain-side bound stays `timeout_height`, now budgeted at twice the observed block interval (4.3, `slowdown_factor = 2`). (2) T10: rebroadcasting stops at `expires` by the executor's wall clock, whatever the height. (3) Section 4.3 states why a halt that delays inclusion past `expires` is still safe. | Regenerated: `timeout_height.json`, `e2e.json` (both now `bank-send-v0-draft.2`). Byte-identical, keeping `bank-send-v0-draft.1`: `msg_send.json`, `tx.json`, `action.json`, `executor.json`, `price_trigger.json`. |
| `bank-send-v0-draft.3` | Hand-off and reconcile (4.1, 4.2). (1) T12 has two bounds: head `> timeout_height`, or wall clock `>= expires + hand_off_grace` (new setting, default 10 min), whichever comes first; either needs a successful status query on the same turn, and the reason names the bound. (2) New T13: a final rejection by the node is followed by one status query after a short wait; committed goes to T11, otherwise the record is handed off with the node's reason. (3) A handed-off record is looked up again by `Resume` and by a repeated `Execute`, and moves to finished if the transaction is found committed. (4) T10 names transient broadcast errors (resent) versus a final rejection (T13). Outcomes for an implementation that followed draft.2 change only for a stalled chain, a rejection and a late inclusion after a hand-off. | Every file byte-identical; none has a T10..T13 vector (chain fake only). |
| `bank-send-v0-draft.4` | Watch loop review (4.1, 4.2, 6). (1) T10: the loop height comes from the status node; a send is skipped when that height is past `timeout_height`; `live` is re-checked by a clock read immediately before every broadcast; head, status and broadcast calls each get a per-call deadline; a failed head read after `expires` no longer ends the call. (2) T12 (a): the height compared with `timeout_height` is read from the node that answers the status query, the bound is `height > timeout_height + indexer_lag_blocks` (new setting, default 3), and a second status query after `confirm_delay` (default 2 s) must also be not committed. (3) New startup rule T0: the rail refuses to start if the status node does not report transaction indexing on. (4) T13: a final rejection stops sending for the call but no longer hands off by itself; the executor keeps watching until a T12 bound, and the hand-off reason carries the node's code and log. Outcomes change for: a send near `expires`, a head read failure after `expires`, a hand-off under T12 (a) (`indexer_lag_blocks` blocks and one status query later), a rejection (watched, not handed off at once), and a node with indexing off (refused at startup). | Every file byte-identical; none has a T0 or T10..T13 vector (chain fake only). |
| `bank-send-v0-draft.5` | Verifier execution check (new section 3.4, rules BX1 to BX8), the checker that core rules EX1 to EX8 call for this action type. It looks up the receipt's `rail_ref` by hash. It checks: the tx bytes hash to `rail_ref`; a strict `TxRaw` decode; `chain_id` equal to the trusted header's; the body rule of 3.3; code 0 (node-attested); an optional inclusion proof (a `ShareProof` in the transaction namespace, with the extra checks of BX6), giving `proven`, otherwise `node-attested`; cross sources agree on height, bytes and code. New sentinels `railverify.ErrTxNotFound`, `ErrTxHashMismatch`, `ErrTxMalformed`, `ErrChainMismatch`, `ErrTxFailed`, `ErrTxProof`, `ErrTxSourceUnavailable`. New rail facts: the `/tx?prove=true` shape and the transaction namespace (VERIFIED, live Mocha). Executor rules and every encoding are unchanged. | Every file byte-identical. No vector for 3.4 yet (live fixture, see section 8). |
| `bank-send-v0-draft.6` | Execution check outcomes under core `v0-draft.27` 20.2.1 (human decisions of 2026-10-07). The rules are evaluated in a new order: BX0, BX1, then per candidate BX2, BX3, BX5, header trust, BX6, then BX8, RP and BX9. Changes: (1) New BX0. A configured chain id other than the action's is `unchecked` (`railverify.ErrChainConfig`); it was `fail`. (2) BX1: a malformed `rail_ref` is still `fail`, now `railverify.ErrRailRefMalformed`. Not found and unavailable set the candidate aside, and alternates are tried. (3) BX2 and BX6: wrong bytes and a bad proof set the candidate aside and end `unchecked` (was `fail`). (4) BX4: compared only with a trusted header. A different chain id is `fail` only with proven inclusion. (5) BX5 runs before header trust. (6) New result proof RP1 to RP6: block results from any source are recomputed to `last_results_hash` of the trusted header at `height + 1`, with the index bound by the share proof or uniform codes. (7) BX7 becomes the fact `outcome`. New BX9: a nonzero code is `fail` only when proven (`ErrTxFailed`); `pass` needs a proven code, or the interim cross confirmation. Cross agreement never gives `fail`. (8) BX8: per-source `agree`, `disagree` or `fault`; a mismatch is `unchecked`. (9) Threat note rewritten. New sentinels `ErrRailRefMalformed`, `ErrChainConfig`, `ErrResultUnconfirmed`, `ErrResultsProof`. `ErrTxHashMismatch` and `ErrTxProof` become `unchecked` classes. Rail facts: results hashing, result order and `block_results` availability. Executor rules and every encoding are unchanged. | Every file byte-identical. New: core `spec/vectors/verifier/execution_outcomes.json` (section 8). |

Editorial clarification of `bank-send-v0-draft.4` (2026-10-05, no bump): T10
names the loop height as the status node's latest committed height and the
call that reads it (node service `Status`), and states the per-call deadline
as an absolute time from one clock read. Draft.4 already required the height
from the status node and named `GetLatestBlock`, which returns the same
value, and its deadline formula is the same instant when evaluated with one
clock read; so no outcome changes for an implementation that followed
draft.4. A non-positive height counted as a failed read only refuses a value
no live chain reports. Every vector file is byte-identical.

The profile depends on the core only through `ActionHash`,
`VerifyAuthorization`, `commitment_hash` and rule I5 as amended in
`v0-draft.10`. Since `bank-send-v0-draft.5`, section 3.4 also depends on core
section 20 (`v0-draft.26`; since `bank-send-v0-draft.6`, `v0-draft.27` and its
outcome rule 20.2.1).

## 1. Threat model

| Mechanism | Defends against | Assumes |
|---|---|---|
| `msg` is the exact protobuf `MsgSend`, spliced verbatim into the transaction (sections 2, 3) | Executing another message than the authorized one; a re-encoding step between what was committed and what is signed | The executor never rebuilds `msg`; the strict decoder (2.3) is used only to check it |
| Strict canonical `MsgSend` decoder (2.3) | One authorized byte string read as two transfers by two parsers. gogoproto accepts 34 of the 39 malformed messages in the vectors (duplicate fields, unknown fields, reordered fields, non-minimal varints, bad amounts and denoms) | Every executor and verifier uses this decoder, checked by shared vectors |
| `chain_id` in the action bytes and in the SignDoc (rule T3, section 3) | Bytes authorized for one chain executed on another (testnet versus mainnet, a fork) | The executor's chain id comes from its node and is cross-checked at startup; SIGN_MODE_DIRECT signs the chain id, so the signature is invalid elsewhere |
| Sender, denom, destination, amount checks (rule T5) | An agent committing to a transfer from another account, in another denom, to an unexpected address or above the operator's limit | The operator configures them; the agent cannot change them |
| Memo = `hex(commitment_hash)` by a byte-exact rule (section 3) | A transfer whose link to its decision is lost or forged | Anyone can recompute the body from the authorized `msg` and the commitment hash and compare bytes (section 3.3) |
| Persist before broadcast, resend identical bytes, `timeout_height`, resend stop at `expires` (section 4) | A double transfer after a crash, a timeout or a lost mempool entry; a transfer started long after its Authorization expired | The chain includes one signed transaction at most once (account sequence); the executor signs only while the Authorization is valid. The chain-side bound is in blocks only: a halt can delay inclusion past `expires` (4.3) |
| Price-trigger context with PT1..PT5 (section 5) | The agent's stated observations and branch diverging from the transfer it made, unnoticed | Detection after the fact by a reader of the payload. These checks never say whether the prices were true or the decision good: Edicta does not evaluate the agent |
| Nothing (open gap) | Whether the transfer is economically sensible; the price source's honesty | The operator and auditors judge that from the published payload |

## 2. Action type `application/vnd.edicta.cosmos.bank-send.v0+cbor`

### 2.1 Action bytes

Canonical CBOR (core section 3 profile), a map of exactly two entries:

| Key | Name | Type | Limit | Semantics |
|---|---|---|---|---|
| 1 | `chain_id` | tstr | 1..50 bytes, `[A-Za-z0-9._-]` | The domain of the action (core 16.2 rule 3): the chain id the transaction is signed for. 50 is CometBFT's `MaxChainIDLen`. |
| 2 | `msg` | bstr | 1..1024 bytes | The canonical protobuf encoding of one `cosmos.bank.v1beta1.MsgSend` (2.3). Opaque at this layer. |

Both keys are required; there are no optional fields. The largest action is
1082 bytes, far below the core `MaxActionSize`.

The memo is not in the action bytes: it holds the commitment hash, which
covers `action.hash`, which covers these bytes, so it could not be inside
them. The transaction body is derived from `msg` and the commitment hash by
the byte rule of section 3 instead.

### 2.2 Action decoding (`bankaction.Decode`)

Strict: the core section 3 profile (shortest heads, definite lengths, uint
keys strictly ascending, no duplicates, no floats, tags or simple values),
the schema of 2.1 (unknown key, missing key, wrong major type, length or
charset), no trailing bytes, and re-encoding MUST give the input. Every
failure is `bankaction.ErrMalformed`. `msg` is not parsed here; the MsgSend
check needs the chain's bech32 prefix (rule T4).

### 2.3 MsgSend decoding (`bankmsg.Decode(msg, hrp)`)

Every failure is `bankmsg.ErrMalformed`.

| Rule | Check |
|---|---|
| M1 | Fields `1 from_address`, `2 to_address`, `3 amount`, each exactly once, in this order, wire type 2; nothing else, no trailing bytes |
| M2 | Every varint (tags and lengths) is in its shortest form; no length exceeds the remaining input |
| M3 | `amount` holds exactly one `cosmos.base.v1beta1.Coin`: fields `1 denom`, `2 amount`, each exactly once, in this order, wire type 2, nothing else |
| M4 | `denom` matches the Cosmos SDK grammar `[a-zA-Z][a-zA-Z0-9/:._-]{2,127}` (3..128 characters) |
| M5 | `amount` is decimal ASCII `[1-9][0-9]*`, value `1..2^63-1`: no sign, no leading zero, no space, no fraction |
| M6 | `from_address` and `to_address` are lower-case bech32 (BIP-173 checksum, not bech32m) with prefix `hrp`, encoding exactly 20 bytes |
| M7 | `from_address != to_address` |
| M8 | Re-encoding the decoded fields gives the input bytes |

`hrp` is the chain's account prefix (section 6). The canonical encoding is
what gogoproto's `MsgSend.Marshal` emits for one coin: fields in number
order, each length-delimited with minimal varints, no empty fields. The
vectors `msg_send.json` are produced by that code (section 8), and the strict
decoder accepts exactly them.

Why so strict: gogoproto's `Unmarshal` keeps the last of duplicate fields,
skips unknown fields and accepts any field order, so two parsers can read one
byte string as two transfers, or a verifier can accept bytes the executor
reads differently. The vectors record, per reject, whether gogoproto accepts
it (`sdk_unmarshal_ok`).

Example (`msg_minimal`, 109 bytes: 1 utia to receiver 1):

```
0a 2f "celestia1qqp0ztywuvn8agqn6znr4k35eda494vv7klwtc"
12 2f "celestia1mzkhlmxtluk4gmet2kja0yv8kxc2n07ml6lld3"
1a 09 0a 04 "utia" 12 01 "1"
```

## 3. Transaction (executor side)

### 3.1 Body bytes (`bankaction.Body(msg, commitment_hash, timeout_height)`)

```
any  = 0x0a 0x1c "/cosmos.bank.v1beta1.MsgSend"           ; Any.type_url, 28 bytes
    || 0x12 varint(len(msg)) msg                           ; Any.value, msg spliced verbatim
body = 0x0a varint(len(any)) any                           ; TxBody.messages[0]
    || 0x12 0x40 hex_lower(commitment_hash)                ; TxBody.memo, 64 ASCII bytes
    || 0x18 varint(timeout_height)                         ; TxBody.timeout_height, 1..2^63-1
```

Varints are protobuf base-128, shortest form. Nothing else: no second
message, no extension options, no non-critical extension options.
`timeout_height` is required and nonzero (a zero would be omitted by proto3
and leave the transaction unbounded). This is byte-for-byte what gogoproto's
`TxBody.Marshal` emits for these fields (vectors `tx.json` `body`, generated
with the real types).

Example (`body_minimal`, `msg_minimal`, `timeout_height = 1`, 212 bytes):

```
0a 8d01 0a 1c "/cosmos.bank.v1beta1.MsgSend" 12 6d <msg_minimal, 109 bytes>
12 40 "958d0e83e933cca5a0b5e7691931bad3c768a8efe0db0fcd3d6086464c097fc4"
18 01
```

### 3.2 Signing and the rail reference

- Sign mode `SIGN_MODE_DIRECT`: `SignDoc{body_bytes = Body(...), auth_info_bytes,
  chain_id = action.chain_id, account_number}`, signature over its
  encoding; `TxRaw{body_bytes, auth_info_bytes, [signature]}`.
- `auth_info_bytes` (signer public key, sequence, fee, gas) are the
  executor's own and are not authorized; they cannot change the transfer.
  The vectors give one illustrative encoding (`tx.json` `signed`).
- The executor MUST check that the `body_bytes` of the `TxRaw` it is about to
  broadcast equal `Body(msg, commitment_hash, timeout_height)`.
- `rail_ref` = lowercase hex of SHA-256(`TxRaw`), 64 characters (the
  transaction hash in the form the receipt's ID charset admits).

### 3.3 Checking a transaction found on chain (`bankaction.CheckBody`)

Anyone holding the authorized action and the commitment hash can check a
transaction: parse `timeout_height` from the tail of `body_bytes` (field 3,
shortest varint, last in the body) and require `body_bytes ==
Body(action.msg, commitment_hash, timeout_height)`. Any difference (memo in
upper case or with `0x`, another or a second message, another type URL,
extension options, reordered fields, trailing bytes, timeout 0) is
`bankaction.ErrBodyMismatch` (vectors `tx.json` `body_reject`). The memo
alone is not proof: anyone can put any hash in a memo; the body equality ties
the transfer to the exact authorized message.

### 3.4 Execution check for verifiers (`railverify`, since `bank-send-v0-draft.5`)

This is the checker that core section 20.2 calls for this action type. Its
inputs are `commitment_hash`, the authorized action bytes and `rail_ref` from
a receipt that passed. Its reads go to tx sources the auditor chooses
(CometBFT RPC base URLs: a primary, optional alternates, optional cross
sources, core EX10) and to the trusted header chain (core 20.4). Since
`bank-send-v0-draft.6`, every finding is classified by core 20.2.1. A
finding is `fail` only if bound objects prove it. If it rests on one
source's answer, it is `unchecked`, or the candidate is set aside and the
next alternate is tried.

Evaluation order: BX0, BX1, then for each candidate in order BX2, BX3, BX5,
header trust at the answer's `height` (core EX5), BX6. Then BX8 over the
used answer, then BX9, which classifies BX4, BX7 and the core rules EX4, EX6
and EX9.

| Rule | Check | Outcome |
|---|---|---|
| BX0 Chain config | `bankaction.Decode(action)` (2.2) succeeds, and its `chain_id` equals the chain id the checker is configured for. | A different chain id: `unchecked`, `railverify.ErrChainConfig`, and no source is asked. The auditor pointed the checker at another chain, which is not a finding about the execution. An undecodable action cannot occur after core stage A and the executor. If it does, it is `bankaction.ErrMalformed`, `fail` (the action bytes are bound, F1). |
| BX1 Lookup | `rail_ref` MUST be 64 lower-case hex characters (3.2). Each candidate is asked with `GET <rpc>/tx?hash=0x<rail_ref upper or lower>&prove=true`. Answer: `result {hash, height, index, tx_result {code}, tx (base64), proof}`. | A malformed `rail_ref`: `fail`, `railverify.ErrRailRefMalformed`, and no source is asked. The receipt is gate-signed (F2), so this is proven. A JSON-RPC error whose data says `not found`: the candidate is set aside, `railverify.ErrTxNotFound`. Absence on one node proves nothing, because the indexer may be off or pruned. Any other error, a timeout or `429`: the candidate is set aside, `railverify.ErrTxSourceUnavailable`. |
| BX2 Hash | `SHA-256(tx) == rail_ref`. The `hash` field of the answer is not used. | The candidate is set aside, `railverify.ErrTxHashMismatch` (`fail` before `bank-send-v0-draft.6`). Bytes that do not hash to `rail_ref` are not the transaction the receipt names, so they say nothing about the execution. Bytes that do hash are bound (F3). |
| BX3 TxRaw | `tx` decodes strictly as `TxRaw`. Fields `1 body_bytes` and `2 auth_info_bytes` appear exactly once each, then `3 signatures` at least once. All are wire type 2, in this order, with shortest varints. Nothing else may appear, and nothing may trail. | `fail`, `railverify.ErrTxMalformed`. The bytes are bound by BX2. |
| BX5 Body | `bankaction.CheckBody(body_bytes, action.msg, commitment_hash)` (3.3): the memo is the commitment hash and the message is exactly the authorized `MsgSend`. It needs no header, so it runs before header trust. | `fail`, `bankaction.ErrBodyMismatch`. The bytes are bound by BX2, so a receipt that names them is proven to name another transfer. |
| BX4 Chain | The action's `chain_id` equals the `chain_id` of the header at the answer's `height`. That header has passed header trust (core EX5) before the comparison. The checker never compares against a header that has not passed it, and it reads the header from the same header chain the verifier walks. | A header at `height` that the trusted chain does not reach (`T < height`, or it does not link): the candidate is set aside (core EX5 (a), (b)). A different chain id is classified by BX9. In the reference verifier it cannot occur: BX0 binds the configured chain id to the action, and core OH2 binds every header to the configured chain id. |
| BX6 Inclusion | If `proof` is present and non-empty, `inclusion = proven` only if every point below holds, against `data_hash` of the trusted header at `height`. (a) `namespace_version = 0` and `namespace_id` is the transaction namespace `0x00...01` (28 bytes). (b) With `t` the `total` of every row proof, `t = 4k` for a power of two `k`. For each row `i`, the row proof's `index = start_row + i` and is below `k`, so the row is a row of the original square, not a column. Its `leaf_hash = SHA-256(0x00 \|\| row_root)`, and the RFC 6962 path from `aunts` reaches `data_hash`. (c) For each row, the NMT range proof over `2k` leaves with `start < end <= k` reaches that row root. Leaves are `namespace (29) \|\| share`. Hashing follows NMT with the ignore-max-namespace rule. (d) The rows are consecutive, and every row but the last ends at `end = k`, every row but the first starts at 0. (e) Every share starts with the namespace of (a) and has share version 0. Parse them as compact shares: info byte, then a 4-byte sequence length if the sequence-start bit is set, then 4 reserved bytes. Start at the unit offset the first share's reserved bytes give (not 0). The length-prefixed units (uvarint) parsed from there contain one unit exactly equal to `tx`. If `proof` is absent or empty, `inclusion = node-attested`. | A present proof that fails any point: the candidate is set aside, `railverify.ErrTxProof` (`fail` before `bank-send-v0-draft.6`). A bad proof shows only that this source did not prove inclusion. Absence is not provable on this path. The candidate is not downgraded to `node-attested`, because a source that sent a bad proof has shown that it is unreliable. |
| BX7 Code | Reported as the fact `outcome`: `success` for `tx_result.code == 0`, otherwise `failure`. `result = proven` if RP1 to RP6 below succeed (the proven code then replaces the source's), `cross-confirmed` under core EX9's interim rule, otherwise `node-attested`. | Classified by BX9. |
| BX8 Cross sources | Each cross source is asked `GET <rpc>/tx?hash=0x<rail_ref>`. Cross sources are distinct by core OH3 from each other, from every candidate and from the headers source. Per source: `agree` if its `tx` hashes to `rail_ref` (and is therefore byte-identical to the used answer) and it reports the same `height` and `tx_result.code`. `disagree` if its `tx` hashes to `rail_ref` but the height or code differs. `fault` if it answers not found, fails, or serves bytes that do not hash to `rail_ref`. The aggregate is computed by core EX6. With no cross source configured, `cross_check = off`. | Reported through `cross_check` and the per-source results. |
| BX9 Classification | First match. (1) The chain id differs (BX4) and `inclusion = proven`: `fail`, `railverify.ErrChainMismatch`. (2) `height <= payload_ref.height` and `inclusion = proven`: `fail` (core EX4). (3) `result = proven` and the proven code != 0: `fail`, `railverify.ErrTxFailed`. (4) The chain id differs: `unchecked`. (5) `height <= payload_ref.height`: `unchecked` (core EX4). (6) `cross_check = mismatch` and the result is not proven: `unchecked` (core EX6). (7) The result is not proven and the code != 0: `unchecked`, `railverify.ErrResultUnconfirmed`. Cross agreement on a nonzero code is not proof. (8) The result is neither proven nor cross-confirmed: `unchecked`. The cause is the RP failure if inclusion is proven (root mismatch `railverify.ErrResultsProof`, index unbound, header at `height + 1` unreachable), otherwise "result code attested by one source". (9) Otherwise `pass`. | Rows 2, 5, 6 and 8 are core rules. The checker MAY return the facts and leave those rows to the core, and the outcome is the same. Each vector case holds at most one violation, so the reported cause is fixed too. |

Result proof (RP, since `bank-send-v0-draft.6`). It proves the result code of
the transaction against the trusted chain, so that a single tx source is
enough for `pass` (human decision of 2026-10-07). The hashing below was read
in celestia-core `v0.42.0`, the module pin of the `celestia` module, and is
byte-identical in `v0.42.3` (`types/results.go`, `state/store.go`
`TxResultsHash`, `state/execution.go`, `crypto/merkle`). It is VERIFIED by
code, and on live Mocha data by the vectors.

| Rule | Requirement | Outcome |
|---|---|---|
| RP1 Read | `GET <rpc>/block_results?height=<height>` from any configured source (tx, cross or headers source; untrusted). Use `result.txs_results[]`: `code` (number), `data` (base64), `gas_wanted`, `gas_used` (decimal strings, int64). Every other field (`log`, `info`, `events`, `codespace`, and celestia-core's `signers`) is ignored. A source that answers with an error is skipped, and the next one is tried. Some operators do not persist the responses: on 2026-10-07 `https://rpc-mocha.pops.one` answered "node is not persisting finalize block responses". | No source answers: the result is not proven. |
| RP2 Inclusion first | RP applies only with `inclusion = proven` (BX6), which ties the tx to block `height`. | Without it, the results of block `height` say nothing about this tx. |
| RP3 Leaves | For each result `i`, the leaf is the protobuf of `ExecTxResult` with only the deterministic fields of `types.NewResults`: field 1 `code` (varint uint32), field 2 `data` (bytes), field 5 `gas_wanted` and field 6 `gas_used` (varint int64; a negative value as its 64-bit two's complement). A zero or empty field is omitted, as gogoproto `Marshal` does, and the fields appear in this order. | - |
| RP4 Root | `root` = CometBFT `merkle.HashFromByteSlices(leaves)` (RFC 6962): no leaves gives `SHA-256("")`; one leaf `x` gives `SHA-256(0x00 \|\| x)`; otherwise split at `k`, the largest power of two below `n`, and `SHA-256(0x01 \|\| root(first k) \|\| root(rest))`. `root` MUST equal `last_results_hash` of the header at `height + 1`, and that header MUST pass header trust (core EX5 rules, so `T >= height + 1`). Why `height + 1`: the state after block `h` stores `TxResultsHash` of block `h`'s results as `LastResultsHash`, and the header of block `h + 1` carries it. | A mismatch: that source's fault (`railverify.ErrResultsProof`), and the next source is tried. `T < height + 1`, or the header at `height + 1` does not link: the result is not proven. |
| RP5 Index | The tx's result is `txs_results[i]`, and `i` MUST be bound. It is bound in two ways. (a) The BX6 proof's first share is share 0 of the square (`start_row = 0`, first share proof `start = 0`). Parsing the compact shares from there as in BX6 (e), `i` is the number of units before the unit equal to `tx`. Why: the transaction namespace is the first in the square, and celestia-app `v10.4.0-mocha` `ProcessProposal` builds the square with go-square `v4.0.1` `Construct` over the block's txs in block order. `Construct` refuses a normal tx after a blob or Fibre tx, and it appends normal txs to the transaction namespace in that order. ABCI returns one result per tx in block order (VERIFIED by code). `UNVERIFIED`: that no namespace below the transaction namespace ever occupies share 0. This holds in the live vector. (b) Every result of the block has the same code. Then that code is this tx's whatever its index, because F5 puts the tx in the block and the root fixes every result. The count must also satisfy `i < n`. | An index that is not bound: the result is not proven. |
| RP6 Outcome | With RP1 to RP5 met, `result = proven` and the code is `txs_results[i].code`. It replaces the code the tx source reported. A source that reported another code is listed as disagreeing. | - |

The checker returns `height`, the hash of the trusted header at `height`,
`inclusion`, `outcome`, `result`, `cross_check` and every
source asked, with its role, result and reason (core EX10). If no candidate
is usable, the `unchecked` error names every candidate with its reason, and
its cause is the last candidate's.

Why BX3 is strict: the chain's decoder reads `TxRaw` with gogoproto, which
keeps the last of a repeated field and accepts any order. A verifier that
took another occurrence of `body_bytes` could check a body that the chain did
not execute. An honest executor emits gogoproto's canonical `TxRaw`, so the
strict decoder refuses nothing honest.

Why BX6 checks more than `ShareProof.Validate`: core section 10.4 notes that
`Validate` checks neither the row index, nor the total, nor that the row is
in the original square. Without (a), a blob in a user namespace could carry
bytes shaped like a transaction. Without (b) and (d), parity or column data,
or rows that are not adjacent, could be stitched into one. Without (e) starting at the
reserved offset, a unit boundary could be chosen to suit.

Threat note (BX). With a proof, inclusion and height rest on the trusted
header and SHA-256 alone. With RP, the result code rests on the trusted
header at `height + 1` and SHA-256 too, so one honest-or-not tx source is
enough. A results source can only fail to prove: a wrong list does not hash
to `last_results_hash`. Without RP, a code is only confirmed by the
agreement of sources (interim `pass`), and it is never enough for `fail`. One
hostile source, of any kind, can only make the check `unchecked` (core 20.2.1
invariant). It can claim not to know the transaction, serve other bytes,
send a bad proof or results, or report another height or code than the
cross sources. Before `bank-send-v0-draft.6` the last of these gave `fail`.
The memo alone proves nothing, because anyone can write any memo. BX2 and
BX5 together tie the included bytes to the receipt and to the authorized
message, and they hold whoever served the bytes. A signature check is not
needed: the bytes are the executor's (`rail_ref` is in its signed record
request). `UNVERIFIED`: that celestia-app's `ProcessProposal` rejects a block
that holds a non-blob transaction whose ante handler fails (signature,
sequence, `timeout_height`). If it holds, `proven` inclusion also implies
that the chain accepted the signature. Even then, a message that fails after
the ante handler gives a nonzero code in an included transaction, so
inclusion never implies `outcome = success`; RP decides it.

## 4. Executor (`examples/tia-transfer/transfer`)

### 4.1 Configuration

| Item | Meaning |
|---|---|
| `gate_id`, `gate_pubkey` | The pinned gate (core I1). |
| `Domain{chain_id, hrp, denom, sender}` | From the node at startup (section 6) and the executor's own key; `sender` is the bech32 address of the key that signs. |
| `destinations` | Optional allowlist of `to_address`; empty disables the check. |
| `max_amount` | Operator limit in base units per transfer; `0` disables it. |
| `max_fee` | Upper bound on the fee the executor attaches. |
| `max_timeout_blocks` | Cap on `timeout_height - H0`, `1..10000`, default 200. |
| `rebroadcast_every` | Resend interval, default 10 s. |
| `skew_s` | Clock tolerance, `0..300`. |
| `hand_off_grace` | How long after `expires` the executor keeps watching a transaction whose `timeout_height` the head has not passed (a stalled or halted chain), default 10 min. Never negative. |
| `indexer_lag_blocks` | How many blocks past `timeout_height` the status node's height must be before T12 (a) applies, default 3. It covers the lag of the node's transaction indexer behind block commit, not reorgs (CometBFT has instant finality). Never negative; 0 is allowed but not recommended. |
| `confirm_delay` | Wait before the second status query of T12 (a), default 2 s, at most `rebroadcast_every`. |
| executor key | Ed25519 key for record requests (core I7), distinct from the chain key. |

### 4.2 Rules

`Execute(authorization, action_bytes)`, in this order:

| Rule | Step | On failure |
|---|---|---|
| T1 | `VerifyAuthorization` with the pinned key and gate id, `type = application/vnd.edicta.cosmos.bank-send.v0+cbor`, the exact action bytes, clock and `skew_s` (core 15.3) | the core sentinel |
| T2 | `bankaction.Decode(action_bytes)` (2.2) | `bankaction.ErrMalformed` |
| T3 | `chain_id == Domain.chain_id`, bytewise (core I4) | `transfer.ErrChainMismatch` |
| T4 | `bankmsg.Decode(msg, Domain.hrp)` (2.3) | `bankmsg.ErrMalformed` |
| T5 | In this order: `from_address == Domain.sender`; `denom == Domain.denom`; `to_address` in `destinations` if set; `amount <= max_amount` if set | `transfer.ErrSenderMismatch`, `transfer.ErrDenomMismatch`, `transfer.ErrDestination`, `transfer.ErrRiskLimit` |
| T6 | `Store.Begin(commitment_hash, expires)`: atomically record the decision as in flight; refuse if any record exists (core I5) | `transfer.ErrSeen` (then `Resume`) |
| T7 | `now + skew_s < expires` (core I6); otherwise abandon | `transfer.ErrExpired` |
| T8 | `timeout_height` by 4.3; no block fits: abandon | `transfer.ErrExpired` |
| T9 | `body = Body(msg, commitment_hash, timeout_height)`; sign (3.2) with `chain_id` from the action; check `body_bytes`; `Store.Prepare(commitment_hash, TxRaw, SHA-256(TxRaw), timeout_height, expires)`, durable **before the first broadcast** | signer error: abandon (nothing was sent) |
| T10 | Each turn, every `rebroadcast_every`: (1) read the height from the status node, the same node that answers the status query (never the bridge); this height is the node's **latest committed block height**, and it is the one used for the send condition below and for T12 (a). Reference rail: the cosmos-sdk node service `cosmos.base.node.v1beta1.Service/Status`, field `height`, on the consensus node's gRPC connection. Not `GetLatestValidatorSet`'s `block_height`, which is the latest committed height + 1 on a caught-up node and the latest committed height while it is block-syncing, so the client cannot tell which; and not `GetLatestBlock`, which gives the same height but downloads the whole block every turn. A height that is not positive counts as a failed height read; (2) query the status by the transaction hash on the same node, after the height (so a transaction included at or before that height is seen); committed goes to T11; (3) check the T12 bounds; (4) broadcast the stored `TxRaw` only if all of: sending has not been stopped by T13 in this call; the height was read on this turn and is `<= timeout_height` (past it the chain can no longer include the transaction, so a send is skipped, not attempted); and `now + skew_s < expires` by a clock read **immediately before the broadcast call** (not the clock at the start of the turn). Every send is the same bytes. Rebroadcasting stops at the latest at `expires`, whatever the height; after that the executor only reads the height and the status. Each height read, status query and broadcast runs under its own deadline, an absolute time computed from one clock read `now` taken when the call starts (the same read that decides `live` for a broadcast): while `now + skew_s < expires`, `min(now + rebroadcast_every, expires - skew_s)`; otherwise (after expiry) `now + rebroadcast_every`. Computing it as a duration and adding it to a second clock read is not equivalent, because the time between the two reads would extend a broadcast past `expires - skew_s`. After expiry the deadline is always in the future, so height reads and status queries keep working while the executor only watches. A transient broadcast error (node unreachable, deadline, mempool full, wrong sequence) is retried with the same bytes on the next turn; "already in the mempool cache" counts as sent. Any other refusal by the node's CheckTx is a final rejection (T13). A failed height read, before or after `expires`, ends nothing: that turn sends nothing and cannot use T12 (a), and the loop continues. A failed status query ends nothing either, except on a turn where a T12 bound holds (T12). Only T11, T12 (a hand-off, or a failed status query on a bound turn) or the caller's context end the call | - |
| T11 | Committed: `Store.Finish(height, code)`. Code 0: optional record request with `rail_ref` (3.2). Code != 0: terminal | `transfer.ErrFailedOnChain` |
| T12 | Not committed on this turn's status query, which MUST have succeeded, and either bound holds: (a) the height read on this turn from the status node is `> timeout_height + indexer_lag_blocks`, and a second status query on the same node, made `confirm_delay` later, has succeeded and is still not committed (committed: T11; failed: no hand-off on this turn); (b) `now >= expires + hand_off_grace` by the executor's wall clock (a stalled chain, where (a) may never come). If this turn's status query failed when a bound holds, the call ends with an error, the record stays prepared and nothing is handed off. Then `Store.HandOff(commitment_hash, reason)`; the reason names the bound and the transaction hash, for (b) states that the transaction may still be included until `timeout_height`, includes the node's code and log of the last final rejection (T13) if there was one, and SHOULD tell the operator to run `Resume` before any manual action. No new transaction is ever built for this decision | `transfer.ErrHandedOff` |
| T13 | Final rejection of a broadcast (T10): stop sending for the rest of this call and keep the node's code and log; nothing is handed off on the rejection itself. The loop continues with height reads and status queries only, until committed (T11; a resend of an already included transaction can fail ante checks before the sequence check) or a T12 bound | - (ends under T11 or T12) |

T0 (startup, before any `Execute` or `Resume`): the rail reads the status
node's transaction indexer setting and refuses to start unless it is reported
on. With indexing off, every status query answers "not found", so every
transfer would be handed off under T12 (a) even when it is on chain. A
setting that cannot be read, or any value other than on, is treated as off
(fail closed). In the reference rail this is `default_node_info.other.tx_index
== "on"` from `cosmos.base.tendermint.v1beta1.Service/GetNodeInfo` on the
consensus node that serves the status query (section 6).

T2 to T5 are pure and covered by `executor.json`, including their order.
T1 is covered by the core `authorization.json`; T0 and T6 to T13 need a chain
fake.

A hand-off is the executor's statement "inclusion not confirmed, the operator
takes over", not "the transaction will never land". Under T12 (b), and
after a T13 rejection, the signed bytes may still sit in some mempool and be included up to block
`timeout_height`. A handed-off record is therefore not final for lookups:
`Resume` and a repeated `Execute` (T6 `ErrSeen`) query the status once more,
and a committed transaction moves the record from handed off to finished
(`Store.Finish` accepts that transition; T11 applies, including the code).
Nothing is signed or sent on that path. An operator MUST run `Resume` before
any manual action on a handed-off decision, and SHOULD repeat it after block
`timeout_height` if the record is still handed off.

`Resume(commitment_hash)` after a crash: begun but not prepared: abandon
(nothing can have been sent, because broadcast happens only after a durable
Prepare); prepared: continue T10 to T13 from the stored bytes (resend only
under the T10 conditions, otherwise height and status only; hand off only on
the T12 bounds, after the status checks T12 requires; a T13 rejection from an
earlier call does not carry over, so a resumed call may send the same bytes
again while `now + skew_s < expires`); handed off: one status query,
finished if committed (as above), otherwise `transfer.ErrHandedOff` again;
finished: return the stored outcome; abandoned: return
`transfer.ErrAbandoned`. Records are kept at least until `expires + skew_s`
and until resolved; a handed-off record at least until the head passes
`timeout_height`.

Threat note (hand-off). Both bounds exist because neither alone suffices.
`timeout_height` is the chain's own guarantee: past it the transaction can
never be included, so a hand-off on (a) is final up to the accuracy of the
status query. On a stalled or halted chain (a) may not come for a long
time, so (b) bounds how long an executor call can hang; it is safe because
nothing is sent after `expires`, nothing new is ever signed, and a late
inclusion is caught by the reconcile on `Resume`. The status query before
every hand-off keeps an included transaction from being reported as not
included. Three measures narrow the remaining error of (a):
- One node. The height and the status come from the same node, so a node
  that lags another cannot make "height past `timeout_height`" and "not
  found" disagree. The bridge or any other reader is not used for (a).
- Indexer lag. A node's transaction index is written asynchronously after
  block commit, so a transaction included at `timeout_height` may not be
  found yet when the node's height first passes it. The margin of
  `indexer_lag_blocks` blocks and the second status query `confirm_delay` later give the indexer that
  time. Assumes the indexer lags by less than `indexer_lag_blocks` blocks plus
  `confirm_delay`.
- Indexer off. T0 refuses a node that does not index transactions.
A hand-off under (a) can still be wrong if the indexer lags by more than the
margin; this is the reason for the `Resume` rule above.
`UNVERIFIED`: that the status query used by the reference rail (`GetTx` on
the consensus node) is served from the transaction indexer and lags block
commit, and by how much under load.

Threat note (send stop). `live` is decided by a clock read immediately
before each broadcast, and the broadcast's deadline ends no later than
`expires - skew_s`, so a slow height read or status query on the same turn
cannot push a send past `expires`. A broadcast cancelled by its deadline may
still have reached the node; those are the same signed bytes, sent while the
Authorization was valid. Per-call deadlines also keep one hung call from
holding the loop past a T12 bound. Assumes the executor's clock is within
`skew_s` of the gate's (core I6).

Threat note (rejection). A final rejection of a resend does not prove that
the transaction will not land: the first send may still sit in another
node's mempool (a load balancer in front of nodes with different minimum gas
prices, a mempool cache eviction), and it can be included up to
`timeout_height`. Handing off at once would record "rejected" for a transfer
that may still happen. The executor therefore only stops sending and waits
for the same bounds as after `expires`.

### 4.3 Timeout height

Inputs: the head height `H0` and its time `T0` (header time floored to
seconds), the block interval `tau_ms`, the Authorization's `expires`, `skew_s`,
`max_timeout_blocks`, and `now`. All arithmetic is exact integer arithmetic.

```
if now + skew_s >= expires:                 ErrExpired          ; T7, I6
end = expires - skew_s
n   = 0                                      if end <= T0
      floor((end - T0) * 1000 / (2 * tau_ms)) otherwise         ; slowdown_factor = 2
n   = min(n, max_timeout_blocks)
if n == 0:                                   ErrExpired          ; no whole block fits
timeout_height = H0 + n                                          ; must be <= 2^63-1
```

The factor 2 is normative (`slowdown_factor` in the vectors): the budget
assumes blocks twice as slow as the slowest recent one, so it gives fewer
blocks than the observed block time suggests. Block `timeout_height` then
falls before `expires - skew_s` unless the chain slows down to more than
twice its largest recent interval. The cost is a shorter inclusion window
(about 22 blocks for 270 s at 6 s blocks).

`tau_ms`: from the last `N >= 2` headers with consecutive heights (default
`N = 11`), the largest interval between neighbours, rounded up to whole
milliseconds, at least 1. Headers out of order or with gaps are an
operational error (the executor does not send).

The chain rejects a transaction when `block_height > timeout_height`
(cosmos-sdk `TxTimeoutHeightDecorator`), so `timeout_height` is the last block
that can include it.

Why not a timestamp. The pinned chain has no transaction timeout by time:
`TxBody` has no `timeout_timestamp` field and the ante chain has no
decorator for one (section 6). A wall-clock bound enforced by the chain is
therefore not available; the executor enforces one on its own side (T10:
no rebroadcast at or after `expires`).

Threat note (halt). `timeout_height` bounds inclusion in blocks, not in
seconds. Block `timeout_height` is reached at about `T0 + n * tau_actual`.
If the chain slows down beyond the budget, or halts and resumes, a
transaction already in a mempool can be included after `expires` in
wall-clock time (up to block `timeout_height`). Safety still holds:
- the transaction was signed only after `VerifyAuthorization` passed and
  T7 held, so it is the action the gate authorized, signed while the
  Authorization was valid; a late inclusion is that one send completing
  (core I6, I5 amendment), not a new execution;
- it cannot execute twice: the gate issues one Authorization per nonce,
  the executor's store refuses a second execution of the same
  `commitment_hash`, it never builds a second transaction, and the account
  sequence lets the chain include the signed bytes at most once;
- no transaction is included after `timeout_height`, and the executor stops
  rebroadcasting at `expires`, so the late window is bounded by the halt
  itself plus `n` blocks.
What is lost is the wall-clock promise "executed before `expires`". A
verifier that wants the time of the transfer reads the block time of its
inclusion height.

Threat note (resend). Every resend is byte-identical: same hash, same account
sequence. The chain includes it at most once, and not after
`timeout_height`. A fresh transaction after a lost send would need a new
signature and possibly a new sequence and could land next to the first; the
executor never builds one. The executor's chain account MUST NOT be used by
any other signer (a Recorder in particular): a foreign transaction taking the
sequence makes the prepared one invalid, which is safe (it hands off) but
loses the transfer.

## 5. Media type `application/vnd.edicta.price-trigger.v0+cbor`

The context of an agent that moves funds when a price leaves a band around a
baseline. It is a payload `context.media_type` (core 9.3). The gate never
reads it. Canonical CBOR, core section 3 profile, arrays allowed as below; no
floats; prices are integers scaled by `10^8`; times are Unix seconds;
`bp` are basis points.

| Key | Field | Type | R/O | Meaning |
|---|---|---|---|---|
| 1 | `strategy_id` | tstr 1..64, core ID charset | R | The strategy name. |
| 2 | `asset` | `{1: feed tstr 1..64 ID, 2: asset_id tstr 1..64 ID, 3: quote tstr [A-Z]{3}}` | R | Which feed, which asset at that feed, which quote currency. |
| 3 | `observations` | array of 1..8 `{1: source tstr 1..64 ID, 2: price uint > 0, 3: observed_at uint > 0, 4: fetched_at uint > 0}` | R | What the agent saw, newest first: `observed_at` non-increasing along the array. `observed_at` is the source's timestamp, `fetched_at` the agent's. |
| 4 | `baseline` | `{1: price uint > 0, 2: set_at uint > 0}` | R | The reference price and when it was set. |
| 5 | `threshold_bp` | uint 1..10000 | R | The move that triggers a branch. |
| 6 | `direction` | uint: 1 up, 2 down | R | Which way the price moved. |
| 7 | `move_bp` | uint | R | `floor(abs(p - b) * 10000 / b)` with `p = observations[0].price`, `b = baseline.price`. |
| 8 | `branch` | `{1: name tstr 1..64 ID, 2: to_address tstr 1..90 [a-z0-9], 3: amount uint > 0, 4: denom tstr (M4 grammar)}` | R | The branch taken and the transfer it implies. |
| 9 | `reason` | tstr, 1..1024 bytes of UTF-8 | O | Free text from the agent. Advisory only; the only field that may contain non-ASCII. |

Every uint is at most `2^63-1`. Decoding: any violation of the encoding or
the table, or a re-encoding that differs, is `pricetrigger.ErrMalformed`.

Replay checks (for a reader of the payload; never gate or executor rules).
The transfer is decoded with 2.3 from the payload's `action.data`, which core
O8 ties to the committed `action.hash`, so it is exactly the authorized one:

| Check | Statement |
|---|---|
| PT1 | `move_bp` equals the formula above (exact integers). |
| PT2 | `direction` is 1 if `p > b`, 2 if `p < b`; neither holds if `p == b`. |
| PT3 | `move_bp >= threshold_bp`. |
| PT4 | `branch.to_address`, `.amount`, `.denom` equal the transfer's `to_address`, amount and denom. |
| PT5 | `observations[0].fetched_at <= issued_at` of the commitment. |

What they mean: the agent's own statements agree with each other and with
the transfer it made. They do not show that the prices were real, that the
source was honest, or that moving funds was a good decision; a reader judges
that by comparing `source` and the timestamps with market data. Testnet
tokens have no market price, so a demo on a test network uses a mainnet
price as its input; the payload names the source either way.

Privacy: the body reveals the strategy, the band and the addresses to every
recipient of the payload (core 9.1); it is never public in clear text.

## 6. Rail facts

| Fact | Status | Source |
|---|---|---|
| celestia-app v10 replaces cosmos-sdk with `github.com/celestiaorg/cosmos-sdk v0.52.12` | VERIFIED | celestia-app `v10.4.0-mocha` `go.mod` |
| `TxBody` fields at that fork: `messages = 1`, `memo = 2`, `timeout_height = 3`, `extension_options = 1023`, `non_critical_extension_options = 2047`; no `timeout_timestamp` and no `unordered` | VERIFIED | `proto/cosmos/tx/v1beta1/tx.proto` and `types/tx/tx.pb.go` at the fork (`celestiaorg/cosmos-sdk v0.52.12`; neither name occurs) |
| The celestia-app ante chain bounds transactions by height only: `ante.NewTxTimeoutHeightDecorator()`, no timestamp decorator | VERIFIED | celestia-app `v10.4.0-mocha` `app/ante/ante.go` (line 46); no `TimeoutTimestamp` in `app/ante` (the only occurrence in `app/app.go` is the IBC packet-forward timeout) |
| The ante handler rejects a transaction when `block_height > timeout_height` (nonzero) | VERIFIED | `x/auth/ante/basic.go` `TxTimeoutHeightDecorator` at the fork |
| Default `MaxMemoCharacters` 256; a 64-character memo fits | VERIFIED default; the value on each network is `UNVERIFIED` and read from auth params at startup | `x/auth/types/params.go` at the fork |
| Denom grammar `[a-zA-Z][a-zA-Z0-9/:._-]{2,127}` | VERIFIED | `types/coin.go` at the fork |
| `MaxChainIDLen = 50` | VERIFIED | celestia-core `v0.42.3` `types/block.go` |
| Bond denom `utia` and account prefix `celestia` are celestia-app constants | VERIFIED at `v10.4.0-mocha`; a forked app may differ, so both are read from the node | celestia-app `pkg/appconsts`, `app/params` |
| `cosmos.auth.v1beta1.Query/Bech32Prefix` is served by celestia-app nodes | `UNVERIFIED`; fallback: configured prefix, cross-checked against the executor's own address | - |
| Account address = RIPEMD-160(SHA-256(compressed secp256k1 key)), 20 bytes | VERIFIED (vectors `tx.json` `signed`, from the SDK's `PubKey.Address`) | cosmos-sdk `crypto/keys/secp256k1` |
| The SDK's transaction decoder rejects unknown fields in `TxBody` except non-critical ones (`RejectUnknownFields`) | VERIFIED | `x/auth/tx/decoder.go` at the fork |
| CheckTx codes in codespace `sdk` used by T10: 19 (transaction already in the mempool cache: counts as sent), 20 (mempool full: transient), 32 (wrong sequence: transient); every other nonzero code is a final rejection | `UNVERIFIED` at the pin | cosmos-sdk `types/errors/errors.go` at the fork |
| `TxStatus` query by hash for the resend loop | `UNVERIFIED` at the pin | celestia-app `proto/celestia/core/v1/tx/tx.proto` |
| A consensus node reports its transaction indexer in `GetNodeInfo` as `default_node_info.other.tx_index`, `"on"` or `"off"` (`"off"` when `tx_index.indexer = "null"`), and a node with it off finds no transaction by hash | `UNVERIFIED` at the pin (CometBFT behaviour; celestia-core fork not checked) | CometBFT `node/setup.go` `makeNodeInfo`, `rpc/core/tx.go` |
| The T10 loop height (send condition and T12 (a)) is the status node's latest committed height, read on the same gRPC connection as the status query with `cosmos.base.node.v1beta1.Service/Status`, field `height`. It equals `cosmos.base.tendermint.v1beta1.Service/GetLatestBlock`'s height; `GetLatestValidatorSet`'s `block_height` is one more on a caught-up node | VERIFIED on Mocha, read-only, 2026-10-05 (`Status` == `GetLatestBlock` height, validator set height == that + 1). Server path for the validator set: `cmtservice.GetLatestValidatorSet` -> CometBFT `Validators` at `latestUncommittedHeight()` (`BlockStore.Height() + 1` unless block-syncing), read in `celestiaorg/cosmos-sdk v0.52.8` and `celestiaorg/celestia-core v0.42.0`; `UNVERIFIED` that this path is unchanged at the pinned `v0.52.12` | cosmos-sdk `client/grpc/node`, `client/grpc/cmtservice`; CometBFT `rpc/core/consensus.go` |
| CometBFT RPC `/tx?hash=0x..&prove=true` on celestia-core returns `proof` as a celestia `ShareProof` (`data`, `share_proofs`, `namespace_id`, `row_proof`, `namespace_version`), not CometBFT's `TxProof`. For an ordinary (non-blob) transaction the namespace is the transaction namespace `0x00...01`, version 0, and the shares are compact shares that hold the transaction as one length-prefixed unit | VERIFIED on live Mocha data, 2026-10-07: tx `A9A1550E...5971` (a `MsgSend`, height 1,442,606) on four operators. Byte-identical answers. An independent Python recompute of the NMT proof, the row proof to `data_hash` and the compact-share parse yields the tx. The celestia-core source at the pin was not read | `docs/tasks/027-demo/endpoints.md` section 3.4 |
| `/tx` `hash` is `SHA-256` of the indexed tx bytes. For a `BlobTx` the index holds the inner SDK tx, not the block's `BlobTx` bytes | VERIFIED on live Mocha data (2026-10-07). Bank-send transactions are not `BlobTx` | same |
| `LastResultsHash` of block `h + 1` = RFC 6962 root over the protobuf of `ExecTxResult{code, data, gas_wanted, gas_used}` of each result of block `h`, in block order; every other field is stripped | VERIFIED by code (celestia-core `v0.42.0`, identical in `v0.42.3`: `types.NewResults`, `deterministicExecTxResult`, `state.TxResultsHash`, `state/execution.go` sets `LastResultsHash`) and on live Mocha block 1,442,606 (Python and Go recompute equal `last_results_hash` of 1,442,607) | section 3.4 RP, `execution_outcomes.json` `result_proof` |
| Block txs are ordered normal txs, then blob txs, then Fibre txs, and normal txs fill the transaction namespace in that order | VERIFIED by code: celestia-app `v10.4.0-mocha` `app/process_proposal.go` calls go-square `v4.0.1` `Construct`, whose `validateTxOrdering` refuses any other order | RP5 |
| `/block_results` is served only by nodes that persist finalize-block responses | Observed 2026-10-07: itrocket, nodes.guru and QuickNode serve height 1,442,606; P-OPS answers "node is not persisting finalize block responses" | RP1 |

## 7. Sentinels

| Sentinel | Rules | Vectors |
|---|---|---|
| `bankaction.ErrMalformed` | 2.2, T2 | `action.json` `reject`, `exec_action_malformed` |
| `bankaction.ErrBodyMismatch` | 3.3 | `tx.json` `body_reject` |
| `bankmsg.ErrMalformed` | 2.3, T4 | `msg_send.json` `reject`, `exec_msg_*` |
| `transfer.ErrChainMismatch` | T3 | `exec_chain_mismatch`, `exec_chain_id_case`, `exec_chain_before_msg` |
| `transfer.ErrSenderMismatch` | T5 | `exec_sender_mismatch`, `exec_sender_before_denom` |
| `transfer.ErrDenomMismatch` | T5 | `exec_denom_mismatch`, `exec_denom_before_destination` |
| `transfer.ErrDestination` | T5 | `exec_destination_refused`, `exec_destination_before_risk` |
| `transfer.ErrRiskLimit` | T5 | `exec_risk_limit` |
| `transfer.ErrSeen` | T6 | none (store state) |
| `transfer.ErrExpired` | T7, T8 | `timeout_height.json` |
| `transfer.ErrFailedOnChain` | T11 | none (chain fake) |
| `transfer.ErrAbandoned` | `Resume` of a record that was begun but never prepared, and any later lookup of it | none (store state) |
| `transfer.ErrHandedOff` | T12 (including after a T13 rejection), `Resume` of a handed-off record still not committed | none (chain fake) |
| `pricetrigger.ErrMalformed` | section 5 | `price_trigger.json` `reject` |
| `railverify.ErrChainConfig` | BX0 (unchecked) | `execution_outcomes.json` `unchecked_chain_config` |
| `railverify.ErrRailRefMalformed` | BX1 (fail) | `fail_rail_ref_malformed` |
| `railverify.ErrTxNotFound` | BX1 (unchecked, candidate set aside) | `unchecked_tx_not_found`, `pass_after_alternate` |
| `railverify.ErrTxSourceUnavailable` | BX1 (unchecked, candidate set aside) | `unchecked_tx_source_unavailable` |
| `railverify.ErrTxHashMismatch` | BX2 (unchecked, candidate set aside) | `unchecked_tx_hash_mismatch`, `unchecked_all_candidates_fault` |
| `railverify.ErrTxMalformed` | BX3 (fail) | `fail_tx_malformed` |
| `railverify.ErrChainMismatch` | BX4, BX9 row 1 (fail) | `fail_chain_mismatch_proven` |
| `railverify.ErrTxProof` | BX6 (unchecked, candidate set aside) | `unchecked_tx_proof_invalid`; proof forms in `proofs` |
| `railverify.ErrTxFailed` | BX9 row 3 (fail, proven code only) | `fail_tx_failed_proven`, `fail_tx_failed_proven_source_says_success` |
| `railverify.ErrResultUnconfirmed` | BX9 row 7 (unchecked) | `unchecked_code_unproven`, `unchecked_code_cross_confirmed_only` |
| `railverify.ErrResultsProof` | RP4 (unchecked, source skipped) | `unchecked_result_root_mismatch`; live `result_proof.mutations` |

The prefix is the Go package under `examples/tia-transfer/`, except
`railverify`, which is the verifier's package in the `celestia` module. The
core sentinels of T1 keep their core names. Each `railverify` sentinel of
class `unchecked` wraps the verifier's unchecked class
(`verifier.ErrExecutionUnchecked`), and each of class `fail` does not. An
`unchecked` with no profile sentinel (header trust, height, cross mismatch,
result not confirmed) is reported by the core with its reason. The vector
`cause` names every case.

## 8. Vectors

Location `spec/vectors/profiles/bank-send/`. Every file has `format`
`edicta-vectors/v0`, `profile` `bank-send` and the `revision` that last
changed it (section 0); uints are decimal strings, bytes lowercase hex.

| File | Written by | Contents |
|---|---|---|
| `msg_send.json` | `banksend-gen` | `type_url`, `upstream`. `cases`: `hrp`, `input` (`from_address`, `to_address`, `amount{denom, amount}`), `from_hex`, `to_hex`, `msg_hex` (gogoproto `MsgSend.Marshal`). `reject`: `hrp`, `msg_hex`, `expect_error` `bankmsg.ErrMalformed`, `sdk_unmarshal_ok` (whether gogoproto `Unmarshal` accepts it; informative). 6 cases, 39 rejects. |
| `tx.json` | `banksend-gen` | `body`: `msg_ref`, `commitment_hash_hex`, `timeout_height`, `memo`, `body_hex` (gogoproto `TxBody.Marshal`). `body_reject`: bodies a 3.3 check refuses, `expect_error` `bankaction.ErrBodyMismatch`. `signed`: `body_ref`, `chain_id`, `account_number`, `sequence`, `fee`, `gas_limit`, `key` (label, private key, compressed public key, address), `auth_info_hex`, `sign_doc_hex`, `signature_hex`, `tx_raw_hex`, `tx_hash_hex`, `rail_ref`. 7 bodies, 12 body rejects, 2 signed. |
| `action.json` | `gen_profile_bank_send.py` | `action_type`. `cases`: `msg_ref` (absent for an opaque msg), `input{chain_id, msg_hex}`, `cbor_hex`, `action_hash_hex`. `reject`: `cbor_hex`, `expect_error` `bankaction.ErrMalformed`. 6 cases, 22 rejects. |
| `executor.json` | `gen_profile_bank_send.py` | `cases`: `domain`, `destinations`, `max_amount`, `action_hex`, optional `expect_error`: rules T2 to T5 and their order. 17 cases. |
| `timeout_height.json` | `gen_profile_bank_send.py` | `bank-send-v0-draft.2`. `slowdown_factor`, `max_timeout_blocks_limit`. `interval`: `headers[{height, time_ns}]`, `tau_ms`. `cases`: `head_height`, `head_time`, `tau_ms`, `expires`, `skew_s`, `max_timeout_blocks`, `now`, and `timeout_height` or `expect_error` `transfer.ErrExpired`. 4 intervals, 12 cases. |
| `price_trigger.json` | `gen_profile_bank_send.py` | `media_type`. `cases`: `input`, `cbor_hex`. `reject`: `cbor_hex`, `expect_error`. `consistency`: `context_cbor_hex`, `msg_ref`, `hrp`, `issued_at`, `expect_failed` (PT ids). 4 cases, 25 rejects, 9 consistency. |
| `e2e.json` | `gen_profile_bank_send.py` | `bank-send-v0-draft.2`. One decision end to end: the gate and params; a commitment by `agent1` (core `keys.json`) with this action type, its envelope and hash (payload fields are placeholders, listed); the action bytes; a price-trigger context consistent with the transfer; the Authorization by `gate1`; the executor's clock, domain, headers, `tau_ms`, `timeout_height`, memo and body. 1 case. |

Section 3.4 has its vectors in the core set,
`spec/vectors/verifier/execution_outcomes.json` (`v0-draft.27`, profile
`bank-send-v0-draft.6`), written by `spec/vectors/check/gen_execution_outcomes.py`
and checked by `check_execution_outcomes.py`. The file holds:
- `defaults`: the decision under test (`action_minimal_mocha`,
  `signed_minimal_mocha`), and the anchor, transaction and checkpoint heights.
- `txs`: the authorized transaction and three mutations (bytes that do not
  hash, `body_bytes` twice, another memo), each with its SHA-256.
- `live` and `proofs`: the live Mocha transaction of section 6 (height
  1,442,606) and 9 BX6 forms of its proof against `data_hash`, one proven
  and 8 `railverify.ErrTxProof`. These expectations were confirmed against
  the reference `railverify.VerifyShareProof`.
- `result_proof`: RP on live Mocha block 1,442,606. It was read with plain
  HTTP GET on 2026-10-07T10:48Z from
  `https://celestia-testnet-rpc.itrocket.net/block_results?height=1442606` and
  `.../header?height=1442607`. The raw answers are in
  `spec/vectors/verifier/live/`. Byte-identical results came from
  `rpc-1.testnet.celestia.nodes.guru` and
  `public-endpoint.celestia-mocha.quiknode.pro`; `rpc-mocha.pops.one` does not
  persist them. The section holds the 5 results (deterministic fields), the
  headers at H and H + 1, the leaves, the root `756b825a...eeb0e` (equal to
  `last_results_hash` of H + 1, also computed by celestia-core
  `types.NewResults(...).Hash()`), the index 0 bound by the live share proof,
  the selected code 0, and 9 mutations (2 still match, because
  non-deterministic fields are ignored; 7 do not).
- `cases`: 37 outcome cases. Each lists the receipt's `rail_ref`, the
  sources in order with their role and answer (`tx` with a transaction,
  height, code and proof `valid`, `invalid` or `none`; `not_found`;
  `unavailable`), and optional overrides of the chain ids, `T`, the state
  of the header at the transaction height, and the result proof outcome. It expects `execution`,
  `header_trust`, verdict, exit code, cause, sentinel, `inclusion`,
  `result`, `cross_check`, `proven_execution`, the normative per-source results and,
  for `unchecked`, the named sources.

A table test feeds each case to the checker through fake tx sources and a
fake header chain. Proof `valid` is an inclusion proof that the test builds
for the answer's bytes and that passes BX6 against the trusted header.
`invalid` is any form that fails BX6. The `proofs` section gives concrete
forms.

Generation order: `cd spec/vectors/tools/banksend-gen && go run .` (needs
network access the first time to download modules; never run by `go test`
of the main module), then
`python3 spec/vectors/check/gen_profile_bank_send.py`. Both are
deterministic; `go run . -check` compares the Go files with a fresh
generation.

Checking: `python3 spec/vectors/check/check_profile_bank_send.py` (also run
by `check_vectors.py` without arguments). It rebuilds every expected byte
string from the case inputs with its own hand-written protobuf, bech32 and
CBOR, so the protobuf files are checked by two independent encoders
(gogoproto and the checker). It also derives the secp256k1 public key and
address from the private key, verifies each signature over its SignDoc (low
S), recomputes each transaction hash, and runs the core `VerifyForGate` and
`VerifyAuthorization` on the end-to-end case. Not checked by Python: that
the signature bytes are the RFC 6979 ones (it verifies them instead).

Example, end to end (`e2e_minimal_mocha`): `commitment_hash =
3725b068...4ce81a`; Authorization `expires = 1791000360`; executor `now =
1791000065`, `skew_s = 30`, head `H0 = 6543260` at `T0 = 1791000064`, `tau_ms
= 6000`: `n = floor((1791000330 - 1791000064) * 1000 / (2 * 6000)) = 22`, so
`timeout_height = 6543282`, and the memo is the full commitment hash in
lower-case hex.
