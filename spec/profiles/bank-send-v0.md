# bank-send profile v0 (Cosmos MsgSend action, price-trigger context)

Edicta profile for a bank transfer on a Cosmos SDK chain, used by the demo in
`examples/tia-transfer`.

Status: revision `bank-send-v0-draft.3` (2026-10-05). Working draft, subject
to change. Built on the core spec `spec/decision-commitment-v0.md`, revision
`v0-draft.11`; section numbers prefixed "core" refer to it.

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

The profile depends on the core only through `ActionHash`,
`VerifyAuthorization`, `commitment_hash` and rule I5 as amended in
`v0-draft.10`.

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
| T10 | Each turn, every `rebroadcast_every`: read the head, then query the status by the transaction hash (in this order, so a transaction included at or before that head is seen); committed goes to T11; then check the T12 bounds. Otherwise broadcast the stored `TxRaw`, only while `now + skew_s < expires` by the executor's wall clock, measured at the start of the turn, and only when the head was read on this turn. Every send is the same bytes. Rebroadcasting stops at the latest at `expires`, whatever the height; after that the executor only queries. A transient broadcast error (node unreachable, timeout, mempool full, wrong sequence) is retried with the same bytes on the next turn; "already in the mempool cache" counts as sent. Any other refusal by the node's CheckTx is a final rejection (T13). After `expires`, a head that cannot be read ends the call with an error and leaves the record prepared | - |
| T11 | Committed: `Store.Finish(height, code)`. Code 0: optional record request with `rail_ref` (3.2). Code != 0: terminal | `transfer.ErrFailedOnChain` |
| T12 | Not committed and either bound holds: (a) the head read on this turn is `> timeout_height`; (b) `now >= expires + hand_off_grace` by the executor's wall clock (a stalled chain, where (a) may never come). The status query of the same turn is the final status check and MUST have succeeded; if it failed, the call ends with an error, the record stays prepared and nothing is handed off. Then `Store.HandOff(commitment_hash, reason)`; the reason names the bound and the transaction hash, and for (b) states that the transaction may still be included until `timeout_height`. No new transaction is ever built for this decision | `transfer.ErrHandedOff` |
| T13 | Final rejection of a broadcast (T10): stop sending, wait a short delay (2 s in the reference executor), query the status once. Committed: T11 (a resend of an already included transaction can fail ante checks before the sequence check). Status error: the call ends with the rejection and the status error, the record stays prepared. Otherwise `Store.HandOff(commitment_hash, "rejected by the node: " + the node's code and log)` | `transfer.ErrHandedOff` |

T2 to T5 are pure and covered by `executor.json`, including their order.
T1 is covered by the core `authorization.json`; T6 to T13 need a chain fake.

A hand-off is the executor's statement "inclusion not confirmed, the operator
takes over", not "the transaction will never land". Under T12 (b) and T13 the
signed bytes may still sit in some mempool and be included up to block
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
under the T10 conditions, otherwise status only; hand off only on the T12
bounds or T13, after the final status check); handed off: one status query,
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
inclusion is caught by the reconcile on `Resume`. The final status check
before every hand-off keeps an included transaction from being reported as
not included. Residual risk: the head and the status may come from
different nodes, and a node's transaction index is updated asynchronously
from block commit (a node with the indexer disabled never finds any
transaction), so a hand-off under (a) can still be wrong for a transaction
that is on chain. This is the reason for the `Resume` rule above.
`UNVERIFIED`: that the status query used by the reference rail (`GetTx` on
the consensus node) is served from the transaction indexer and lags block
commit.

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
| `transfer.ErrHandedOff` | T12, T13, `Resume` of a handed-off record still not committed | none (chain fake) |
| `pricetrigger.ErrMalformed` | section 5 | `price_trigger.json` `reject` |

The prefix is the Go package under `examples/tia-transfer/`. The core
sentinels of T1 keep their core names.

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
