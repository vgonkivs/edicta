# dca-agent profile v0 (IBKR order action, DCA context)

Edicta profile for the dogfood agent in `examples/dca-agent`.

Status: revision `dca-agent-v0-draft.1` (2026-10-04). Working draft, subject
to change. Built on the core spec `spec/decision-commitment-v0.md`,
revision `v0-draft.9`; section numbers prefixed "core" refer to it.

Keywords MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119. Items marked
`UNVERIFIED` are facts about IBKR that must be confirmed before a real
Web API client relies on them. Everything else is normative for
this profile.

The core treats every action as an opaque byte string with a type (core 4.3,
5.1). This document gives one type its meaning, defines the context media type
the agent publishes, and states what an executor that places IBKR orders MUST
do. It is the first profile and the reference for core section 16.2.

## 0. Versioning

| Change | Rule |
|---|---|
| Editorial | No version change. |
| Any change to an encoding, a check or its outcome, while in draft | Bump `dca-agent-v0-draft.N`, regenerate the profile vectors, record the change. |
| Any such change after freeze | New media types (`...ibkr.order.v1+cbor`, `...dca.v1+cbor`). The version is in the type name, so the bodies carry no version field. |

The profile depends on the core only through `ActionHash`, `VerifyAuthorization`
and `commitment_hash`; a core draft bump that keeps those three unchanged does
not change this profile's bytes.

## 1. Threat model

| Mechanism | Defends against | Assumes |
|---|---|---|
| Strict canonical order decoding (section 2.3) | One byte string read as two different orders by two parsers (the only malleability left after the core's exact-bytes match) | Every executor and replay tool uses this decoder, checked by shared vectors |
| Account inside the order bytes, checked by the executor (rule X4) | An order authorized for one IBKR account placed in another (paper versus live, or two client accounts behind one gate) | The executor is configured with the single account its credentials trade; IBKR paper account ids differ from live ones |
| Executor dedupe plus `cOID` (rules X6, X7) | One Authorization placed twice: a replay, a retry after a timeout, a crash between send and record | The executor's store is durable; IBKR deduplication by `cOID` is a second line only (`UNVERIFIED`, section 4.1) |
| Operator risk limit (rule X5) | An agent (or its key) committing to a large order that the operator never meant to allow | The operator sets `max_notional`; the agent cannot change it. It replaces the draft.8 `max_notional` constraint, which the agent chose itself |
| MKT orders refused (rule V3) | An order whose execution price the decision does not bound | - |
| DCA context with DCA1..DCA5 (section 5) | An agent's stated reasoning diverging from the order it placed, unnoticed | Detection after the fact: the context is what the agent claims it saw, signed by its key |
| Nothing (open gap) | The order is authorized and placed; whether it fills, and at what price, is the broker's business | Fills come from broker statements, which carry the `cOID` |

## 2. Action type `application/vnd.edicta.ibkr.order.v0+cbor`

### 2.1 Order body

The action bytes are the canonical CBOR (core section 3 profile) of:

| Key | Name | Type | Limit | R/O | Scale | Semantics |
|---|---|---|---|---|---|---|
| 1 | `account` | tstr | 1..32, core ID charset | R | - | The IBKR account the order is for. The domain identifier of this format (core 16.2): the executor refuses an order for another account. |
| 2 | `conid` | uint | `1..2^63-1` | R | - | IBKR contract id. The authoritative instrument identity. |
| 3 | `symbol` | tstr | 1..32, printable ASCII `0x20..0x7e` | O | - | Informational only. Never sent to IBKR and never used to route. |
| 4 | `side` | uint enum | `1 = BUY`, `2 = SELL` | R | - | |
| 5 | `qty` | uint | `1..2^63-1` | R | `10^4` | Quantity in units of 1/10000 share. `100000` is 10 shares. |
| 6 | `order_type` | uint enum | `1 = LMT`, `2 = MKT` | R | - | `MKT` is reserved and refused (V3). |
| 7 | `limit_price` | uint | `1..2^63-1` | R if LMT, else absent | `10^8` | Price per share in `currency`. `19050000000` is 190.50. |
| 8 | `currency` | tstr | exactly 3, `[A-Z]` | R | - | ISO 4217 code. |
| 9 | `tif` | uint enum | `1 = DAY`, `2 = GTC`, `3 = IOC` | R | - | Order lifetime at the broker. |

The keys, types and scales are those of the draft.8 core `ibkr.order.v0`
params, so the order a draft.8 commitment carried in key 8 is, byte for byte,
a valid body of this type. The body is a top-level map (depth 1); at most 16
entries; no arrays.

### 2.2 Scales and arithmetic

- `qty` uses `10^4`; every money value (`limit_price`, the executor's
  `max_notional`, the DCA context's money fields) uses `10^8`. One money scale
  gives one comparison rule.
- Notional rule: `qty * limit_price <= max_notional * 10^4`, computed exactly
  in at least 128 bits (Go: `math/bits.Mul64` on each side, compare high words
  then low words; Python: `int`). Every operand is below `2^63`, so both
  products are below `2^127`: no overflow, no rounding. Vector
  `exec_notional_uint64_wrap` (`qty = limit_price = 2^32`) is accepted by a
  naive `uint64` multiplication and MUST be refused.
- Decimal text for an API is produced exactly from the integers, never through
  floating point: `qty / 10^4` and `limit_price / 10^8` written as integer
  part, `.`, and the fractional digits without trailing zeros (`190.5`, `10`,
  `0.0001`). Vectors carry `qty_decimal` and `limit_price_decimal`.

### 2.3 Decoding (`ibkrorder.Decode`)

Strict: the core section 3 profile (shortest heads, definite lengths, uint
keys strictly ascending, no duplicate keys, no floats, tags or simple values,
depth at most 4, at most 16 entries), the schema above (unknown key, wrong
major type, missing required key, length or charset violation), no trailing
bytes, and re-encoding the decoded order MUST give the input bytes. Every
failure is `ibkrorder.ErrMalformed`. Enum and integer fields decode at full
uint64 width; their ranges are validation rules.

Reasoning: after the core's exact-bytes match, the only way one authorized
byte string could mean two orders is a lenient decoder. With canonical-only
decoding, the authorized bytes have exactly one meaning (vector
`order_nonminimal_conid`: the same order with `conid` in a 9-byte head is
refused here, and is also simply not authorized by the core, vector
`action_reencoded_noncanonical`).

### 2.4 Validation (`ibkrorder.Validate`)

In this order; every failure is `ibkrorder.ErrInvalid`:

| Rule | Check | Vectors |
|---|---|---|
| V1 | Every uint `<= 2^63-1` | `order_qty_2pow63` |
| V2 | `side in {1,2}`, `order_type in {1,2}`, `tif in {1,2,3}` | `order_side_0`, `order_side_256`, `order_type_3`, `order_tif_9` |
| V3 | `order_type != 2` (MKT) | `order_mkt` |
| V4 | `conid`, `qty`, `limit_price` (if present) are nonzero | `order_conid_0`, `order_qty_0`, `order_limit_price_0` |
| V5 | `limit_price` present if and only if `order_type == 1` | `order_lmt_no_price` |

## 3. Executor (`examples/dca-agent/ibkr`)

### 3.1 Configuration

| Item | Meaning |
|---|---|
| `gate_id`, `gate_pubkey` | The pinned gate (core I1). |
| `account` | The one IBKR account this executor's credentials trade. |
| `max_notional` | Operator risk limit, `10^8` scale, per order; `0` disables it. |
| `skew_s` | Clock tolerance for `VerifyAuthorization`, `0..300`. |
| `exec_timeout` | Bound on one placement call. |

### 3.2 Rules

`Execute(authorization, action_bytes)` runs, in this order:

| Rule | Check or step | On failure |
|---|---|---|
| X1 | `VerifyAuthorization(authorization, {gate_pubkey, gate_id, type = application/vnd.edicta.ibkr.order.v0+cbor, action_bytes, now, skew_s})` (core 15.3) | the core sentinel |
| X2 | `ibkrorder.Decode(action_bytes)`: the order is parsed from the authorized bytes, never taken from the caller (core I3). The broker request is built only from this result, by the total mapping of 3.3 (`RequestFromOrder`); the executor never calls `ibkrorder.Encode`, never fills defaults, and sends nothing the order does not contain except `cOID` and the account path | `ibkrorder.ErrMalformed` |
| X3 | `ibkrorder.Validate(order)` | `ibkrorder.ErrInvalid` |
| X4 | `order.account == account` | `ibkr.ErrAccountMismatch` |
| X5 | If `max_notional != 0`: notional rule of section 2.2 | `ibkr.ErrRiskLimit` |
| X6 | `Store.Begin(commitment_hash, expires)`: atomically record the decision as in flight; refuse if any record for it exists | `ibkr.ErrSeen` |
| X7 | Re-check `now + skew_s < expires`, then place the order once with `cOID = ClientOrderID(commitment_hash)` (section 4) and the field mapping of 3.3, within `exec_timeout` | broker error; the record stays in flight |
| X8 | On the broker's acknowledgment, `Store.Finish(commitment_hash, order_id)`; then optionally `gate.Record(envelope, order_id)` (core 14.3) | - |

Vectors (`ibkr_order.json` `executor`) cover X2 to X5 and their order:
validation before the account check (`exec_invalid_before_account`), the
account check before the risk limit (`exec_account_before_risk`), and an end
to end case whose bytes come from the core Authorization vector
`auth_minimal_lmt_da` (`exec_minimal_from_authorization`). X1 is covered by the
core `authorization.json`; X6 to X8 need a broker fake (example tests).

Crash and timeout handling (replaces the draft.8 gate's Unknown state, now
local to the executor):
- A record that is in flight after a crash or a placement timeout is resolved
  by `FindByClientOrderID(cOID)` (section 4.2), never by placing again.
- Reconciliation is separate from execution: resolving an in-flight record
  needs no live Authorization (it may run after `expires`) and may move the
  record to a terminal state. Placing an order, including a resubmission of
  an in-flight record, is never allowed once `now + skew_s >= expires`.
- The executor treats "not found" as final only when its lookup covers every
  place the order could appear for the time it could have been sent (4.2
  rule 2), and not before `expires + settle`, so an order in flight is not
  declared absent. Otherwise the record stays in flight for an operator.
- The dedupe record is kept at least until `expires + skew_s` (core I5); the
  in-flight record until it is resolved.

### 3.3 Field mapping to the IBKR Web API

One element of `orders` in `POST /iserver/account/{accountId}/orders`
(schema `singleOrderSubmissionRequest`, OpenAPI document version `2.40.0`,
SHA-256 `382be29e138e19c96cf4aa51dd8d9ca32210ab9dabf7f5f634e0bd51832e1e44`,
fetched 2026-10-03 and again 2026-10-04 with the same hash):

| Order field | Web API field | Value | Status |
|---|---|---|---|
| `account` | path `{accountId}` and `acctId` (string) | as is | Field names verified in the schema |
| `conid` | `conid` (integer) | as is | Verified in the schema |
| `side` | `side` (string, enum `BUY`, `SELL`) | `1 -> BUY`, `2 -> SELL` | Verified in the schema |
| `qty` | `quantity` (number) | `qty / 10^4` as exact decimal text (2.2) | Type verified; that fractional quantities are accepted, and with what precision, is `UNVERIFIED` (account permission dependent) |
| `order_type` | `orderType` (string) | `1 -> LMT` | Type verified; the schema lists no enum, `LMT` is from the documentation examples, `UNVERIFIED` |
| `limit_price` | `price` (number) | `limit_price / 10^8` as exact decimal text | Type verified; the price precision IBKR accepts per contract (tick size) is `UNVERIFIED`; an order IBKR rounds or rejects is the broker's answer, not a re-encoding by the executor |
| `tif` | `tif` (string, enum includes `DAY`, `IOC`, `GTC`) | `1 -> DAY`, `2 -> GTC`, `3 -> IOC` | Verified in the schema |
| `currency` | not sent (the contract fixes it) | the executor MAY compare it with the contract's currency | `UNVERIFIED` whether a mismatch can be detected from the placement API |
| `symbol` | not sent | - | - |
| - | `cOID` (string, at most 64 characters, unique for 24 h) | `ClientOrderID(commitment_hash)` | Verified in the schema; see 4.1 |

The JSON numbers are written from the exact decimal text; a JSON encoder that
goes through a binary float MUST NOT be used for them.

## 4. Client order id

```
ClientOrderID(commitment_hash) -> string     ; pure, deterministic
                                 = lowercase hex of commitment_hash   ; exactly 64 characters, [0-9a-f]
```

No truncation: the full 256 bits are used, so two different commitments get
the same id only through a SHA-256 collision. The same decision always gets
the same id, which is the point: a resend of the same decision is a duplicate
at the broker. This is the core's non-normative idempotency key (core 16.3)
made normative for this profile; it fits IBKR's 64-character limit exactly.

### 4.1 IBKR facts

Sources: the IBKR Web API OpenAPI document served at
`https://api.ibkr.com/gw/api/v3/api-docs` (version `2.40.0`, fetched
2026-10-03, SHA-256 of the fetched JSON
`382be29e138e19c96cf4aa51dd8d9ca32210ab9dabf7f5f634e0bd51832e1e44`), the Web
API endpoint pages under `https://www.interactivebrokers.com/docs/web-api/`,
and the TWS API reference under `https://www.interactivebrokers.com/docs/tws-api/`.

| Question | Web API (Client Portal) | TWS API | Status |
|---|---|---|---|
| Client-supplied id field | `cOID` in each element of `orders` of `POST /iserver/account/{accountId}/orders` (schema `singleOrderSubmissionRequest`) | `Order.orderRef` (string). The TWS `orderId` is a client-managed int32 that must be strictly increasing per client id, so it cannot be derived from a hash | Verified (documentation) |
| Length limit | "The value can be no longer than 64 characters" | Not documented | Web API verified; TWS `UNVERIFIED` |
| Charset | Not documented (examples: `"AAPL-BUY-100"`, `"66807300"`, `"my-fb-order"`) | Not documented | `UNVERIFIED`: that 64 lowercase hex characters are accepted |
| Uniqueness | "The value must be unique for a 24 hour span" | Not documented as unique; `orderRef` is a free reference | Requirement documented; whether IBKR rejects a duplicate `cOID`, and with what error, is `UNVERIFIED`. Whether the 24 h scope is per account, per user or global is `UNVERIFIED` |
| Echo on placement | The bracket-order guide shows `local_order_id` equal to the `cOID` in the placement response; the OpenAPI success schema lists only `order_id`, `order_status`, `encrypt_message` | `openOrder` returns the `Order`, including `orderRef` | `UNVERIFIED` that `local_order_id` is always returned |
| Lookup of a placed order | `GET /iserver/account/orders`: working, filled and cancelled orders of the current brokerage session; the endpoint page lists `order_ref` ("Value is set using cOID"), the OpenAPI schema omits it. No server-side filter by `cOID`; the adapter filters client-side | `reqOpenOrders` / `reqAllOpenOrders` (active orders only), `reqCompletedOrders` (current day: executed, rejected, or cancelled), filtered client-side on `orderRef` | Verified (documentation); exact session boundary `UNVERIFIED` |
| Lookup of fills | `GET /iserver/account/trades`, up to 7 days, has `order_ref` ("Specified via cOID") | `reqExecutions`: current day only; `Execution.orderRef`; the filter has no `orderRef` field | Verified (documentation) |
| Rejected orders | `order_cancellation_by_system_reason` is "only present for Cancelled orders" and gives the reason an order was "cancelled or rejected by the system", so a system-rejected order appears in the session list | `reqCompletedOrders` includes rejected orders | Verified (documentation); whether an order refused synchronously at submission (`{"error": ...}`) leaves any record is `UNVERIFIED` |
| Orders never acknowledged | A placement that returns a reply prompt (`/iserver/reply/{replyId}`) is not working until confirmed; per the endpoint page an unconfirmed reply is invalidated when another order is sent | Not applicable | Documented; whether an order lost in transit can surface later in the session is `UNVERIFIED` |

### 4.2 Rules for the IBKR executor

1. Web API: set `cOID = ClientOrderID(commitment_hash)` on every order.
   TWS API: set `orderRef` to the same string. The executor MUST NOT set any
   other client id from the decision.
2. `FindByClientOrderID(id)` returns `NotFound` only if its queries cover
   every place the order could appear for the time it could have been sent:
   the session order list (Web API) or open plus completed orders (TWS), and
   the trades or executions list. If the executor cannot cover that window
   (for example the brokerage session or the trading day has rolled over
   since the send), it MUST return `Unknown`, never `NotFound`. With the Web
   API this window is bounded by the brokerage session: a session lasts at
   most until the daily reset (midnight New York, Zug or Hong Kong time,
   depending on the server), ends after about 5 to 6 minutes without requests
   or `/tickle`, and ends when the same username logs in to a brokerage
   session elsewhere. After any such break, `GET /iserver/account/orders` no
   longer covers the send, and only fills remain findable
   (`/iserver/account/trades`, 7 days). An order that was placed and never
   filled can then only be resolved by the operator.
3. The executor treats `NotFound` as final only after `expires + settle`
   (executor configuration), so an order in flight is not declared absent.
4. If placement returns a reply prompt, the executor confirms it within the
   same `Execute` call or leaves the record in flight. It reports a definitive
   refusal only when IBKR refused the order definitively.

Threat notes:
- Broker deduplication is a second line of defence only. At-most-once
  placement rests on the executor's own store (X6). If IBKR does enforce
  `cOID` uniqueness for 24 h, that window covers every possible resend: the
  executor sends only while `now + skew_s < expires`, and `expires <=
  valid_until <= issued_at + 3600` (core S14).
- Deriving the id from the hash means anyone with access to the account's
  order history can link an order to its public decision. That is intended:
  it is what makes the audit trail work without the receipt.
- A different `ClientOrderID` encoding is allowed only by a profile change;
  the verifier and reconciliation must compute the same string.

## 5. Media type `application/vnd.edicta.dca.v0+cbor`

The context type for a dollar-cost-averaging (DCA) agent. It is a payload
`context.media_type` (core 9.3); its body is `context.data`. Edicta's gate
never reads it. The SDK checks only the media type syntax; a verifier or
replay tool that knows this type decodes the body with the rules below. The
version is in the name: an incompatible change gets a new media type
(`...dca.v1+cbor`), so the body has no version field. Moved unchanged from
the draft.8 core Appendix A; the bytes and vectors are identical.

Encoding: canonical CBOR, core section 3 profile (shortest heads, definite
lengths, uint keys strictly ascending, optional fields absent, no floats,
tags or simple values, depth at most 4, at most 16 entries per map or array).
Every uint is at most `2^63-1`. Scales as in section 2.2: quantities `10^4`,
money `10^8`, times Unix seconds.

```
DCAContext = { 1: strategy_id tstr 1..64, ID charset,
               2: schedule    { 1: period_s uint > 0, 2: period_start uint > 0 },
               3: budget      { 1: currency tstr 3 [A-Z], 2: per_period uint > 0, 3: spent uint },
               4: price       { 1: source tstr 1..64 ID charset, 2: conid uint > 0, 3: price uint > 0, 4: observed_at uint > 0 },
               5: last_fills  [ { 1: filled_at uint > 0, 2: side uint {1,2}, 3: qty uint > 0, 4: price uint > 0 } x 1..8 ] (O),
               6: order       { 1: side uint {1,2}, 2: qty uint > 0, 3: limit_price uint > 0 } }
```

| Key | Field | Type, scale | R/O | Meaning |
|---|---|---|---|---|
| 1 | `strategy_id` | tstr 1..64, ID charset | R | The agent's strategy name, for example `dca-spy-weekly`. |
| 2.1 | `schedule.period_s` | uint `> 0`, seconds | R | Length of one buying period (`604800` = weekly). |
| 2.2 | `schedule.period_start` | uint `> 0`, Unix seconds | R | Start of the period this decision belongs to. |
| 3.1 | `budget.currency` | tstr, exactly 3, `[A-Z]` | R | Currency of every money field in this body. |
| 3.2 | `budget.per_period` | uint `> 0`, `10^8` | R | Spend limit per period. |
| 3.3 | `budget.spent` | uint, `10^8` | R | Already spent in this period before this decision (`0` allowed). |
| 4.1 | `price.source` | tstr 1..64, ID charset | R | Where the price came from, for example `ibkr.snapshot`. |
| 4.2 | `price.conid` | uint `> 0` | R | Instrument of the snapshot. |
| 4.3 | `price.price` | uint `> 0`, `10^8` | R | Snapshot price per share. |
| 4.4 | `price.observed_at` | uint `> 0`, Unix seconds | R | When the snapshot was taken. |
| 5 | `last_fills` | array of 1..8 fills | O | Most recent fills the agent saw (newest first by convention; not checked); absent when none. Each fill: `filled_at` (Unix s), `side` (1 BUY, 2 SELL), `qty` (`10^4`), `price` (`10^8`). |
| 6 | `order` | map | R | The order the strategy computed: `side`, `qty` (`10^4`), `limit_price` (`10^8`). |

Decoding: any violation of the encoding or the table is `dca.ErrMalformed`
(one sentinel; vectors `dca_context.json` `reject`).

Consistency with the authorized order (replay checks; a replay tool SHOULD
report each failure; they are not gate or executor rules). The order is
decoded with section 2.3 from the payload's `action.data`, which O8 (core 9.4)
ties to the committed `action.hash`, so it is exactly the authorized order:

| Check | Statement | Vector |
|---|---|---|
| DCA1 | `order.side`, `order.qty`, `order.limit_price` equal the order's `side`, `qty`, `limit_price`. | `dca1_qty_differs` |
| DCA2 | `price.conid == order.conid`. | `dca2_conid_differs` |
| DCA3 | `budget.currency == order.currency`. | `dca3_currency_differs` |
| DCA4 | `budget.spent <= budget.per_period`. If this fails, DCA5 is not evaluated. | `dca4_spent_over_budget` |
| DCA5 | `order.qty * order.limit_price <= (budget.per_period - budget.spent) * 10^4`, exact (section 2.2). | `dca5_notional_over_remaining`, `dca5_notional_equal_remaining` (holds) |

Example (`dca_minimal`, 107 bytes; the context of core vector
`pb_one_recipient_dca`):

```
input  strategy_id "dca-spy-weekly"; schedule {604800, 1790726400};
       budget {"USD", 120000000000, 0}; price {"ibkr.snapshot", 756733, 57200000000, 1790999970};
       order {1, 20000, 57250000000}
cbor   a5016e6463612d7370792d7765656b6c7902a2011a00093a80021a6abc510003a301635553
       44021b0000001bf08eb000030004a4016d69626b722e736e617073686f74021a000b8bfd031b
       0000000d5162bc00041a6ac07da206a3010102194e20031b0000000d545dac80
```

Threat notes:
- The body is what the agent claims it saw. Edicta proves it was committed and
  public before the action, not that the price was real: `price.source` and
  `observed_at` let an auditor compare it with market data afterwards.
- DCA1 to DCA5 tie the stated reasoning to the authorized order; a mismatch is
  evidence against the agent, signed by its own key.
- Privacy: the body reveals the strategy, budget and recent fills to every
  recipient (core 9.1); it is never public in cleartext.

## 6. Sentinels

| Sentinel | Rules | Vectors |
|---|---|---|
| `ibkrorder.ErrMalformed` | 2.3, X2 | `ibkr_order.json` `malformed`, `exec_malformed` |
| `ibkrorder.ErrInvalid` | V1 to V5, X3 | `ibkr_order.json` `invalid`, `exec_invalid_before_account` |
| `ibkr.ErrAccountMismatch` | X4 | `exec_account_mismatch`, `exec_account_before_risk` |
| `ibkr.ErrRiskLimit` | X5 | `exec_notional_over`, `exec_notional_uint64_wrap` |
| `ibkr.ErrSeen` | X6 | none (store state; example tests) |
| `dca.ErrMalformed` | section 5 | `dca_context.json` `reject` |

The prefix is the Go package under `examples/dca-agent/`. The core sentinels
of X1 keep their core names.

## 7. Vectors

Location `spec/vectors/profiles/dca-agent/`, generated by
`spec/vectors/check/gen_profile_dca_agent.py` from the core draft.9 set and
checked by `spec/vectors/check/check_profile_dca_agent.py` (both also run by
`check_vectors.py` without arguments). Every file has `format`
`edicta-vectors/v0`, `profile` `dca-agent` and `revision`
`dca-agent-v0-draft.1`; uints are decimal strings, bytes lowercase hex.

| File | Contents |
|---|---|
| `ibkr_order.json` | `action_type`. `cases`: `input` (section 2.1 names), `cbor_hex`, `action_hash_hex` (core 5.1 under this type), `qty_decimal`, `limit_price_decimal`, optional `core_commitment_ref` (the core `valid.json` case whose action these bytes are). `malformed`: `cbor_hex`, `expect_error` `ibkrorder.ErrMalformed`. `invalid`: canonical bodies that fail validation, `expect_error` `ibkrorder.ErrInvalid`. `executor`: `config` (`account`, `max_notional`), `cbor_hex`, optional `authorization_ref` (a core `authorization.json` case whose `check` holds these bytes), optional `expect_error`. 6 cases, 21 malformed, 10 invalid, 9 executor. |
| `dca_context.json` | `media_type`. `cases` and `reject`: the draft.8 core `payload_blob.json` `dca` section, moved unchanged (2 cases, 10 rejects). `consistency`: `dca_cbor_hex`, `order_cbor_hex`, `expect_failed` (the DCA check ids that fail; empty when consistent), 7 cases. |
| `client_order_id.json` | `core_revision`; `cases`: one per core `valid.json` case: `commitment_ref`, `commitment_hash_hex`, `client_order_id`. 14 cases. Replaces the draft.8 core `client_order_id.json`; the `rail` input and its rejects are gone with the rail enum. |

The checker also verifies, against the core set: every core action of this
type decodes and validates; the bytes of `exec_minimal_from_authorization`
pass `VerifyAuthorization` with the core vector's `check`; every core
`payload_blob.json` case whose context is `application/vnd.edicta.dca.v0+cbor`
passes DCA1 to DCA5 against its action.
