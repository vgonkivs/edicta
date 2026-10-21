# eden-escrow profile v1 (NativeEscrow deposit on Eden)

Edicta profile for a payment into the `NativeEscrow` contract on Eden, an
EVM chain on the Evolve stack. Use case: an x402 agent pays a capped
escrow deposit that a facilitator later settles. Eden is only the payment
rail. Commitments use any core `da` (the first Eden release uses `da = 2`,
fast or strict mode), and nothing in this profile touches the anchoring.

Status: revision `eden-escrow-v1-draft.6` (2026-10-21), **draft, not
frozen**. Built on the core spec `spec/decision-commitment-v1.md`, revision
`v1.2`, and on `spec/policy-v1.md` (`policy-v1.0`). Section numbers prefixed
"core" refer to the core spec; "policy" refers to the policy spec. The `v1`
in the profile name and in its media type is the profile's own version, not
the core's.

Keywords MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119. Items marked
`UNVERIFIED` are facts about Eden, Evolve, the escrow or the Houston payment
server that no read-only record (R0, R2, 2026-10-21) settled and no funded
test has confirmed yet; the human or the requester confirms them. In
particular, every statement about what the Houston server does with a
signed deposit or a `Payment-Signature` is `UNVERIFIED` until the
requester's funded test: the paid retry has never been observed. Open items
before the freeze are listed in section 12. Everything else is normative
for this profile.

This profile adds no core rule, no wire byte, no tag of the core or policy
families, no archive kind and no sentinel to section 21 of the core. The
core invariants are unchanged. The settlement report of section 7 (report key `rail_settlement`) is a
profile-defined, verdict-neutral report field.

## 0. Versioning

| Change | Rule |
|---|---|
| Editorial | No version change. |
| Any change to an encoding, a check, a table row or an outcome, while in draft | Bump `eden-escrow-v1-draft.N`, regenerate the profile vectors, record the change below. |
| After the freeze, any such change | New media type (`...escrow-deposit-tx.v2+cbor`) and new extractor ID (`eden/escrow-deposit-tx/v2`). The version is in the type name and in the ID. A new table row is such a change (policy X1: any change of the extractor's output for any input is a new ID). |

Freeze conditions: the requester answered Q-E2 (which networks) and Q-E3
(the escrow-upto flow) (both answered 2026-10-21: form T, Eden testnet for
development, 714 as the target); the requester's funded test settled the
`UNVERIFIED` server items of section 9 (RF27 to RF29); one raw
`PAYMENT-REQUIRED` header is recorded for a wire-byte `R` vector; and the
human approved.

Freeze condition on the server (for the requester; Edicta cannot enforce
it): on the paid retry the payment server checks that the address
recovered from the `Payment-Signature` is the escrow's `buyer` of that
`paymentId`, and accepts each `Payment-Signature` (each `paymentId`) at
most once (RF27). Without the first check, the quote's own
`serverSignature` is a valid payment proof for anyone who saw the quote,
because with field `paymentId` both sign the same 32-byte message (5.1,
S11 threat notes). Without the second, anyone who sees the header can
spend the payment again. The requester confirms both in writing or by the
funded test before the freeze.

| Revision | Change | Vectors |
|---|---|---|
| `eden-escrow-v1-draft.1` | First draft: form T action and its strict decoder, escrow table, extractor `eden/escrow-deposit-tx/v1`, signer rules S1 to S10, `rail_ref`, settlement report EE1 to EE9 with levels L0 to L2. Form A is a placeholder (section 8). | Initial set (section 11). |
| `eden-escrow-v1-draft.2` | Table pinned from read-only records of the deployment (section 3): the runtime code hash; the testnet row at the CREATE2 address, now in every build; the dev row moves to that same address. New signer rule S3c (escrow code hash before signing). RF8, RF19, RF20 settled from the verified source and bytecode. Outcome changes: chain 3735928814 to the CREATE2 address is accepted (was `ErrUnknownDomain`); chain 31337 to the 714 address is refused in `edictadev` builds (was accepted). | All files regenerated (`revision` draft.2). New input `live/escrow-code.json`; new section `escrow_code` and case `tx_f14_testnet` in `action.json`; rejects `tx_testnet_mainnet_address`, `tx_714_copy_address`, `tx_dev_mainnet_address` replace `tx_chain_testnet_pending`. |
| `eden-escrow-v1-draft.3` | Audit fixes. (1) `edictadev` builds register the type under a separate extractor ID, `eden/escrow-deposit-tx-dev/v1`, which alone holds the dev row; `eden/escrow-deposit-tx/v1` has the same output in every build (policy X1, X2), so a production verifier reports `policy_no_extractor` for a dev decision instead of a false `facts_mismatch`. (2) EE1: a malformed `rail_ref` is `unchecked`, no longer `violated`; the order is 7.2, EE1, then the source rules. (3) S6 and S7 in one durable write. (4) Fee bounds: `MaxFeePerAction` and `MaxFeePerHour` (S7). (5) S3c before every signature is a MUST, failing closed. (6) The nonce release path (5.3), one payer key per served chain (S1), chain-id uniqueness (RF1, RF2), settlement evidence not archived (7.6). | All files regenerated (`revision` draft.3). `action.json`: `extractors` (two IDs, rows per ID), `extractor_ids` per case, `extractor_id` per reject, 9 new rejects (ET2 straddling item and long-form empty list; ET3 leading zeros on `chain_id`, fee and tip, 9-byte `nonce` and `gas_limit`, 33-byte tip, `chain_id` 2^63). `signed.json`: `status` on EE1 cases; EE3 cases `r_equals_n`, `s_zero`, `r_not_on_curve`, `y_parity_zero_byte`, `s_as_list`. `settlement.json`: `event_other_index`. |
| `eden-escrow-v1-draft.4` | Wording only: the verifier report key of the settlement report is `rail_settlement` (the core report already has `settlement` for da = 1 anchors). No encoding, check, table row or outcome changes. | Vector files regenerated for the `revision` string only. |
| `eden-escrow-v1-draft.5` | The requester's x402 v2 `escrow-upto` flow. (1) `R` is the base64-decoded `PAYMENT-REQUIRED` response header, not the body (2.5); the `/deposit/build` answer converts to form T as is (2.2a, rules BJ1 to BJ7); `paymentId` is the server's (2.3). (2) Outcome change: facts `amount = value + gas_limit * max_fee_per_gas` (EF2), and an amount above 32 bytes is refused (EF3); profile fields `payment_id_hex`, `facilitator`, `expires_at` and others for the signer and the report (4.1), not policy facts. (3) Signer: S4 checks on `R` with the optional `serverSignature` check; S11 `Payment-Signature` (EIP-191 by the payer key, field by configuration, only after the deposit is executed at L1, only for the decision's own values); S8 amended. (4) Broadcaster rules: Houston relay or direct, `/deposit/status` never evidence (5.4). (5) Settlement: sources carry an operator; L1 counts distinct operators; the verifier and Await default to L1 with `MinSources = 2`; Await states and the multi-source outcome rules (5.5, 7.4); report field `deposit` (7.5). (6) Section 8 closed (form A not planned); rail facts RF2a, RF23 to RF31. | All files regenerated (`revision` draft.5). New inputs `live/houston-deposit-build.json` and `live/houston-payment-required.json` (the requester's fixtures, byte for byte). New `x402.json` (build to action and facts, 7 accepted and 44 refused build answers, S4 with 5 accepted and 30 refused `R`, `serverSignature`, Payment-Signature digests and signatures for both fields) and `multi_source.json` (21 outcome cases). `action.json`: every `amount` changes (EF2); `profile_fields` per case; cases `tx_amount_max_714`, `tx_amount_overflow_714`; `tx_max_714` now refused by the extractor (EF3). `signed.json`: two more cases and two more `exact_tx` passes (8 and 29 in all). |
| `eden-escrow-v1-draft.6` | Audit fixes of draft.5, all on the signer, the producer step and Await; no change to the decoder, the table, the extractors or the facts. (1) S11: only field `paymentId` is offered (`nonce` refuses to start: no server signature covers it, so the agent would choose the signed bytes); S11 needs `CheckServerSignature` and runs S4 a to f with S4f on the `R` bound by the action; with S11 enabled, S4 is a MUST before the deposit is signed. (2) S11 needs the decision's S2 material (envelope, Authorization, action bytes, salt) re-verified, and the request's API credential pinned to the envelope's agent key (one credential per agent is a MUST while S11 is enabled), so one agent cannot fetch another agent's Payment-Signature. (3) S11 refuses a committed `resource` that does not start with `https://`. (4) Await Q5: a source that served the transaction (set aside after the lookup) blocks `not_executed` and the nonce release. (5) Operator labels: explicit or defaulted, shown in the report; S11 needs explicit labels; L1's trust statement names the labels. (6) BJ0 and S4c: body and `R` sizes, nesting depth 16, strings checked after unescaping under the core JT4 text rules; timeouts for the build and relay calls; B3 direct fallback after `RelayGrace`. (7) S3: the pending-nonce check is a MUST. (8) S8 wording; freeze condition on the server's `buyer` and single-use checks (section 0). Outcome changes: S11 refusals (field `nonce`, `http://` resource, missing or unsigned `R`, a request without the agent's own credential; S11 enabled with a shared credential or an unlabelled source refuses to start); a deposit without `R` when S11 is enabled; a nonce other than the pending one; Await `unknown` instead of `not_executed` when a set-aside source served the transaction. | All files regenerated (`revision` draft.6). `x402.json`: `build.resource` is now the `https://` form of `R`'s URL (action 334 bytes, new `cbor_hex` and `action_hash_hex`), new `build.requirements_resource_url`, `build_limits`; `build_escaped_name` now really escapes; `build_accept` 11 (new: `build_escaped_value`, `build_size_max`, `build_nesting_16`, `build_nonce_2_53_minus_1` with its own `cbor_hex`), `build_reject` 54 (new: `build_too_large`, `build_nesting_17`, `build_lone_surrogate`, `build_raw_control`, `build_invalid_utf8` as `json_hex`, `build_nan`, `build_data_missing`, `build_type_null`, `build_value_escaped_sign`, `build_data_empty`); `requirements` `max_depth`, `accept` 9 (new: `r_size_max`, `r_server_sig_high_s`, `r_escaped_value`, `r_nesting_16`), `reject` 40 (new: `r_server_sig_r_n`, `r_server_sig_s_n`, `r_server_sig_wrong_parity`, `r_server_sig_wrong_parity_27`, `r_nesting_17`, `r_lone_surrogate`, `r_raw_control`, `r_invalid_utf8`, `r_nan`, `r_scheme_escaped_other`); `payment_signature`: the `nonce` case removed, `refused_fields`, 9 `requests` (S11 steps a, c, d). `multi_source.json`: `operator_label` on every source; 26 cases (new: `aside_found_two_not_found_until`, `aside_hash_mismatch_two_not_found_until`, `aside_unavailable_after_lookup_until`, `aside_chain_config_two_not_found_until`, `default_labels_agree`); no earlier case changed its outcome. |

## 1. Threat model

| Mechanism | Defends against | Assumes |
|---|---|---|
| The action carries the exact unsigned EIP-1559 transaction; the signer signs `keccak256` of those bytes and splices the signature in (sections 2, 5.2) | Executing another transaction than the authorized one; a re-encoding step between what was committed and what is signed (core I3) | The signer never builds the transaction from a struct; the strict decoder (2.4) is used only to check the bytes |
| Strict decoders: canonical CBOR, canonical RLP, exact calldata words (2.4) | One authorized byte string read as two payments by two parsers. go-ethereum's RLP decoder reads 23 of the 40 type-2 transaction rejects of the vectors as a valid payload (field `geth_rlp_decodes`) | Gate, signer and verifier use this decoder, checked by shared vectors |
| `chain_id` inside the transaction, signed by EIP-1559; `to` must be the table's escrow for that chain (ED1) | Bytes authorized for one chain or contract executed on another (testnet against mainnet, the dev chain against either) | The table is compiled in (policy X2); the dev row belongs only to the dev extractor ID, registered only in `edictadev` builds |
| Escrow runtime code hash per row (section 3), checked by the signer before signing (S3c) and by the verifier (EE5) | A copy at the testnet or dev address whose code differs, so that a deposit log means something else; a deposit sent to the CREATE2 address before the copy exists, which would be a plain transfer to an address with no code | The hash is pinned from the verified mainnet deployment |
| Facts count the deposit `value` (the cap) plus the fee bound `gas_limit * max_fee_per_gas` (section 4) | A mandate that counts only what the facilitator later settles, after the money left; gas burned outside the principal's limits (a compromised agent sending many reverting or high-fee deposits) | The facilitator settles at most the cap (contract rule, RF6); the sender pays at most `gas_limit * max_fee_per_gas` in fees (EIP-1559) and Eden charges no other fee (RF29, `UNVERIFIED`) |
| `/deposit/build` JSON converted by one strict rule set (2.2a), with size and nesting limits | Two producers (TS and Go) building different bytes from one server answer; a server field silently dropped; a hostile server exhausting the producer's memory or stack | The committed bytes are what the signer signs; the conversion runs before the commitment, never after |
| `requirements_hash` over the exact header bytes `R` (2.5); signer checks S4 when `R` is presented, and always when S11 is enabled | A deposit whose calldata does not match the server's quote; a quote not issued by the pinned facilitator (`serverSignature`, S4f) | `R` is untrusted input until S4 passed; `serverSignature` covers only `paymentId` (RF26) |
| Payment-Signature only over the decision's own `paymentId` (`w0`), which the pinned facilitator signed in `R` (S4f enforced); only to the decision's own agent (its pinned API credential, plus the re-verified S2 material); only for an `https://` resource; only after the deposit executed at L1 with explicitly labelled operators (S11) | The payer key used as an EIP-191 oracle for bytes a compromised agent chose; one agent taking another agent's payment proof; a payment proof sent in clear; a payment claim before any money moved | The payer key is dedicated to this profile (S1); the allowlisted facilitator does not sign `paymentId` values chosen to be harmful elsewhere; the payment server checks `buyer` and single use (section 0, RF27) |
| Inclusion checked through at least two Eden RPC operators (L1), never through the server's `/deposit/status` (5.4, 5.5, 7.4) | One RPC operator, or the payment server, saying a deposit landed when it did not | Those operators do not collude, and the configured labels name distinct operators (labels are the configurer's statement, not proof of independence; a defaulted label is the host and does not detect two hosts in front of one node) |
| Signer pins: facilitator allowlist, refund delay, fees, gas, payer without code (S3); fee budgets (S7) | A deposit that names an attacker's facilitator; a refund that goes to the facilitator because the payer's receive costs more than 30,000 gas; fee drain, per transaction and per hour | The operator configures them; the agent cannot change them; facts carry none of them |
| `expiresAt <= expires` (S5) | A deposit taking effect after the Authorization expired | The escrow refuses a deposit with `expiresAt <= block.timestamp` (RF5); the block time is the sequencer's |
| One digest per `commitment_hash`, durable before signing; deterministic signatures (S6) | Two different transactions for one decision; a re-sign after a crash producing new bytes | The account nonce lets one signed transaction land at most once |
| `rail_ref` = `keccak256` of the signed bytes, lower-case hex (section 6) and EE3 | An executor claiming a transaction that is not the authorized one | Keccak-256 is collision resistant; anyone can rebuild the bytes from chain data |
| Settlement levels L0 to L2 (section 7) | Trusting one RPC operator's word for inclusion, status and logs | L0: one source; L1: N operators do not collude; L2: the header is attested by N operators. No level proves Eden data availability or survives a sequencer rollback (section 7.6). Disagreement between sources is never a violation (5.5) |
| Nothing (open gap) | Whether the price was fair, the resource worth it, or how much the facilitator settles | The principal and auditors judge that from the payload; Edicta never evaluates the agent |

## 2. Form T action

Type: `application/vnd.edicta.eden.escrow-deposit-tx.v1+cbor`.

A plain type-2 (EIP-1559) transaction from an externally owned account
(EOA) that calls `deposit` on the escrow, wrapped with the x402 purpose
binding. The core hashes the action bytes as given (core 5.1); it never
parses them.

### 2.1 Action bytes

Canonical CBOR (core section 3 profile), a map of exactly four entries:

| Key | Name | Type | Limit | Semantics |
|---|---|---|---|---|
| 1 | `version` | uint | `= 1` | Body version inside this type. Any other value is refused. |
| 2 | `tx` | bstr | 1..512 bytes | The exact unsigned EIP-2718 type-2 payload (2.2). The signer signs `keccak256(tx)`. |
| 3 | `resource` | tstr | 1..2048 bytes, each byte `0x21..0x7e` | The x402 resource URL the payment is for, as requested (percent-encoded, no spaces). Committed and audited; never sent on chain. |
| 4 | `requirements_hash` | bstr | exactly 32 | `H(tag("edicta/eden-escrow/v1/requirements") \|\| R)`, with `R` the exact bytes of the server's `PAYMENT-REQUIRED` statement (2.5). Committed and audited; never sent on chain. |

All keys are required; there are no optional fields. The whole action is at
most 4096 bytes; a valid one is at most 2444 bytes (vector `tx_max_714`: 2438,
with a 2-byte `chain_id`).

### 2.2 The `tx` field

```
tx = 0x02 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas,
                  gas_limit, to, value, data, access_list])
```

This is the EIP-1559 signing preimage: `keccak256(tx)` is the hash an
Ethereum signer signs for this transaction (vectors: `sighash_hex`, equal to
go-ethereum's `LatestSignerForChainID(chain_id).Hash`). It is not a
transaction that can be broadcast; the signer appends the signature (5.2).
A valid `tx` is at most 350 bytes (`tx_max_714`: 344).

### 2.2a From the server's `/deposit/build` answer to `tx` (producer step)

In the requester's flow the payment server builds the deposit: the client
sends `POST {base}/deposit/build` with `{from, accepted}` (`from` = the
payer address, which the agent gets from the signer; `accepted` = the
chosen quote entry of `R`) and receives JSON `{txData, paymentId}`. Form T
takes that transaction as is: the producer (SDK, JSON API or the TS
wrapper) converts the JSON to `tx` by the rules below, builds the action
(2.1) and commits it. The server's answer is untrusted input: the decoded
`tx` (2.4) and the signer's checks (S3 to S5) are what count, never the
JSON.

| Rule | Check (every failure is `edenescrow.ErrMalformed`, rule named in the vectors) |
|---|---|
| BJ0 Size | The body is 1 to 16384 bytes. The producer reads at most 16385 bytes of the answer and refuses a longer one before parsing. |
| BJ1 Document | The body is one JSON document under core 18.4 JT3 (UTF-8 without a byte order mark; whitespace only space, tab, LF, CR; nothing after the value; member names compared after unescaping), with no member name repeated in any object at any depth, arrays and objects nested at most 16 deep (the top-level object is depth 1), and no `NaN` or `Infinity`. Every string, member names and values, ignored members included, is taken after unescaping under the core JT4 text rules: an unpaired surrogate, a raw control character below `0x20` or invalid UTF-8 refuses. BJ2 to BJ7 compare and parse the unescaped strings. It is an object with a member `txData` (an object) and a member `paymentId` (a string). Other top-level members are ignored. |
| BJ2 Members | `txData` has exactly the members `to`, `data`, `value`, `nonce`, `gasLimit`, `maxFeePerGas`, `maxPriorityFeePerGas`, `chainId`, and optionally `type` and `accessList`. Any other member (`from`, `gas`, `gasPrice`, `authorizationList`, ...) and any missing one is refused. |
| BJ3 Integers | `value`, `gasLimit`, `maxFeePerGas`, `maxPriorityFeePerGas`: JSON strings of 1 to 78 decimal digits, no sign, no leading zero other than `"0"` itself, no spaces. `nonce`, `chainId`: JSON numbers in the core JT4 uint form (digits only, no sign, fraction or exponent; at most `2^53 - 1`). |
| BJ4 Hex | `to`: `"0x"` and exactly 40 hex digits; `data`: `"0x"` and an even number of hex digits; `paymentId`: `"0x"` and exactly 64 hex digits. Digits of either case; the prefix is lower-case `0x`; an EIP-55 checksum is not checked (the bytes are what count). |
| BJ5 Type | `type`, if present, is the JSON number `2`; `accessList`, if present, is the empty array `[]`. |
| BJ6 Build | `tx = 0x02 \|\| rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, []])` with canonical RLP integers (ET3: minimal big-endian, zero is `0x80`); the action (2.1) with `resource` and `requirements_hash` (2.5); then 2.4 runs on the action, and its first failing rule (ET3 for 2^256 or a 2^63 gas limit, ET4, ET6, ET8, ED1, ...) is the refusal. |
| BJ7 `paymentId` | The top-level `paymentId` equals `w0` of the calldata (2.3). |

The rules run in order BJ0 to BJ7. The step is outside the trust
boundary: a producer that converts differently only produces an action the
signer refuses or a deposit the server rejects; the committed bytes are
exactly what the signer signs, so the "no re-encoding after commitment"
rule (core I3) is unaffected. Producers SHOULD also run S4 (5.1) on
`(R, tx)` before committing, as the requester's client checks the deposit
against the quote.

Escapes: a JSON string may spell the same text in several ways (`"to"` or
`"\u0074o"`). Every check reads the unescaped text, so all spellings are
accepted alike and none can smuggle a sign, a space or another character
past BJ3 or BJ4 (vectors `build_escaped_name`, `build_escaped_value`,
`build_value_escaped_sign`). Parsers MUST check the nesting depth before
they descend, so that no parser recurses deeper than 16 levels.

Timeouts: the producer's calls to `/deposit/build` and `/deposit/send`
(5.4) each have a deadline (`ServerTimeout`, default 10 s, at most 60 s).
A build that times out produces no action and no commitment; a relay that
times out falls back to a direct send (B3).

Threat note: the server's answer is read before anything is committed, by
a process that holds no key. The size, depth and time limits bound what a
hostile or broken server costs that process: memory, stack and waiting
time, never a wrong commitment.

Observed on the fixture (`x402.json` `build`, 2026-10-21): the server
chose `nonce` 508260 (the pending nonce of `from`, `UNVERIFIED`), gas
224145, max fee 1533 wei, tip 0, chain 714 (RF24); no `type`, no
`accessList`, no `from`. The resulting `tx` is 245 bytes, the action 334
bytes (with the `https://` resource); the decoder and both extractors
accept it as is. The server picks the nonce, so a client builds one
deposit at a time per payer (two concurrent builds get the same nonce; the
second signed transaction fails at the chain or is refused by S3's
pending-nonce check).

### 2.3 Deposit calldata (`data`)

```
deposit(bytes32 paymentId, address payTo, address facilitator,
        uint256 expiresAt, uint256 refundAfter, uint256 tiaPriceUsd)
selector = keccak256("deposit(bytes32,address,address,uint256,uint256,uint256)")[0..4] = b707d860
data = b707d860 || w0 || w1 || w2 || w3 || w4 || w5      ; 196 bytes, each w 32 bytes
```

| Rule | Check (every failure is `edenescrow.ErrMalformed`) |
|---|---|
| DC1 | `data` is exactly 196 bytes. |
| DC2 | The first 4 bytes are `b707d860`. |
| DC3 | `w1` (`payTo`), then `w2` (`facilitator`): the 12 high bytes are zero and the low 20 bytes are not all zero. |
| DC4 | `w3` (`expiresAt`), then `w4` (`refundAfter`): the 24 high bytes are zero and the value is in `1..2^63-1`; then `refundAfter > expiresAt`. |
| DC5 | `w5` (`tiaPriceUsd`) is not zero. It is kept as 32 bytes and never interpreted. |

`w0` (`paymentId`) is any 32 bytes to the decoder. In the requester's flow
the server chooses it: it is `extra.paymentId` of the quote entry in `R`
and the top-level `paymentId` of the `/deposit/build` answer (verified on
the client code and fixtures, R2). The quote's `extra.serverSignature` is
the facilitator's EIP-191 `personal_sign` over the 32 bytes of `paymentId`
and nothing else (verified on the fixture: it recovers to `w2`; RF26). The
escrow refuses a second deposit with the same `paymentId` (RF5).

Why so strict: Solidity 0.8's decoder reverts on dirty address words
(`UNVERIFIED` for this build of the escrow), but other ABI decoders take the
low 20 bytes; a non-zero `payTo` and `facilitator`
are this profile's rules, the contract does not check them (RF5). The
64-bit bound keeps times in the core's integer range.

### 2.4 Strict decoder (`edenescrow.DecodeTxAction`)

The rules run in this order; the first failure decides. The vectors record
the rule (`rule`) of every reject.

| Rule | Check | Sentinel |
|---|---|---|
| EA1 | `1 <= len(action) <= 4096`, checked before parsing. | `edenescrow.ErrMalformed` |
| EA2 | Core 6.2 generic well-formedness (D1 to D13): one data item, nothing after it, shortest heads, definite lengths, no floats, simple values or tags, uint map keys strictly ascending and not repeated, valid UTF-8. | same |
| EA3 | Schema of 2.1: the item is a map; per key in encoded order, an unknown key, a wrong major type, then the value rule (version, lengths, charset); then any missing key. | same |
| ET1 | `tx[0] = 0x02`. | same |
| ET2 | `tx[1..]` is exactly one canonical RLP list and nothing follows it. Its payload is exactly 9 canonical items: items 0 to 7 are strings, item 8 is a list. Canonical: a single byte below `0x80` is encoded as itself; a payload of at most 55 bytes uses the short form; the long form has a length of length without a leading zero byte; no item extends past its enclosing list. | same |
| ET3 | Integers (`chain_id`, `nonce`, `max_priority_fee_per_gas`, `max_fee_per_gas`, `gas_limit`, `value`) have no leading zero byte (zero is the empty string `0x80`). `chain_id`, `nonce`, `gas_limit` are at most 8 bytes and `<= 2^63-1`; the fees and `value` are at most 32 bytes. | same |
| ET4 | `max_priority_fee_per_gas <= max_fee_per_gas` (otherwise no chain accepts it). | same |
| ET5 | `to` is exactly 20 bytes (no contract creation). | same |
| ET6 | `value >= 1` (the escrow refuses a zero deposit, RF5). | same |
| ET7 | `access_list` is the empty list `0xc0`. | same |
| ET8 | `data` passes DC1 to DC5. | same |
| ED1 | `chain_id` is a row of the table of the extractor ID this build registers (sections 3, 4), and `to` equals that row's escrow address. | `edenescrow.ErrUnknownDomain` |

The decoder is pure and total: no I/O, no clock, no configuration other
than the compiled table. A format failure always wins over a domain failure
(vector `tx_chain_1_and_dirty_data`). The decoder neither checks
`expiresAt` against time nor the facilitator: the signer does (S3, S5).

Not bounded by the decoder (signer pins instead, S3): fees, gas, `nonce`,
`refundAfter - expiresAt`, the facilitator. The decoder fixes the meaning
of the bytes; the signer decides whether to sign them.

### 2.5 Purpose binding: `resource` and `requirements_hash`

The two fields bind the payment to what was bought for an auditor who
holds the payload, without sending anything extra on chain. The gate
does not read them (invariant 3: no semantics); the facts do not
contain them.

- `R` is the byte string obtained by base64-decoding the value of the
  `PAYMENT-REQUIRED` header of the server's 402 response (x402 v2 HTTP
  transport; header names are case-insensitive, the requester's server
  sends `payment-required`). Not the body: in x402 v2 the body is free-form
  and the requirements travel in the header. Decoding: the header value as
  the HTTP library returns it (leading and trailing whitespace removed by
  HTTP itself), standard base64 alphabet (RFC 4648 section 4), padding
  optional; any other character refuses. `R` is the whole decoded
  `PaymentRequired` document (`x402Version`, `resource`, `accepts`, ...),
  not one entry, so the hash also binds the resource the server named and
  the alternatives it offered. Draft.4 said "the whole response body"; that
  was wrong for x402 v2.
- Only the decoded bytes are hashed, so two base64 spellings of the same
  bytes give one hash; producers SHOULD still keep the header value as
  received in the payload, beside `R`.
- `R` is at most 16384 bytes (S4a); a producer refuses a larger header.
- `resource` (key 3) is the URL the client requested. It MAY differ from
  `R`'s `resource.url` (observed: the server names `http://` while the
  client calls `https://`, RF23); `R` keeps the server's version. The
  signer issues a Payment-Signature only when `resource` starts with
  `https://` (S11), so a producer that wants one commits the `https://`
  URL it actually calls.
- Tag `edicta/eden-escrow/v1/requirements` (34 bytes, `tag(t)` first byte
  `0x22`), family `eden-escrow` under policy 2.1. It is a hash tag only:
  no Edicta key signs under it, and no core or policy tag has this ASCII.
- Producers SHOULD put `R` and the resource into the payload plaintext so
  that an auditor can recompute the hash. The gate never reads `R`
  (invariant 3). The signer checks it when it is presented (S4), and MUST
  have it, with a valid `serverSignature`, before it signs a deposit while
  S11 is enabled and before every Payment-Signature (S11).
- Timing: the producer sets the commitment's `valid_until` so that the
  Authorization's `expires >= expiresAt` of the quote; otherwise S5 refuses
  every quote. The observed `expiresAt` is about 300 s after the quote
  (fixture and F14), well inside MaxTTL for da = 2.
- Vectors: `action.json` keeps mock bodies (`requirements_hex`, marked
  `"mock":true`). `x402.json` uses the requester's saved document
  (`live/houston-payment-required.json`) as `R`: real values, but a
  pretty-printed re-serialization, not the header's wire bytes
  (`wire_bytes: false`). A raw header capture replaces it before the
  freeze. The `build` action commits the `https://` form of `R`'s URL
  (`resource`), the URL the requester's client calls; `R`'s own
  `http://` URL is kept as `requirements_resource_url`.

Threat note: without the binding, an action names only a deposit; the
purpose (which call, at what quoted price) would rest on payload text that
nothing ties to the money. The hash ties the exact server statement to the
committed bytes.

### 2.6 Example (`tx_f14_714`)

A deposit on chain 714 with the recorded mainnet calldata and value (the
mainnet flow itself was form A, through a relayer; this action is the same
deposit sent as form T). The `tx` (243 bytes):

```
02 f8 f0
   82 02ca                       chain_id 714
   07                            nonce 7
   80                            max_priority_fee_per_gas 0
   82 08fb                       max_fee_per_gas 2299
   83 030d40                     gas_limit 200000
   94 65d77c98...86a94c8         to = the 714 escrow
   87 3972f538a8081d             value 16170471215597597 wei
   b8 c4 b707d860 e7b0fe0c...    data, 196 bytes (paymentId, payTo, facilitator,
         ...08c9da13856cd000           expiresAt, refundAfter, tiaPriceUsd)
   c0                            access_list
```

`keccak256(tx)` = `000b4232c55eb69fb5deff817d99757389c801b69d361087d70007702822f583`.

### 2.7 Example from the requester's fixtures (`x402.json` `build`)

The `/deposit/build` fixture converted by 2.2a: `tx` 245 bytes,
`keccak256(tx)` =
`2b459989ad782892ebe827e4a050ba1b2d1ac9eafe7d261f410cf0979d4ad8dc` (equal to
go-ethereum's signing hash); with `resource` =
`https://inference.bot.fun/v1/chat/completions` (`R`'s URL with the
`https://` scheme the client uses) and `requirements_hash` over the saved
document, the action is 334 bytes.
Facts (4): `{kind: x402-payment, asset: eip155:714/native, amount:
068e6a28ffe5 (7208392580248 + 224145 * 1533 = 7208736194533 wei), scale: 18,
recipient: eip155:714:0xc5aaa301b580d31e64b3bf546846586d934416dc}`.

## 3. Escrow table

Compiled into the extractor, the signer and the verifier; never
configuration (policy X2). A row binds a chain to one escrow address and the
keccak-256 hash of that address's runtime code (`EXTCODEHASH`, the
`keccak256` of `eth_getCode`).

| Row | `chain_id` | Network | Escrow | Builds |
|---|---|---|---|---|
| R714 | 714 | Eden mainnet | `0x65d77c98e73dfbea91ecb72b27c9753e186a94c8` | all |
| R-testnet | 3735928814 | Eden testnet | `0xe851a9b22d949ae005f65e1ba97c9b0c18354e5d` | all |
| R-dev | 31337 | compose dev chain | `0xe851a9b22d949ae005f65e1ba97c9b0c18354e5d` | `edictadev` only |

Runtime code hash, the same for every row:
`281a5ec0494b3c25ba7d7e36648a4f00f9f910d3889cc09d706755bd894300e5`
(`keccak256` of the 2,809-byte runtime code).

How the constants were fixed (read-only, 2026-10-21; records in
`spec/vectors/profiles/eden-escrow/live/escrow-code.json`, checked by the
generator and the checker, section `escrow_code` of `action.json`):

- R714. Blockscout lists `NativeEscrow` (`src/NativeEscrow.sol`, solc
  `v0.8.28+commit.7893614a`, optimizer 200 runs, EVM `prague`, fully
  verified 2026-06-04, no proxy, no constructor arguments), created by the
  plain contract-creation transaction
  `0x50b371c88ab7aecc7804fbd041612e7314e3d88868fec6ee6b5fa1ded1d28135` from
  the EOA `0x63f8077424c1df3ada3569311a7984c4d36674c1` at nonce 9. The
  address recomputes as `keccak256(rlp([creator, 9]))[12..32]`. The
  transaction input equals the explorer's creation bytecode, and
  `eth_getCode` on `https://rpc.eden.gateway.fm/` equals its deployed
  bytecode. The 714 deployment did not use the deterministic deployer.
- Creation code = a 26-byte constructor
  (`60808060405234601557610af9908161001a8239f35b5f80fdfe`: refuse value,
  copy 0xaf9 bytes, return) followed by the runtime code byte for byte. So
  the contract has no immutables and its constructor writes no storage
  (no `SSTORE`): a copy of the runtime code anywhere behaves as the 714
  contract.
- R-testnet. The CREATE2 address of that creation code through the
  deterministic deployer `0x4e59b44847b379578588920ca78fbf26c0b4956c` with
  salt 32 zero bytes: `keccak256(0xff || deployer || salt ||
  keccak256(init_code))[12..32]`, `keccak256(init_code)` =
  `7d841880f9d1d038341a5c78933a9964e96947edea5b8a455f7d885e3ca315fd`. The
  deployer is present on testnet (69 bytes); on 2026-10-21 neither this
  address nor `0x65d7...94c8` had code on testnet. Anyone can deploy the
  copy with one transaction to the deployer (the creation code as calldata
  after the salt), and the result is the same address with the same code;
  until then S3c and EE5 refuse it.
- R-dev. The same CREATE2 address, filled by the dev chain's genesis alloc
  with the runtime code (correct, since no immutables and no constructor
  storage). If the alloc route fails, the compose init step sends the same
  CREATE2 deployment, and the address does not move.
- The dev row belongs only to the dev extractor ID (section 4), which only
  `edictadev` builds register; a production build refuses chain 31337 as
  unknown (vector `tx_dev_row_in_production`). The testnet
  row is in every build so that answering Q-E2 needs no new extractor ID;
  using it still needs a funded payer and the deployment (C11).
- Domains: each row pairs one chain with one address. The CREATE2 address
  on 714 and the 714 address on testnet are refused (vectors
  `tx_714_copy_address`, `tx_testnet_mainnet_address`), so one byte string
  never names two escrows.

## 4. Policy extractors `eden/escrow-deposit-tx/v1` and `eden/escrow-deposit-tx-dev/v1`

The policy v1 extractors (policy section 5) for the form T type. Gate and
verifier run them on the exact action bytes.

| ID | Rows (section 3) | Registered by |
|---|---|---|
| `eden/escrow-deposit-tx/v1` | R714, R-testnet | production builds |
| `eden/escrow-deposit-tx-dev/v1` | R714, R-testnet, R-dev | `edictadev` builds only, instead of the first (policy X5: one extractor per type per registry) |

Each ID has one table, so its output for any input is the same in every
build (policy X1, X2). A dev decision's verdict names the dev ID; a
production verifier, which does not register it, reports
`policy_no_extractor` (`unchecked`, policy 13) rather than a false
`facts_mismatch`. The two IDs give identical facts for every action both
accept (vectors: `extractor_ids` per case).

| Step | Rule |
|---|---|
| EF1 | Decode with 2.4, using the ID's table. |
| EF2 | Facts: `kind = "x402-payment"`; `asset = "eip155:" + chain_id + "/native"`; `amount` = `value + gas_limit * max_fee_per_gas` (exact integer arithmetic) as minimal big-endian bytes; `scale = 18`; `recipient = "eip155:" + chain_id + ":0x" + lower-case hex of payTo`. `chain_id` is decimal without leading zeros. |
| EF3 | If that `amount` is at least `2^256` (more than the 32 bytes policy section 3 allows), the extractor refuses: `policy.ErrFactsInvalid`. The decoder still accepts such bytes (ET3 bounds each field, not the sum). |

Any failure of EF1 (`ErrMalformed` or `ErrUnknownDomain`), EF3, and facts
that fail policy section 4 are `policy.ErrFactsInvalid` (a deny, policy
X4). Constants fixed by the ID: the kind, the scale, the asset and recipient
forms, the amount formula, the table. Example: `tx_f14_714` gives
`{kind: x402-payment, asset: eip155:714/native, amount: 3972f5541005dd
(16170471215597597 + 200000 * 2299), scale: 18, recipient:
eip155:714:0xc5aaa301b580d31e64b3bf546846586d934416dc}`.

- `amount` is the most the payer can lose to this transaction: the deposit
  cap (the facilitator later settles at most `value`, any time while
  funded, RF6) plus the most gas it can burn (EIP-1559: the sender pays
  `gas_used * effective_gas_price <= gas_limit * max_fee_per_gas`). The
  gate must count the maximum before the money leaves, so the settled
  amount and the gas actually used are never facts. A mandate's
  `per_action_max` and `periods` for `eip155:<chain>/native` therefore
  bound deposits and fees together, in TIA, without an oracle
  (`tiaPriceUsd` is never read).
- Why not a separate fee fact or a mandate fee rule (requested in H-E4):
  policy v1 `Facts` (keys 1 to 5) and `Mandate`/`AssetRule` are frozen
  closed maps; a new key is a new policy family version. Fee-only caps and
  crediting back refunds after `refundAfter` (a release, as SessionRelease)
  are policy v2 backlog items. Until then the over-count is safe: a
  refunded remainder and unused gas stay counted.
- Assumption: Eden charges the sender nothing beyond gas (no separate data
  or L1 fee, as OP-stack chains have). `UNVERIFIED` (RF29); if it does,
  that fee is not in `amount`.
- `kind = x402-payment` is meant for every x402 spend, whatever the scheme,
  so one mandate `kinds` entry covers them.
- `asset` is Edicta's own domain-qualified form (as bank-send's
  `cosmos:<chain>/utia`), not CAIP-19: a CAIP-19 name for native TIA on an
  EVM chain would need a SLIP-44 coin type, which is `UNVERIFIED`. Compared
  bytewise: `eip155:714/native` and `eip155:31337/native` are different
  assets, so a mandate written for mainnet never covers dev payments.
- Not facts (policy v1 facts have no field for them): `facilitator`,
  `expiresAt`, `refundAfter`, `tiaPriceUsd`, `paymentId`, the fee as its
  own number, gas, `resource`, `requirements_hash`. The signer binds the
  facilitator (S3, S4f) and `expiresAt` (S5); section 4.1 exposes them.

Gate fit: the gate's action-type allowlist (core rule C2) admits the type;
the registry (policy X5, X6) holds this extractor; stage 4p runs on its
facts; nothing else in the gate reads the bytes (invariant 3).

### 4.1 Profile fields (deposit view)

A deterministic view of a decoded action, for the signer's log and
responses, the S11 request, the TS wrapper and the settlement report
(`deposit`, 7.5). It is **not** policy facts: no mandate rule reads it, the
gate never computes it, and it is not hashed or signed anywhere.

| Field (JSON) | Value |
|---|---|
| `payment_id_hex` | `w0`, 64 lower-case hex |
| `pay_to` | `w1`, lower-case `0x` hex |
| `facilitator` | `w2`, lower-case `0x` hex |
| `escrow` | `to`, lower-case `0x` hex |
| `expires_at`, `refund_after` | `w3`, `w4`, decimal |
| `value` | `value`, decimal (the deposit cap) |
| `fee_bound` | `gas_limit * max_fee_per_gas`, decimal |
| `tia_price_usd_hex` | `w5`, 64 lower-case hex, never interpreted |

Vectors: `profile_fields` on every `action.json` case and on `x402.json`
`build`.

## 5. Signer (the executor)

The executor is `edicta-signer`: it holds the payer key, verifies, signs
and hands back the signed transaction, and after the deposit executed it
signs the server's `Payment-Signature` message (S11). It is the only
holder of the payer key; the agent never holds it (in the requester's
client the agent process no longer has the wallet key). Core 16.1 (I1 to
I7) applies; the rules below are the profile's checks (core 16.2 item 4).

### 5.1 Rules S1 to S11 (form T)

| Rule | Requirement | Refusal |
|---|---|---|
| S1 Pins | Configured out of band, never taken from a request: `gate_id -> gate_pubkey`; the set of agent public keys it serves; this action type; the chain ids it serves (rows of its build's table); per chain: the payer address (the signing key's address, checked at startup; one payer key per served chain SHOULD hold, so a key never signs for two chains), the allowed facilitators, `MaxRefundDelay` (seconds), `MaxFeePerGas`, `MaxGas` and `MaxFeePerAction`; operator caps (S7); `skew_s`; `RefuseFast`; the Eden RPC sources for S3c, S3e, the pending nonce (S3) and Await, each with a class and an `operator` label (5.5), `AwaitLevel` (default and minimum for S11: `L1`) and `MinSources` (default 2, at least 2); `PaymentSignatureField` (`paymentId`, the default, or `off`; any other value, `nonce` included, refuses to start); `CheckServerSignature` (default true). S11 is **enabled** when `PaymentSignatureField = paymentId` and `CheckServerSignature = true`; then every Await source MUST carry an explicitly configured `operator` label (a source without one refuses to start). The API credentials: each pinned to exactly one served agent public key; one credential per agent SHOULD be configured, and while S11 is enabled it MUST be (a credential shared by several agents, or not pinned to an agent key, refuses to start). `ServerTimeout` and `RelayGrace` and the broadcaster mode (5.4). The escrow address comes from the compiled table, never from configuration. The payer key is dedicated to this profile: it signs nothing but S8 and S11 messages, holds only native TIA, has no token balances or approvals, and its address is used with no other service that authenticates by EIP-191 signatures. | refuses to start |
| S2 Two signatures | The request carries the signed envelope, the Authorization, the action bytes and the salt. The envelope passes core stages D, S and G with an agent key from the pinned set; its `action.type` is this type and stage A matches the bytes and salt; its `commitment_hash` equals the Authorization's; `VerifyAuthorization` (core 15.3) passes with the pinned gate key and id, this type, the exact action bytes, the salt, the signer's clock and `skew_s`. A gate signature alone never suffices. | `ErrNotAuthorized` |
| S3 Decode and pins | Strict decode (2.4) with the build's table; `chain_id` is a served chain; `w2` (facilitator) is in the chain's allowlist; `refundAfter - expiresAt <= MaxRefundDelay`; `max_fee_per_gas <= MaxFeePerGas`; `gas_limit <= MaxGas`; `max_fee_per_gas * gas_limit <= MaxFeePerAction`. S3c: `keccak256(eth_getCode(escrow, "latest"))` equals the table's code hash, read through the signer's own Eden RPC, at startup for every served chain and before every signature (MUST); an RPC error refuses (fail closed). S3e: the payer address has no code (no EIP-7702 delegation): checked at startup, and SHOULD be checked before every signature through the signer's own Eden RPC. S3n: before a new reservation (S6; not for the repeat of a stored one), the transaction's `nonce` MUST equal the payer's pending nonce, `eth_getTransactionCount(payer, "pending")` read through the signer's own Eden RPC; a different nonce and an RPC error both refuse with `ErrPinMismatch` (fail closed). The signer SHOULD also refuse a `nonce` it signed for another `commitment_hash` whose Await state is not yet final. | `ErrMalformed`, `ErrUnknownDomain`, `ErrPinMismatch`, `ErrEscrowCode` |
| S4 `R` checks | For the deposit (S2 to S9): `R` SHOULD be presented and, when presented, MUST pass before the deposit is signed; while S11 is enabled (S1), `R` MUST be presented and pass, S4f included, so that the signer never pays a deposit whose Payment-Signature it would refuse. For S11: MUST pass with S4f enforced (S11d). In order, the first failure decides: **S4a** `1 <= len(R) <= 16384`. **S4b** `H(tag \|\| R)` (2.5) equals the action's `requirements_hash`. **S4c** `R` is one JSON document under BJ1's document rules (JT3, no repeated member names at any depth, nesting at most 16 deep, no `NaN`, every string taken after unescaping under the core JT4 text rules; S4d to S4f compare unescaped strings); an object; `x402Version` is the JSON number `2`; `accepts` is an array. **S4d** Exactly one element of `accepts` is an object with `scheme = "escrow-upto"` and an `extra` object whose `paymentId` (`"0x"` and 64 hex digits) equals `w0`; other elements are ignored. **S4e** In that entry: `network = "eip155:" + chain_id`; `asset = "native"`; `amount` (BJ3 decimal string) `= value`; `payTo` (BJ4 address) `= w1`; `extra.escrowContract = to`; `extra.facilitator = w2`; `extra.expiresAt = w3` and `extra.refundAfter = w4` (JT4 uint numbers); `extra.tiaPriceUsd` (decimal string) `= w5` as an integer; `extra.chainId = chain_id` (JT4 uint); `extra.nonce`, if present, is `"0x"` and 64 hex digits. Other members are ignored. **S4f** (when `CheckServerSignature`, which S11 requires) `extra.serverSignature` is `"0x"` and 130 hex digits, `r \|\| s \|\| v` with `v` in {0, 1, 27, 28} and `r`, `s` in `1..n-1`, and the address recovered from `personal_sign(w0)` (5.6) equals `w2`. | `ErrRequirements` |
| S5 Time | `expiresAt <= expires` of the Authorization; `now + skew_s < expires` (core I6). SHOULD refuse `expiresAt <= now + skew_s` (the deposit would revert). | `ErrExpired` |
| S6 One digest per decision | Before signing, the signer durably reserves `commitment_hash -> keccak256(tx)`, in the same durable write as the S7 counters. A repeat of the same request returns the stored signed bytes and counts nothing; any request for that `commitment_hash` with another digest is refused. Signatures are deterministic (RFC 6979, low `s`), so a re-sign after a crash gives the same bytes. | `ErrDigestConflict` |
| S7 Operator caps | `value <= MaxValuePerAction`; in any rolling 3600 s window, the sum of `value` `<= MaxValuePerHour` and the sum of the fee bound `max_fee_per_gas * gas_limit` `<= MaxFeePerHour`. Counted when reserved (S6, same durable write, before signing), not when landed; a reserved action stays counted even if never sent. A risk limit of the operator, beside the principal's mandate. | `ErrRiskLimit` |
| S8 What is signed | Exactly `keccak256(tx)` of the bytes S3 decoded, with the payer key. The output is built by the splice rule of 5.2; nothing is re-encoded from a struct. The only other transaction the payer key ever signs is the nonce release of 5.3. The only other message it signs is the S11 `personal_sign` digest; that digest is `keccak256(0x19 \|\| ...)`. `0x19` lies in the EIP-2718 type range (`0x00` to `0x7f`) but is not `0x02`, the only type this key signs, and is not an RLP list prefix (`0xc0` and above, a legacy transaction), so neither preimage can stand for the other. | |
| S9 Mode | Accepts `mode = 2` (fast) by default: the principal consented through the mandate's `fast_mode_max_delay` (invariant 9). `RefuseFast = true` refuses it. Logs `mode` and `anchor_deadline`. | `ErrFastModeRefused` |
| S10 Record | Optional record request (core 14.3), signed with the executor key, only when `Await` (5.5) reached state `executed` or `reverted` at `AwaitLevel`. `rail_ref` has the form of section 6. Never recorded in any other state. | |
| S11 Payment-Signature | On a request naming a `commitment_hash` and a field, in this order (the first failure decides): **S11a** Enabled: S11 is enabled (S1) and the named field is `paymentId`; otherwise `ErrPinMismatch`. **S11b** Requester: the request carries the decision's S2 material (signed envelope, SignedAuthorization, action bytes, salt), and it passes S2, except that the clock checks (core 15.3 X4, S5's `now + skew_s < expires`) use the time stored with the S6 reservation instead of `now`; the envelope's `commitment_hash` is the one named; a stored S6 reservation exists for it (the signer itself signed its deposit); `keccak256(tx)` of these action bytes equals the reserved digest; and the request's API credential is pinned (S1) to the envelope's `agent_pubkey`. Otherwise `ErrNotAuthorized`. **S11c** Resource: the action's `resource` (key 3) starts with the 8 bytes `https://`; otherwise `ErrRequirements`. **S11d** Requirements: S4 a to f pass, S4f enforced, on `R`: the bytes stored with the reservation when the deposit was signed, or the bytes presented in this request (S4b binds either to the committed `requirements_hash`, so only one `R` can pass); no `R` or a failure is `ErrRequirements`. **S11e** Executed: Await (5.5) reached state `executed` at level `L1` or higher (at least two operators, EE8 included) for the reservation's `rail_ref`, and every Await source has an explicit operator label; otherwise `ErrNotExecuted`. **S11f** Message: `m = w0` of the reserved `tx`; S4d made it the selected entry's `paymentId`, and S4f the 32 bytes the pinned facilitator signed. **S11g** Signature: the payer key's `personal_sign` of `m` (5.6), deterministic, stored per `commitment_hash`; a repeat request runs S11a to S11d again and returns the stored signature. Nothing else is ever signed through this path: not the request's bytes, not a hash or nonce the agent names. | `ErrPinMismatch`, `ErrNotAuthorized`, `ErrRequirements`, `ErrNotExecuted` |

Refusal names are the `signer` package's sentinels (to be defined with the
signer skeleton); the vectors do not cover them, since they depend on
configuration and state.

Threat notes:
- S2 is core D10: a compromised gate cannot pay alone, because the signer
  also needs the agent's envelope; a compromised agent cannot pay without
  the gate. Neither ever holds the payer key.
- S3c: a transaction with value to an address without code succeeds as a
  plain transfer. Before the testnet copy is deployed (section 3), a
  deposit to the CREATE2 address would move the money to an address no one
  controls and record no escrow; the code check refuses it.
- S3e: the escrow refunds the remainder to the buyer with a 30,000 gas
  stipend and, if that fails, pays it to the facilitator (RF6). An EOA
  without code always accepts it; an EIP-7702 delegated account may not.
- S5: the escrow refuses a deposit once `block.timestamp >= expiresAt`
  (RF5), so `expiresAt <= expires` bounds the deposit's effect by the
  Authorization in chain time. The transaction itself may still land later
  and revert; that costs gas and consumes the nonce, nothing else.
- S7 and the mandate count the cap, not the settled amount. The fee
  budget bounds what a compromised agent can burn in gas within its
  mandate (many tiny deposits, or reverting ones): at most
  `MaxFeePerAction` per transaction and `MaxFeePerHour` per hour.
- S6 and S7 share one durable write, as the gate keeps the policy counter in
  the nonce transaction: a crash can never leave a stored signature that
  the caps did not count.
- S3c: code at an address cannot change after creation (EIP-6780), but a
  soft block holding the copy's deployment can be rolled back by the
  sequencer; the check before every signature catches that.
- S4 moves the client's own quote-versus-transaction check to the key
  holder, so a compromised agent cannot get a deposit signed whose
  calldata contradicts the quote it committed. The gate still reads no
  semantics (invariant 3). S4f shows only that the pinned facilitator
  issued `paymentId`; `serverSignature` covers nothing else (amount,
  `payTo`, times and price are unsigned by the server, RF26), so S4e's
  equalities are checks of consistency, not of the server's authority.
- S11 makes the payer key an EIP-191 signer for 32-byte messages, so who
  chooses those bytes is the question. Bounds: one message per authorized,
  signed and executed deposit; `m` is always `w0` of the committed
  transaction, and S11d with S4f enforced requires that the pinned,
  allowlisted facilitator signed exactly those 32 bytes in the committed
  `R`. A compromised agent can commit any `w0` in its own form T bytes
  (the decoder and the escrow accept any unused 32 bytes), but without the
  facilitator's signature over them S11 refuses. So the signed bytes are
  chosen by the facilitator, never by the agent. Residual: a compromised or
  colluding allowlisted facilitator can choose them; `personal_sign`
  cannot authorize a transaction or an EIP-712 permit, and the dedicated
  payer key (S1) has no other use, so what remains is a signature that no
  other system should accept (some contracts, for example a Safe, do
  accept `eth_sign`-style owner signatures: hence the dedicated key).
- Why not field `nonce`: `extra.nonce` is not covered by `serverSignature`
  (RF26). A compromised agent could commit an `R` whose `nonce` is any 32
  bytes (a Safe transaction hash, say), pay one real deposit within its
  mandate and obtain the payer key's signature of those bytes. No check
  the signer can run closes that, so this revision does not offer the
  field; a server that verifies `nonce` needs a later revision in which a
  server signature covers it (section 12).
- Why S11b: the `commitment_hash` is public. Without S11b, any client of
  the signer API (a compromised agent included) could fetch another
  agent's Payment-Signature and spend the payment the victim made. Two
  parts, because neither suffices alone:
  - The S2 material ties the request to an authorized decision that the
    signer itself paid, re-verified rather than read from storage. It is
    not a secret: the envelope is public, the Authorization is archived
    (kind 4), and without auditors in the mandate the decision record (kind 17,
    form 1) holds the action bytes and the salt in clear, as does a
    reveal (kind 18). So it does not identify the requester.
  - The per-agent credential does: while S11 is enabled each credential is
    pinned to one agent key (S1), and S11b requires the envelope's agent
    key. Agent B, holding only its own credential, is refused for agent
    A's `commitment_hash`.
  Residual: the credential is a bearer secret of the agent's process; a
  thief of it acts as that agent, here and at every other signer
  endpoint. An agent signature over the S11 request would remove the
  bearer secret, but the core states that an agent key signs only
  commitments and publish requests (core 17.1), so it needs a core change
  (section 12).
- S11 after execution only: a Payment-Signature before the deposit
  landed would let the server (or anyone holding the header) claim
  payment for a deposit that may never execute. L1 with explicit operator
  labels is the floor, so that a single RPC operator, or two hosts that
  the configurer did not name as distinct operators, cannot trigger it.
- Soft confirmation: S11e rests on Eden's soft blocks (`ConfirmDepth`
  blocks past the head of each source). The single sequencer can still
  roll a soft block back before it reaches Celestia (7.6); a deposit
  dropped that way leaves a Payment-Signature that was issued for money
  that never moved. Accepted for fast settlement; the server's own check
  of the escrow (`buyer`, RF27) at redemption time is what catches it.
- With field `paymentId`, the Payment-Signature message is the same
  32-byte message as the facilitator's `serverSignature` (vector
  `payment_id_digest_equals_server_signature_digest`). The server must
  therefore check that the recovered signer is the escrow's `buyer`;
  otherwise the quote's own `serverSignature` would be a valid payment
  proof for anyone who saw the quote. Edicta cannot enforce this; it is a
  freeze condition (section 0, RF27).
- Replay and transport: a Payment-Signature is a bearer proof for one
  deposit. Anyone who sees it (the server, or an on-path observer if the
  resource is called over plain HTTP) can present it again; single use is
  the server's rule (freeze condition, section 0). The key holder never
  sees where the client sends the header, so the part it can enforce is
  S11c: the committed `resource` names `https://`. A client that commits
  `https://` and then calls `http://` defeats it; that is outside what the
  signer can see.

### 5.2 Signed transaction (splice rule)

Let `P` be the payload of the list in `tx[1..]` (the 9 item encodings,
verbatim). With the signature `(y_parity, r, s)` over `keccak256(tx)`:

```
signed = 0x02 || rlp_list_header(len(P) + len(Y) + len(Rr) + len(Ss)) || P || Y || Rr || Ss
Y  = rlp_uint(y_parity)      ; 0x80 for 0, 0x01 for 1
Rr = rlp_uint(r), Ss = rlp_uint(s)   ; minimal big-endian, 1 <= r < n, 1 <= s <= n/2
```

`rlp_uint` is the canonical RLP integer (ET3). The result equals
go-ethereum's `SignTx(...).MarshalBinary()` for every vector case. Output to
the caller: `signed` and `rail_ref` (section 6).

### 5.3 Sequence, `Await`, crashes

```
0 producer: R from PAYMENT-REQUIRED; /deposit/build -> tx (2.2a); S4 SHOULD; commit (da = 2, fast)
  (resource = the https:// URL it calls)
1 gate: Authorization (core invariant 5: nonce marked durably before it leaves)
2 signer: S1..S9 (S4 when R is presented, always while S11 is enabled); S6 reserve (MAY keep R); sign; store signed bytes; rail_ref known now
3 broadcaster (5.4): I5 in-flight record (commitment_hash -> rail_ref),
  then the Houston relay or eth_sendRawTransaction(signed)
4 Await(rail_ref, until = expiresAt + AwaitGrace): EE2..EE8 per source, combined by 5.5 at AwaitLevel
5a executed or reverted at AwaitLevel -> record request (S10)
5b executed at L1 -> S11 Payment-Signature on the agent's request -> the client retries the paid call
5c not_executed (5.5) after until -> no record request; never sign other bytes
5d disputed or unknown -> no record, no S11, no release; retried later, then the operator
```

Defaults: `ConfirmDepth` 20 blocks (about 2 s at Eden's 100 ms blocks),
`AwaitGrace` 300 s. `until` is a chain time; the local clock only decides
when to stop polling.

Core I5 amendment (resends): this profile allows re-sending the stored
`signed` bytes, byte-identical, until `until`. The account nonce makes the
chain include them at most once; the escrow's `expiresAt` check bounds the
deposit's effect (not the inclusion) in chain time. After `until` the
record goes to the operator; the signer never builds a second transaction
for the same `commitment_hash`.

Nonce release: after `until`, the operator MAY release the nonce of a
stuck transaction. The release is a type-2 transaction from the payer to
the payer, value 0, empty data and access list, with the same `nonce`. It
is the only transaction the payer key signs without an Authorization. It
is operator-only (never reachable through `POST /v1/sign` or any request
that an agent or a gate can send), it needs the `commitment_hash` of the
record it releases, whose state must be `not_executed` past `until`, and
it is logged with that `commitment_hash`. It moves no money (only the gas),
so it widens nothing the mandate bounds; if the original lands first, the
release fails on the nonce. Since draft.5 `not_executed` is the
multi-source state of 5.5: a single source that shows the deposit blocks
the release, including (since draft.6) a source set aside after it served
the transaction.

| Case | Behaviour |
|---|---|
| Crash between reserve and signature | S6: the repeat gives the same signature or a refusal, never other bytes. |
| Crash after signing, before broadcast | Re-send the stored bytes; same `rail_ref`. |
| Crash after broadcast, before the record | I5: look up `rail_ref` (never re-sign), then 5a or 5b. |
| Stuck in the sequencer's private pool, or censored (RF16) | 5b after `until`; if it lands later the deposit reverts (`expiresAt` passed). |
| Reverted deposit | Recorded honestly with its `rail_ref`; the decision is consumed. |
| Eden RPC down | Await polls until `until`; if too few operators answered, the state stays `unknown` (not 5c) and the lookup is retried later. |
| Relay accepted the bytes but never broadcast them | Await sees nothing; once `RelayGrace` has passed since the relay's answer with no source showing `rail_ref`, the broadcaster sends the same bytes directly (5.4 B3); 5c after `until` if still not found. |
| Two decisions with identical action bytes | Same digest, same signed bytes (RFC 6979), same hash: the payment lands once, both decisions are counted by the mandate (over-count, safe), both may record the same `rail_ref`. |

Idempotency key (core 16.3): the rail has no idempotency field for a plain
transfer; at-most-once comes from the nonce and S6.

### 5.4 Broadcaster

The broadcaster (the signer, `edicta commit` or the TS wrapper) sends the
stored `signed` bytes and nothing else. It is pluggable:

| Mode | Send | Default for |
|---|---|---|
| `houston-relay` | `POST {base}/deposit/send` with JSON `{"signedTx": "0x" + lower-case hex of signed, "paymentId": "0x" + lower-case hex of w0}` | the requester's server (the requester advises it; whether the server needs it is `UNVERIFIED`, RF28) |
| `direct` | `eth_sendRawTransaction(signed)` to one or more configured Eden RPCs | every other case, and the fallback |

Rules:
- B1 Bytes: only the stored `signed` bytes, byte-identical on every send
  and through every path (5.3 resends). Sending through both modes is
  allowed: one nonce, one hash.
- B2 `paymentId` in the relay body is `w0` of the signed transaction,
  taken from the decoded action, never from the agent's request or the
  server's earlier answers.
- B3 The relay's answer is never evidence. Success moves no state; a
  transaction hash in the answer (observed keys `txHash`, `hash`,
  `transactionHash`, possibly under `result`, `tx`, `transaction`) is only
  compared with `rail_ref`: a different hash is logged as a relay fault and
  the broadcaster sends directly. An error (observed: `failed to broadcast
  transaction`), a timeout (`ServerTimeout`, 2.2a) or an answer longer
  than 16384 bytes (read no further) leads to a direct send of the same
  bytes. After a success, if no Await source shows `rail_ref` within
  `RelayGrace` (default 30 s, at most `AwaitGrace`), the broadcaster also
  sends directly: a relay that answers success and withholds the bytes
  costs at most `RelayGrace`.
- B4 `GET {base}/deposit/status/:txHash` is never evidence and never an
  Await source: observed, it answers `confirmed` for any hash already on
  Eden, whatever transaction it is (RF25). It MUST NOT change any state of
  the signer or the verifier; a client MAY show it to a human, labelled as
  the server's view.
- B5 Inclusion is decided only by Await (5.5) through Eden JSON-RPC
  sources, whatever the mode.

Threat note: the relay sees the signed bytes before inclusion. It can
delay, withhold or front-run them only as any public mempool observer
could: it cannot change them (the signature covers every field) and cannot
make a different transaction count (EE3, S6). Withholding costs at most
`RelayGrace`, after which the direct fallback sends the same bytes.

### 5.5 Await states and the multi-source rule

Await combines per-source results (EE2 to EE8 on each Eden JSON-RPC source)
into one state. A source's result is `pass` (with outcome and binding:
`blockHash`, `transactionIndex`, receipt consensus encoding), `not_found`,
`unconfirmed` (EE6 below `ConfirmDepth`), `unavailable`, or `set_aside`
(any other EE failure, with its reason). A source is **seen** when it
served a transaction for `rail_ref`: every `pass` and `unconfirmed`, and
every `set_aside` whose reason comes after the lookup (EE2
`settlement_hash_mismatch` and `settlement_tx_type`, EE7
`settlement_disagree`, EE8 `settlement_log_mismatch`, and
`settlement_source_unavailable` when a call failed after the transaction
was served). EE5's `settlement_chain_config` and `settlement_code_mismatch`
come before the lookup and are not seen; neither is a failure of the
lookup itself (`unavailable`). Sources count by **operator**: each
configured source carries an `operator` label, explicit (configured) or
defaulted (its OH3 host), and two sources with one label count once. The
label is the configurer's statement; Edicta cannot check independence
(RF30: whether Blockscout's `api/eth-rpc` reads its own node or
`rpc.eden.gateway.fm` is unknown), and a defaulted label cannot detect two
hosts in front of one node. S11 therefore needs explicit labels on every
source (S1, S11e).

| Order | Condition | Await state | Report (7.5, `MinLevel` = `AwaitLevel`) |
|---|---|---|---|
| Q1 | Two passing sources differ in binding (block, index, status or logs) | `disputed` | `unchecked`, `settlement_disagree` |
| Q2 | Passing operators `k >= MinSources` | outcome (`executed` or `reverted`) at `L1` | `pass`, `L1` |
| Q3 | `1 <= k < MinSources` and `AwaitLevel = L0` (explicit configuration) | outcome at `L0` | `pass`, `L0` |
| Q4 | Before `until`, otherwise | `pending` (keep polling) | `unchecked`, reason as 7.5 |
| Q5 | After `until`: no source seen (so `k = 0` and none `unconfirmed`), and at least `MinSources` distinct operators answered `not_found` | `not_executed` | `unchecked`, reason as 7.5 |
| Q6 | After `until`, otherwise | `unknown` (retried later) | `unchecked`, reason as 7.5 |

| State | S10 record | S11 Payment-Signature | Nonce release (5.3) |
|---|---|---|---|
| `executed` at L1 | yes | yes, if every source's label is explicit | no |
| `executed` at L0 | yes | no (L1 is the floor) | no |
| `reverted` | yes | no | no |
| `pending`, `disputed`, `unknown` | no | no | no |
| `not_executed` | no | no | yes (operator only) |

Properties:
- Disagreement alone is never `violated`, never `not_executed` and never
  a release: it is `disputed`, and a later poll may resolve it (a lagging
  source catches up, a rolled-back block disappears everywhere). Only EE3
  gives `violated` (7.5), and it rests on the signed `rail_ref`, not on a
  source.
- One source showing the deposit blocks `not_executed`, whatever the
  others say, even when that source was set aside after it served the
  transaction (vector `aside_found_two_not_found_until`); one source alone
  never reaches `executed` at L1.
- Set-aside sources never count as passing operators or as `not_found`
  answers; a seen one blocks `not_executed`.
- Defaults for this profile: `AwaitLevel = L1`, `MinSources = 2`
  (configuration validation refuses a `MinSources` below 2). Recommended
  sources: the operator's own Eden full node (class `own-node`) and
  `https://rpc.eden.gateway.fm`; a third operator when available.

Vectors: `multi_source.json` (26 cases: per-source results with the
operator label's origin, `MinSources`, `min_level`, phase, the report, the
Await state and what it allows).

Threat note (Q5): a source that served the transaction and then failed a
later check (a lying log, a bad hash, a missing receipt) is evidence that
the transaction may exist. Counting it as nothing would let two silent
operators produce `not_executed` and a nonce release while a third showed
inclusion; the release then only fails on the nonce (gas lost), but the
operator and the auditor would read "not executed" for a deposit that may
have landed.

### 5.6 `personal_sign` (S4f and S11)

For a 32-byte message `m` (EIP-191 version `0x45`, as Ethereum wallets'
`personal_sign` and ethers' `signMessage(bytes)`):

```
digest = keccak256(0x19 || "Ethereum Signed Message:\n32" || m)    ; 28 + 32 bytes hashed
signature = r || s || v                                             ; 65 bytes
```

- S11 output: secp256k1 over `digest` with the payer key, RFC 6979 nonce,
  low `s`, `v = 27 + y_parity`, sent as `"0x"` and 130 lower-case hex
  digits. Whether the server also accepts `v` in {0, 1} is `UNVERIFIED`
  (the client library emits 27 or 28).
- S4f input: `v` in {0, 1, 27, 28} (the server's own signature uses `v = 0`,
  RF26), `r` and `s` in `1..n-1`; high `s` is accepted, since only the
  signer's identity matters, not the signature's uniqueness.
- The client builds the header itself: `PAYMENT-SIGNATURE` = base64 of JSON
  `{x402Version: 2, resource, accepted: <quote entry>, payload: {signature,
  paymentId, nonce}}` (the requester's client shape; `payload` carries both
  values whichever field was signed). The signer returns only the
  signature. Which field the server verifies is `UNVERIFIED` (RF27): the
  client signs `nonce` by default, `paymentId` by option. This profile
  offers only `paymentId`: it is `w0` of the authorized transaction and
  the facilitator signed it (S4f); `nonce` is covered by nothing the
  signer can check (S11 threat notes). If the server verifies only
  `nonce`, S11 cannot serve it until a later revision.

Vectors: `x402.json` `payment_signature` (field `paymentId`: message,
preimage, digest, the `payer1` signature; `refused_fields`; `requests`,
the stateless S11 steps a, c and d) and `requirements` `server_signature`.

## 6. `rail_ref` and receipts

`rail_ref` (receipt key 6) is exactly 64 lower-case hex characters
`[0-9a-f]`, without `0x`, of `keccak256(signed)`: the Eden transaction
hash. Any other form does not conform to this profile, and the
settlement report gives `unchecked` for it (EE1); signers MUST NOT
record another form. Only the receipt carries
it; no signed object of the decision does (invariant 6).

- The core receipt decoder enforces only the ID charset and length (core
  14.1); the shape is this profile's rule, checked by the settlement report,
  not by the receipt decoder.
- Kind 19 (`execution_result`) cannot carry Eden evidence: its `rail_ref` is
  SHA-256 of the transaction bytes and its body is CometBFT-specific. The
  settlement report never reads `exec/` records and ignores archived
  execution results, so a record placed under `exec/<anything>/<rail_ref>`
  cannot influence it.
- Nothing about the Eden transaction is archived (no archive kind for EVM
  evidence exists in v1.2). The check is online only; after an RPC prunes
  the block, a later check is `unchecked` (`settlement_not_found`). The
  decision's own archive rules (core 10.7) are unchanged.

## 7. Settlement report (verifier, verdict-neutral)

### 7.1 Placement

The core `execution` check (core 20.2) cannot give `pass` for Eden: EO3
needs a header that passed header trust and an inclusion proof against it,
and EX4 compares the rail height with `payload_ref.height`, a Celestia
height. So this profile registers **no** checker for core `execution`:
`edicta verify --execution` on this type gives `unchecked` with the core
reason `no_checker`.

Instead the verifier, on request (`--settlement`), adds a report field
`rail_settlement` defined here. It is not one of the checks of core 20.1. It
never changes the verdict or the exit code: like `gate_integrity`, it
reports, and a proven violation reads `violated` while the decision verdict
stays what the core checks give. Tooling that wants to fail on it reads
the field.

`UNVERIFIED` for the human (core wording): core 20.10 lists the report
fields without a hook for profile-defined fields. This profile treats
`rail_settlement` as an additional field that no core rule reads. A core
clarification may want to say so.

### 7.2 Inputs

| Input | Bound by |
|---|---|
| Action bytes, decoded by 2.4 (`A`, its `tx` and items) | stage A of the decision (salted `action_hash`) |
| `rail_ref` from a receipt that passed core 14.2 | the gate's and the executor's signatures (a claim, not a fact) |
| `expires` (Authorization), `T_ref` | signed objects of the decision |
| Escrow address and code hash for `chain_id` | the build's table (section 3) |
| Sources: Eden JSON-RPC endpoints, each of class `public-rpc` or `own-node`, with an `operator` label, explicit or defaulted to the OH3 host | configuration; each is distinct by core OH3 (normalized host); L1 counts distinct operators (5.5); the report shows each label's origin |
| `data_da_height` of the Eden block (optional) | the operator's own ev-node; report only |

Configuration: `MinLevel` (default `L1` since draft.5; `L0` only by
explicit configuration), `MinSources` (default 2, at least 2, used by L1),
`ConfirmDepth` (default 20). The payment server's `/deposit/status` is not
an Eden JSON-RPC endpoint and MUST NOT be configured as a source (5.4 B4).

If the action bytes fail 2.4 under the verifier's build (for example a dev
row in a production verifier, or bytes a gate without a mandate authorized
unparsed), no rule runs and the report is `unchecked` with
`settlement_action_refused`: without the decoded action nothing can be
compared, and the bytes alone prove no executor fault.

### 7.3 Rules EE1 to EE9

EE1, EE3 and EE4 are pure. The others read sources. A source "set aside"
is dropped with its reason, and the next one is tried. Order: the action
decode of 7.2, then EE1, then per source EE5, EE2, EE6, EE7, EE8; EE3 and EE4 run once, on
the first bytes that pass EE2; EE9 runs on the result.

| Rule | Check | On failure |
|---|---|---|
| EE1 `rail_ref` form | Section 6: matches `[0-9a-f]{64}`; decodes to 32 bytes `R`. | `unchecked`, `malformed_rail_ref`; nothing else runs. A `0x` prefix or upper-case hex may name the right transaction, so a form defect is a nonconformant claim, not a proven fault (core 14.1: a verifier never rejects a receipt for the shape of `rail_ref`). |
| EE2 Bytes | The source serves the transaction for hash `R` (`eth_getTransactionByHash`). Eden's RPC has no raw-transaction method (RF10), so the verifier rebuilds the EIP-2718 bytes `S` from the served fields for the served type (go-ethereum `Transaction.MarshalBinary`; types 0 to 4) and requires `keccak256(S) = R`. From here on `S` is fixed, whatever the source. | Not found: `settlement_not_found`; error or timeout: `settlement_source_unavailable`; `keccak256(S) != R`: `settlement_hash_mismatch`; a type the verifier cannot rebuild: `settlement_tx_type`. The source is set aside. |
| EE3 Exact action | `S[0] = 0x02`; `S[1..]` is one canonical RLP list (ET2's canonical form) of exactly 12 string items, nothing after it; items 0 to 8 are byte-identical, as encodings, to the 9 items of the action's `tx` (equivalently, the list payload of `S` starts with `P`); item 9 (`y_parity`) is `0x80` or `0x01`; items 10 and 11 (`r`, `s`) are canonical integers with `1 <= r < n`, `1 <= s <= n/2`; a public key recovers (EE4). Items are compared as encoded; nothing is re-encoded from a struct. | `violated`, `wrong_tx`. Rests only on `R` (signed claim) and `S` (its keccak preimage): the executor claimed a transaction that is not the authorized one, whether or not it landed. |
| EE4 Payer | `payer` = the address recovered from `(y_parity, r, s)` over `keccak256(tx)`. | Report only. The signer pins the payer (S1); the verifier does not know the pin. |
| EE5 Source domain | The source's `eth_chainId` equals the action's `chain_id`, and that chain is a row of the verifier's build; then `keccak256(eth_getCode(escrow, "latest"))` equals the row's code hash. | `settlement_chain_config` or `settlement_code_mismatch`; the source is set aside. |
| EE6 Inclusion | The source names `blockHash`, `blockNumber` and `transactionIndex` for `R`; its head minus `blockNumber` is at least `ConfirmDepth`. Eden's `safe` and `finalized` equal the head (RF15) and carry no weight. | Below the depth: `settlement_unconfirmed` (retry later); the source is set aside. |
| EE7 Status | The receipt for `R` (`eth_getTransactionReceipt`) names the same block hash and index as EE6. `status = 1` gives outcome `executed`; `status = 0` gives outcome `reverted` (a finding at the level, not a source fault) and requires an empty log list. | Receipt missing or naming another block or index: `settlement_disagree`; set aside. |
| EE8 Deposit event | With `status = 1`: the receipt has exactly one log (RF8); its `address` is the row's escrow; `removed` is false; its `transactionHash`, `blockHash`, `transactionIndex` equal `R` and EE6's; it has exactly 4 topics: `topic0` = `keccak256("NativeEscrowDeposited(bytes32,address,address,address,uint256,uint256,uint256,uint256)")` = `4e8468b036003985396bfb5e6fc36f0e8395146648e829557ea1fd48d2b9a6ff` (RF7), `topics[1] = w0`, `topics[2]` = 12 zero bytes `\|\|` payer (EE4), `topics[3] = w1`; `data` is exactly `w2 \|\| uint256(value) \|\| w3 \|\| w4 \|\| w5` (160 bytes). With `status = 0`, a non-empty log list is this failure too. | `settlement_log_mismatch`; set aside. The executed bytes and status 1 determine the log, so a mismatch shows a lying source or other code at the address. |
| EE9 Times | `after_expires` when the block's `timestamp > expires`; `before_reference` when it is `< T_ref`. Chain time against signed times only, never a local clock; the sequencer sets the block time. | Warning only. |

`n` is the secp256k1 group order. EE5 reads the code at `latest`: since
EIP-6780 (Cancun; Eden runs Prague and Osaka from genesis, RF1) code at an
address changes only through a self-destruct in its creating transaction, and the
escrow has no proxy (RF3), so the code at `latest` is the code that ran.
`latest` also works on pruned nodes, which do not keep old state.

### 7.4 Levels

Each level includes the ones below. Two passing sources that disagree on
`blockHash`, `transactionIndex` or the receipt bytes make the result
`unchecked`, `settlement_disagree`, at any level, and never `violated`.
L1 is the node-attested check of H-E4 (5): at least two independent
operators agree. The combination of per-source results is the table of
5.5 (rows Q1 to Q3 give the report's level), the same for the verifier
and for the signer's Await.

| Level | Name | Adds | Trust left |
|---|---|---|---|
| L0 | `node-attested` | EE2 to EE8 pass on one source. | That source. Class `own-node`: the operator's own node that checks the sequencer's signatures and re-executes, plus the sequencer's ordering. Class `public-rpc`: the RPC operator's word. |
| L1 | `multi-source` | At least `MinSources` sources of distinct operators (and distinct by OH3) pass L0 and agree on `blockHash`, `transactionIndex` and the receipt's consensus encoding (`type \|\| rlp([status, cumulativeGasUsed, logsBloom, logs])`, rebuilt from each served receipt). | Collusion of those operators, and that the configured operator labels name distinct operators: a label is the configurer's own claim, and a defaulted label (the host) does not detect two hosts in front of one node. |
| L2 | `receipt-proven` | From any source: the header fields hash to `blockHash` (`keccak256(rlp(header))`, RF11); all transactions of the block, `S` at `transactionIndex`, rebuild `transactionsRoot` (go-ethereum `DeriveSha`, RF12); all receipts (`eth_getBlockReceipts`, or one per transaction) rebuild `receiptsRoot` (RF13), and the one at `transactionIndex` equals the agreed receipt. The header itself is attested at L1. | The header is attested by the L1 operators; the block's contents are exact for that header. |

A failure of the L2 proofs gives `settlement_block_proof` when `L2` was
required, and the result stays at L1 otherwise. A verifier that does not
know every field of a served header (a fork after Osaka) MUST NOT claim L2.

### 7.5 Outcome and report

Outcome rule (as core EO4): a violation wins (`violated`, EE3 only);
otherwise if the required level is not reached, `unchecked`; otherwise
`pass` at the highest level reached, with outcome `executed` or
`reverted`. When no source reaches the level, the reason is
`settlement_unconfirmed` if any source failed only at EE6, else
`settlement_below_level` if some passed but too few, else the first
source's reason in configuration order. No source can produce `violated`:
only EE3 gives it, and EE3 rests on the signed `rail_ref` and its keccak
preimage.

Report field `rail_settlement` (JSON names):

| Field | Content |
|---|---|
| `profile` | `eden-escrow-v1` |
| `status` | `pass`, `unchecked` or `violated` |
| `reason` | for `unchecked` and `violated` (7.7) |
| `level` | `L0`, `L1` or `L2` (for `pass`) |
| `outcome` | `executed` or `reverted` (for `pass`) |
| `rail_ref`, `chain_id`, `block_number`, `block_hash`, `transaction_index`, `block_time` | from the used source(s) |
| `payer` | EE4, lower-case `0x` hex |
| `warnings` | EE9 names |
| `da_included` | optional: `{height, source}` from the own ev-node's `data_da_height`, node-attested, report only |
| `deposit` | the profile fields of 4.1 for the decoded action (present whenever the action decodes) |
| `sources` | every source asked: name (OH3 host), class, `operator`, `operator_label` (`explicit` or `default`), result (`used`, `agree`, `set_aside`, `not_found`, `unconfirmed`, `unavailable`) and reason |

### 7.6 What the levels do not prove

- No data-availability statement about the Eden block (that needs Eden as
  a publication target, deferred). `da_included` is a node's word.
- The single sequencer can reorder, delay, censor, and roll back soft
  blocks before they reach Celestia; no fraud or validity proof exists. A
  re-check after a rollback gives `settlement_not_found` or
  `settlement_disagree`, never a violation.
- No level judges the price, the resource or the settled amount. A
  settle lookup by `paymentId` is informational only and not part of these
  rules.
- A second, different deposit for the same decision is prevented by S6 and
  the nonce, not detected here: EE checks only the claimed transaction.
- Settlement evidence is not archived in this release (no archive kind
  for EVM evidence exists, section 6). The report is online only: once the
  RPCs prune the block (RF22), a re-check is `unchecked`, and a later
  audit cannot reproduce L0 to L2. An archive kind for this evidence is a
  later revision.

### 7.7 Reasons

| Reason | Class | Rule |
|---|---|---|
| `malformed_rail_ref` | unchecked | EE1 |
| `wrong_tx` | violated | EE3 |
| `settlement_not_found` | unchecked (source set aside) | EE2 |
| `settlement_source_unavailable` | unchecked (source set aside) | EE2, any source call |
| `settlement_hash_mismatch` | unchecked (source set aside) | EE2 |
| `settlement_tx_type` | unchecked (source set aside) | EE2 |
| `settlement_chain_config` | unchecked (source set aside) | EE5 |
| `settlement_code_mismatch` | unchecked (source set aside) | EE5 |
| `settlement_unconfirmed` | unchecked (retry later) | EE6 |
| `settlement_disagree` | unchecked | EE7, L1 agreement |
| `settlement_log_mismatch` | unchecked (source set aside) | EE7 (status 0 with logs), EE8 |
| `settlement_below_level` | unchecked | 7.5 |
| `settlement_block_proof` | unchecked | L2 |
| `settlement_action_refused` | unchecked | 7.2 (action fails 2.4 in this build) |
| `after_expires`, `before_reference` | warning | EE9 |

These are profile names, not core section 20.1.1 reasons. The Go sentinels
(package `edenexec`) mirror them: `ErrWrongTx` (wraps a violation type),
`ErrMalformedRailRef`, `ErrNotFound`, `ErrSourceUnavailable`,
`ErrHashMismatch`, `ErrTxType`, `ErrChainConfig`, `ErrCodeMismatch`,
`ErrUnconfirmed`, `ErrDisagree`, `ErrLogMismatch`, `ErrBelowLevel`,
`ErrBlockProof`, `ErrActionRefused`.

## 8. Form A (HoustonAgent `ExecuteWithAuthorization`): not planned

**Not normative; history.** Q-E3 is answered (2026-10-21): the requester's
client pays with form T (the payer signs the `/deposit/build` transaction
itself). Form A is not planned for the first Eden release; the text below
records what a later revision would have to solve. The recorded mainnet flow (F14) is form A:
an EIP-7702 account delegated to `HoustonAgent` signs an EIP-712
`ExecuteWithAuthorization(Call[] calls,uint256 validAfter,uint256
validBefore,bytes32 nonce)` (domain `HoustonAgent`, version `1`,
`verifyingContract` = the account), and a relayer submits it through
`HoustonForwarder.executeBatch`
(`0xeb35f99ed9b10cb724698076b5be63de0ed14c3a`). Provisional type
`application/vnd.edicta.eden.escrow-deposit-auth.v1+cbor`, extractor
`eden/escrow-deposit-auth/v1`; neither is registered, and no build accepts
them until this section is written.

Known residuals that this section must address if form A is ever selected:
the relayer's gas reimbursement is not signed; the account owner key, every
session key and the 7702 key each move funds alone (the recorded deposit
was authorized by a session key), so the signer must hold all of them and
the agent none; the `nonce` and `paymentId` derivations (tags
`edicta/eden-escrow/v1/nonce` and `edicta/eden-escrow/v1/payment-id` are
reserved for them and used nowhere yet); EE3 for a relayed transaction;
S3e for a 7702 account. The vectors already show that the recorded form A
transaction is `wrong_tx` against a form T action with the same deposit
(`f14_relayed_deposit`), and that its receipt fails EE8's one-log rule
(`event_f14_all_logs`).

## 9. Rail facts

| # | Fact | Status | Source |
|---|---|---|---|
| RF1 | Eden mainnet `eth_chainId` 714, 100 ms blocks, Prague and Osaka active from genesis, single sequencer | verified (R0) | Eden RPC, ev-reth chainspec |
| RF2 | Eden testnet chain id 3735928814 (`0xdeadbfee`) | verified (R0, P1b) | Eden RPC |
| RF2a | No other public chain uses 714 or 3735928814 (a chain-registry check, e.g. chainlist / ethereum-lists `chains`). 31337 is every local Hardhat or Anvil chain, which is why its row is dev-only. The deployer and the CREATE2 copy can exist on any chain, so only `chain_id` separates domains; S1 keeps one payer key per chain | 714: verified 2026-10-21 (ethereum-lists `eip155-714.json`: "Eden", TIA, 18 decimals, RPC `rpc.eden.gateway.fm`). 3735928814: no registry entry; `UNVERIFIED` that no other chain uses it | ethereum-lists `chains` |
| RF3 | `NativeEscrow` at `0x65d77c98...186a94c8` on 714: verified source (solc 0.8.28), no proxy, no owner, no fee; created by a plain creation transaction from an EOA at nonce 9 | confirmed, re-confirmed (R0); creation verified 2026-10-21 (section 3) | Blockscout verified contract, Eden RPC |
| RF4 | `deposit` selector `b707d860`, `settle` `79f48d4c` | verified (recomputed; vectors) | ABI |
| RF5 | `deposit`: `buyer = msg.sender`, `amount = msg.value > 0`; `paymentId` single use; `expiresAt > block.timestamp`; `refundAfter > expiresAt`; `tiaPriceUsd > 0`, stored, never used; no zero check of `payTo` or `facilitator` | confirmed (source, R0) | verified source |
| RF6 | `settle` only by the escrow's facilitator, `actualAmount <= amount`, no time check; remainder to the buyer with a 30,000 gas stipend, else to the facilitator; `refundExpired` by anyone after `refundAfter` | confirmed (source, R0) | verified source |
| RF7 | Event `NativeEscrowDeposited(bytes32,address,address,address,uint256,uint256,uint256,uint256)`, indexed `paymentId`, `buyer`, `payTo`; data `facilitator`, `amount`, `expiresAt`, `refundAfter`, `tiaPriceUsd` | verified: the recomputed topic equals the recorded log's `topic0`, and every data word equals the recorded calldata and value (vectors `settlement.json`) | F14 receipt |
| RF8 | A form T deposit emits exactly one log and calls no other contract | verified from the verified source (`deposit` has no external call and one `emit`), and observed on the recorded receipt (one escrow log; the other four come from the 7702 account and the forwarder) | `live/escrow-code.json` source, F14 receipt |
| RF9 | Eden transactions are EIP-2718; type 2 signing hash `keccak256(0x02 \|\| rlp(9 items))` | verified (go-ethereum; the recorded transactions are type 2, as were all 59 sampled mainnet transactions) | R0, vectors |
| RF10 | The RPC serves no raw bytes; the bytes rebuilt from `eth_getTransactionByHash` hash to the transaction hash and equal the bytes in the Eden data blob on Celestia | verified on the recorded deposit and settle (vectors `rebuild`) | R0 |
| RF11 | Block hash = `keccak256(rlp(header))` over the 21 fields Eden's RPC serves (London to Prague, including `withdrawalsRoot`, `blobGasUsed`, `excessBlobGas`, `parentBeaconBlockRoot`, `requestsHash`) | verified on block 227899844 (vector `block`); other blocks and later forks `UNVERIFIED` | F14 block |
| RF12 | `transactionsRoot` = `DeriveSha` of the block's transactions | verified on block 227899844 | F14 block |
| RF13 | `receiptsRoot` rebuild; whether Eden's RPC serves `eth_getBlockReceipts` | `UNVERIFIED` (the other receipt of that block is not recorded) | |
| RF14 | Receipt consensus encoding and `logsBloom` recompute from the served receipt | verified on the recorded deposit receipt | F14 receipt |
| RF15 | RPC `safe` and `finalized` equal the head | verified (R0) | Eden RPC |
| RF16 | Transactions go to the sequencer's private pool via `eth_sendRawTransaction`; ordering is the sequencer's | confirmed (docs); not testable read-only | Eden docs |
| RF17 | Per-transaction gas cap 16,777,216 (Osaka) | `UNVERIFIED` for ev-reth | reth |
| RF18 | Deterministic deployer `0x4e59b448...` present on both networks; the escrow address has no code on testnet | verified (R0) | Eden RPC |
| RF19 | Escrow runtime code hash on 714 = `281a5ec0...894300e5` (2,809 bytes) | verified 2026-10-21 (`eth_getCode` equals the verified deployed bytecode) | Eden RPC, Blockscout |
| RF20 | The escrow has no immutables and no constructor-set storage | verified: the creation code is a 26-byte constructor without `SSTORE` followed by the runtime code verbatim | Blockscout creation bytecode, creation tx input |
| RF21 | EIP-7702 delegations exist on Eden (an EOA can carry code) | verified (the recorded account is delegated, `0xef0100 \|\| ...`) | F14 account read |
| RF22 | History depth of the public RPC (how long receipts stay available) | `UNVERIFIED` | |
| RF23 | The requester's flow is x402 v2 over HTTP with a non-public scheme `escrow-upto`: requirements in the `PAYMENT-REQUIRED` header (base64 JSON), `network eip155:714`, `asset native`, `amount` = the deposit cap in wei, `extra` {`paymentId`, `escrowContract`, `facilitator`, `refundAfter`, `expiresAt`, `nonce`, `chainId`, `tiaPriceUsd`, `serverSignature`}; no `maxTimeoutSeconds` (required by x402 v2); `resource.url` names `http://` while the client calls `https://`. That F14 itself was this scheme stays `UNVERIFIED` | verified from the client code and its saved fixtures (R2); the server code is not public | requester's client, x402 v2 spec |
| RF24 | `/deposit/build` chooses `nonce` (observed: the pending nonce of `from`), gas limit and fees; it returns JSON without `type`, `accessList` or `from` | observed on one fixture; nonce choice `UNVERIFIED` | fixture |
| RF25 | `GET /deposit/status/:txHash` answers `pending` for an unknown hash and `confirmed` for any hash already on Eden | observed by the client's author; not evidence (5.4 B4) | R2 |
| RF26 | `serverSignature` is the facilitator's `personal_sign` over the 32 bytes of `paymentId` only, `r \|\| s \|\| v` with `v = 0`, low `s` | verified on the fixture (recovers to `extra.facilitator`, the facilitator of the F14 settle) | fixture, F14 |
| RF27 | What the server checks on the paid retry: which 32 bytes the `Payment-Signature` covers (`nonce` or `paymentId`), that the recovered signer is the escrow's `buyer`, the amount, the expiry, single use; whether `v` 27/28 and 0/1 are both accepted | `UNVERIFIED`: the paid retry was never observed; the requester's funded test this week. The `buyer` check and single use are a freeze condition (section 0) | requester |
| RF28 | Whether `/deposit/send` is required, or any broadcast of the signed bytes suffices; its success body. Observed: a body without `paymentId` is refused; a bogus transaction gives `failed to broadcast transaction` | `UNVERIFIED` | requester |
| RF29 | Eden charges the sender only `gas_used * effective_gas_price` (no separate data or L1 fee), so `value + gas_limit * max_fee_per_gas` bounds the payer's loss | `UNVERIFIED` (ev-reth fee model not checked) | |
| RF30 | Independence of the candidate sources: Blockscout's `https://eden.blockscout.com/api/eth-rpc` serves `eth_chainId`, `eth_getCode`, `eth_getTransactionByHash`, `eth_getTransactionReceipt` (observed 2026-10-21); whether it reads a node other than `rpc.eden.gateway.fm` | serving observed; independence `UNVERIFIED` | R2 |
| RF31 | The quote's `amount` equals the deposit `value` (the cap), and the client's own spend check counts `amount + gasLimit * maxFeePerGas` | verified on the fixture and the client code | fixture, client |
| RF32 | `eth_getTransactionCount(payer, "pending")` on the signer's own Eden node counts the payer's transactions still in the sequencer's private pool (RF16), so S3n sees a nonce the signer already used | `UNVERIFIED`; if it does not, two signatures in flight can share a nonce until one lands (the second fails at the chain, gas only), and S3n's SHOULD (the signer's own in-flight nonces) is what prevents it | ev-reth, Eden team |

## 10. Sentinels

| Sentinel | Rules | Vectors |
|---|---|---|
| `edenescrow.ErrMalformed` | DC1 to DC5, EA1 to EA3, ET1 to ET8; BJ0 to BJ5 and BJ7 (producer step) | `deposit_call.json` `reject`, `action.json` `reject`, `x402.json` `build_reject` (rule in `expect`) |
| `edenescrow.ErrUnknownDomain` | ED1 | `action.json` `reject` (rule `ED1`), `x402.json` `build_reject` |
| `policy.ErrFactsInvalid` | section 4 (wraps both), EF3 | `action.json` `extractor_expect_error` (rejects, and cases with `extractor_rule` `EF3`) |
| signer refusals | S2 to S11; S4 is `ErrRequirements`; S11 uses `ErrPinMismatch` (S11a), `ErrNotAuthorized` (S11b), `ErrRequirements` (S11c, S11d) and `ErrNotExecuted` (S11e) | `x402.json` `requirements` (rule only), `payment_signature` `requests` (S11a, S11c, S11d with the sentinel); the rest depends on configuration and state |
| `edenexec` sentinels | section 7.7 | `signed.json` `rail_ref`, `exact_tx`; `settlement.json` |

## 11. Vectors

Location `spec/vectors/profiles/eden-escrow/`. Every file has `format`
`edicta-vectors/v0`, `profile` `eden-escrow`, `revision`
`eden-escrow-v1-draft.6`; uints are decimal strings, bytes lower-case hex.
Written by `spec/vectors/tools/edenescrow-gen` (go-ethereum v1.17.8, its own
module, no network: recorded data comes only from `live/`);
checked independently, without go-ethereum, by
`spec/vectors/check/check_profile_eden_escrow.py` (also run by
`check_vectors.py`). `go run . -check` in the generator's directory fails
if a file differs from a fresh generation.

| File | Contents |
|---|---|
| `live/f14.json` | Recorded Eden mainnet data (read-only, 2026-10-21): block 227899844 as served, its two transactions as stored in the Eden data blob on Celestia height 15152868, the F14 deposit (raw bytes, `eth_getTransactionByHash`, `eth_getTransactionReceipt`, the inner deposit call) and the F14 settle. Input only. |
| `live/escrow-code.json` | Read-only records of 2026-10-21: the Blockscout verified-contract record of the 714 escrow (metadata, MIT source, creation and deployed bytecode, creator and creation transaction), the creation transaction from Eden RPC, and `eth_chainId`, `eth_blockNumber`, `eth_getCode` answers on both networks for the escrow, its CREATE2 address and the deployer. Input only. |
| `deposit_call.json` | Section 2.3. `cases`: `data_hex` and the decoded fields (the F14 call and two synthetic bounds). `reject`: `data_hex`, `expect_error`, `rule`, `cause`. 3 cases, 16 rejects. |
| `action.json` | Sections 2, 3, 4. `extractors` (per ID: build, kind, scale, rows with code hash), `escrow_code` (code hash, constructor prefix, init code hash, CREATE and CREATE2 derivations, recorded code on both networks), `requirements_tag`, `limits`. `cases`: `build`, `extractor_ids` (the IDs that accept it, with equal facts), the transaction fields, `data_ref`, `resource`, `requirements_hex` (mock), `requirements_hash_hex`, `tx_hex`, `sighash_hex` (equal to go-ethereum's), `cbor_hex`, `action_salt_hex`, `action_hash_hex` (core 5.1), `facts` and `facts_cbor_hex` (`null` when the extractor refuses), `extractor_expect_error` and `extractor_rule` (`null` unless EF3 refuses), `profile_fields` (4.1). `reject`: `build`, `extractor_id`, `cbor_hex`, `expect_error`, `extractor_expect_error`, `rule`, `cause`, and for transaction-level rejects `geth_rlp_decodes` (informative). 8 cases (one testnet, one `edictadev`; `tx_max_714` and `tx_amount_overflow_714` refused by EF3, `tx_amount_max_714` at the 32-byte limit), 66 rejects. |
| `live/houston-deposit-build.json`, `live/houston-payment-required.json` | The requester's client fixtures, byte for byte (SHA-256 in `x402.json` `inputs`): a `/deposit/build` answer (never signed) and the decoded `payment-required` header of a live 402, as saved (pretty-printed; not wire bytes). Input only. |
| `x402.json` | Sections 2.2a, 2.5, 2.7, 4, 5.1 S4 and S11, 5.6. `build`: the fixture's transaction fields, `tx_hex` (245 bytes), `sighash_hex` (equal to go-ethereum's), `resource` (the `https://` form), `requirements_resource_url` (`R`'s own URL), `requirements_hash_hex` over the saved `R`, `cbor_hex` (334 bytes), salt, `action_hash_hex`, `facts`, `facts_cbor_hex`, `profile_fields`. `build_limits` (16384 bytes, depth 16). `build_accept` (11 bodies: `type 2`, empty `accessList`, unknown top-level member, upper-case hex, escaped member name, escaped value, whitespace, exactly 16384 bytes, depth 16 give the fixture's action; `nonce` 2^53-1 gives the action in its own `cbor_hex`) and `build_reject` (54, with the first failing rule BJ0 to BJ7 or the 2.4 rule). A body is in `json`, or in `json_hex` when it is not valid UTF-8. `requirements`: `max_length`, `max_depth`, `server_signature` (message, digest, signature, recovered = `w2`); `accept` (9) and `reject` (40) `R` byte strings with the `requirements_hash` the action carries and the S4 rule (S4a to S4f). `payment_signature`: field `paymentId` with the message, the EIP-191 preimage and digest, and the `payer1` signature (`v` 27 or 28); `refused_fields` (`nonce`); `requests` (9 cases of the stateless S11 steps: field, `check_server_signature`, the action's `resource`, `requirements_ref` (the `R` the action commits), `cbor_hex`, `r_ref` (the `R` stored or presented, or `null`), and `pass` with `message_hex` or the step, sentinel and S4 rule). |
| `multi_source.json` | Section 5.5. 26 cases: sources (host, operator, `operator_label`, result, outcome and binding label, set-aside reason), `min_sources`, `min_level`, phase (`polling` or `until_passed`), and the expected report (`status`, `level` or `reason`), Await state, `record_allowed`, `payment_signature_allowed`, `nonce_release_allowed`. No case is `violated`. |
| `signed.json` | Sections 5.2, 6, 7.3. `keys.payer1` (label, private key, public key, address; vector-only). `cases`: the signature `(y_parity, r, s)` (RFC 6979, low `s`), `signed_hex` (splice rule, equal to go-ethereum's), `rail_ref`, `payer`. `rail_ref`: EE1 cases (8; `status` `unchecked` on each malformed one). `exact_tx`: EE3 and EE4 cases (8 pass, 21 `wrong_tx`, including the recorded form A transaction, `r = n`, `s = 0`, an `r` off the curve, `y_parity` as `0x00`, `s` as a list). |
| `settlement.json` | Section 7.3, recorded data. `event` (signature, topic0, equality with the recorded log). `rebuild`: EE2 on the recorded deposit and settle answers (bytes equal the Celestia copy) and one lying answer. `receipt`: consensus encoding and bloom of the recorded receipt. `deposit_event`: EE7 and EE8 on the recorded escrow log (22 cases: 1 executed, 1 reverted, 20 `settlement_log_mismatch`). `block`: header RLP and hash, transactions root of block 227899844. |

The vector key `payer1` is derived from a public label; it MUST NOT hold
funds on any chain.

Not covered by vectors: the signer rules other than S4 and the stateless
S11 steps (configuration and state; the signer's tests cover S3n, S11b
with agent B asking for agent A's `commitment_hash`, S11e, and the
startup refusals of S1), the per-source sequencing of 7.3 (C13 tests it
with fakes and recorded answers; 5.5 combination is in `multi_source.json`),
L2 receipts (RF13), the S3c code check (needs an RPC), the broadcaster
(5.4, needs a server).

The `build_reject` and `requirements` reject labels are written by the
generator by hand (one defect each, anchored on the fixture text) and
re-derived by the independent Python checker
(`profile_eden_escrow_x402.py`).

## 12. Open items

| Item | Needs | Blocks |
|---|---|---|
| Testnet use and the copy's deployment | one CREATE2 transaction (human's go) | C11 |
| Raw `PAYMENT-REQUIRED` header capture (wire bytes) for a non-mock `R` vector | the requester (said to be sent; not received) | freeze |
| Which field the server's `Payment-Signature` check uses; `v` forms (RF27) | the requester's funded test | S11 for that server: if it verifies only `nonce`, a revision in which a server signature covers `nonce` |
| The server checks recovered signer = escrow `buyer` and accepts each Payment-Signature once (RF27; section 0) | the requester, in writing or by the funded test | freeze |
| Agent signature over the S11 request instead of the per-agent credential (S11b): removes the bearer secret, but the core says an agent key signs only commitments and publish requests (core 17.1) | the human (core wording) | none; S11b uses credentials until then |
| `eth_getTransactionCount` `pending` and the sequencer's private pool (RF32) | the Eden team or a funded test | S3n's strength |
| `/deposit/send` required or not; its success body (RF28) | the requester | default broadcaster mode |
| Eden fee model beyond gas (RF29) | ev-reth source or the Eden team | EF2's bound |
| Independence of a second public Eden RPC operator (RF30) | the Eden team or the operator | L1 with public sources only |
| Fee-only caps, refund release (H-E4 (2), (3)) | policy v2 | none for this release |
| `eth_getBlockReceipts` and receipts root (RF13) | one recorded full block with receipts | L2 |
| Core hook for profile report fields (7.1) | the human | none |
