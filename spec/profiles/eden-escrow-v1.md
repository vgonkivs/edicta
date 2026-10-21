# eden-escrow profile v1 (NativeEscrow deposit on Eden)

Edicta profile for a payment into the `NativeEscrow` contract on Eden, an
EVM chain on the Evolve stack. Use case: an x402 agent pays a capped
escrow deposit that a facilitator later settles. Eden is only the payment
rail. Commitments use any core `da` (the first Eden release uses `da = 2`,
fast or strict mode), and nothing in this profile touches the anchoring.

Status: revision `eden-escrow-v1-draft.3` (2026-10-21), **draft, not
frozen**. Built on the core spec `spec/decision-commitment-v1.md`, revision
`v1.2`, and on `spec/policy-v1.md` (`policy-v1.0`). Section numbers prefixed
"core" refer to the core spec; "policy" refers to the policy spec. The `v1`
in the profile name and in its media type is the profile's own version, not
the core's.

Keywords MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119. Items marked
`UNVERIFIED` are facts about Eden, Evolve or the escrow that the R0 recording
(2026-10-21, read-only) did not settle; the human confirms them. Open items
before the freeze are listed in section 12. Everything else is normative
for this profile.

This profile adds no core rule, no wire byte, no tag of the core or policy
families, no archive kind and no sentinel to section 21 of the core. The
core invariants are unchanged. The settlement report of section 7 is a
profile-defined, verdict-neutral report field.

## 0. Versioning

| Change | Rule |
|---|---|
| Editorial | No version change. |
| Any change to an encoding, a check, a table row or an outcome, while in draft | Bump `eden-escrow-v1-draft.N`, regenerate the profile vectors, record the change below. |
| After the freeze, any such change | New media type (`...escrow-deposit-tx.v2+cbor`) and new extractor ID (`eden/escrow-deposit-tx/v2`). The version is in the type name and in the ID. A new table row is such a change (policy X1: any change of the extractor's output for any input is a new ID). |

Freeze conditions: the requester answered Q-E2 (which networks) and Q-E3
(the escrow-upto flow), and the human approved.

| Revision | Change | Vectors |
|---|---|---|
| `eden-escrow-v1-draft.1` | First draft: form T action and its strict decoder, escrow table, extractor `eden/escrow-deposit-tx/v1`, signer rules S1 to S10, `rail_ref`, settlement report EE1 to EE9 with levels L0 to L2. Form A is a placeholder (section 8). | Initial set (section 11). |
| `eden-escrow-v1-draft.2` | Table pinned from read-only records of the deployment (section 3): the runtime code hash; the testnet row at the CREATE2 address, now in every build; the dev row moves to that same address. New signer rule S3c (escrow code hash before signing). RF8, RF19, RF20 settled from the verified source and bytecode. Outcome changes: chain 3735928814 to the CREATE2 address is accepted (was `ErrUnknownDomain`); chain 31337 to the 714 address is refused in `edictadev` builds (was accepted). | All files regenerated (`revision` draft.2). New input `live/escrow-code.json`; new section `escrow_code` and case `tx_f14_testnet` in `action.json`; rejects `tx_testnet_mainnet_address`, `tx_714_copy_address`, `tx_dev_mainnet_address` replace `tx_chain_testnet_pending`. |
| `eden-escrow-v1-draft.3` | Audit fixes. (1) `edictadev` builds register the type under a separate extractor ID, `eden/escrow-deposit-tx-dev/v1`, which alone holds the dev row; `eden/escrow-deposit-tx/v1` has the same output in every build (policy X1, X2), so a production verifier reports `policy_no_extractor` for a dev decision instead of a false `facts_mismatch`. (2) EE1: a malformed `rail_ref` is `unchecked`, no longer `violated`; the order is 7.2, EE1, then the source rules. (3) S6 and S7 in one durable write. (4) Fee bounds: `MaxFeePerAction` and `MaxFeePerHour` (S7). (5) S3c before every signature is a MUST, failing closed. (6) The nonce release path (5.3), one payer key per served chain (S1), chain-id uniqueness (RF1, RF2), settlement evidence not archived (7.6). | All files regenerated (`revision` draft.3). `action.json`: `extractors` (two IDs, rows per ID), `extractor_ids` per case, `extractor_id` per reject, 9 new rejects (ET2 straddling item and long-form empty list; ET3 leading zeros on `chain_id`, fee and tip, 9-byte `nonce` and `gas_limit`, 33-byte tip, `chain_id` 2^63). `signed.json`: `status` on EE1 cases; EE3 cases `r_equals_n`, `s_zero`, `r_not_on_curve`, `y_parity_zero_byte`, `s_as_list`. `settlement.json`: `event_other_index`. |

## 1. Threat model

| Mechanism | Defends against | Assumes |
|---|---|---|
| The action carries the exact unsigned EIP-1559 transaction; the signer signs `keccak256` of those bytes and splices the signature in (sections 2, 5.2) | Executing another transaction than the authorized one; a re-encoding step between what was committed and what is signed (core I3) | The signer never builds the transaction from a struct; the strict decoder (2.4) is used only to check the bytes |
| Strict decoders: canonical CBOR, canonical RLP, exact calldata words (2.4) | One authorized byte string read as two payments by two parsers. go-ethereum's RLP decoder reads 23 of the 40 type-2 transaction rejects of the vectors as a valid payload (field `geth_rlp_decodes`) | Gate, signer and verifier use this decoder, checked by shared vectors |
| `chain_id` inside the transaction, signed by EIP-1559; `to` must be the table's escrow for that chain (ED1) | Bytes authorized for one chain or contract executed on another (testnet against mainnet, the dev chain against either) | The table is compiled in (policy X2); the dev row belongs only to the dev extractor ID, registered only in `edictadev` builds |
| Escrow runtime code hash per row (section 3), checked by the signer before signing (S3c) and by the verifier (EE5) | A copy at the testnet or dev address whose code differs, so that a deposit log means something else; a deposit sent to the CREATE2 address before the copy exists, which would be a plain transfer to an address with no code | The hash is pinned from the verified mainnet deployment |
| Facts count the deposit `value`, the cap (section 4) | A mandate that counts only what the facilitator later settles, after the money left | The facilitator settles at most the cap (contract rule, rail fact RF6) |
| Signer pins: facilitator allowlist, refund delay, fees, gas, payer without code (S3); fee budgets (S7) | A deposit that names an attacker's facilitator; a refund that goes to the facilitator because the payer's receive costs more than 30,000 gas; fee drain, per transaction and per hour | The operator configures them; the agent cannot change them; facts carry none of them |
| `expiresAt <= expires` (S5) | A deposit taking effect after the Authorization expired | The escrow refuses a deposit with `expiresAt <= block.timestamp` (RF5); the block time is the sequencer's |
| One digest per `commitment_hash`, durable before signing; deterministic signatures (S6) | Two different transactions for one decision; a re-sign after a crash producing new bytes | The account nonce lets one signed transaction land at most once |
| `rail_ref` = `keccak256` of the signed bytes, lower-case hex (section 6) and EE3 | An executor claiming a transaction that is not the authorized one | Keccak-256 is collision resistant; anyone can rebuild the bytes from chain data |
| Settlement levels L0 to L2 (section 7) | Trusting one RPC operator's word for inclusion, status and logs | L0: one source; L1: N operators do not collude; L2: the header is attested by N operators. No level proves Eden data availability or survives a sequencer rollback (section 7.6) |
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
| 4 | `requirements_hash` | bstr | exactly 32 | `H(tag("edicta/eden-escrow/v1/requirements") \|\| R)`, with `R` the exact `PaymentRequirements` bytes received from the server (2.5). Committed and audited; never sent on chain. |

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

`w0` (`paymentId`) is any 32 bytes. Who chooses it, the server or the
client, is `UNVERIFIED` until Q-E3 (section 8); either way
`requirements_hash` binds the server's statement.

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

- `R` is the exact byte string of the `PaymentRequirements` the server
  sent. Which element of the 402 response that is (the whole body, one
  entry of `accepts`) is `UNVERIFIED` until the escrow-upto wire format is
  known (Q-E3). Until then producers MUST use the whole response body as
  received, and the vectors use a mock body (field `requirements_hex`,
  marked `"mock":true`).
- Tag `edicta/eden-escrow/v1/requirements` (34 bytes, `tag(t)` first byte
  `0x22`), family `eden-escrow` under policy 2.1. It is a hash tag only:
  no Edicta key signs under it, and no core or policy tag has this ASCII.
- Producers SHOULD put `R` and the resource into the payload plaintext so
  that an auditor can recompute the hash. A mismatch is visible to an
  auditor only; the gate and the signer cannot check it without `R`.

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
| EF2 | Facts: `kind = "x402-payment"`; `asset = "eip155:" + chain_id + "/native"`; `amount` = `value` as minimal big-endian bytes (the RLP integer content, 1..32 bytes); `scale = 18`; `recipient = "eip155:" + chain_id + ":0x" + lower-case hex of payTo`. `chain_id` is decimal without leading zeros. |

Any failure of EF1 (`ErrMalformed` or `ErrUnknownDomain`) and facts that
fail policy section 4 are `policy.ErrFactsInvalid` (a deny, policy X4).
Constants fixed by the ID: the kind, the scale, the asset and recipient
forms, the table. Example: `tx_f14_714` gives
`{kind: x402-payment, asset: eip155:714/native, amount: 3972f538a8081d,
scale: 18, recipient: eip155:714:0xc5aaa301b580d31e64b3bf546846586d934416dc}`.

- `amount` is the cap: the facilitator later settles at most this, any
  time while funded (RF6). The gate must count the maximum before the
  money leaves, so the settled amount is never a fact.
- `kind = x402-payment` is meant for every x402 spend, whatever the scheme,
  so one mandate `kinds` entry covers them.
- `asset` is Edicta's own domain-qualified form (as bank-send's
  `cosmos:<chain>/utia`), not CAIP-19: a CAIP-19 name for native TIA on an
  EVM chain would need a SLIP-44 coin type, which is `UNVERIFIED`. Compared
  bytewise: `eip155:714/native` and `eip155:31337/native` are different
  assets, so a mandate written for mainnet never covers dev payments.
- Not facts (policy v1 facts have no field for them): `facilitator`,
  `expiresAt`, `refundAfter`, `tiaPriceUsd`, `paymentId`, fees, gas,
  `resource`, `requirements_hash`. The signer binds the facilitator (S3).

Gate fit: the gate's action-type allowlist (core rule C2) admits the type;
the registry (policy X5, X6) holds this extractor; stage 4p runs on its
facts; nothing else in the gate reads the bytes (invariant 3).

## 5. Signer (the executor)

The executor is `edicta-signer`: it holds the payer key, verifies, signs
and hands back the signed transaction. It is the only holder of the payer
key; the agent never holds it. Core 16.1 (I1 to I7) applies; the rules
below are the profile's checks (core 16.2 item 4).

### 5.1 Rules S1 to S10 (form T)

| Rule | Requirement | Refusal |
|---|---|---|
| S1 Pins | Configured out of band, never taken from a request: `gate_id -> gate_pubkey`; the set of agent public keys it serves; this action type; the chain ids it serves (rows of its build's table); per chain: the payer address (the signing key's address, checked at startup; one payer key per served chain SHOULD hold, so a key never signs for two chains), the allowed facilitators, `MaxRefundDelay` (seconds), `MaxFeePerGas`, `MaxGas` and `MaxFeePerAction`; operator caps (S7); `skew_s`; `RefuseFast`. The escrow address comes from the compiled table, never from configuration. | refuses to start |
| S2 Two signatures | The request carries the signed envelope, the Authorization, the action bytes and the salt. The envelope passes core stages D, S and G with an agent key from the pinned set; its `action.type` is this type and stage A matches the bytes and salt; its `commitment_hash` equals the Authorization's; `VerifyAuthorization` (core 15.3) passes with the pinned gate key and id, this type, the exact action bytes, the salt, the signer's clock and `skew_s`. A gate signature alone never suffices. | `ErrNotAuthorized` |
| S3 Decode and pins | Strict decode (2.4) with the build's table; `chain_id` is a served chain; `w2` (facilitator) is in the chain's allowlist; `refundAfter - expiresAt <= MaxRefundDelay`; `max_fee_per_gas <= MaxFeePerGas`; `gas_limit <= MaxGas`; `max_fee_per_gas * gas_limit <= MaxFeePerAction`. S3c: `keccak256(eth_getCode(escrow, "latest"))` equals the table's code hash, read through the signer's own Eden RPC, at startup for every served chain and before every signature (MUST); an RPC error refuses (fail closed). S3e: the payer address has no code (no EIP-7702 delegation): checked at startup, and SHOULD be checked before every signature through the signer's own Eden RPC. The signer SHOULD refuse a `nonce` other than the payer's pending nonce. | `ErrMalformed`, `ErrUnknownDomain`, `ErrPinMismatch`, `ErrEscrowCode` |
| S4 `paymentId` | Placeholder (Q-E3): if the client is to derive `paymentId`, the derivation and its check go here. Until then no check; `requirements_hash` binds the server's choice. | none yet |
| S5 Time | `expiresAt <= expires` of the Authorization; `now + skew_s < expires` (core I6). SHOULD refuse `expiresAt <= now + skew_s` (the deposit would revert). | `ErrExpired` |
| S6 One digest per decision | Before signing, the signer durably reserves `commitment_hash -> keccak256(tx)`, in the same durable write as the S7 counters. A repeat of the same request returns the stored signed bytes and counts nothing; any request for that `commitment_hash` with another digest is refused. Signatures are deterministic (RFC 6979, low `s`), so a re-sign after a crash gives the same bytes. | `ErrDigestConflict` |
| S7 Operator caps | `value <= MaxValuePerAction`; in any rolling 3600 s window, the sum of `value` `<= MaxValuePerHour` and the sum of the fee bound `max_fee_per_gas * gas_limit` `<= MaxFeePerHour`. Counted when reserved (S6, same durable write, before signing), not when landed; a reserved action stays counted even if never sent. A risk limit of the operator, beside the principal's mandate. | `ErrRiskLimit` |
| S8 What is signed | Exactly `keccak256(tx)` of the bytes S3 decoded, with the payer key. The output is built by the splice rule of 5.2; nothing is re-encoded from a struct. The only other transaction the payer key ever signs is the nonce release of 5.3. | |
| S9 Mode | Accepts `mode = 2` (fast) by default: the principal consented through the mandate's `fast_mode_max_delay` (invariant 9). `RefuseFast = true` refuses it. Logs `mode` and `anchor_deadline`. | `ErrFastModeRefused` |
| S10 Record | Optional record request (core 14.3), signed with the executor key, only after `Await` (5.3) saw the transaction at `ConfirmDepth`, executed or reverted. `rail_ref` has the form of section 6. Never recorded when not found by `until`. | |

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
1 gate: Authorization (core invariant 5: nonce marked durably before it leaves)
2 signer: S1..S9; S6 reserve; sign; store signed bytes; rail_ref known now
3 broadcaster (signer or `edicta commit`): I5 in-flight record (commitment_hash -> rail_ref),
  then eth_sendRawTransaction(signed)
4 Await(rail_ref, until = expiresAt + AwaitGrace): EE2..EE8 at L0, own node first if configured
5a found, depth >= ConfirmDepth, executed or reverted -> record request (S10)
5b not found by until -> state not_executed; no record request; never sign other bytes
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
release fails on the nonce.

| Case | Behaviour |
|---|---|
| Crash between reserve and signature | S6: the repeat gives the same signature or a refusal, never other bytes. |
| Crash after signing, before broadcast | Re-send the stored bytes; same `rail_ref`. |
| Crash after broadcast, before the record | I5: look up `rail_ref` (never re-sign), then 5a or 5b. |
| Stuck in the sequencer's private pool, or censored (RF16) | 5b after `until`; if it lands later the deposit reverts (`expiresAt` passed). |
| Reverted deposit | Recorded honestly with its `rail_ref`; the decision is consumed. |
| Eden RPC down | Await polls until `until`; if no source ever answered, the state stays `unknown` (not 5b) and the lookup is retried later. |
| Two decisions with identical action bytes | Same digest, same signed bytes (RFC 6979), same hash: the payment lands once, both decisions are counted by the mandate (over-count, safe), both may record the same `rail_ref`. |

Idempotency key (core 16.3): the rail has no idempotency field for a plain
transfer; at-most-once comes from the nonce and S6.

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
`settlement` defined here. It is not one of the checks of core 20.1. It
never changes the verdict or the exit code: like `gate_integrity`, it
reports, and a proven violation reads `violated` while the decision verdict
stays what the core checks give. Tooling that wants to fail on it reads
the field.

`UNVERIFIED` for the human (core wording): core 20.10 lists the report
fields without a hook for profile-defined fields. This profile treats
`settlement` as an additional field that no core rule reads. A core
clarification may want to say so.

### 7.2 Inputs

| Input | Bound by |
|---|---|
| Action bytes, decoded by 2.4 (`A`, its `tx` and items) | stage A of the decision (salted `action_hash`) |
| `rail_ref` from a receipt that passed core 14.2 | the gate's and the executor's signatures (a claim, not a fact) |
| `expires` (Authorization), `T_ref` | signed objects of the decision |
| Escrow address and code hash for `chain_id` | the build's table (section 3) |
| Sources: Eden JSON-RPC endpoints, each of class `public-rpc` or `own-node` | configuration; each is distinct by core OH3 (normalized host) |
| `data_da_height` of the Eden block (optional) | the operator's own ev-node; report only |

Configuration: `MinLevel` (default `L0`), `MinSources` (default 2, used by
L1), `ConfirmDepth` (default 20).

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
`unchecked`, `settlement_disagree`, at any level.

| Level | Name | Adds | Trust left |
|---|---|---|---|
| L0 | `node-attested` | EE2 to EE8 pass on one source. | That source. Class `own-node`: the operator's own node that checks the sequencer's signatures and re-executes, plus the sequencer's ordering. Class `public-rpc`: the RPC operator's word. |
| L1 | `multi-source` | At least `MinSources` sources, distinct by OH3, pass L0 and agree on `blockHash`, `transactionIndex` and the receipt's consensus encoding (`type \|\| rlp([status, cumulativeGasUsed, logsBloom, logs])`, rebuilt from each served receipt). | Collusion of those operators. |
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

Report field `settlement` (JSON names):

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
| `sources` | every source asked: name (OH3 host), class, result (`used`, `agree`, `set_aside`) and reason |

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

## 8. Form A (HoustonAgent `ExecuteWithAuthorization`): placeholder

**Not normative. Pending Q-E3.** The recorded mainnet flow (F14) is form A:
an EIP-7702 account delegated to `HoustonAgent` signs an EIP-712
`ExecuteWithAuthorization(Call[] calls,uint256 validAfter,uint256
validBefore,bytes32 nonce)` (domain `HoustonAgent`, version `1`,
`verifyingContract` = the account), and a relayer submits it through
`HoustonForwarder.executeBatch`
(`0xeb35f99ed9b10cb724698076b5be63de0ed14c3a`). Provisional type
`application/vnd.edicta.eden.escrow-deposit-auth.v1+cbor`, extractor
`eden/escrow-deposit-auth/v1`; neither is registered, and no build accepts
them until this section is written.

Known residuals that this section must address when Q-E3 selects form A:
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
| RF2a | No other public chain uses 714 or 3735928814 (a chain-registry check, e.g. chainlist / ethereum-lists `chains`). 31337 is every local Hardhat or Anvil chain, which is why its row is dev-only. The deployer and the CREATE2 copy can exist on any chain, so only `chain_id` separates domains; S1 keeps one payer key per chain | `UNVERIFIED` (registry not checked) | |
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
| RF23 | That the recorded flow is x402 `escrow-upto` | `UNVERIFIED` | |

## 10. Sentinels

| Sentinel | Rules | Vectors |
|---|---|---|
| `edenescrow.ErrMalformed` | DC1 to DC5, EA1 to EA3, ET1 to ET8 | `deposit_call.json` `reject`, `action.json` `reject` |
| `edenescrow.ErrUnknownDomain` | ED1 | `action.json` `reject` (rule `ED1`) |
| `policy.ErrFactsInvalid` | section 4 (wraps both) | `action.json` `extractor_expect_error` |
| signer refusals | S2 to S9 | none (configuration and state) |
| `edenexec` sentinels | section 7.7 | `signed.json` `rail_ref`, `exact_tx`; `settlement.json` |

## 11. Vectors

Location `spec/vectors/profiles/eden-escrow/`. Every file has `format`
`edicta-vectors/v0`, `profile` `eden-escrow`, `revision`
`eden-escrow-v1-draft.3`; uints are decimal strings, bytes lower-case hex.
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
| `action.json` | Sections 2, 3, 4. `extractors` (per ID: build, kind, scale, rows with code hash), `escrow_code` (code hash, constructor prefix, init code hash, CREATE and CREATE2 derivations, recorded code on both networks), `requirements_tag`, `limits`. `cases`: `build`, `extractor_ids` (the IDs that accept it, with equal facts), the transaction fields, `data_ref`, `resource`, `requirements_hex` (mock), `requirements_hash_hex`, `tx_hex`, `sighash_hex` (equal to go-ethereum's), `cbor_hex`, `action_salt_hex`, `action_hash_hex` (core 5.1), `facts`, `facts_cbor_hex`. `reject`: `build`, `extractor_id`, `cbor_hex`, `expect_error`, `extractor_expect_error`, `rule`, `cause`, and for transaction-level rejects `geth_rlp_decodes` (informative). 6 cases (one testnet, one `edictadev`), 66 rejects. |
| `signed.json` | Sections 5.2, 6, 7.3. `keys.payer1` (label, private key, public key, address; vector-only). `cases`: the signature `(y_parity, r, s)` (RFC 6979, low `s`), `signed_hex` (splice rule, equal to go-ethereum's), `rail_ref`, `payer`. `rail_ref`: EE1 cases (8; `status` `unchecked` on each malformed one). `exact_tx`: EE3 and EE4 cases (6 pass, 21 `wrong_tx`, including the recorded form A transaction, `r = n`, `s = 0`, an `r` off the curve, `y_parity` as `0x00`, `s` as a list). |
| `settlement.json` | Section 7.3, recorded data. `event` (signature, topic0, equality with the recorded log). `rebuild`: EE2 on the recorded deposit and settle answers (bytes equal the Celestia copy) and one lying answer. `receipt`: consensus encoding and bloom of the recorded receipt. `deposit_event`: EE7 and EE8 on the recorded escrow log (22 cases: 1 executed, 1 reverted, 20 `settlement_log_mismatch`). `block`: header RLP and hash, transactions root of block 227899844. |

The vector key `payer1` is derived from a public label; it MUST NOT hold
funds on any chain.

Not covered by vectors: the signer rules (configuration and state), the
source sequencing and levels (C13 tests them with fakes and recorded
answers), L2 receipts (RF13), the S3c code check (needs an RPC).

## 12. Open items

| Item | Needs | Blocks |
|---|---|---|
| Testnet use and the copy's deployment | Q-E2, then one CREATE2 transaction (human's go) | C11 |
| `PaymentRequirements` bytes `R`, `paymentId` derivation, form A | Q-E3 | 2.5, S4, section 8 |
| `eth_getBlockReceipts` and receipts root (RF13) | one recorded full block with receipts | L2 |
| Core hook for profile report fields (7.1) | the human | none |
