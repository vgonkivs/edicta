# Profiles and executors

The core treats an action as opaque bytes with a media type. A profile gives
those bytes a meaning on one rail and states what its executor must check.
This guide is for integrators who write or run an executor. Spec:
`spec/decision-commitment-v1.md`, sections 15 and 16; the profiles in
`spec/profiles/`.

## Profiles in this repository

| Profile | Action type | Executor | Public execution |
|---|---|---|---|
| bank-send (`spec/profiles/bank-send-v0.md`) | `application/vnd.edicta.cosmos.bank-send.v0+cbor` | `examples/tia-transfer/transfer` | yes |
| dca-agent (`spec/profiles/dca-agent-v0.md`) | `application/vnd.edicta.ibkr.order.v0+cbor` | `examples/dca-agent/ibkr` | no |

The `v0` in a profile name or media type is the profile's own version; both
profiles run on the v1 core.

## What a profile must define

From the core spec, section 16.2:
1. Its action type, lower case, with the version in the name.
2. A strict decoder: one byte string, one meaning.
3. Domain self-identification: the bytes name where they may execute (the
   chain id in a bank send, the IBKR account in an order), and the executor
   compares it with its own.
4. The executor's checks, the field mapping to the rail's API, and the
   idempotency key.
5. The rail facts it relies on, unverified ones marked.

For a gate with a mandate, the action type also needs a policy extractor
that reads the facts (kind, asset, amount, recipient) from the bytes. Only
the bank-send extractor (`celestia/tia-transfer/v1`) exists; `edictad`
refuses to start with a mandate if an allowed action type has none.

## The executor's Authorization check

The executor receives three things from the integrator: the signed
Authorization, the exact action bytes and the 32-byte action salt. It pins
the gate's key, the gate id and its action type itself (never from the
Authorization, the caller or the agent), then calls:

```go
sa, _, err := commitment.VerifyAuthorization(authorization, commitment.AuthorizationCheck{
    GatePubKey: pinnedGateKey,
    GateID:     pinnedGateID,
    ActionType: myActionType,
    Action:     actionBytes, // the bytes about to be executed
    ActionSalt: salt,
    Now:        uint64(time.Now().Unix()),
    SkewS:      skew, // 0..300
})
```

It is pure (no I/O). Order: strict decoding, static checks (`version = 1`,
`path`, `mode`, `anchor_deadline` present iff `mode = 2`), the gate
signature, then the action: gate id (`ErrScopeMismatch`), size
(`ErrActionSize`), salt present and 32 bytes (`ErrMissingField`,
`ErrFieldSize`), the salted action hash (`ErrActionMismatch` for other bytes,
another type or another salt), and finally `now + skew < expires`
(`ErrExpired`). Core spec, section 15.3.

The salt comes from the agent, next to the action bytes. The executor never
derives it. It is as secret as the bytes: anyone with both can test them
against the public `action_hash`.

Then, in this order (core spec, section 16.1):
- Parse the authorized bytes as they are with the profile's decoder and act
  on that parse. Never rebuild the rail request from a caller's struct and
  never re-encode to compare.
- Check the domain the bytes name.
- Dedupe by `commitment_hash`: record it as in flight before or with the
  send; refuse a second execution; keep the record at least until
  `expires + skew`. After a crash, look the action up at the rail, never
  send again.
- Do not start a send once `now + skew >= expires`.
- Optionally report the rail reference to the gate (`POST /v1/record`),
  signed with the executor's own Ed25519 key, which the gate operator lists
  in `gate.executor_keys`. That key signs nothing else.

The bank-send profile allows resending the identical signed transaction
bytes inside a window bounded by the transaction's timeout height, because
the chain includes them at most once; it never builds a second transaction
for one decision (`spec/profiles/bank-send-v0.md`, section 4).

## Fast-mode policy

An Authorization has `mode = 1` (strict: the payload was anchored on L1
before the gate signed) or `mode = 2` (fast: the gate checked the anchor
intent and the availability evidence, and the anchor is due by
`anchor_deadline`).

Both reference executors have a `RefuseFastMode` setting
(`transfer.Config.RefuseFastMode`, `ibkr.ExecutorConfig.RefuseFastMode`;
`refuse_fast_mode` in the profile documents). It is checked right after the
Authorization and before the action is parsed, and refuses with
`transfer.ErrFastModeRefused` or `ibkr.ErrFastModeRefused`.

The default is false: a gate issues fast mode only under a mandate whose
principal stated `fast_mode_max_delay`, and an executor default should not
silently override that consent. Set it to true if you need "anchored before
the action". If the anchor never lands, the decision is provably invalid
afterwards, possibly after the action ran.

The profiles also say an executor that accepts fast mode SHOULD act only
while its own chain head is below `anchor_deadline`. Neither reference
executor reads a chain head for this; they rely on `expires`, which the
profiles allow for an executor without a chain-head source.

## Public execution and reveals

A profile states `public_execution`: whether an executed action is public
anyway.

- bank-send: true. An executed transfer is a public transaction. Under a
  private mandate the gate may then publish the action salt once a receipt
  names the transaction (a reveal record), which lets a keyless verifier tie
  the public transaction to the salted `action_hash`. The operator turns this
  on per type with `gate.reveal_on_execution` in `edictad`.
- dca-agent: false. An IBKR order is off chain; revealing its salt would make
  the low-entropy order bytes testable against the public hash. The gate
  refuses to start with this type in `reveal_on_execution` (cause
  `reveal_not_public_execution`).

The flag is taken from profiles compiled into the gate, not from
configuration (`edictad` knows only the bank-send profile).

`ActionFromTx` is the bank-send reconstruction a verifier uses on the reveal
path: from the transaction bytes that hash to the receipt's `rail_ref`, it
takes the `MsgSend` verbatim and rebuilds the action bytes with the chain id
the checker is configured for (`celestia/railverify.ActionFromTx`;
`spec/profiles/bank-send-v0.md`, section 3.5). The core accepts the result
only if it hashes, with the revealed salt, to the agent-signed
`action_hash`, so a wrong chain id or a wrong transaction gives `unchecked`,
never a false pass. The verifier sets the chain id with `--exec-chain-id`.

## What is verified, what is not

Verified by `VerifyAuthorization`: the gate signed this Authorization for
exactly these bytes, this type and this salt, at your gate, and it has not
expired. Verified by the profile's executor: the bytes parse strictly and
name your domain; your own limits (amount, notional, destinations).

Not verified by Edicta: that an executor actually runs these checks (an
integrator that skips them has no protection, and the gate cannot see it);
that the action is safe or sensible for the rail; that the rail executed it.
The Authorization is a bearer token: whoever holds it, the bytes and the salt
can present it until `expires`, so at-most-once execution depends on your
dedupe.
