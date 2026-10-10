# dca-agent example

A worked example of a profile built on top of the core: a dollar-cost-averaging
agent that decides to buy on an IBKR paper account. It lives outside the core.
The core knows nothing about orders, accounts or brokers; everything
order-specific is here. The profile is specified in
[spec/profiles/dca-agent-v0.md](../../spec/profiles/dca-agent-v0.md); its `v0`
is the profile's own version, and it runs on the Edicta v1 core. Executor
guide: [guide/profiles.md](../../guide/profiles.md).

## Flow

```
agent -> SDK -> gate Authorize -> executor -> gate Record
```

1. The agent (`dca`, `ibkrorder`) builds its DCA reasoning and the exact order
   bytes, and the SDK publishes and commits to them before anything happens.
   The commitment carries the salted action hash; the SDK draws a fresh
   32-byte salt that travels with the order bytes and inside the encrypted
   payload.
2. The gate's `Authorize` checks the commitment, the order bytes and the salt
   and returns a signed Authorization v1, which states its mode (strict or
   fast).
3. The executor (`ibkr`) verifies that Authorization for exactly those bytes
   and that salt, refuses fast mode if `RefuseFastMode` is set (off by
   default), parses the bytes as they are (never re-encoding), checks the
   account and the operator's risk limit, dedupes by commitment hash, and
   places the order once.
4. The gate's `Record` signs a receipt for `commitment_hash -> order id`. The
   receipt is the gate's attestation of what the integrator reported, not
   proof that the order was executed.

A verifier can later open the payload and check that the reasoning matches the
order that was authorized and sent.

The order is executed off chain, so the profile has `public_execution = false`:
the gate never reveals the salt of an order (a gate refuses to start with this
type in `reveal_on_execution`). No policy extractor exists for this action
type yet, so a gate with a mandate cannot allow it.

## Offline only

Nothing here touches a network. The broker is a fake (`test/brokerfake`), the
publisher and the gate's chain and storage are in-process fakes. The real IBKR
client is a later adapter behind the `ibkr.Broker` interface. See
`e2e_test.go` for the whole flow.
