# dca-agent example

A worked example of a profile built on top of the core: a dollar-cost-averaging
agent that decides to buy on an IBKR paper account. It lives outside the core.
The core knows nothing about orders, accounts or brokers; everything
order-specific is here. The profile is specified in
[spec/profiles/dca-agent-v0.md](../../spec/profiles/dca-agent-v0.md).

## Flow

```
agent -> SDK -> gate Authorize -> executor -> gate Record
```

1. The agent (`dca`, `ibkrorder`) builds its DCA reasoning and the exact order
   bytes, and the SDK publishes and commits to them before anything happens.
2. The gate's `Authorize` checks the commitment and the action bytes and
   returns a signed Authorization.
3. The executor (`ibkr`) verifies that Authorization for exactly those bytes,
   parses them as they are (never re-encoding), checks the account and the
   operator's risk limit, dedupes by commitment hash, and places the order once.
4. The gate's `Record` notarizes `commitment_hash -> order id` in a receipt.

A verifier can later open the payload and check that the reasoning matches the
order that was executed.

## Offline only

Nothing here touches a network. The broker is a fake (`test/brokerfake`), the
publisher and the gate's chain and storage are in-process fakes. The real IBKR
client is a later adapter behind the `ibkr.Broker` interface. See
`e2e_test.go` for the whole flow.
