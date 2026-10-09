# Edicta

**Edicta — the boundary between decision and execution.**

> Agents decide freely. They execute only what they committed to beforehand,
> within the policy their principal signed, and anyone can verify it.

Precisely: "execute only what they committed to" holds when the executor
enforces the gate's Authorization (or, later, with an on-chain gate). Where the
executor does not enforce it, an agent can still act outside its commitment,
but it cannot do so undetected.

## Why

When an automated actor acts with someone else's money, the only evidence of
what it decided, and why, sits today with its operator. The operator can
rewrite or hide that evidence after the fact. Edicta makes the decision public
and committed before the action, so the record no longer depends on the party
it is supposed to hold to account.

## First use case: AI agents that spend other people's money

Example: a trading agent manages a client's brokerage account. Before each
order it publishes its decision (the market data it saw, its model and
policy, and the exact order bytes) and commits to it. The gate authorizes
only that exact order, inside the limits the client signed, and the broker
connector places it only with that Authorization. Afterwards the client, or
an auditor, can check every order against what was decided and when.

The core makes no AI assumptions. A trading bot, a DeFi keeper or a cron
script that moves funds uses Edicta in exactly the same way.

## What it does

An agent's decision (its context, policy, model and the exact action bytes) is
published to a data availability layer and committed to, with the agent's
signature, before the action happens. A gate authorizes only valid
commitments and returns a signed Authorization for exactly the committed
action bytes. The integrator's executor checks that Authorization, runs
exactly those bytes, and runs them once, keyed by `commitment_hash`. An
optional receipt maps `commitment_hash` to the rail reference (an order id, a
transaction hash); it is the gate's attestation of what the executor
reported, not proof of execution.

Afterwards anyone can verify that the decision existed before the action,
that exactly that action ran, and that the gate authorized it.

## What it does not do

Edicta never evaluates the agent: not its logic, not the truth of its inputs
(prices, for example), not the quality of the decision. Judging the agent is
the operator's or auditor's job, using the published payload.

The core is platform-agnostic. An action is an opaque byte string; rails,
brokers and chains live in profiles. The gate verifies and authorizes, it
never executes and holds no rail credentials.

## Try it

One command runs the whole flow on the Celestia Mocha testnet in 3 to 5
minutes. An agent decides on a TIA transfer, and the decision is published as
a Celestia blob and anchored on chain. A gate, started in-process and reached
over its real HTTP API, authorizes it. An executor sends exactly the
committed transfer, and the decision, the Authorization and the payload go to
the archive. An independent verifier then checks all of it from the archive
and public RPCs, including proof of the executed transaction. Finally the demo
tries to cheat four ways (a different amount, a reused decision, a tampered
archive, a rogue executor) and shows each attempt refused or caught.

```sh
make demo                      # builds everything into celestia/bin, then runs the demo
make demo ARGS="--json"        # pass demo flags through ARGS
```

The demo prints an address to fund with testnet TIA and starts only after you
press Enter. Using your own funded key, the trust root, the verdicts and how
to re-verify a run offline: [celestia/demo/README.md](celestia/demo/README.md).

`make build` only builds (`edicta`, `edictad`, `edicta-live`, `edicta-verify`
into `celestia/bin/`); `make vet` and `make test` run both Go modules. To run
the tests directly, from the repository root:

```sh
go test ./...
go -C celestia test ./...
```

The older manual runner (`edicta-live`, with your own `edictad` and
endpoints), step by step: [celestia/README.md](celestia/README.md).

## Flow

```
agent --payload--> Recorder --> DA layer (Celestia blob or Fibre), anchored at height H
  |
  +- signs commitment (payload hash, locator, action {type, hash}, nonce, expiry)
       |
       v
  commitment + action bytes --> gate: verify, consume nonce --> signed Authorization
                                                                     |
                                                                     v
                         executor: check Authorization, run the exact bytes once
                                                                     |
                                                                     v
                           optional receipt: commitment_hash -> rail reference
```

## Gate invariants

1. The agent's signature over `commitment_hash` is valid.
2. The payload is available (DA layer or archive) and its hash matches.
3. The action bytes presented to the gate hash to the committed `action.hash`, and the action type is one the gate is configured for. Exact match, no semantics.
4. The commitment has not expired, its lifetime is well below DA retention, and the Authorization never outlives it.
5. The nonce is unused and is marked used atomically with issuing the Authorization: at most one Authorization per `(agent_pubkey, nonce)`.
6. `commitment_hash` is computed over the canonical encoding and is not a field of what it hashes; no decision or Authorization carries a tx hash or rail reference.
7. The gate signs only after 1 to 6 hold, under its own domain tags; gate, agent and executor keys never overlap.

## Format

- Deterministic CBOR (RFC 8949 core deterministic encoding, further restricted: integer map keys, no floats, no tags, optional fields absent rather than null).
- SHA-256 for every hash, Ed25519 for every signature.
- Every hash and signature is domain-separated by a length-prefixed tag (`edicta/v1/...`).
- The action is opaque: `{type, hash}`, where `type` is a media type and `hash` is a tagged hash over the type, a fresh 32-byte salt and the exact action bytes; the salt travels with the bytes to the gate and the executor and inside the encrypted payload.

Specification: [spec/decision-commitment-v1.md](spec/decision-commitment-v1.md).
Profiles: [spec/profiles/](spec/profiles/).
Cross-language test vectors (with an independent Python checker): [spec/vectors/](spec/vectors/).

## Data availability

- `celestia_blob` (default): the payload is a share-version-1 blob on Celestia L1, paid by `MsgPayForBlobs`. Live on the Mocha testnet; this is what the demo uses.
- Fibre: the payload is a Fibre blob, anchored on L1 by a `MsgPayForFibre` transaction. A first-class mode, implemented in the Recorder, the gate and the verifier; not part of the demo, and its first live run is still pending.
- Archive: long-term copy of the payload for verification after DA retention ends. The hash proves integrity, so the archive is trusted only for availability.

## Status

Wire version 1 (the earlier v0 drafts are superseded and unsupported). The gate, the Go SDK, the Recorder, the
`edictad` daemon, the archive and the verifier (`edicta verify`, `edicta
replay`) work end to end; the demo above, with the `celestia_blob` mode, ran
live on Celestia Mocha. Fibre support is implemented but has not run live
yet. Principal-signed policy (mandates with spending limits) is in progress.
Not production-ready.

## Repository layout

| Path | Contents |
|---|---|
| `/` (module `github.com/vgonkivs/edicta`) | Core: `commitment` (encoding, hashing, checks), `gate`, `archive`, `verifier`, `sdk`, `edictaapi` (HTTP API), `dacommit`, `test` |
| `celestia/` (own module) | Recorder, chain client for the gate, `edictad` daemon, `edicta` CLI (demo, verify), `edicta-live` runner |
| `fibre/` (own module) | Fibre blob commitment |
| `examples/` | Profiles in use: `tia-transfer` (Cosmos `MsgSend` on a price trigger) and `dca-agent` (IBKR order, offline with a fake broker) |
| `spec/` | Specification, profiles, test vectors and their generators |
