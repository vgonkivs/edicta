# Edicta

Edicta — verifiable decision layer for autonomous agents.

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

## Try it: the demo

One command runs the whole flow on the Celestia Mocha testnet in a few
minutes: an agent decides on a TIA transfer, the decision is published and
anchored on Celestia, the gate authorizes it, an executor sends exactly the
committed transfer, and an independent verifier checks all of it. Then the
demo tries to cheat (a different amount, a reused decision, a tampered
archive, a rogue executor) and shows each attempt refused or caught.

```sh
go -C celestia build -o bin/edicta ./cmd/edicta
celestia/bin/edicta demo
```

The demo prints an address to fund with testnet TIA and starts only after you
press Enter. Using your own funded key, the trust root, the verdicts and how
to re-verify a run offline: [celestia/demo/README.md](celestia/demo/README.md).

## What it does not do

Edicta never evaluates the agent: not its logic, not the truth of its inputs
(prices, for example), not the quality of the decision. Judging the agent is
the operator's or auditor's job, using the published payload.

The core is platform-agnostic. An action is an opaque byte string; rails,
brokers and chains live in profiles. The gate verifies and authorizes, it
never executes and holds no rail credentials.

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
- Every hash and signature is domain-separated by a length-prefixed tag (`edicta/v0/...`).
- The action is opaque: `{type, hash}`, where `type` is a media type and `hash` is a tagged hash over the type and the exact action bytes.

Specification: [spec/decision-commitment-v0.md](spec/decision-commitment-v0.md).
Profiles: [spec/profiles/](spec/profiles/).
Cross-language test vectors (with an independent Python checker): [spec/vectors/](spec/vectors/).

## Data availability

- `celestia_blob` (default): the payload is a share-version-1 blob on Celestia L1, paid by `MsgPayForBlobs`. Live on the Mocha testnet.
- Fibre: the payload is a Fibre blob, anchored on L1 by a `MsgPayForFibre` transaction. A first-class v0 mode, in progress.
- Archive: long-term copy of the payload for verification after DA retention ends. The hash proves integrity, so the archive is trusted only for availability.

## Status

The v0 wire format is frozen. The gate, the Go SDK, the Recorder, the `edictad`
daemon and the tia-transfer demo work end to end on Celestia Mocha. Fibre
support, the archive and the standalone verifier are in progress. Not
production-ready.

## Repository layout

| Path | Contents |
|---|---|
| `/` (module `github.com/vgonkivs/edicta`) | Core: `commitment` (encoding, hashing, checks), `gate`, `sdk`, `edictaapi` (HTTP API), `dacommit`, `test` |
| `celestia/` (own module) | Recorder, chain client for the gate, `edictad` daemon, `edicta-live` demo runner |
| `fibre/` (own module) | Fibre blob commitment |
| `examples/` | Profiles in use: `tia-transfer` (Cosmos `MsgSend` on a price trigger) and `dca-agent` (IBKR order, offline with a fake broker) |
| `spec/` | Specification, profiles, test vectors and their generators |

## Try it

One-command demo on Mocha (`edicta demo`): [celestia/demo/README.md](celestia/demo/README.md).

The older manual runner (`edicta-live`), step by step: [celestia/README.md](celestia/README.md).

Tests, from the repository root:

```
go test ./...
go -C celestia test ./...
```
