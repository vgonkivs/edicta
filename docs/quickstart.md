# Quickstart

Edicta v1 in one page: the flow, the one-command demo, and the two
publication modes (strict and fast). Spec: `spec/decision-commitment-v1.md`.

## The v1 flow

```
agent: payload (context, model, policy, action bytes + action salt)
   |  encrypt to recipients, publish through a Recorder
   v
DA layer (celestia_blob or Fibre) --anchor on Celestia L1 at height H (strict)
   |                                  or anchor intent at h0, anchor due later (fast)
   v
agent signs the commitment: payload_ref, action {type, salted hash}, nonce, valid_until [, mandate_ref]
   |
   v
POST /v1/authorize {envelope, action bytes, action salt}  -> gate checks -> signed Authorization v1
   |
   v
executor: VerifyAuthorization(exact bytes, salt) -> run the bytes once (key: commitment_hash)
   |
   v
optional POST /v1/record -> gate-signed receipt commitment_hash -> rail_ref
   |
   v
anyone: edicta verify <commitment_hash> ...
```

What changed from the v0 drafts, for anyone who read them:
- The action hash is salted: `H(tag("edicta/v1/action") || uint8(len(type)) ||
  type || salt32 || action_bytes)`. The 32-byte salt is fresh per decision and
  travels with the action bytes to the gate, to the executor and inside the
  encrypted payload. A missing salt is refused; a wrong one is
  `ErrActionMismatch`. Core spec, section 5.1.
- Every tag is `edicta/v1/...`; HTTP paths are `/v1/*` only.
- The Authorization carries `mode` (1 strict, 2 fast) and, in fast mode,
  `anchor_deadline`, a block height. Core spec, section 15.1.
- A gate may enforce a principal-signed mandate (spending limits, recipients,
  fast-mode consent). Policy spec, `spec/policy-v1.md`.

## Set up a self-hosted stack: init, fund, doctor

`edicta init` prepares a Mocha + Base Sepolia stack in one directory (the
Edicta home, `$EDICTA_HOME` or else `~/.edicta`), and `edicta doctor` checks
it:

```sh
make build
bin/edicta init                         # flags: --home, --preset, --set, --max-per-payment, --max-per-hour
# fund the addresses it prints, then:
bin/edicta doctor
```

`init` first checks that the preset's endpoints answer and are on the
right chains; if not, it writes nothing. Then it creates, with mode `0600`
and never over an existing file: separate Ed25519 keys for the agent, gate,
executor and principal, Celestia keyrings for the Recorder and publisher
accounts with their passphrase files, a payer key for the settlement chain,
a starter mandate signed by the principal key (default limits 0.10 USDC per
payment and 1 USDC per hour; change them with `--max-per-payment` and
`--max-per-hour`, in USDC), the agent allowlist `agents.toml`, an empty
`archive/` and `edicta.toml`. It prints the public keys, the mandate as the
gate will enforce it, and the addresses to fund: TIA on Mocha for the
Recorder and publisher, USDC on Base Sepolia for the payer (no ETH needed,
the facilitator pays gas), each with its faucet link.

Re-running `init` is safe: it reports what exists and creates only what is
missing. A second `init` at the same time is refused while one holds the
home's lock. The home and key directories must belong to you and be closed
to others; see [operator.md](operator.md), "Keys and home: permission
rules". The principal key signs mandates only: once the mandate is signed,
move that key off the machine.

`doctor` then reports `ok`, `warn` or `fail` for each part, with the fix for
the last two, and exits `0` when nothing failed. A zero USDC or TIA balance
is the usual first finding until the faucets have paid. The checks, the
exit codes and `--json`: [operator.md](operator.md), "Checking the setup".

What this stack does not do yet: the starter gate is set up for x402
payments, and the x402 extractor that lets a gate read such an action against
the mandate is not in this build. Today the `init` stack is for `doctor` and
for the configuration; it cannot authorize a decision end to end. To run one
end to end, use the demo or the manual path below.

## Run the demo (strict mode, Mocha testnet)

```sh
make demo
```

It builds `edicta`, `edictad`, `edicta-verify`, `edicta-signer` and the
example binaries into `bin/`, then runs `bin/edicta-demo`. It needs a
terminal, prints an address to fund with testnet TIA, and starts only after
you press Enter. In 3 to 5 minutes it publishes a decision as a Celestia blob, has a
gate with a mandate authorize it, sends exactly the committed transfer,
verifies everything from the archive and public RPCs, and then tries five
ways to cheat. Details, flags, exit codes and offline re-verification:
[../examples/tia-transfer/demo/README.md](../examples/tia-transfer/demo/README.md).

## Run your own gate and agent (strict mode)

1. Write an `edictad` configuration (or an `edicta.toml`, which `edictad -config`
   also accepts, see [operator.md](operator.md)) from
   `celestia/cmd/edictad/edictad.example.toml` and start it:
   ```sh
   go -C celestia run ./cmd/edictad -config ~/edicta-live/edictad.toml -print-config
   go -C celestia run ./cmd/edictad -config ~/edicta-live/edictad.toml
   ```
   See [operator.md](operator.md).
2. Run the price agent and executor against it with `edicta-live`, first with
   `--dry-run`. The full command and every flag:
   [../examples/tia-transfer/README.md](../examples/tia-transfer/README.md), section 4.
3. Verify the decision:
   ```sh
   bin/edicta verify <commitment hash> --gate-key <gate public key hex> \
     --archive <archive dir> --headers-rpc <CometBFT RPC> --checkpoint <HEIGHT>:<HASH>
   ```
   See [verifier.md](verifier.md).

Against a gate with a `[policy]` mandate, pass `--mandate-hash <64 hex>`
(the mandate's hash) to `edicta-live`: it becomes the commitment's
`mandate_ref`, and a gate with a mandate refuses a commitment that names none
(`ErrMandateRefMissing`, core spec section 8.8). The demo sets `mandate_ref`
through the Go SDK (`sdk.Config.MandateHash`).

## Your own agent in Go

The SDK builds, encrypts, publishes and signs; the API client talks to
`edictad`:

- `sdk.New(cfg, deps)`, then `Builder.Commit(ctx, payload)` returns a
  `Result` with `Envelope`, `Action`, `ActionSalt` and `CommitmentHash`.
  `cfg.MandateHash` sets `mandate_ref` when the agent acts under a mandate
  (the principal's tool prints the hash). `cfg.SubmitterTrust` is required:
  `SubmitterSameOperator` when you run the Recorder yourself,
  `SubmitterUntrusted` otherwise (then `deps.Inclusion` must be an
  independent inclusion verifier).
- `edictaapi.NewClient(baseURL, token, signer, httpClient)`, then
  `Client.Authorize(ctx, envelope, action, salt)` returns the signed
  Authorization. Hand the executor the Authorization, the action bytes and
  the salt, nothing else.

The salt is as secret as the action bytes: keep it wherever the bytes are
kept, and never log it.

## Strict and fast mode

| | Strict (`mode = 1`) | Fast (`mode = 2`) |
|---|---|---|
| Reference the agent signs | included: the anchor is on L1 at `H` | pending: an anchor intent at `h0`, anchor expected in `[h0, anchor_deadline]` |
| What the gate checks before signing | the anchor on L1 | the archived, signed anchor intent: the Fibre 2/3 certificate (`da = 1`), or acceptance of the signed PayForBlobs by the gate's own node (`da = 2`) |
| Needs | nothing extra | `[gate.fast]`, a mandate with `fast_mode_max_delay`, the operator's own consensus node |
| Latency | wait for inclusion | no wait for inclusion |
| If the anchor never lands | not applicable | the decision is provably invalid afterwards (`anchor_absent`); the action may already have run |

Fast mode exists only with the principal's consent: the mandate must state
`fast_mode_max_delay` (blocks), and the gate clamps the deadline to it. An
executor may refuse fast mode (`refuse_fast_mode`, see
[profiles.md](profiles.md)). Core spec, sections 11, 13, 15.

### Fast mode end to end

1. Operator: `[gate.fast]` and `[policy]` in `edictad`, and the Recorder's
   fast keys (`recorder.fast = true`, `fast_dedicated_account = true`, the
   Recorder namespace in `gate.fast.pending_namespaces`). See
   [operator.md](operator.md).
2. Principal: a mandate with `fast_mode_max_delay`. See
   [principal.md](principal.md).
3. Agent: the Recorder returns a pending reference (`anchor = 2`,
   `h0 = payload_ref.height`). Before signing, the agent verifies the anchor
   intent the way the gate does (rule W5-P, core spec section 11.2); in the
   Go SDK that is `sdk.Deps.Pending`, without which a pending reference is
   refused. The commitment must carry `mandate_ref`.
4. Gate: authorizes with `mode = 2` and `anchor_deadline`.
5. Recorder: writes the anchor evidence at `H` when the anchor lands.
6. Auditor: `verify` reports `mode: fast`, `h0`, `anchor_deadline` and the
   anchor height, or proves the anchor absent with `edicta-verify absence`
   (see [verifier.md](verifier.md)).

`edicta-live --fast --mandate-hash <64 hex> --archive-url <URL>` runs the
price agent in fast mode: it checks the anchor intent of the pending reference
through its own `--grpc-addr` (and `--bridge-addr` with `--da blob`) before it
signs, a same-operator check, so with `--da blob` it accepts only
`--inclusion self` (the default). `--mandate-hash` is required with
`--fast`, because only a gate with a mandate accepts fast mode.

Fast mode has not run live yet. The live run on Mocha is a manual checklist,
[mocha-checklist.md](mocha-checklist.md), that nobody has run so far.

## What is verified, what is not

Verified by the gate before it signs: the agent signature; the payload
hash and its DA commitment; the anchor (strict) or the anchor intent (fast);
the exact action bytes under the salted hash and an allowed action type;
time bounds; the unused nonce; the mandate, when one is configured.
Verified by the executor: the Authorization for exactly the bytes it runs.
Verified afterwards by anyone: all of the above from the archive and
trusted headers, and optionally the executed transaction.

Not verified: whether the agent's inputs were true, whether its decision
was good, and whether an executor that skips the Authorization check
executed anything; the latter is detectable afterwards, not preventable by
Edicta. A receipt is the gate's attestation of what the executor reported,
not proof of execution. Fibre mode is implemented but has not run live yet.
