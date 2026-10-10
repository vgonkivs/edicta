# Edicta architecture and design rationale

This document explains how Edicta is put together and why. It is written for
readers outside the project: integrators, auditors and reviewers. It is not
normative. The specification is the source of truth:
[spec/decision-commitment-v1.md](spec/decision-commitment-v1.md) (core,
revision `v1.0`), [spec/policy-v1.md](spec/policy-v1.md) (mandates,
revision `policy-v1.0`), [spec/ERRATA.md](spec/ERRATA.md) and the profiles in
[spec/profiles/](spec/profiles/). User guides are in [guide/](guide/README.md).

## What Edicta is

A verifiable decision layer for automated actors. Before it acts, an agent
publishes its decision (context, policy, model and the exact action bytes) to
a data availability layer and signs a commitment to it. A gate authorizes only
a valid commitment, and only for exactly the committed bytes. The
integrator's executor acts only with that Authorization. Afterwards anyone can
check what was decided, on what context, that it was public before the
action, and that exactly that action was authorized.

"Agent" means any automated decider that holds a signing key: an AI agent, a
trading bot, a keeper, a cron script. The core makes no AI assumptions.

## What Edicta is not

- It never judges the agent: not its logic, not the truth of its inputs (a
  price, for example), not the quality of the decision. That is the operator's
  or auditor's job, using the published payload.
- It is not a rail adapter. The core knows no broker, chain or account; an
  action is an opaque byte string. Rails live in profiles.
- The gate never executes and holds no rail credentials. Enforcement exists
  only where the executor (a signer, a contract, middleware in front of a
  broker API) checks the Authorization on the exact bytes it runs. Where it
  does not, an agent can still act outside its commitment, but not
  undetected.
- A receipt (`commitment_hash -> rail reference`) is the gate's attestation
  of an executor's claim, not proof of execution.
- Out of scope for v1: TEE attestation, zkTLS, MPC, multi-agent decisions,
  an own rollup, an on-chain gate.

## Layers

| Layer | Role | Trusted for |
|---|---|---|
| Fibre | Proves the payload was available at decision time: validators sign an availability certificate (more than 2/3 of voting power). Short retention (hours). | Availability, under the Celestia honest-majority assumption |
| Celestia L1 | The anchor: a PayForFibre transaction (or, for small payloads, a share-version-1 blob paid by PayForBlobs) at height `H`. For Fibre the payload itself is not on L1, only the commitment and the certificate. | Ordering and time of the anchor |
| Archive | Long-term copy of the payload, the availability certificate, the anchor proof and the gate's records, for verification after DA retention ends. | Availability only: every record is re-checked against hashes and recomputed DA commitments |
| Recorder | Submits the payload and the anchor for the agent and returns a payload reference. | Liveness only: it can refuse or delay; the agent recomputes the DA commitment and checks inclusion itself before signing |
| Gate | Verifies the commitment, applies the mandate, consumes the nonce, signs an Authorization. Never executes. | Its own checks; its key is pinned by executors |
| Executor | The integrator's component that holds rail credentials. Checks the Authorization, runs exactly the authorized bytes, at most once (keyed by `commitment_hash`). | Integrator-owned; Edicta cannot force it to check |
| Verifier | `verify`, `replay` and `absence`: re-checks a decision from the archive and public chain data. Outcomes are `valid`, `invalid` (only from verified data) or `unchecked` with a reason; gate integrity is reported separately. | Nothing: a hostile source can only make a check `unchecked`, never `invalid` or `valid` |

Gate modes: **strict** waits for the anchor on L1; **fast** authorizes on
verified availability evidence before the anchor lands (see below).

## Gate invariants

One line each. The normative text is
[spec/decision-commitment-v1.md](spec/decision-commitment-v1.md), section 1.1.

1. The agent's signature over `commitment_hash` is valid.
2. The payload is available (DA layer or archive) and its hash matches; a pending reference also needs a verified anchor intent.
3. The presented action bytes, with the agent's 32-byte salt, hash to the committed action hash, and the action type is allowlisted. Exact match, no semantics.
4. `now < valid_until`, `valid_until` well below DA retention from the reference time, and the Authorization's `expires <= valid_until`.
5. The nonce is unused and is marked used atomically and durably before the Authorization leaves; at most one Authorization per `(agent_pubkey, nonce)`.
6. `commitment_hash` is over the canonical encoding and never a field of what it hashes; no signed object carries a tx hash or rail reference.
7. The gate signs only after 1 to 6, 8 and 9 hold, under its own domain tags; agent, gate, executor and principal keys never overlap.
8. With a mandate, an Authorization is issued only if the verdict for exactly the committed action allows; deny-only and fail-closed; counters update in the nonce transaction; `mandate_ref` must equal the mandate in force, and without a mandate a `mandate_ref` is refused.
9. The Authorization states its mode and, in fast mode, the anchor deadline height; fast mode needs the principal's consent in the mandate, and a missing anchor by the deadline is provable.

## Key design decisions

### One supported format: v1

v1 is the first and only supported wire version. Earlier v0 drafts had no
users, so they were dropped before the v1 freeze instead of being carried as
a second decoder, a version dispatch and dual vectors. That removed a class of
downgrade and parser-differential risks for no cost. The v0 text is kept for
history in [spec/historical/](spec/historical/); v0 domain tags are never
reused, so no signature can verify across versions. Any later change to wire
bytes, a hash or signature preimage, or a check outcome needs a new version
(`version = 2`, `edicta/v2/...` tags).

Encoding: deterministic CBOR (RFC 8949 core deterministic, restricted further),
SHA-256, Ed25519, and a length-prefixed domain tag on every hash and
signature. A strict decoder accepts exactly one byte string per object, so
signatures cannot be made malleable and Go and Python readers cannot disagree;
shared vectors with an independent Python checker enforce this.

### Salted action hash

`action_hash = H(tag || len(type) || type || salt32 || action_bytes)`. The
salt is 32 fresh random bytes per commitment, chosen by the agent. It travels
with the action bytes to the gate and the executor and sits inside the
encrypted payload. Why: many actions have low entropy (an order of a known
size, a transfer of a round amount), and an unsalted public hash would let
anyone test guesses. The type is inside the hash so the same bytes cannot be
authorized under another format. Matching is exact; the core never interprets
the bytes, and a re-encoding of "the same" action is simply not authorized.
Executors run the authorized bytes as-is and never re-encode them from their
own structures.

### Mandates: `mandate_ref` and a fail-closed policy

A principal (the owner of the money) signs a mandate: which agents, which
assets, per-action and rolling-window limits, recipient and kind allowlists,
validity period. It is bound to one `gate_id` and carries a stable id and a
monotonic version. Facts are extracted deterministically from the exact
action bytes by one vectored extractor per profile, shared by gate and
verifier; no extractor, or bytes it cannot parse, is a deny. The rule engine
is a fixed catalog of pure functions, not a scripting language, so a third
party can recompute every verdict and the principal can read what they sign.

The policy can only refuse what the core checks would allow, never the
reverse, and any policy error refuses. Spend is counted at authorization, in
the same durable transaction as the nonce mark. Rules run on the reference
time (header time of the anchor, or of the reference height in fast mode), not
the gate clock, so a verifier can recompute them.

The agent signs `mandate_ref` (the exact mandate hash) into its commitment.
This stops a gate from authorizing under a mandate the agent did not act
under, and stops a silent drop of the mandate from switching the principal's
limits off. A mismatch is refused and writes no decision record, because the
decision was never policy-evaluated; the attempt stays visible in DA, since
the payload is published before authorization.

### Fast mode

Fast mode cuts latency from "wait for L1 inclusion" to "wait for
availability evidence": for Fibre, the validators' availability certificate;
for blobs, a signed anchor transaction accepted by the gate's own node. The
anchor lands in parallel. The agent signs a pending reference that includes
the reference height `h0`, so neither the gate nor the Recorder can move the
reference time afterwards.

- **Principal consent.** Fast mode weakens "anchored before the action" to
  "available before the action, anchored by the deadline". The principal, not
  the operator, accepts that: the mandate must state `fast_mode_max_delay` in
  blocks (1 to 1000). No mandate, no fast mode; a gate configured for fast
  mode without a mandate refuses to start.
- **Anchor deadline.** The gate-signed Authorization states `mode` and
  `anchor_deadline`, a height (never a tx hash). The deadline is within the
  principal's bound and leaves a minimum slack above the current head so the
  anchor can still land.
- **Absence proofs.** If the anchor is not in `[h0, anchor_deadline]`, the
  verifier proves its absence from block data against trusted headers, and
  the decision is `invalid` with `publication: failed`, attributed to the
  account that signed the anchor intent. A hostile data source can only
  withhold (absence unproven), never forge absence.
- **Residual risk (accepted).** A fast-mode action may run before its anchor
  is known to have landed. If the anchor misses the deadline, the action may
  already have executed; Edicta then proves the failure, it does not prevent
  it. Mitigations: the mandate bounds the window; executors should act only
  while their own head is below `anchor_deadline`; a strict-only executor can
  refuse fast-mode Authorizations explicitly (executors accept them by
  default, because the principal opted in).

### Private mandates and residual leakage

In private mode the mandate body, the decision content, the archived action
bytes, the verdict facts, deny reasons and counter state are encrypted with
HPKE to auditor keys the principal names. What verdict chaining and fork
detection need stays public, but as salted or blinded hashes (counter state
hashes are blinded by a per-counter secret salt), so public values cannot be
used to test guesses about amounts or limits. A deny publishes no reason or
amount, so limits cannot be probed. Auditor key ids are derived from the key,
and the rendered mandate shows each auditor's label as "not verified" next to
its full key fingerprint; the fingerprint, checked out of band, is the trust
step.

Private mode does not hide what is public by nature. The normative list is
[spec/policy-v1.md](spec/policy-v1.md), section 9.6; in short:

- executed transactions on public rails (amounts, recipients, times, hence
  aggregate spend), and the salt of an executed public-rail action, revealed
  so keyless verifiers can match the transaction;
- existence, timing and frequency of decisions;
- each decision's envelope (agent key, gate, nonce, times, action type,
  payload reference, `mandate_ref`, sizes);
- the allow/deny bit and verdict counts, including how many distinct deny
  reasons a decision got;
- linkage of mandate versions of one counter, auditor key ids, record lengths
  and bucket-rollover timing, the first allow of a counter;
- a removed auditor keeps the counter's state salt; a new mandate id is the
  remedy.

On off-chain rails (for example a broker order) action bytes are never
public, so private mode hides nearly everything except the items after the
first. Timing and length padding are not in v1.

### Principal signature schemes and rendered text

A principal signs with one of three schemes, selected by `sig_type` inside the
mandate hash (so `mandate_ref` also names the scheme):

- **Ed25519**, over a domain-tagged mandate hash.
- **Cosmos ADR-036** (Keplr, Leap `signArbitrary`), over the canonical
  human-readable rendering of the mandate followed by a line with the mandate
  hash. The wallet then shows the actual rules, and the last line binds the
  text to the CBOR. The verifier re-renders the mandate deterministically and
  verifies over the rebuilt document, so a signature over any other text
  fails. This was chosen over signing an opaque hash because a principal
  should see what they consent to.
- **EIP-712** (MetaMask), typed data carrying the mandate hash, id, version
  and gate id. Wallets show these fields, not the limits, so consent rests on
  the CLI render being what was hashed (the same as for Ed25519).

ECDSA signatures must be low-s with range checks before any curve operation,
so each signature has one encoding.

### Four disjoint key roles, and the Recorder key

Agent, gate, executor and principal keys never overlap, compared as
`(sig_type, bytes)`; auditor keys only encrypt. Domain tags already make a
signature of one role useless in another; the disjointness rule is defence in
depth, so a compromised or misconfigured gate key cannot also decide and an
audit reader never has to ask which role a signature played. The gate refuses
to start with its own key in its agent allowlist, or with a principal key that
is also a gate, executor or agent key.

The Recorder's anchor-signing key is not one of the four roles, but it signs
chain transactions with secp256k1, the same curve as ADR-036 and EIP-712
principals. Comparing only `(sig_type, bytes)` would miss the same private key
used as a Cosmos address and as an Ethereum address. The rule is therefore
stricter: `edictad` refuses to start, and refuses a new mandate version, when
the Recorder key is the mandate's principal under any scheme. In fast mode the
Recorder account must also be dedicated: it signs nothing but its own anchor
transactions, since any other transaction moves its sequence and makes an
archived anchor intent unlandable.

### Archive: availability only

The archive is trusted only to serve bytes. Integrity comes from the payload
hash signed by the agent and from recomputing the DA commitment from the
archived bytes with the upstream code, which closes "anchor blob X, sign the
hash of blob Y". Anchor proofs are checked against trusted headers, and the
validator set needed to re-check a Fibre certificate after the chain pruned it
is archived and tied to the header chain. A withheld or altered record makes a
verifier check `unchecked` with a reason, never `invalid`.

### Errata and release tags

The frozen texts are the source of truth. An erratum may only fix a
conformance expectation, or wording that contradicts other frozen text; it
never changes wire bytes, hashes, domain tags or invariants (that needs a new
format version). An erratum keeps the revision labels and gets an annotated
patch tag listing the erratum ids and the new vector manifest hashes;
`v1.0.0` never moves. The rule when a frozen vector contradicts frozen text:
fix the vector, because otherwise implementations invent a rule no text
defines.

- `v1.0.0`: the frozen v1 format (core `v1.0`, policy `policy-v1.0`).
- `v1.0.1`: erratum E1 (two expected error causes in one policy vector file;
  no wire bytes changed).

Details: [spec/ERRATA.md](spec/ERRATA.md). Vector hashes:
`spec/vectors/MANIFEST.sha256`.

## Known limitations and what has not run live

- **Enforcement depends on the integrator.** The gate cannot detect an
  executor that skips the Authorization check. The Authorization is a bearer
  token: at-most-once execution needs executor dedupe by `commitment_hash`.
- **Gate attestation in fast mode.** The availability evidence is
  gate-attested at authorization; the verifier only sees the anchor or its
  absence later.
- **Undetected-at-authorization gaps.** The gate never decrypts the payload,
  so an agent can encrypt a payload unrelated to its action, or for no usable
  recipient, and still be authorized; any recipient can prove it afterwards.
  Semantically wrong action bytes are the profile's and executor's concern.
- **Withholding gate.** A gate that withholds allows from every chain and
  evidence source is not detected until the verdict-chain head is anchored
  (planned, not in v1).
- **Not verified live:** fast mode has not run live (the
  [Mocha checklist](guide/mocha-checklist.md) has not been run, for either DA
  mode); Fibre mode has not run live; Keplr (ADR-036) and MetaMask (EIP-712)
  principal signing is vector-tested but not tested with real wallets, and
  some wallet facts (Keplr data limits and multi-line display, MetaMask
  accepting a domain without `chainId`) are marked `UNVERIFIED` in the spec.
- The `celestia_blob` mode with a mandate in strict mode has run live on the
  Mocha testnet (the `make demo` flow).
- Not production-ready.

## Further reading

- [spec/decision-commitment-v1.md](spec/decision-commitment-v1.md): core
  specification; section 1 is the threat model, section 1.1 the invariants.
- [spec/policy-v1.md](spec/policy-v1.md): mandates and policy.
- [spec/ERRATA.md](spec/ERRATA.md): errata to the frozen texts.
- [spec/profiles/](spec/profiles/): rail profiles.
- [spec/vectors/](spec/vectors/): cross-language test vectors.
- [guide/](guide/README.md): user guides for operators, principals,
  integrators and auditors.
