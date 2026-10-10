# DecisionCommitment v1

Edicta — verifiable decision layer for autonomous agents.

Status: revision `v1.0` (2026-10-09), spec revision `v1.0.4` (2026-10-11,
section 0). Frozen. Wire version: `version = 1`.
Domain tags: `edicta/v1/...`. This document is the whole core specification;
the policy layer is `spec/policy-v1.md` (revision `policy-v1.0`,
"policy"). The earlier `v0` drafts are superseded and unsupported; they are
kept for history in `spec/historical/decision-commitment-v0.md`, and nothing
here depends on them.

The core knows no rail, broker or chain. An action is an opaque byte string
bound to the commitment by its type, a salt and a tagged hash. Rail-specific
formats, checks and identifiers live in profiles; the first one is the
dca-agent profile (`spec/profiles/dca-agent-v0.md`: IBKR order action, DCA
context, IBKR client order id, executor rules); the second is the bank-send
profile (`spec/profiles/bank-send-v0.md`: Cosmos `MsgSend` action,
price-trigger context, transaction body rule, executor rules). A profile's
version is its own: the `v0` in a profile name or media type is not the core
version.

Keywords MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119. Items marked
`UNVERIFIED` are facts about Celestia, Fibre or wallets that a Celestia
protocol engineer must confirm; section 23 lists them. Everything else is
normative.

## 0. Versioning of this document

| Change | Rule |
|---|---|
| Editorial (wording, examples, sources) | No version change. |
| Any change to wire bytes, a hash or signature preimage, a limit, or the outcome of any check, while in draft | Bump `v1-draft.N`, regenerate every vector the change touches, record it below. |
| After the freeze: any change to wire bytes, a hash or signature preimage, a domain tag, a limit, an archive record layout or the meaning of a byte string | Never in v1. The v1 wire format is frozen for good. Such a change is a new wire `version` (2) with new tags `edicta/v2/...`. A v1 verifier refuses `version != 1` (`ErrUnsupportedVersion`). The archive record `format`, the payload plaintext and blob versions and the receipt version follow the same rule, each independently. |
| After the freeze: a spec change that leaves the wire format alone | Patch revision `v1.0.N` (below), one typed changelog entry. |
| After the freeze: a check outcome moved toward INCONCLUSIVE | Patch revision, only to close a path to a false `valid` or a false `invalid`, with the human's explicit approval and a changelog entry of type `security`. A verifier check may move only from `pass` (toward a `valid` verdict) or from `fail` (toward `invalid`) to `unchecked` (the INCONCLUSIVE verdict `unchecked`, exit 2); never from `pass` to `fail`, from `fail` to `pass`, or away from `unchecked`. The gate, the decoders and the executor have no INCONCLUSIVE outcome: for them the patch-level move is an acceptance that becomes a refusal (the fail-closed outcome), never the reverse. |
| After the freeze: any relaxation, that is any move away from INCONCLUSIVE or from a refusal (`unchecked` that becomes `pass` or `fail`, a refusal that becomes an acceptance), and any move between `pass` and `fail` | Never in a patch revision. Minor revision `v1.M` (`v1.1`, ...), with its own amendment of this section and the human's approval. Defining a reserved value (section 4.6) is such a minor revision: it only turns a refusal into an acceptance, and no byte string accepted before changes meaning (rule V6). |

The domain tags carry the version, so a signature never verifies across
versions even if a byte layout were identical.

Post-freeze revisions (amended 2026-10-10, human decision). The spec has one
revision counter after the freeze: `v1.0.1`, `v1.0.2`, ... Each revision
has exactly one changelog entry in the table below, of one type:

| Type | Scope |
|---|---|
| `erratum` | A conformance expectation (a vector) or wording that contradicts other frozen text; the frozen text wins (`spec/ERRATA.md`). |
| `security` | A check outcome moved toward INCONCLUSIVE (a verifier `pass` or `fail` that becomes `unchecked`; for the gate, decoders and executor an acceptance that becomes a refusal) to close a path to a false `valid` or `invalid`, as in the table above. |
| `clarification` | Wording that states what the frozen rules already do, a definition, a report label, an `UNVERIFIED` item settled, or a writer rule that no reader depends on. No check outcome changes. |

Every revision gets the annotated tag `spec-v1.0.N` (the human creates it;
`spec-v1.0.1` is on commit `0ac2689`). Frozen vector files keep their bytes
and their meaning: a new case goes into a new file, and
`spec/vectors/MANIFEST.sha256` changes in the same commit; the `revision`
field of a frozen file stays `v1.0`. Software releases are tagged with
semantic versions (`v1.0.0`, `v1.0.1`, ...), a separate sequence: their
release notes state which spec revision they implement. The software tag and
the spec tag may sit on one commit (`v1.0.1` and `spec-v1.0.1`), and their
numbers need not agree. No freeze tag ever moves.

Threat note (versioning). A patch revision that relaxed a check would let an
implementation of an older revision and one of a newer revision give opposite
verdicts on the same archive, with nothing on the wire to tell them apart.
A patch revision that moves an outcome toward INCONCLUSIVE never makes two
revisions give opposite definite verdicts: where they differ, the older one
says `valid` or `invalid` and the newer one says `unchecked`, and the move is
allowed only where the older definite verdict was a false one. A relaxation,
and any change between `valid` and `invalid`, therefore needs a minor
revision that readers and auditors can see.

Superseded vector cases (security revisions). A frozen vector file stays
byte-identical: its cases are correct for the revision they name. When a
`security` revision changes the expectation of a case, the case is listed in
`spec/vectors/SUPERSEDED.json` (file, case, revision of the changelog entry,
replacing file and case), and the new expectation on the same inputs goes
into a new file. A checker or test of the current revision skips a frozen
case only through that list, and runs the replacing case. An `erratum` is
different: there the frozen vector contradicted frozen text, was never
correct, and is fixed in place (`spec/ERRATA.md`).

| Revision | Date | Change | Vectors |
|---|---|---|---|
| `v1-draft.1` to `v1-draft.4` | 2026-10-09 | Drafts of task 031, written as additions to the `v0` drafts. The history is in git and in the task folder. | |
| `v1-draft.5` | 2026-10-09 | One self-contained v1 document (human decisions of 2026-10-09, Rounds 4 to 6: `v0` dropped before the v1 freeze). (1) Every core rule the `v0` drafts held is restated here for version 1; the version dispatch, `AcceptV0`, `ErrVersionNotAccepted`, the `/v0/` routes and alias, the Authorization of version 0, the unsalted action hash and the payload schema chosen by the commitment version are gone. (2) Receipt, record request, publish request and the payload AEAD and HPKE tags move to `edicta/v1/*`; receipt `version = 1`; payload blob `version = 1`; payload plaintext `version = 1` with the action salt (sections 9, 14, 17). (3) Archive records `format = 1`: kinds 17 (decision) and 18 (reveal) keep their numbers, kind 3 is unassigned, the evidence record drops `promise_valset` (key 18) and the legacy anchor-proof form 0 (section 19). (4) Verifier: the Authorization rules are A1 (mode) and A2 (deadline range); the reason `replay_unconfirmed` is gone with form 0; new reason `gate_signed_inconsistent_private_part` and the matching policy rule (policy 13); O8 runs before the payload-versus-archive salt comparison (section 20.11). (5) HTTP paths `/v1/*` only; the authorize request requires its key 3. | Core vectors under `spec/vectors/v1/` carry the coverage of the `v0` sets as v1 cases (`v1-draft.5`); the `v0` sets moved unchanged to `spec/vectors/historical/v0/` and are not checked. Archive, policy, absence, reasons, API and profile files regenerated (section 22). |
| `v1-draft.6` | 2026-10-09 | Pre-freeze re-audit fixes (task 031, `audit-2.md`). Later note, no new revision: invariant 8 in section 1.1 now states the M0 refusal and the no-record rule, with the rationale in section 8.8; `CLAUDE.md` carries one-line summaries, not a verbatim copy. Later note, fix verification (`audit-2.md` F1, F4, F6 to F8), no new revision: AB4 never gives absent at an app version other than the pinned one, `S` empty included (not proven), and AB3 states that its row selection assumes the pinned layout (F1; outcome change: such a height was absent, now unproven; vector `fibre_s_empty_other_app_version` in `da/absence.json`, other cases byte-identical); section 10.9 threat notes say HR (F4); the `RevealOnExecution` registry check runs in the constructor, the registry being a dependency the integrator's build fills (F6); a mandate version whose `fast_mode_max_delay` is below the slack is refused as a whole, with the reason (F7); 8.8 restates the stored-retry check through the 8.7 retry rule (F8). (1) AB4: a `PFF_NS` unit that does not decode as a PFF tx makes the height not proven, at any app version, and at an app version other than the pinned one units without a candidate prove nothing (section 20.8); NA5 states that the gate may skip such a unit (MJ1). (2) Stage 4m runs at every gate: new rule M0, a gate without a mandate refuses a commitment with `mandate_ref` (`ErrMandateMismatch`); the verifier requires the `policy` check whenever the envelope has `mandate_ref` (sections 8.7, 8.8, 20.5) (MJ2). (3) After an M0 or M2 refusal the gate writes no decision record, no kind 15 record and no marker; `ErrMandateMismatch` is no longer a marker name (sections 8.7, 8.8, 19.2) (MJ3). (4) `RevealOnExecution` admits only types whose compiled profile has `public_execution = true` (cause `reveal_not_public_execution`) (section 8.9). (5) With `FastMode` on, a mandate whose `fast_mode_max_delay < MinFastSlackBlocks + 1` is refused at start and at adoption (cause `fast_delay_below_slack`) (section 8.9). (6) Rule ids: the at-height rules of section 10.9 are HR1 to HR5 (were AH1 to AH5, which collided with the action-hash rules of 5.1), the verifier Authorization rules of 20.5 are AM1 and AM2 (were A1 and A2, which collided with stage A). (7) Editorial: the salt in the inputs of 8.6 and 8.7; section 22 explains the `edicta-vectors/v0` file labels. | `da/absence.json` (new synthetic cases `fibre_unit_undecodable`, `fibre_no_candidate_other_app_version`); new `v1/stage4m.json`; `v1/archive.json` (record `rejection_ErrMandateMismatch` replaced by `rejection_ErrMandateRefMissing`, new reject `rejection_mandate_mismatch_not_a_marker`, `marker_names`); `archive/records.json` (`verdicts`); `api/errors.json` (example `authorize_mandate_ref_without_mandate`, rules `M0, M2`); `policy/verify.json` (`mandate_ref_without_verdict`); `v1/gate.json` (`profile_registry`; `reveal_type_allowlisted` now uses the bank-send type; new `reveal_type_offchain_profile`, `reveal_type_without_profile`, `fast_delay_below_slack`, `fast_delay_at_slack_plus_1`, `fast_delay_low_fast_mode_off`); `v1/verify.json` (`rule` values `AM1`, `AM2`). |
| `v1.0` | 2026-10-09 | Frozen; identical rules to `v1-draft.6` plus later notes (invariant 8 in section 1.1 with the M0 refusal and the no-record rule; dedup-hit marker rule of policy 12.1). Revision labels of the vector files are `v1.0`. | all core vectors |
| `v1.0.1` | 2026-10-10 | Type `erratum`. E1 (`spec/ERRATA.md`): the record causes of `policy/archive.json` follow the general record reader of 19.1. Tag `spec-v1.0.1`. | `policy/archive.json` (two `cause` values) |
| `v1.0.2` | 2026-10-10 | Type `clarification`. E2 (`spec/ERRATA.md`), human decisions of 2026-10-10 (task 045): "anchored" means inclusion proven, never a result code (new section 10.6.3). `da = 2`: the blob's commitment proof against the data root of the trusted header. `da = 1`: the complete `PFF_NS` namespace proof against `data_hash`, the PFF selected by its commitment, CV2, and the certificate CV3 to CV7 offline against the archived `historical_info` with the promise header on the trusted chain. The anchor tx result code is reported as `node-reported, not part of the claim` (20.9, 10.6.1, 20.10); CV8 keeps requiring the archived code 0 (dropping it would be a relaxation). Settled `UNVERIFIED` items: shard retention is independent of the PFF outcome, a PFF can be included with a non-zero code only through an ante failure, and the keeper's height window at the pin (sections 10.4, 10.6.1, 13.1, 23). The 10.7 item on block results for a proven settlement level becomes MAY. Human answers R3 (task 045): 10.6.3 states that v1.0 verifiers additionally require `tx_code == 0` (CV8) and that v1.1 removes it; the included-reference height window is an explicit assumption with the pinned ProcessProposal call path, and the pending-reference window is the gate's K-fast rule, with its vectors and tests named; new re-pin checklist (section 23.2). No check outcome changes. | none |
| `v1.0.3` | 2026-10-10 | Type `security` (human decision of 2026-10-10, task 045, "AB5 security fix"; closes a path to a false `invalid`). `da = 1` absence: a PFF candidate for the reference inside `[h0, anchor_deadline]` counts as present whatever its result code, so absence is never proven at its height. Up to `v1.0.2` a candidate whose code AB5 proved non-zero made the height absent, and an honest anchor whose PFF was included with a non-zero code (an ante failure in FinalizeBlock, section 10.4 facts) gave `anchor_absent`, a false `invalid`. AB5 now classifies a candidate height as present (a proven code 0), present unpaid (every code proven, none 0) or not proven (section 20.8). Presence still needs code 0 in v1.0 (CV8), so a present-unpaid height gives `anchor` `unchecked` with the new reason `anchor_unpaid` ("anchor included, non-zero result code; not confirmable by v1.0 verifiers"), never `fail` (sections 20.1.1, 20.6, 20.10, 10.6.3). Outcome moves: `fail` `anchor_absent` to `unchecked` `anchor_unpaid` only. Section 0 states the patch-level rule (toward INCONCLUSIVE only) and the handling of superseded vector cases; `spec/ERRATA.md` and the errata procedure record the erratum versus security distinction. The reason enum has 44 reasons. | `da/absence.json` and `verifier/reasons.json` byte-identical; superseded cases listed in the new `SUPERSEDED.json`: `da/absence.json` `fibre_candidate_nonzero_code` and `window_three_heights_proven`. New files: `da/absence_v1.0.3.json` (the two cases on the same inputs, `window_unpaid_with_unproven_height`, `window_paid_after_unpaid`), `v1/verify_v1.0.3.json` (pending decisions with an in-window unpaid candidate, end to end), `verifier/reasons_v1.0.3.json` (the reason `anchor_unpaid`, additive to `reasons.json`). |
| `v1.0.4` | 2026-10-11 | Type `clarification`. E3 (`spec/ERRATA.md`), human decision Q2 of 2026-10-10 (task 044): the header-trust bound of a pending reference, `max(D, H)` (and `D + 1` for an AB5 results proof, section 20.6; HT1), holds for every kind of header trust, a trusted header file, an explicit or agreed checkpoint (20.4) or any other trust an implementation adds. A trust that cannot name its checkpoint height `T` cannot show that bound, so `header_trust` stays `unchecked` (HT1, HT7), never `pass`. The frozen rules already said this; no check outcome of the spec changes. Conformance note: an implementation whose header-trust kind accepted a checkpoint below the bound, or an unknown one, gave a `pass` the frozen text never allowed; its fix moves that outcome only toward INCONCLUSIVE (`pass` to `unchecked`) and is a conformance bug fix of the implementation, recorded here, not a `security` revision of the spec. No frozen vector expects a `pass` with a checkpoint below the bound (every `pass` case of `v1/verify.json` has `trusted_head` 4200127 with `anchor_deadline` 4200126). | none |

Editorial note, no revision: the post-freeze rows of the first table and the
revision scheme above were amended on 2026-10-10 by the human's decision. The
amendment changes no wire byte, check outcome or vector.

## 1. Threat model in one table

Each mechanism below names what it defends against and what it assumes.
Policy section 1 adds the mandate layer.

| Mechanism | Defends against | Assumes |
|---|---|---|
| Ed25519 over a tagged hash (section 5) | Forged or altered commitments; cross-protocol reuse of signatures | Agent private key is secret; gate allowlist maps `agent_id` to the right key (section 8.7) |
| Public key validity, rule G0 (section 5) | Universal forgery under a small-order `agent_pubkey` (for the identity key, `R = identity, S = 0` verifies for every message); key aliasing through non-canonical encodings | Ed25519 discrete log is hard in the prime-order subgroup |
| Canonical CBOR, strict decoder (section 6) | Two byte strings for one commitment (malleability); parser differentials between Go and Python; decoder DoS | Both implementations follow this document, checked by shared vectors |
| Scope `gate_id` (section 4.2) and the gate's action-type set (rule C2) | Replay at another gate; a commitment for an action type this gate was not set up for | Each gate has a unique `gate_id`. Scope does **not** bind an account, rail or chain: cross-domain binding is the profile's job (section 16) |
| Salted action hash (section 5.1) | Executing other bytes than the committed ones, or the same bytes under another type (type confusion between formats); an ambiguous `type \|\| salt \|\| bytes` split; a dictionary search of low-entropy actions (order parameters, amounts) against the public `action_hash` | SHA-256 collision and preimage resistance. Exact match only: the core never interprets the bytes, so a re-encoding of "the same" action is simply not authorized. The 32-byte salt is fresh from a CSPRNG per commitment and stays wherever the action bytes are secret (payload, gate, executor, auditors) |
| Nonce (section 4.1) | Replay at the same gate | The gate consumes the nonce atomically with issuing the Authorization and returns the Authorization only after the mark is durable (invariant 5, section 8.7); at most one Authorization per `(agent_pubkey, nonce)` |
| `valid_until`, MaxTTL (section 12), Authorization `expires <= valid_until` (section 15) | Stale decisions authorized or executed late; executing after the payload may have left Fibre | Gate clock within 30 s of true time; the executor's clock within `skew_s` of the gate's |
| Authorization (section 15) | An executor acting on a decision the gate did not verify; reusing an Authorization for other bytes, another type or at another gate's executor; taking a gate signature for an agent or receipt signature | Gate key secret, and pinned by the executor as `gate_id -> gate_pubkey` out of band. It is a **bearer token**: whoever holds it, the action bytes and the salt can present it until `expires`, so it gives at-most-once execution only together with executor dedupe |
| `mode` and `anchor_deadline` in the gate-signed Authorization (section 15) | An executor or auditor unable to tell an anchored decision from an only attested one; a gate that never states when the anchor was due | Executors read the Authorization alone; the deadline is a height, not a tx hash (invariant 6) |
| Executor dedupe by `commitment_hash` (section 16) | One Authorization executed twice: replay at the executor, a retry after a timeout, a crash between send and record | The integrator implements it, atomically with execution or through rail-native idempotency; the record outlives `expires + skew_s` |
| Domain self-identification in the action format (section 16) | Bytes authorized for one domain executed in another (another broker account, chain or contract) | The profile's format names its domain inside the bytes (EVM: `chain_id` in the transaction; dca-agent profile: the IBKR account in the order) and the executor compares it with its own. The core provides only `gate_id` and the type allowlist |
| Integrator enforcement (section 16) | Nothing by itself: the core cannot make an executor check anything | **Open dependency.** Edicta protects a rail only where whatever holds the rail credentials (a signer, a contract, middleware in front of a broker API) runs `VerifyAuthorization` on the exact bytes it executes and refuses otherwise. An integrator that skips this has no Edicta protection, and the gate cannot detect it |
| `ciphertext_hash`, `payload_size` (section 9) | Archive or DA serving different bytes; oversized fetches | SHA-256 collision resistance |
| `plaintext_hash` with 32-byte salt (section 9) | Brute-forcing a low-entropy plaintext from the public commitment | Salt is uniformly random and stays inside the ciphertext |
| Action salt inside the payload (section 9.3) | A payload recipient unable to check that the payload's action is the committed one (O8) | The payload is the agent's, bound by `plaintext_hash` |
| `payload_ref` + L1 anchor (section 10) | Claiming a payload was public when it was not | More than 2/3 of voting power is honest (Celestia assumption) |
| `payload_ref.signer` with share version 1 (section 10.5) | An L1 blob with the same bytes posted by another account being taken as the Edicta anchor; an unrecomputable share commitment | Same as the row above: the blob-signer rule is enforced in CheckTx and ProcessProposal |
| `mandate_ref` in the agent-signed commitment (sections 4.1, 8.8) | A gate authorizing under a mandate the agent did not commit to; an allow after a silent mandate change; a gate with no mandate at all (dropped from the configuration) authorizing a decision committed under one, so the principal's limits are silently off | The agent knows the hash of the mandate it acts under (the principal CLI prints it) and omits key 14 when it acts under none; the gate's refusal (M0, M2), the verifier's `mandate_ref_mismatch` and the verifier's rule that `mandate_ref` makes the `policy` check required (section 20.5) all read signed data |
| `h0` inside the agent-signed commitment, plus `MaxH0AgeBlocks` (sections 11.2, 13) | A gate or Recorder choosing or shifting the reference height (and so `T_ref`, the policy clock and the deadline) after the agent signed; a stale `h0` used to land spend in an old window | The agent signs only after verifying the anchor intent (W5-P); the gate's head is honest within the gate's own node; the verifier checks `H >= h0` |
| K-fast: verified anchor intent before a fast-mode Authorization (section 13) | Authorizing a payload that was never made available, in exchange for latency | Fibre: the 2/3 certificate under the network's quorum rule against the validator set at `h0` (section 10.6.1); blob: the gate's own node accepted the signed PFB for exactly this blob. Both are gate-attested at authorization; the verifier only sees the anchor or its absence later |
| K-fast slack: `anchor_deadline >= head + MinFastSlackBlocks`, and for Fibre a promise that does not expire within `MinPromiseSlackSeconds` (section 13) | A fast-mode Authorization whose anchor can no longer land in `[h0, anchor_deadline]` | The slack covers mempool latency of the gate's own node; a tx already included in the window waives it (section 13.3) |
| Fast mode only with a mandate and its `fast_mode_max_delay` (sections 8.3 C5a, 8.9; policy 6.1, 8.2) | An operator enabling fast mode for a principal who never accepted the weaker guarantee | A gate with `FastMode` refuses to start without a mandate; the principal signed the bound; the gate clamps the deadline to it; the verifier requires the `policy` check for `mode = 2` and checks the bound from signed data (section 20.5) |
| Absence proof over `[h0, anchor_deadline]` (section 20.8) | A fast-mode decision whose anchor never landed passing as valid | Header trust (section 10.6.2) reaches `anchor_deadline` (or `anchor_deadline + 1`); SHA-256 and NMT completeness. A hostile source can only withhold (`absence_unproven`), never forge absence |
| Reserved values refused (section 4.6) | A v1.0 reader silently accepting a future batch-leaf or attestation reference under a meaning it does not implement | Readers implement the refusal; defining a value later needs the human's approval |
| Archive fallback (section 12.3) | Fibre pruning before the commitment expires | Archive is honest for availability only; integrity comes from the hash (P2) and the recomputed DA commitment (P3) |
| DA commitment recompute, rule P3 (section 8.5) | "Anchor X, sign H(Y)": an agent or Recorder anchors blob X, archives blob Y and signs `ciphertext_hash = H(Y)`, so a hash-only check accepts bytes that were never public | SHA-256 collision resistance; the recompute is the upstream code at the pin (`fibre.NewBlob` for `da = 1`, go-square for `da = 2`), checked by vectors generated from that code alone |
| Reference time `T_ref` and rules K1, K2 (section 12.2) | A commitment signed before its payload was public; a commitment whose validity outlives the DA retention window being executed as if the DA layer still served the payload | The gate reads true header time from a node it trusts (the operator's own node is recommended; a public endpoint is allowed). Every read at a past height, on every module and on both `da` paths, is used only if the response echoes the requested height and, where the content allows, is bound to the header at that height (HR1 to HR5, section 10.9). At-height retention comes from such a read on an endpoint that passed the canary, or from the gate's own persisted observations (observations-only mode when the endpoint ignores heights); a non-monotone pair of changes between two observations (for example a change and its revert) is missed (RS1 to RS6, section 12.2) |
| PFF certificate check, one rule for gate, Recorder and verifiers (section 10.6.1) | A forged or under-signed availability certificate presented after the chain pruned the state that could re-check it | More than 2/3 of voting power honest at `PaymentPromise.height`; the archived validator set is the one the chain used, tied by `next_validators_hash` to the header at `PaymentPromise.height` and that header to the chain by the hash chain of section 10.6.2; Ed25519 |
| Fibre anchor proof from namespace data, rules NA1 to NA7 (section 10.4) | A bridge or an archive presenting a PFF that was not in block `height`, hiding one that was (a false `ErrAnchorNotFound`, or an earlier promise that would move K2's `start`), or a cut or padded tx | The header at `height` is the chain's: the gate's trusted node or the W5 verifier (section 10.9), and for verifiers the header trust of section 10.6.2; SHA-256; NMT completeness as in nmt `v0.24.3` or later; more than 2/3 of voting power honest, so the square follows the protocol. Result code 0 stays `node-attested` |
| "Anchored" means inclusion proven, never a result code (section 10.6.3) | A verifier calling a payload published on a node's word. Adversary: one party that writes the archive and also controls the node the anchor's result code was read from | `da = 2`: the commitment proof against the data root of the trusted header. `da = 1`: the complete `PFF_NS` namespace proof against `data_hash`, CV2, and the certificate (CV3 to CV7) against the archived `HistoricalInfo` tied to the trusted chain. The archived `tx_code` is the only node-attested field of the evidence and is not part of the claim, so that adversary can hide an unpaid escrow, not fake a publication. Validators keep their shards whatever the PFF's result (time-only pruning); more than 2/3 of voting power honest, so every included PFF passed its message, height window included, in ProcessProposal |
| Startup compatibility check (section 10.8) | Silent divergence after an upstream change: another Fibre encoding, another sign-bytes layout, another chain or a node that answers in another format | The pinned versions and the known-answer vectors describe the network; the check runs before the gate serves |
| Registry epoch, rule E1 (section 8.7) | Replay after the nonce registry was lost or recreated | The gate clock did not step back across the recreation |
| Signed receipt and record request (section 14) | A fabricated `commitment_hash -> rail_ref` mapping in an archive or report; two different mappings for one decision; a third party who holds the (non-secret) envelope recording a bogus `rail_ref` first and so owning the decision's only receipt | Gate and executor private keys are secret; the gate admits a claim only if it is signed by a key in its executor allowlist, over a message that names this gate, this decision and this `rail_ref`; the receipt carries the executor key and signature, so a verifier needs no trust in the gate for who claimed what; the gate stores at most one receipt per authorized decision. **Not proof of execution**: the receipt attests that a known executor claimed `rail_ref`, and that the gate recorded that claim; whether the rail executed anything is only in the rail's own records. A compromised or malicious allowlisted executor can still claim a false `rail_ref` first |
| HPKE-wrapped DEK per recipient, payload AEAD (section 9.1) | Reading the decision without a recipient key; using a payload ciphertext or a wrapped DEK under another Edicta or non-Edicta purpose (length-prefixed `edicta/v1/payload*` tags) | X25519 CDH is hard; recipient private keys are secret; the DEK is fresh per blob. Base mode authenticates no sender: authenticity comes only from the agent signature over `ciphertext_hash` and `plaintext_hash` |
| Public `kid` per recipient (section 9.1) | Nothing: it is a label that lets a recipient find its entry | **Leaks** the auditor and counterparty identities when kids are meaningful labels (`auditor-1`, a fund or broker name), the recipient count of every payload, and links all payloads that share a recipient. Accepted. HPKE base mode does not reveal `pkR` from `enc`, so random per-blob kids (recipients try every entry) remove the leak without a format change |
| `plaintext_hash` checked before parsing, rule O7 (section 9.4) | A malicious agent showing two recipients two different decisions from one blob: ChaCha20-Poly1305 is not key-committing, so one ciphertext can open under two DEKs wrapped for different recipients (vector `pb_key_commitment_two_deks`) | SHA-256 collision resistance; every recipient runs O7 on the full AEAD plaintext before using it. A recipient that only runs the AEAD is not protected |
| Strict blob decoding, rules B0..B7 (section 9.2) | Two recipients or verifiers disagreeing on which entries or ciphertext a blob holds | Every reader implements B0..B7; shared vectors |
| Local DA commitment recompute before signing, rule W4 (section 9.5) | A buggy or malicious Recorder that anchors blob X while the agent signs `ciphertext_hash = H(Y)`: the agent's key would sign a false "Y was public at H". The gate would still reject at P2 or P3, so this protects the agent's reputation and liveness, not gate safety | The producer recomputes from its own bytes, for `da = 1` with the Fibre committer (section 10.4); a producer built without it refuses unless explicitly opted out |
| Decision record, private form (sections 19.2, 20.11) | The action bytes of a private-mode decision read from a shared archive, including a decision refused because it names another mandate than the one in force (M0, M2: no record is written, section 8.8) | Private form stores the action only HPKE-encrypted to the auditors (kind 15 plaintext 5); the gate gets the bytes from the integrator, never from the archive |
| Reveal on execution (sections 19.2, 19.7, 20.11) | A keyless verifier unable to tie a public on-chain execution to the salted `action_hash` | The tx is public anyway and the receipt links it to the decision; the revealed salt is self-verifying against the agent-signed `action_hash`; only actions with a receipt and a `public_execution` profile are revealed |
| Private mode (policy 9.6) | Everyone reading the mandate's rules and the decision content from a shared archive | What private mode does not hide is listed normatively in policy 9.6 (residual leakage) |
| Nothing (open gap) | An agent that wraps a DEK no recipient can use, or that encrypts a payload unrelated to the action, still gets authorized: the gate never decrypts | Detected after the fact: any recipient holding the envelope and blob has signed evidence (O5, O6, O7 or O8 failure). Not prevented |
| Nothing (out of core scope) | Action bytes that are malformed, unsafe or semantically wrong for the rail (notional, price, instrument): the core authorizes exactly what the agent committed and checks no semantics | The profile's strict decoder and the executor's own limits (for example the dca-agent profile's account check and operator risk limit). A malicious caller can obtain an Authorization only for bytes the agent committed to |
| Nothing (accepted) | A fast-mode anchor that misses its deadline: the action may already have run | The executor MAY refuse `mode = 2` (profile rule) and SHOULD act only while its own head is below `anchor_deadline` (profiles); the mandate bounds the window; the decision is provably `invalid` afterwards (`anchor_absent`, `publication: failed`) |
| Blob submitter (Recorder, relay) trusted for liveness only; rules W4, W5, W6 (section 9.5) | A submitter that anchors other bytes, anchors under an unexpected account or namespace, or reports a false height or block time, getting the agent to sign a false "public at H" | The submitter is untrusted for integrity: it can refuse, delay, or anchor under its own account, and nothing else. The producer recomputes the DA commitment from its own bytes (W4), verifies inclusion of that commitment under a header it verified itself from sources the submitter does not control (W5, W5-P for a pending reference), and only then signs; the gate re-checks K0 (or K-fast), K1, P1 to P3. Worst case: censorship or delay, visible as a missing or late decision, bounded by W6 |
| Independent inclusion check, rule W5, three trust levels (section 9.5) | A lying submitter or a lying proof-serving node | `Light` (cryptographic): a trust anchor, more than 2/3 of voting power honest at H, and at least one honest header provider among primary and witnesses. `CrossCheck` (weaker interim substitute, MUST be identified as such): at least one of two or more independent header providers is honest and they do not collude; no signature is checked. `SelfCheck`: the operator's own node, allowed only when submitter and producer are one operator. A commitment proof can come from any node: it is checked against the verified header's data root |
| Agent-signed publish request (section 17) | A party without an allowlisted agent key spending the Recorder operator's fees; probing the allowlist; reusing an agent signature of another kind as a publish request; replaying a request at another Recorder | Agent keys are secret; each server's `gate_id` is unique (it is signed into the message). Domain separation (tag length 25, unique) keeps publish requests apart from commitment signatures. A replay at the same server inside the window is answered from the dedupe record (PR6) or finds the earlier submission (PR8), so it spends no second fee; it never creates a decision. Quotas are per `agent_id`, count requests rather than fees (PR7), and are checked before anything is submitted |
| DA allowlist, rule C3 (section 8.3) | A gate authorizing a `da` it cannot check on its chain (for example `da = 1` where `x/fibre` is absent) | The operator configures the set; a gate that allows `da = 1` refuses to start if it cannot read Fibre parameters |
| Byte-identical resend, amended rule I5 (section 16.1) | A transfer lost in a mempool never landing, and a "fix" that builds a second transaction and executes twice | The rail includes the same signed bytes at most once (an account sequence) and the profile bounds the window (a timeout height). The bound is in blocks, not seconds: a slower chain moves the last possible inclusion later in wall-clock time (bank-send profile, section 4) |
| Verifier online mode: HTTP archive reads, agreed checkpoint, cross-check (sections 20.3, 20.4) | An archive server or header source that withholds, alters or fabricates data in order to make `verify` print `valid` | The archive is trusted for availability only, because every record is re-checked. The checkpoint is as honest as the agreeing operators: with `quorum = 1` a single operator that colludes with the archive's writer can fake the chain (HT4 checks no signatures). The report names that operator, and one honest cross-check source turns the fake into `unchecked` (`header_disagreement`). A withheld or altered archive record gives `unchecked` with a reason (20.1.1), never `invalid` |
| Execution check (section 20.2 and the profile's checker) | A receipt whose `rail_ref` names no transaction, another transaction, one before the anchor, or one that failed | The trusted header and SHA-256: inclusion proof (F5) and result proof against `last_results_hash` (F7). Agreement of tx sources (F6) is reported only, and it never decides the outcome. A hostile source can only make the check `unchecked` (20.2.1). Does not detect a second execution of the same decision |

### 1.1 Invariants (source of truth)

The gate invariants of the project, one line each. `CLAUDE.md` carries a
one-line summary of each invariant with a reference to this section; any
change to an invariant here updates `CLAUDE.md` in the same commit, and the
auditor checks that both agree. Section numbers without
a prefix are this document; "POL" is `spec/policy-v1.md`.

1. Agent signature over `commitment_hash` is valid (5, 8.1, 8.7 stage 1).
2. Payload available (Fibre or archive) and its hash matches; a pending reference also needs a verified anchor intent (8.5, 8.7 stage 9, 13).
3. Presented action bytes are exactly the committed ones, no semantics, and `action_type` is allowlisted: `action_hash = H(tag("edicta/v1/action") || uint8(len(type)) || type || salt32 || action_bytes)` with the agent's 32-byte salt presented alongside (missing salt refused, wrong salt `ErrActionMismatch`) (5.1, 8.3 C2, 8.4, 15.3 X3).
4. `now < valid_until`, `valid_until` well below Fibre retention measured from `T_ref`, Authorization `expires <= valid_until` (12.2, 15.1).
5. Nonce unused; marked used atomically and durably before the Authorization leaves; at most one per `(agent_pubkey, nonce)` (8.7 stage 12; POL 11.4).
6. `commitment_hash` over canonical encoding, never a field of what it hashes; no signed object carries a tx hash or rail reference (`anchor_deadline` is a height) (5, 15.1; POL 10.2).
7. The gate signs only after 1-6, 8, 9 hold, under its own tags; four signing roles never overlap: agent, gate, executor, principal keys, compared as `(sig_type, bytes)`; auditor keys only encrypt, never sign (2, 8.7; POL 2.1, 6.1).
8. With a mandate: issue only if the verdict for exactly the committed action allows; facts by the registered extractor, else deny; rules on the policy clock `T_ref` (header time at `h0` for a pending fast-mode reference, else `T_H`); counter update in the nonce transaction; deny-only, fail-closed; mandate principal-signed under its `sig_type`, bound to `gate_id`, version not lower; `mandate_ref` equals the mandate in force. Without a mandate, a commitment that carries `mandate_ref` is refused. A refusal for a `mandate_ref` other than the mandate in force (or present without one) writes no decision record (8.7 stage 4m, 8.8 M0 and M2, 12.2; POL 8, 11.2).
9. The Authorization states `mode` (strict iff the reference is included, fast iff pending) and, in fast mode, the `anchor_deadline` height; fast mode only with principal consent (mandate `fast_mode_max_delay` present; no mandate, no fast mode), deadline within that bound and at least `MinFastSlackBlocks` above the head; a missing anchor by the deadline is provable by absence proofs (8.3, 8.9, 13.3, 15.1, 20.8; POL 8.2 P15).

Process rule: any change to an invariant in the spec updates this block and
the matching `CLAUDE.md` summary line in the same commit; the auditor checks
that the spec and `CLAUDE.md` agree.

## 2. Notation and tags

- `||` is byte concatenation. `len(x)` is a length in bytes.
- `uint` is a CBOR major type 0 integer. All integers in a commitment are in
  `[0, 2^63-1]` (rule S2).
- Hex is lowercase. Times are Unix seconds (UTC, no leap-second smearing
  assumptions beyond what the host clock does).
- `H(x) = SHA-256(x)`.
- "The operator's own node" is a node the operator chose and controls (its
  configuration and, where it signs, its keys). It need not be self-hosted:
  a node on rented or managed infrastructure under the operator's sole
  control counts. Its host is trusted like any host of the operator.
- "Agent" is any decider that signs commitments: an LLM agent, a bot, a
  keeper or a script. The gate never asks the agent why an action is
  allowed. It verifies mathematically that an existing commitment (and the
  mandate, if one is configured, `spec/policy-v1.md`) allows exactly these
  action bytes.
- `tag(t) = uint8(len(t)) || ASCII(t)`, with `1 <= len(t) <= 255`. One length
  byte means there is no width or endianness choice to get wrong.
- `canon(x)` is the canonical CBOR encoding of `x` in the section 3 profile.

| Tag name | ASCII (length, `tag(t)` first byte) | Use |
|---|---|---|
| `TagCommitment` | `edicta/v1/decision-commitment` (29, `0x1d`) | `commitment_hash = H(tag \|\| canon(Commitment))` (section 5) |
| `TagSig` | `edicta/v1/sig` (13, `0x0d`) | agent signature over `tag \|\| commitment_hash` (46 bytes) |
| `TagAction` | `edicta/v1/action` (16, `0x10`) | `action_hash = H(tag \|\| uint8(len(type)) \|\| type \|\| action_salt \|\| action_bytes)` (section 5.1); hash only |
| `TagAuthorization` | `edicta/v1/authorization` (23, `0x17`) | `authorization_hash = H(tag \|\| canon(Authorization))` (section 15) |
| `TagAuthorizationSig` | `edicta/v1/authorization-sig` (27, `0x1b`) | gate signature over `tag \|\| authorization_hash` (60 bytes) |
| `TagReceipt` | `edicta/v1/receipt` (17, `0x11`) | the receipt hash (section 14) |
| `TagReceiptSig` | `edicta/v1/receipt-sig` (21, `0x15`) | the gate's receipt signature over `tag \|\| receipt_hash` (54 bytes) |
| `TagRecordRequest` | `edicta/v1/record-request` (24, `0x18`) | an executor's record request, signed directly (section 14.3) |
| `TagPublishRequest` | `edicta/v1/publish-request` (25, `0x19`) | an agent's publish request to a Recorder, signed directly (section 17) |
| `TagPayloadAEAD` | `edicta/v1/payload` (17, `0x11`) | aad of the payload AEAD (section 9.1); never hashed or signed |
| `TagPayloadDEK` | `edicta/v1/payload-dek` (21, `0x15`) | HPKE `info` for wrapping the DEK (section 9.1); never hashed or signed |
| `TagAuditorKid` | `edicta/v1/auditor-kid` (21, `0x15`) | `kid = H(tag \|\| auditor X25519 pubkey)[0..16]` (policy 6.1); hash only, never signed |
| `TagBatchLeaf` (reserved) | `edicta/v1/batch-leaf` (20, `0x14`) | reserved for a batch leaf hash; not used in v1.0 (section 4.6) |

Every hash that is signed or compared is under its own tag (`TagCommitment`,
`TagReceipt`, `TagAction`, `TagAuthorization`, `TagAuditorKid`), and every
signature is over its own signature tag, with signed-message lengths 46
(agent), 54 (receipt) and 60 (Authorization) bytes. An executor's record
request (section 14.3) is signed directly, without a hash, and its tag has a
length (24) that no other hashed or signed tag has, so its first byte already
differs from every other preimage. An agent's publish request (section 17) is
also signed directly, under a tag of length 25, which likewise no other hashed
or signed tag has. No two hashing tags and no two signature tags are equal, so
no Edicta hash or signature can stand in for another (rule H3).

`TagPayloadAEAD` has the length of `TagReceipt`, and `TagPayloadDEK` that of
`TagReceiptSig`. That is harmless: the length byte carries only the length,
the ASCII differs, and the payload tags are never hashed or signed, only used
as AEAD `aad` and HPKE `info` (vectors `pb_aead_aad_receipt_tag`,
`pb_hpke_info_payload_tag`). `TagAuditorKid` also has the length and first
byte of `TagReceiptSig`: the kid preimage `0x15 || "edicta/v1/auditor-kid" ||
pubkey32` is 54 bytes like the receipt's signed message, but the ASCII
differs at byte 11 and the kid is never signed, so neither stands in for the
other.

Tag namespace: every tag family has the form `edicta/<family>/v<N>/<name>`;
this core uses `edicta/v1/<name>`. Tags are never reused, and no two tags of
any family are equal. The tags `edicta/v0/*` of the superseded drafts are
never used again. The policy family `edicta/policy/v1/*` (`TagPrivatePart`,
`TagPrivateAEAD`, `TagPrivateDEK`, `TagStateBlind`, `TagBlindKey` and the
others) and its rules are in policy section 2.

## 3. Wire format and CBOR profile

```
SignedCommitment = { 1: Commitment, 2: signature }    ; the "envelope"
```

The CBOR profile is RFC 8949 section 4.2.1 (core deterministic encoding)
restricted further:

1. Only these data items appear: major 0 (uint), major 2 (byte string),
   major 3 (text string), major 5 (map). Major 4 (array) appears only in the
   payload blob (section 9), never in a commitment, an Authorization, a
   receipt or the payload plaintext. Major 1, 6 and 7 never appear. (Profile
   bodies such as a context media type define their own rules.)
2. Every head uses its shortest form.
3. Every length is definite.
4. Map keys are uints. In the commitment all keys are in `1..23`, so each key
   is one byte and bytewise order equals numeric order. Keys are strictly
   ascending.
5. Optional fields are absent when unset. They are never encoded as `null`
   or as an empty value.
6. Required fields are always present, including when their value is zero.
   Go structs MUST NOT tag required fields `omitempty`.
7. Text strings are UTF-8 and restricted to ASCII charsets (section 4.5).

Size limits, all checked before or during parsing so decoding is bounded:

| Limit | Value | Sentinel |
|---|---|---|
| Envelope bytes | `<= 2176` (`MaxSignedSize`), checked before parsing | `ErrTooLarge` |
| Commitment bytes (the value of envelope key 1) | `<= 2048` (`MaxCommitmentSize`) | `ErrTooLarge` |
| Container nesting depth (envelope = depth 1) | `<= 4` | `ErrNestingTooDeep` |
| Entries per map or array | `<= 16` | `ErrTooLarge` |
| `payload_size` | `<= 2^27` (`MaxPayloadSize`) | `ErrPayloadTooLarge` |
| Action bytes supplied to the gate or an executor | `1..65536` (`MaxActionSize`), checked before hashing | `ErrActionSize` |
| SignedAuthorization bytes | `<= 256` (`MaxAuthorizationSize`), checked before parsing | `ErrTooLarge` |
| SignedReceipt bytes | `<= 512` (`MaxReceiptSize`), checked before parsing | `ErrTooLarge` |

A schema-valid commitment is at most 596 bytes (envelope 665; keys 1 to 13
at their longest plus 35 bytes for key 14 and 2 for `payload_ref` key 6, the
map heads staying one byte), the largest SignedAuthorization 233 bytes and
the largest SignedReceipt 452 bytes, so these limits only bite on hostile
input (vectors `v1/limits.json`).

`MaxActionSize` reasoning: an empty action is meaningless; 64 KiB fits any
order and typical EVM call data (the EVM initcode limit is 49152 bytes). An
action larger than that commits to a digest inside its own format.

## 4. Field tables

Columns: CBOR key, name, type, size limit, R (required) or O (optional),
scale, semantics, and the gate invariant (section 1.1) the field serves.

```
SignedCommitment = { 1: Commitment, 2: signature bstr 64 }
Commitment = {
  1:  version         uint = 1,
  2:  agent_id        tstr 1..64, ID charset,
  3:  agent_pubkey    bstr 32,                    ; G0
  4:  nonce           bstr 16,
  5:  issued_at       uint > 0,
  6:  valid_until     uint > issued_at, TTL <= MaxTTL(da),
  7:  scope           { 1: gate_id tstr 1..64 },
  8:  action          { 3: type tstr 3..128, 4: hash bstr 32 },
  10: payload_ref     PayloadRef,
  11: ciphertext_hash bstr 32,
  12: plaintext_hash  bstr 32,
  13: payload_size    uint 1..2^27,
  ? 14: mandate_ref   bstr 32
}
PayloadRef = {
  1: da          uint enum {1 fibre, 2 celestia_blob},
  2: namespace   bstr 29, S8,
  3: commitment  bstr 32,
  4: height      uint > 0,       ; included: anchor height H; pending: reference height h0
  ? 5: signer    bstr 20,        ; required iff da = 2, not defined for da = 1
  ? 6: anchor    uint enum {2 pending}   ; absent = included; a present 1 is refused
}
```

Unassigned keys are never given a meaning, and a present one is refused
(`ErrUnknownKey`; in the payload plaintext `payload.ErrMalformed`):
commitment keys 9 and 15 (15 is reserved, section 4.6), scope keys 2 to 4,
action keys 1 and 2, `payload_ref` keys 7 and 8 (reserved), payload key 6,
payload action keys 1 and 2, receipt keys 5 and 7. The same holds for the
rule ids not listed in this document (D20, S4, S5, S9 to S11, S13, S15,
S16, R3, R4): they are never used.

### 4.1 Commitment (envelope key 1)

| Key | Name | Type | Limit | R/O | Scale | Semantics | Inv. |
|---|---|---|---|---|---|---|---|
| 1 | `version` | uint | `= 1` | R | - | Wire format version (rule S1). | 6 |
| 2 | `agent_id` | tstr | 1..64, ID charset | R | - | Allowlist key. The gate checks `allowlist[agent_id] == agent_pubkey` (section 8.7). | 1 |
| 3 | `agent_pubkey` | bstr | exactly 32 | R | - | Raw Ed25519 public key (RFC 8032 encoding). Verifies `signature`. MUST pass G0 (canonical, not small order). | 1 |
| 4 | `nonce` | bstr | exactly 16 | R | - | 128 uniformly random bits. Registry key is `(agent_pubkey, nonce)`. | 5 |
| 5 | `issued_at` | uint | `> 0` | R | seconds | When the agent signed. MUST be after the anchor tx at `payload_ref.height` was included (included reference) or after the anchor intent was archived (pending reference); the gate enforces this against `T_ref` up to `skew_s` (rule K1, section 12.2). | 4 |
| 6 | `valid_until` | uint | `> issued_at`, TTL `<= MaxTTL(da)` | R | seconds | Hard expiry, and the only one. Every Authorization for this commitment has `expires <= valid_until`. | 4 |
| 7 | `scope` | map | section 4.2 | R | - | Which gate may authorize this commitment. | scope |
| 8 | `action` | map | section 4.3 | R | - | The exact action, by type and salted hash. The bytes and the salt travel next to the envelope (gate input) and inside the encrypted payload (replay). | 3 |
| 10 | `payload_ref` | map | section 4.4 | R | - | DA locator of the payload blob: included or pending. | 2 |
| 11 | `ciphertext_hash` | bstr | exactly 32 | R | - | `H(blob)` over the exact published blob bytes (section 9). | 2 |
| 12 | `plaintext_hash` | bstr | exactly 32 | R | - | `H(salt \|\| plaintext)`, salt 32 bytes (section 9). | 2 |
| 13 | `payload_size` | uint | `1..2^27` | R | bytes | `len(blob)`. Bounds every fetch. Never compared with `da`. | 2 |
| 14 | `mandate_ref` | bstr | exactly 32 | O | - | `mandate_hash` (policy 6.2) of the mandate the agent acts under. Absent when the agent acts under no mandate. The gate compares it with the mandate in force (section 8.8); the verifier with the gate-signed verdict (section 20.1, rule `mandate_ref_mismatch`). | 8 |

There is no field for the commitment hash, the signature, the action salt,
any transaction hash or any rail reference (invariant 6). Unknown keys are
rejected, so none can be smuggled in. `payload_ref.commitment` is a DA blob
commitment, not a transaction hash.

Key numbering rule: a field whose meaning is unchanged keeps its key; a
key that is not assigned is never given a meaning later in this version.

### 4.2 Scope (commitment key 7)

| Key | Name | Type | Limit | R/O | Semantics |
|---|---|---|---|---|---|
| 1 | `gate_id` | tstr | 1..64, ID charset | R | MUST equal the gate's own id (rule C1). |

Threat note: scope binds only the gate. Account, chain and broker binding
live in the action bytes, where the profile defines it and the executor
checks it (section 16). A gate in front of two accounts of one broker
therefore authorizes an order for either account; the executor of each
account refuses an order that names the other.

### 4.3 Action (commitment key 8)

| Key | Name | Type | Limit | R/O | Semantics |
|---|---|---|---|---|---|
| 3 | `type` | tstr | 3..128 bytes, media-type grammar (section 4.5) | R | What the action bytes are, for example `application/vnd.edicta.ibkr.order.v0+cbor`. Not interpreted by the core: the gate only checks that it is in its configured set (rule C2). |
| 4 | `hash` | bstr | exactly 32 | R | `ActionHash(type, action_salt, action_bytes)` (section 5.1). The salt is not a commitment field. |

The action bytes themselves are not in the commitment. Definition: the
action bytes are **the exact bytes the executor will act on**, for example a
canonical IBKR order body of the dca-agent profile, an RLP-encoded EVM
transaction, or a JSON request body. The core hashes them as given and never
parses, normalizes or re-encodes them; two different byte strings always have
different hashes, so a re-encoding is simply not authorized. The remaining
risk is a parser differential inside one profile (one byte string, two
meanings); that is the profile's job (a strict, canonical decoder, section 16).

Why opaque: the core cannot validate a schema it does not know, and forcing
native formats into a core wrapper would add a translation step between what
is committed and what is executed, which is exactly the gap Edicta closes.

Lower case only, for the same reason as payload media types (section 9.3):
one byte string per type, so executors and replay tools dispatch on bytes.

There are no constraint fields: semantic bounds are profile or executor rules
(the dca-agent profile has an operator risk limit in its executor), and
`valid_until` is the only expiry.

### 4.4 PayloadRef (commitment key 10)

Keys 1 to 4 exist for both DA types; `da` selects the meaning of keys 3 and
4. Key 5 exists only for `da = 2`. Key 6 selects the reference form.

| Key | Name | Type | Limit | R/O | `da = 1` (fibre) | `da = 2` (celestia_blob) |
|---|---|---|---|---|---|---|
| 1 | `da` | uint enum | `{1, 2}` | R | Fibre blob anchored by `MsgPayForFibre` (PFF) | L1 blob paid by `MsgPayForBlobs` (PFB), share version 1 |
| 2 | `namespace` | bstr | exactly 29 | R | Namespace in the PaymentPromise | Namespace of the blob |
| 3 | `commitment` | bstr | exactly 32 | R | Fibre blob commitment (rsema1d) | Share commitment of the share-version-1 blob |
| 4 | `height` | uint | `> 0` | R | Included: L1 height at which the PFF was included. Pending: `h0`, the `PaymentPromise.height` of the upload (section 11.1) | Included: L1 height at which the PFB was included. Pending: `h0`, the head the Recorder read before it built the PFB |
| 5 | `signer` | bstr | exactly 20 | R if `da = 2`; not defined if `da = 1` | Not defined (`ErrUnknownKey`) | Raw 20-byte account address of the PFB signer, embedded in the blob's first share. Not bech32 text. |
| 6 | `anchor` | uint enum | `{2}` | O | Absent: included reference. `2`: pending reference (section 11) | as `da = 1` |

Details, sources and the namespace rule are in section 10; the pending
reference is section 11.

### 4.5 Charsets and grammars

| Name | Characters | Used by |
|---|---|---|
| ID | `A-Z a-z 0-9 . _ : / -` | `agent_id`, `gate_id` (commitment, Authorization, receipt), receipt `rail_ref` |
| media type | `name "/" name`, `name = [a-z0-9][a-z0-9!#$&^_.+-]*`: lower case, exactly one `/`, no parameters (`;`), no whitespace (RFC 6838 restricted-name characters, lower case only) | `action.type` (3..128 bytes), payload `action.type` (3..128) and `media_type` (1..64, section 9.3) |

Lengths are in bytes, which equals characters because every charset is ASCII.
Restricting identifiers to ASCII prevents look-alike scopes such as a
`gate_id` with a Greek omicron in place of `o` (vector `gate_id_unicode`).
`action.type` is checked first for its length (D18, `ErrFieldSize`), then for
the grammar (D19, `ErrInvalidString`). The shortest type is `a/b` (3 bytes).
The core has no amounts; scales and notional arithmetic are profile rules.

### 4.6 Reserved values

| Item | Reserved for | v1.0 reader | Intended meaning (not normative) |
|---|---|---|---|
| `payload_ref.da = 3` | batch leaf | `ErrInvalidEnum` (S3) | `commitment` names a Fibre batch blob; the payload is one leaf of it |
| `payload_ref` key 7 | `leaf_hash` bstr 32 | `ErrUnknownKey` (D15) | `H(tag("edicta/v1/batch-leaf") \|\| blob)` |
| `payload_ref` key 8 | `leaf_index` uint | `ErrUnknownKey` (D15) | position of the leaf in the batch |
| `TagBatchLeaf` | batch leaf hash | not used | |
| archive kind 16 | `batch` record | not defined (a reader refuses it as an unknown kind) | the batch blob and its leaf list |
| commitment key 15 | TEE attestation or code-measurement reference | `ErrUnknownKey` (D15) | a hash naming an attestation held in the agent's registration (a new tagged object, designed after v1.0) |

| Rule | Statement |
|---|---|
| V1-5 | The reserved values above are refused with the listed sentinel (`da = 3` at S3; the keys at D15). |
| V6 | Reserved values are never given another meaning. Defining one later is a minor revision of v1 that only turns that refusal into an acceptance. |

Only the reservations are frozen: these values mean nothing else, ever. The
intended meanings may change when the features are designed. zkTLS needs no
reservation: its proofs live in the opaque payload.

Threat note. A reader that ignored an unknown key or enum would accept a
commitment whose author meant something it does not check (for example a
batch leaf it never locates, or an attestation it never verifies). Refusal
keeps v1.0 readers fail-closed until the feature exists.

## 5. Hashing and signing (byte-exact)

```
canon            = the canonical CBOR bytes of the Commitment map (envelope key 1 value)
commitment_hash  = H( 0x1d || "edicta/v1/decision-commitment" || canon )         ; 32 bytes
signed_message   = 0x0d || "edicta/v1/sig" || commitment_hash                    ; 46 bytes
signature        = Ed25519-Sign(agent_sk, signed_message)                          ; 64 bytes
envelope         = canonical CBOR of { 1: <canon spliced verbatim>, 2: signature }
```

| Rule | Statement | Inv. |
|---|---|---|
| H1 | `commitment_hash` is computed over `canon` only, never over the envelope. The signature is outside the hashed struct. | 6 |
| H2 | The decoder has already proven `canon` is canonical (rule D21), so hashing the received bytes and hashing a re-encoding give the same result. Implementations MAY do either. | 6 |
| H3 | The hash has a length-prefixed domain tag, so it cannot collide with a receipt, action or Authorization hash or any other Edicta hash over the same bytes (section 2). | 6 |
| H4 | The commitment never contains its own hash, its signature, a transaction hash or any rail reference, and neither does the Authorization (section 15). A rail reference (order id, tx hash) appears only in the optional receipt, which is keyed by `commitment_hash` (section 14). | 6 |
| G0 | `agent_pubkey` is a valid public key: (a) it decodes under RFC 8032 section 5.1.3 exactly as written, so the 255-bit `y` is `< p = 2^255 - 19`, a square root `x` exists, and `x = 0` with the sign bit set is rejected; and (b) the decoded point `A` is not of small order, i.e. `[8]A != identity` (A is not one of the 8 points of the 8-torsion subgroup). Equivalently: A is the canonical encoding of a curve point outside the 8-torsion. Checked before G1 and G2. Failure is `ErrInvalidPublicKey`. | 1 |
| G1 | The signed bytes are exactly `signed_message`. Never the raw CBOR, never the bare hash. Pure Ed25519 (RFC 8032 section 5.1), no context string, no prehash. Verification uses `agent_pubkey` and is **cofactorless**: with `A` the decoded `agent_pubkey`, `R` the first 32 signature bytes as received, `S` the last 32 (already `< L` by G2) and `k = SHA-512(R || agent_pubkey || signed_message) mod L`, accept iff `encode([S]B - [k]A) == R` bytewise. The cofactored check `[8][S]B = [8]R + [8][k]A` MUST NOT be used. Failure is `ErrSignatureInvalid`. | 1 |
| G2 | `S` (the last 32 bytes of the signature, little-endian) MUST be `< L = 2^252 + 27742317777372353535851937790883648493`. Go `crypto/ed25519.Verify` and OpenSSL (via Python `cryptography`) both enforce it; the Python checker also checks it explicitly. Failure is `ErrSignatureInvalid`. | 1 |

Threat note (G0): Ed25519 verification as implemented by Go
`crypto/ed25519` and OpenSSL checks `[S]B = R + [k]A` without rejecting
small-order `A`. For `A` in the 8-torsion, `[k]A` is itself a torsion point,
so `R = -[k]A, S = 0` verifies for any message after at most a few nonce
tries; for the identity key every message verifies with `R = identity`.
Both libraries also accept non-canonical encodings of `A` (`y >= p`, or
`x = 0` with the sign bit set). Measured at revision draft.3: Go 1.26
`crypto/ed25519.Verify` and OpenSSL 4.0.3 via `cryptography` 50.0.2 accept
all 14 small-order forgery vectors. G0 must therefore be an explicit check,
not a property of the library. Mixed-order keys (a prime-order point plus a
non-zero torsion component) pass G0: forging under them still needs the
discrete log of the prime-order component, and honest RFC 8032 keys are never
mixed-order. The same rule is used by libsodium (`crypto_sign_verify_detached`
rejects non-canonical and small-order public keys; `UNVERIFIED` against a
specific libsodium release). Small-order `R` with a valid `A` is not a
forgery vector and is not restricted.

Threat note (G1, cofactorless): RFC 8032 section 5.1.7 permits both the
cofactored and the cofactorless equation, and they disagree when `R` carries a
torsion component, so two conforming-looking verifiers would split on the same
signature (the parser-differential class of section 1). Go `crypto/ed25519`
and OpenSSL are cofactorless; libsodium and ZIP-215 libraries are cofactored
(`UNVERIFIED` against specific releases; any later verifier or on-chain gate
built on such a library MUST add the cofactorless check). Only the key owner
can build such a signature (`R = [r]B + T`, `T` of order 8); a third party who
adds `T` to an honest `R` changes `k` and fails both equations. Mixed-order
keys remain allowed by G0; the cofactorless rule pins their outcome too.
Vector: `sig_torsion_r`.

Threat note: a signature over the raw CBOR would tie verification to one
encoder and lets a lenient decoder accept a second encoding that verifies.
Signing a fixed 46-byte tagged message removes both problems. Ed25519
signatures are deterministic, so every vector signature is reproducible from
the RFC 8032 test seed.

Worked example (vector `minimal_lmt` of `v1/valid.json`, signer `agent1` = RFC
8032 TEST 1; `canon` is 351 bytes, the envelope 420):

```
canon[0:8]       ac 01 01 02 6b 64 63 61     ; map(12), 1: 1, 2: tstr(11) "dca..."
canon key 8      08 a2 03 78 29 "application/vnd.edicta.ibkr.order.v0+cbor"
                    04 58 20 c21980427cdcfca858ef667e6057510f6c2139e81cac657eb6c000051eab0d0f
commitment_hash  2024a4ac8a2366f3c3658fcbbd4e4e2429e2698cbfa32a63b69ee0e9f3d366fe
signed_message   0d6564696374612f76312f736967 || commitment_hash
signature        75da0f32dd8fd62f4e18e6f648a5f2d581fe63ec62ab4b32e0e1f133753887a7
                 8cca32a39d80926da721fa597c4e82e541f7fe90f30d84f15ff9dc953372280f
```

### 5.1 Action hash

```
ActionHash(action_type, action_salt, action_bytes) -> action_hash, or ErrActionSize, ErrInvalidString
action_hash = H( 0x10 || "edicta/v1/action"
                 || uint8(len(action_type)) || action_type
                 || action_salt                                ; exactly 32 bytes
                 || action_bytes )                             ; to the end, as supplied
```

| Rule | Statement | Inv. |
|---|---|---|
| AH1 | `action_type` is inside the preimage, after a one-byte length (`len <= 128`). An executor recomputes the hash with the type it expects, so bytes committed under another type never match, and the Authorization need not carry the type. The length byte makes the split unambiguous. | 3 |
| AH2 | `action_bytes` run to the end of the preimage; no length prefix is needed. They are hashed exactly as supplied: never parsed, normalized or re-encoded. | 3 |
| AH3 | `1 <= len(action_bytes) <= 65536` (`MaxActionSize`), checked before hashing (`ErrActionSize`); `action_type` passes the section 4.5 grammar (`ErrInvalidString`). | 3 |
| AH4 | Comparison of a recomputed hash with a committed one is constant-time. | 3 |
| AH5 | `action_salt` is exactly 32 bytes and sits between the type and the bytes; its fixed width makes `type \|\| salt \|\| bytes` split one way only. | 3 |
| AH6 (producer) | The salt is 32 bytes from a CSPRNG, fresh per commitment, never reused. A reused salt makes equal actions of two decisions hash equal and lets one dictionary run test both. The SDK writes it into the payload (section 9.3) and hands it, with the action bytes, to the gate and to the executor. No production API takes it from the caller; vectors fix it from labels (section 22). | 3 |

Threat notes:
- Hiding. Under a secret 256-bit salt the public `action_hash` is not a
  dictionary oracle for low-entropy actions such as order parameters.
  Whoever holds the salt (the payload's recipients, the gate, the executor,
  the auditors; in public mode every archive reader, kind 17 form 1) can test
  candidates, but each of them also holds or can read the action bytes, so
  nothing new leaks. The salt must stay secret wherever the bytes are secret:
  in private mode it is stored only encrypted (kind 15 plaintext 5), until a
  reveal on execution (kind 18) for a public-rail action whose bytes are
  public anyway. The public `action_hash` in a private-form PolicyVerdict
  (policy 10.1) is safe only because it is salted (policy 9.6).
- Type confusion: without AH1, an attacker could present the committed bytes
  to an executor of another format whose parser reads them differently. With
  the type in the preimage, that executor recomputes under its own type and
  gets another hash.
- Tag separation: `TagAction` is used for nothing else, so no other Edicta
  hash can stand in for an action hash (H3).

Worked example (`minimal_lmt`; the action is the minimal IBKR order of the
dca-agent profile, 45 bytes; the salt is the vector salt of label
`minimal_lmt`):

```
action_type      application/vnd.edicta.ibkr.order.v0+cbor            ; 41 bytes (0x29)
preimage prefix  10 6564696374612f76312f616374696f6e 29 6170706c...63626f72   ; 58 bytes
action_salt      aa697e02c466b796bcf0d5b680a59fab232a6345cc4493ec49a29ead42b34126
action_bytes     a80169445531323334353637021a00040d7e0401051a000186a00601071b000000046f77ee8008635553440901
action_hash      c21980427cdcfca858ef667e6057510f6c2139e81cac657eb6c000051eab0d0f
```

Vectors: every `v1/valid.json` case carries `action_type`, the bytes
(`action_hex`, or a pattern for large actions), `action_salt_hex`,
`action_preimage_prefix_hex` (the salt and the bytes follow it) and
`action_hash_hex`; `v1/action.json` gives full preimages and the salt rules;
stage A rejects of `v1/reject.json`.

## 6. Strict decoding (stage D)

Input is the envelope bytes. Decoding is three passes. Each rule names its
sentinel and the vectors that exercise it.

### 6.1 Pass 0: size

| Rule | Check | Sentinel | Vectors |
|---|---|---|---|
| D0 | `len(input) <= 2176`, before any parsing | `ErrTooLarge` | `too_large` |

### 6.2 Pass 1: generic well-formedness

Walk the whole input depth-first in byte order. For each data item head:

| Rule | Check | Sentinel | Vectors |
|---|---|---|---|
| D1 | Input not truncated; additional info is not 28, 29 or 30; additional info 31 is not used with major 0, 1, 6 or 7 (a stray "break"); a string, array or map length does not exceed the remaining input | `ErrMalformed` | `truncated`, `reserved_additional_info` |
| D2 | Nothing follows the top-level item | `ErrTrailingData` | `trailing_byte` |
| D3 | No floats: major 7 with additional info 25, 26 or 27 | `ErrFloat` | `float_payload_size`, `float16_height` |
| D4 | No simple values: any other major 7 item (`false`, `true`, `null`, `undefined`, others) | `ErrSimpleValue` | `null_action_type`, `true_da` |
| D5 | No tags: major 6 | `ErrTag` | `tag_bignum_payload_size` |
| D6 | No indefinite lengths: additional info 31 on major 2, 3, 4 or 5 | `ErrIndefiniteLength` | `indef_map`, `indef_tstr` |
| D7 | Every head (integer value, length, or map key) is in its shortest form | `ErrNonMinimalInt` | `nonminimal_uint`, `nonminimal_len`, `nonminimal_key` |
| D8 | Container depth `<= 4` (envelope 1, commitment 2, scope/action/payload_ref 3; a schema-valid commitment reaches depth 3 only) | `ErrNestingTooDeep` | `deep_nesting` |
| D9 | At most 16 entries in any map or array, checked at the head before reading entries | `ErrTooLarge` | `map_17_pairs` |
| D10 | Map keys strictly ascending | `ErrUnsortedMap` | `unsorted_map` |
| D11 | No key repeated within one map | `ErrDuplicateKey` | `dup_key` |
| D12 | Every map key is a uint | `ErrKeyType` | `tstr_key` |
| D13 | Every text string is valid UTF-8 | `ErrInvalidString` | `invalid_utf8` |

Within one head the checks run in the order D1 (reserved info), D6/D1
(info 31), D3/D4 (major 7), D5 (major 6), D1 (truncated argument), D7, then
for containers D8, D9, D1 (length vs remaining input). For each map key:
D12, then D11 (equal to the previous key), then D10 (less than the previous
key).

### 6.3 Pass 2: schema

Apply the schema of section 4, starting with the envelope `{1: commitment
map, 2: signature bstr(64)}`.

| Rule | Check | Sentinel | Vectors |
|---|---|---|---|
| D14 | The commitment (envelope key 1 value) is at most 2048 bytes, checked before descending into it | `ErrTooLarge` | `commitment_too_large` |
| D15 | Every key is defined for its map; unassigned and reserved keys (section 4, V1-5) are not defined. In `payload_ref`, key 5 (`signer`) is not defined when `da == 1` | `ErrUnknownKey` | `unknown_top_key`, `unknown_action_key`, `unknown_payload_ref_key`, `unknown_envelope_key`, `signer_on_fibre`, `signer_on_fibre_pending`, `retired_constraints_key`, `retired_key_9`, `retired_action_kind_key`, `retired_action_params_key`, `retired_scope_rail_key`, `retired_scope_account_key`, `retired_scope_chain_id_key`, `draft8_shape_envelope`, `commitment_key_15_reserved`, `payload_ref_key_7_reserved`, `payload_ref_key_8_reserved` |
| D16 | Every value has the major type in the schema. A negative integer where a uint is expected, a bstr for a tstr, or an array for a map are all type errors | `ErrWrongType` | `nint_payload_size`, `bstr_for_tstr`, `array_for_scope`, `action_hash_tstr`, `signer_bech32_tstr`, `anchor_tstr`, `mandate_ref_tstr` |
| D17 | Every required key is present. In `payload_ref`, key 5 (`signer`) is required when `da == 2` | `ErrMissingField` | `missing_nonce`, `missing_action_hash`, `missing_height`, `missing_locator_commitment`, `missing_locator_signer`, `missing_signer_blob_pending`, `missing_signature`, `version_absent` |
| D18 | Byte and text strings are within their length limits. V1-2: `mandate_ref`, when present, is exactly 32 bytes (its value is not checked statelessly) | `ErrFieldSize` | `nonce_15_bytes`, `sig_63_bytes`, `namespace_28_bytes`, `share_commitment_31_bytes`, `fibre_commitment_33_bytes`, `signer_19_bytes`, `signer_32_bytes`, `agent_id_empty`, `agent_id_65_chars`, `action_type_129_chars`, `action_type_empty`, `action_type_2_chars`, `action_hash_31_bytes`, `mandate_ref_31_bytes`, `mandate_ref_33_bytes` |
| D19 | Text strings use their charset or grammar (section 4.5) | `ErrInvalidString` | `gate_id_unicode`, `action_type_uppercase`, `action_type_space`, `action_type_no_slash`, `action_type_two_slashes`, `action_type_parameter`, `action_type_bad_first_char`, `action_type_unicode` |

Within one map, keys are visited in ascending order; for each key D15, D16,
D18, D19 apply, then nested maps recurse; D17 is checked after the map.

The `signer` conditions read `da` (key 1), which precedes key 5 in canonical
order, so they are decided in a single pass. If `da` is neither 1 nor 2,
`signer` is optional at stage D and S3 rejects the `da` value
(`ErrInvalidEnum`, vectors `da_0`, `da_3`, which carry a signer). The
anchor key (6) is read after `da` and is optional at stage D; V1-3 decides
its value at stage S.

Enum and integer fields decode at full uint64 width. A value such as
`da = 256` is a valid uint at stage D and fails at S3 with `ErrInvalidEnum`
(vector `da_256`), not with a decoder overflow error. Values above
`2^63-1` likewise pass stage D and fail at S2.

### 6.4 Pass 3: re-encode

| Rule | Check | Sentinel | Vectors |
|---|---|---|---|
| D21 | Re-encoding the decoded commitment yields exactly the input commitment bytes | `ErrNonCanonical` | none; see below |

Given D1 to D19, every accepted input is already canonical, so D21 is a
safety net against implementation bugs (for example a library that silently
normalizes something). It has no must-reject vector because no input can
reach it in a conforming decoder; it is exercised by the Go fuzz test
`FuzzDecode`, which asserts that every accepted input re-encodes to
identical bytes.

### 6.5 Error precedence

The stage order D, S, G, T, C is normative: an implementation MUST NOT
report a later-stage sentinel when an earlier stage fails. Within a stage,
the orders above are the reference order and the Python checker follows
them. Every must-reject vector contains exactly one defect, so the expected
sentinel is unambiguous. For hostile input with several defects in one stage,
any applicable sentinel of that stage is conformant.

Threat note: two decoders that disagree on whether bytes are valid let an
attacker show one party a commitment that another party never accepts. The
pre-scan plus re-encode comparison makes "accepted" mean "byte-identical to
the unique canonical encoding" in every implementation.

## 7. Static validation (stage S)

`ValidateStatic(c, params)` runs after decoding and before the signature. It
needs no key and no state except `params`, which the gate reads from chain
state at check time (section 12). Normative order:

| Rule | Check | Sentinel | Vectors | Inv. |
|---|---|---|---|---|
| S1 | `version == 1` | `ErrUnsupportedVersion` | `version_0`, `version_2` | 6 |
| S2 | Every uint field `<= 2^63-1`, `payload_ref` key 6 (`anchor`) included | `ErrIntRange` | `height_2pow63`, `anchor_2pow63` | 2, 4 |
| S3 | `da in {1,2}` (`3` is reserved, section 4.6) | `ErrInvalidEnum` | `da_0`, `da_3`, `da_256`, `da_3_reserved`, `da_3_with_anchor_2` | 2 |
| V1-3 | `anchor` (already `<= 2^63-1` by S2) is absent or `2`. A present `1` is refused so that "included" has one encoding (the absent key) | `ErrInvalidEnum` | `anchor_0`, `anchor_1`, `anchor_3` | 2 |
| S6 | Nonzero: `issued_at`, `height`, `payload_size` | `ErrZeroValue` | `issued_at_0`, `height_0`, `payload_size_0`, `height_0_pending` | 2, 4 |
| S7 | `payload_size <= 2^27` | `ErrPayloadTooLarge` | `payload_size_2pow27_plus1` | 2 |
| S8 | `namespace` is a valid user blob namespace (section 10.3) | `ErrInvalidNamespace` | `namespace_version_1`, `namespace_nonzero_prefix`, `namespace_reserved` | 2 |
| S12 | `valid_until > issued_at` | `ErrTimeOrder` | `valid_until_eq_issued`, `valid_until_lt_issued` | 4 |
| S14 | `valid_until - issued_at <= MaxTTL(da)` (section 12.1) | `ErrTTLTooLong` | `ttl_3601`, `ttl_ok_at_4h_rejected_at_10m`, `ttl_floor_division` | 4 |

A commitment whose key 1 is not the uint `1` is refused by these rules: key 1
absent is `ErrMissingField` (D17), not a uint is `ErrWrongType` (D16), any
other uint is `ErrUnsupportedVersion` (S1). A commitment of the superseded
`v0` drafts (version 0) fails S1 or an earlier stage; nothing reads it as
another version.

S2 keeps every value representable as a signed 64-bit integer, so SQL
stores, JSON consumers and languages without unsigned types handle them
without loss. The anchor key is read after `da`, so `da = 3` with `anchor =
2` is `ErrInvalidEnum` from S3.

There is deliberately no rule comparing `payload_size` with `da`: any size
up to the limits is valid for either `da` (vectors `fibre_small_payload`,
fibre, 1024 bytes, and `blob_large_payload`, celestia_blob, 262144 bytes).

Single DA per instance (normative for deployments). A gate/Recorder
instance runs exactly one DA, chosen by configuration: its Recorder
publishes only through that DA, and its gate's allowed DA set (rule C3) is
exactly that one `da`. A payload that does not fit the chosen DA is refused;
the Recorder never falls back to the other DA. Switching DA means restarting
with another configuration; the nonce registry is DA-independent and is
kept, and commitments made for the other DA are then refused by C3
(`ErrDANotAllowed`, fail closed).

Gate rules on a verified pending reference (stage K-fast, section 13):

| Rule | Stage | Statement | Sentinel |
|---|---|---|---|
| V1-4 | gate K-fast | With `anchor = 2`, `height` is `h0` and is fixed by the agent's signature: it MUST equal `PaymentPromise.height` of the anchor intent (`da = 1`) or the intent record's `ref_height` (`da = 2`). | `ErrAnchorIntentInvalid` (gate) |
| V1-6 | gate K-fast; verifier | At authorization the gate refuses `head - h0 > MaxH0AgeBlocks` (section 8.9; default 10 blocks; 30 s at 3 s blocks is a per-network example). The bound is the gate's, not signed. The verifier checks that the final anchor height satisfies `H >= h0`. | `ErrH0TooOld` (gate); `source_corrupt` (verifier) |

## 8. Signature, time, scope, action, payload checks

### 8.1 Stage G: signature

Rules G0, G1 and G2 in section 5, checked in the order G0, G2, G1. G1 is
cofactorless: accept iff `encode([S]B - [k]A) == R` bytewise, with `S < L`
(G2). Pinning the equation matters because a cofactored verifier accepts
signatures whose `R` has a torsion component, so two verifiers would disagree
on one input (a parser differential at the signature layer).
G0 vectors (`ErrInvalidPublicKey`): the 8 canonical torsion points
`pubkey_identity`, `pubkey_order2`, `pubkey_order4_a`, `pubkey_order4_b`,
`pubkey_order8_a` to `pubkey_order8_d`; the 6 non-canonical encodings that
lenient decoders map to torsion points `pubkey_identity_negzero`,
`pubkey_order2_negzero`, `pubkey_order4_y_eq_p`, `pubkey_order4_y_eq_p_sign`,
`pubkey_identity_y_eq_p_plus_1`, `pubkey_identity_y_eq_p_plus_1_sign`; and
`pubkey_noncanonical_y` (`y = p + 3`, a large-order point) and
`pubkey_not_on_curve`. Every small-order vector carries a signature
`R || S = 0` that satisfies the cofactorless verification equation, so an
implementation without G0 accepts it. Vectors for G1 and G2: `wrong_sig_tag`, `sig_under_authorization_sig_tag`,
`sig_tag_no_length_prefix`, `wrong_hash_tag`, `hash_without_tag`,
`sig_raw_cbor`, `sig_raw_hash`, `sig_wrong_key`, `flipped_field`,
`sig_torsion_r` (G1) and `sig_noncanonical_s` (G2), all `ErrSignatureInvalid`.
`sig_torsion_r` is signed by `agent1` with `R = [r]B + T`, `T` of order 8, and
`S = r + k*a mod L`: it passes G0 and G2 and the cofactored equation, and
fails only the cofactorless one.

### 8.2 Stage T: time

`CheckTime(c, now, params)`, with `now` the gate clock in Unix seconds and
`skew = params.skew_s` (default 30):

| Rule | Check | Sentinel | Vectors |
|---|---|---|---|
| T1 | `issued_at <= now + skew` | `ErrNotYetValid` | `future_issued` |
| T2 | `now + skew < valid_until` | `ErrExpired` | `expired`, `expiry_within_skew` |

Skew is asymmetric: it lets a commitment from a slightly fast agent
clock in, and it shortens validity at the end. It never extends validity.
Vector `issued_at_within_skew` (valid) has `issued_at = now + 30`.

### 8.3 Stage C: scope

`CheckScope(c, gate)`, where the gate knows its own `gate_id` and a non-empty
set of action types it is configured for (`GateScope{GateID, ActionTypes}`;
each entry passes the section 4.5 grammar):

| Rule | Check | Sentinel | Vectors |
|---|---|---|---|
| C1 | `scope.gate_id == gate.gate_id` | `ErrScopeMismatch` | `foreign_gate_id` |
| C2 | `action.type` is in `gate.action_types`, by bytewise equality | `ErrActionTypeNotAllowed` | `action_type_not_allowed`, `action_type_suffix_differs` |
| C3 | `payload_ref.da` is in the gate's configured DA set (`allowed_da`); an unset set means `{1, 2}` | `ErrDANotAllowed` (package `gate`) | none (gate configuration; gate tests) |
| C4 | `da = 1` only, and only on a gate with a `da = 1` committer: `payload_size <= fibre_max_data_bytes` (section 10.4, Fibre payload limit; default 16 MiB) | `ErrPayloadAboveCap` (package `gate`) | none (gate configuration; gate tests) |
| C5a | `anchor = 2` only at a gate with `FastMode` on **and** a mandate configured (defence in depth for library gates; section 8.9 already refuses `FastMode` without a mandate) | `ErrAnchorPending` (package `gate`) | none (gate configuration; `api/errors.json` examples) |
| C5b | `anchor = 2` only with `payload_ref.namespace` in `PendingNamespaces` (bytewise) | `ErrNamespaceNotAllowed` (package `gate`) | none (gate configuration) |

C3 to C5 are gate rules, not part of `VerifyForGate`: the gate evaluates
them, in the order C3, C4, C5a, C5b, right after `VerifyForGate` succeeds and
before stage 2 of section 8.7, so they are never an oracle for unsigned
input, and they write no decision record and no marker. C4 does not apply to
a gate without a `da = 1` committer (it delegates P3 and never encodes). With
`allowed_da` unset, C3 always holds. A gate that does not
allow `da = 1` need not read Fibre parameters: it passes `fibre_retention_s =
2^63-1` to `VerifyForGate`, which only satisfies `Params.Validate`; S14 then
caps a `da = 1` TTL at 3600 s, and every `da = 1` commitment that passes S14
fails C3. The value is normative so that two gates report the same sentinel
for a `da = 1` commitment (`ErrTTLTooLong` above 3600 s, `ErrDANotAllowed`
otherwise). A gate whose set contains 1 MUST read `fibre_retention_s` at
startup and refuse to start if it cannot (for example on a chain without
`x/fibre`), with a configuration error.

Threat note (C3): a gate on a chain without `x/fibre` cannot evaluate S14, K2
or P3 for `da = 1`; without C3 it would either fail every such commitment
with an operational error or, worse, read a substituted value. C3 turns it
into a fixed, configured rejection.

Threat note (C4): P3 for `da = 1` encodes the whole blob, more than 12 times
`payload_size` in memory (about 1.6 GB per check at `2^27` bytes). C4 refuses
an oversize commitment from `payload_size` alone, before any fetch, so an
agent cannot make the gate download and encode a blob it would never
accept. `ErrPayloadAboveCap` is distinct from `ErrPayloadTooLarge` (S7): S7
is the same for every gate, C4 depends on this gate's configuration, and the
two must not share an API code (section 18.3).

Threat note (C2): the allowlist is how an operator says which executors stand
behind this gate. Without it, a gate in front of an IBKR executor would also
authorize, say, EVM transactions that some other executor trusting the same
gate key might run. Membership is exact: no prefix, suffix or case folding.

Threat note (C5b): the allowlist bounds which namespaces a gate will look up
and rebroadcast for; without it any party could make the gate's node carry
PFBs for arbitrary namespaces.

A mandate in force without key 16 (`fast_mode_max_delay`) does not stop the
gate from starting with `FastMode`: it logs a warning, and every pending
reference is denied by P15 with a signed verdict (policy 8.2). Invariant
test: a fast-mode Authorization is issued only under a mandate whose key 16
is present.

### 8.4 Stage A: action match

`CheckAction(c, action_bytes, action_salt)`, on the bytes and the salt the
caller supplied with the envelope:

| Rule | Check | Sentinel | Vectors |
|---|---|---|---|
| A0 | `1 <= len(action_bytes) <= 65536`, before hashing | `ErrActionSize` | `action_empty`, `action_too_large` |
| A0s | `action_salt` is present and exactly 32 bytes | `ErrMissingField` (absent or empty), `ErrFieldSize` (any other length) | `action_salt_31`; `v1/action.json` `action_v1_salt_missing`, `action_v1_salt_31`, `action_v1_salt_33` |
| A1 | `ActionHash(c.action.type, action_salt, action_bytes) == c.action.hash` (section 5.1), constant-time | `ErrActionMismatch` (wrong bytes, wrong type or wrong salt) | `action_byte_flipped`, `action_truncated`, `action_extra_byte`, `action_qty_differs`, `action_reencoded_noncanonical`, `action_wrong_salt`, `action_hash_of_other_type`, `action_hash_untagged`, `action_hash_type_unprefixed`, `action_unsalted`, `action_hash_bare_sha256`; `v1/action.json` `action_v1_wrong_salt`, `action_unsalted`, `action_v1_salt_after_bytes` |

Exact match, no semantics (invariant 3). `action_qty_differs` and
`action_reencoded_noncanonical` show the consequence: an order that differs in
one field, or the same order in a non-canonical encoding, is simply other
bytes. Each stage A vector carries `committed_preimage_hex`, so a checker can
see that exactly one thing is wrong: the supplied bytes, the supplied salt,
or the way the committed hash was built.

A0s runs after stage 1 (the envelope verified), so salt presence is never an
oracle for unsigned input. All three refuse before stage 4a, so no decision
record and no marker are written. The gate receives the action bytes and the
salt from the integrator, never from the archive. A missing salt is a
separate error from a wrong one because it is an integration fault; the
salt's presence is not secret, so the distinction leaks nothing.

### 8.5 Stage P: payload bytes

`CheckPayload(c, blob)`, given the bytes from DA or the archive, then the DA
commitment check:

| Rule | Check | Sentinel | Vectors |
|---|---|---|---|
| P1 | `len(blob) == payload_size`, checked first and cheaply. A source that returns more bytes is rejected before hashing | `ErrPayloadSizeMismatch` | `blob_truncated` |
| P2 | `H(blob) == ciphertext_hash` | `ErrPayloadHashMismatch` | `blob_flipped_byte`, `blob_with_share_padding` |
| P3 | The DA commitment recomputed from `blob` equals `payload_ref.commitment` (`da = 2`: section 10.5; `da = 1`: section 10.4). MUST hold on every path the gate accepts bytes from; how it is established depends on the path and `da` (table below) | `ErrDACommitmentMismatch` (gate) | `da/blob_commit.json`, `da/fibre_commit.json` (Go only) |

P1, P2 and P3 run in this order on each path, cheapest first. P1 and P2 live in
package `commitment`; P3 lives in the gate (`DACommitter`, keyed by `da`).

| Path (Authorization `path`) | `da` | When the gate may use it | P3 is established by |
|---|---|---|---|
| DA, `path = 1` | 2 `celestia_blob` | K2 holds (section 12.2) | The gate itself: `CreateCommitment(NewV1Blob(namespace, blob, signer), RFC6962, 64)` (section 10.5). The node is trusted for nothing about the bytes. |
| DA, `path = 1` | 1 `fibre` | K2 holds | With a `da = 1` committer (required for a gate whose configured DA is `fibre`, below): the gate itself, `fibre.NewBlob(blob, DefaultBlobConfigV0()).ID().Commitment() == payload_ref.commitment` (section 10.4), whichever client or bridge returned the bytes. Without one (a library gate with `allowed_da` unset): delegated to the operator's own node, which downloads `BlobID = 0x00 \|\| payload_ref.commitment` and verifies every row against it; that `Download` never returns partial or unverified data and returns exactly the submitted bytes (header and row padding stripped) was VERIFIED on Mocha on 2026-10-05 with the client at the pin. The delegated form is a self-check and proves nothing to a party that distrusts that node. |
| Archive, `path = 2` | 2 | K2 fails, or the DA path failed for any reason (not found, error, timeout, P1/P2/P3 failure) | The gate itself, on the full archived blob, as for the DA path. Mandatory: an archive copy is accepted only if P1, P2 and P3 all pass. |
| Archive, `path = 2` | 1 | As for `da = 2` | The gate itself, with its `da = 1` committer, as on the DA path. Mandatory, as for `da = 2`. A gate without a `da = 1` committer MUST refuse with `ErrArchiveRecomputeUnsupported` **before fetching**. |

Committers (normative). The gate holds at most one DA committer per `da`. `ErrArchiveRecomputeUnsupported` means exactly: the archive path is needed and the gate has no committer for this `da`. A gate whose configured DA (section 7, single DA per instance) is `fibre` MUST have a `da = 1` committer, MUST use it on both paths, and MUST refuse to start without one. A library gate with `allowed_da` unset and no `da = 1` committer refuses the `da = 1` archive path, which is what the `da = 1` cases of `v1/anchor.json` `k2_included` describe; `spec/vectors/da/fibre_commit.json` restates those cases for a gate with the committer (route `archive`). The `da = 1` committer lives in a Go module separate from the core, so that the core and `celestia_blob` users never import celestia-app. It is pure computation, copies its input (`NewBlob` takes ownership of the slice and may reuse it as row storage) and refuses a blob above a configured size cap before encoding, because encoding needs about 12 times the data size in memory; the cap MUST be at least the Fibre payload limit of the Recorder in the same deployment. A blob that is empty, above the cap or above the Fibre maximum (`2^27 - 5` bytes, while S7 allows `2^27`) gives `ErrDACommitmentMismatch`: no commitment can be computed for it, and no such blob can have been anchored (vectors `fibre_empty`, `fibre_size_134217724`).

Threat note (P3, "anchor X, sign H(Y)"). An agent or a Recorder (1) anchors
blob X at height H, (2) writes blob Y to the archive, (3) signs a commitment
with `payload_ref.commitment = C(X)` and `ciphertext_hash = H(Y)`. On the DA
path the DA layer serves X, so P2 fails. On the archive path P2 alone accepts
Y, and the gate would authorize on a payload that was never public. P3 computes
`C(Y) != C(X)` and rejects (vector `anchor_x_sign_hash_y` in `da/blob_commit.json`; for `da = 1`, `fibre_anchor_x_sign_hash_y` in `da/fibre_commit.json`).
P3 also rejects bytes from a share-version-0 blob, from another signer or from
another namespace (vectors `commitment_share_v0`, `commitment_other_signer`,
`commitment_other_namespace`). What the archive path keeps: publication at H
is still proven by the anchor (section 10.6), and P3 proves the archived bytes
are that blob. What it loses: evidence that the DA layer still served the
bytes during the validity window; the Authorization records this as `path = 2`.

Error precedence when no path succeeds (normative, so two gates report the
same sentinel): `ErrPayloadSizeMismatch` and `ErrPayloadHashMismatch` (P1,
P2; in that order) > `ErrDACommitmentMismatch` > `ErrArchiveRecomputeUnsupported`
> `ErrAnchorTooOld` > `ErrPayloadUnavailable`. `ErrAnchorTooOld` means K2
failed and the archive did not return the blob; it MUST also match
`ErrPayloadUnavailable` (Go: `errors.Is`). Failures on the DA path that only
cause a fall back to the archive are not reported unless the archive path
also fails; when both fail, the sentinel with the higher precedence is
reported and the other cause MAY be attached.

Archive read faults (normative). When the archive path
is taken and the archive payload record exists but cannot be read or fails
strict decoding (section 19.6), the gate answers `ErrArchiveUnavailable`
instead of any sentinel above: the archive path did not finish, so there is
no verdict, and the copy that could have passed P1 to P3 may still be
readable on a retry. Like every operational failure it marks nothing (AR5)
and consumes no nonce. Threat note: reporting a corrupt record as
`ErrPayloadUnavailable` would record a verdict, and a rejection marker,
against a decision whose payload is only unreadable on this gate's disk;
reporting it as absent would let a damaged archive look like a pruned one.

### 8.6 Normative pipeline (stateless part)

`VerifyForGate(envelope, now, gate, params)` = `params.Validate()`, then
D, S, G, T, C. Then the gate calls `CheckAction(c, action_bytes,
action_salt)` for the bytes and the salt it was given and `CheckPayload` for the fetched blob. `Params.Validate` requires
`fibre_retention_s` and `blob_retention_s` in `1..2^63-1` and `skew_s` in
`0..300`; otherwise `ErrInvalidParams` (Go unit tests only).

For a pending reference (section 12) the payload comes from the archive
(`da = 2`) or from the Fibre download and then the archive (`da = 1`); P3 is
always computed locally.

### 8.7 Gate authorization order (stateful stages)

The gate verifies and authorizes; it never executes and holds no rail
credentials. Its input is the envelope bytes, the action bytes and the
action salt; it never accepts a decoded struct from its caller. Its output is a signed
Authorization (section 15). The gate issues an Authorization only if every
stage below passes, in this order. An implementation MUST NOT report a later
stage's sentinel when an earlier stage fails. Stages 4p and 10p exist only
at a gate with a mandate configured (policy section 11); stage 4m runs at
every gate (section 8.8).

| # | Stage | Rule | Check | Sentinel | Inv. |
|---|---|---|---|---|---|
| 1 | D, S, G, T, C | section 8.6, C3 to C5 | `VerifyForGate` with `now` read once from the gate clock and params read from chain state; C includes C2 (action type allowed); then C3 (DA allowed), C4 (`da = 1` payload cap), C5a and C5b (pending reference), section 8.3 | stage D to C sentinels, `ErrDANotAllowed`, `ErrPayloadAboveCap`, `ErrAnchorPending`, `ErrNamespaceNotAllowed` | 1, 4, 6, 9 |
| 2 | E | E1 | `issued_at > epoch + skew_s`, where `epoch` is the gate clock when the nonce registry was created, persisted inside the registry in its creation transaction and never rewritten | `ErrBeforeRegistryEpoch` | 5 |
| 3 | L | L0, L1, L2 | `agent_pubkey` is not a gate key: not the gate's own key (which signs Authorizations and receipts) and not any gate key in its configuration (L0). The allowlist has `agent_id` (L1), and maps it to exactly `agent_pubkey` (L2). Checked in the order L0, L1, L2, after G, so it is never an oracle for unsigned input | `ErrAgentKeyIsGateKey`, `ErrAgentNotAllowed`, `ErrAgentKeyMismatch` | 1, 7 |
| 4 | A | A0, A0s, A1 | `CheckAction(c, action_bytes, action_salt)` on the supplied bytes and salt (section 8.4) | `ErrActionSize`, `ErrMissingField`, `ErrFieldSize`, `ErrActionMismatch` | 3 |
| 4m | M | M0, M1, M2 | Mandate reference (section 8.8): M0 at a gate without a mandate, M1 and M2 at a gate with one | `ErrMandateRefMissing`, `ErrMandateMismatch` | 8 |
| 4p | Admission | policy 8.2 | Policy admission, including P15 (fast-mode consent); only with a mandate | policy deny sentinels (signed verdict) | 8, 9 |
| 4a | AR | AR1 to AR4 | Archive the decision before any Authorization exists (below): write the decision record (kind 17, section 19.2) under `commitment_hash`, idempotently, and wait until the write is durable. Form 2 (private) iff the mandate in force has `auditors`; then the kind 15 `(5, action_hash)` record holding the salt and the action bytes encrypted to the auditors is written first; otherwise form 1 with the action bytes and the salt in clear. Also runs after an M1 refusal or a 4p deny; never after an M0 or M2 refusal (section 8.8). Required for a gate with an archive configured (every `edictad` gate); a library gate without one skips this stage. Writes nothing to the nonce registry | `ErrArchiveUnavailable` (503, `Retry-After`) | 2, 5 |
| 5 | N0 | N1 | No registry entry exists for `(agent_pubkey, nonce)`. Advisory; stage 12 is authoritative. If one exists, the retry rule below applies | `ErrNonceUsed` | 5 |
| 6 | K or K-fast | K0; F1 to F6, B1 to B5 | Included reference: the anchor tx exists at `payload_ref.height` (section 10.4 for `da = 1`: proven from the PayForFibre namespace data of that block, result code 0, rules NA1 to NA7; 10.5 for `da = 2`), and the header time `T_ref = T_H` is readable. Pending reference: stage K-fast (section 13) | `ErrAnchorNotFound`; K-fast sentinels (section 13) | 2, 9 |
| 7 | K1 | K1 | Section 12.2, on `T_ref` | `ErrIssuedBeforeAnchor` | 4 |
| 8 | K2 | K2 | Section 12.2, on `T_ref` and, for a Fibre pending reference, the intent's `created_at`. Selects the DA or archive path only, never a rejection by itself | none | 2, 4 |
| 9 | P | P1, P2, P3 | Section 8.5, per path. On the archive path, an archive payload record that is unreadable or corrupt (section 19.6) is an operational failure, not a verdict | P sentinels, precedence in 8.5; `ErrArchiveUnavailable` (operational, 503, `Retry-After`) for an unreadable or corrupt archive payload record: no rejection marker (AR5), nonce not consumed | 2 |
| 10 | T' | T1, T2 | `CheckTime` again with a fresh clock reading `authorized_at`, because fetches take time | `ErrNotYetValid`, `ErrExpired` | 4 |
| 10p | Evaluation | policy 8.3, 8.4 | Policy evaluation on `T_ref`; only with a mandate | policy deny sentinels (signed verdict) | 8 |
| 11 | Z | Z1 | Build the Authorization (section 15.1): `commitment_hash`, `action_hash = c.action.hash`, the gate's `gate_id`, `expires = min(valid_until, authorized_at + MaxAuthorizationTTL)`, `path` of stage 9, `mode` from the reference form (1 included, 2 pending) and, for `mode = 2`, `anchor_deadline` from K-fast. Sign it with the gate key under `TagAuthorizationSig` and verify the signature before use. Nothing is stored yet | (operational: signer error, timeout) | 7, 9 |
| 12 | N | N1 | Atomically create the registry entry for `(agent_pubkey, nonce)` holding `commitment_hash`, the canonical SignedAuthorization and, for the reveal on execution (section 19.7), the `action_salt` (gate-local, in clear, like the PrivatePart bytes of policy 11.4); fails if the key exists. With a mandate the policy counter update is committed in the same transaction. Committed durably before stage 13. Nothing fast-mode-specific is written before this stage | `ErrNonceUsed` | 5, 8 |
| 13 | R | | Return the SignedAuthorization bytes | - | - |

Every gate runs stage 4m. A gate with a mandate also runs stages 4p and
10p, and its stage 12 also commits the policy counter (invariant 8);
`spec/policy-v1.md` section 11 defines 4p and 10p. Without a mandate, 4p and
10p are skipped and 4m only refuses a commitment that names a mandate (M0).

`MaxAuthorizationTTL` is gate configuration (default 300 s) and MUST exceed
`skew_s`. Stage 10 enforces `authorized_at + skew_s < valid_until`, so a fresh
Authorization passes an executor whose clock agrees with the gate's.

Retry rule (normative). When stage 5 or stage 12 finds an existing entry for
`(agent_pubkey, nonce)`, the gate returns `ErrNonceUsed`, and returns the
stored SignedAuthorization with it **only if** both hold:
1. the stored `commitment_hash` equals the hash of the presented envelope; and
2. `ActionHash(c.action.type, presented action salt, presented action bytes)`
   equals the stored Authorization's `action_hash`.

Otherwise nothing from the stored entry is returned. If (2) fails, the result
is the normal mismatch error `ErrActionMismatch`; if (1) fails, `ErrNonceUsed`
alone. A same-commitment retry receives the same bytes as the first answer,
so there is still exactly one Authorization per `(agent_pubkey, nonce)`
(invariant 5), with the same `mode` and `anchor_deadline`; a retry never
re-runs the deadline computation of K-fast.

Precedence (normative): the stage order decides. Stage A runs before any
registry read, so bytes that do not hash to the presented commitment's
`action.hash` give `ErrActionMismatch` whether or not the nonce is used, and
no registry read happens. Bytes and a salt that pass A1 on a used nonce give
`ErrNonceUsed`, with the stored Authorization attached only under (1) and
(2). For the same commitment the stored `action_hash` equals `c.action.hash`,
so (2) is implied by A1; the gate still compares against the stored value,
so the rule holds even for an entry written by a faulty or older gate, and
reports `ErrActionMismatch` with nothing stored if that comparison fails.
(Non-normative: an implementation SHOULD log that case at error level and
raise a metric or alert, because it indicates a gate bug or registry
corruption.)

Threat note (retry rule). Returning the stored Authorization gives crash
liveness: if the gate committed stage 12 and then crashed or lost the
connection, the caller's retry gets the decision instead of a burned nonce.
Condition (1) keeps a different commitment that reuses the nonce from learning
anything about the stored one. Condition (2) and the precedence keep the gate
from handing an Authorization to a caller that cannot present the committed
bytes, and keep a caller without those bytes from learning whether a nonce is
taken.

Archive before authorize (normative):

| Rule | Requirement |
|---|---|
| AR1 | The record is keyed by `commitment_hash` and holds the envelope bytes and, in form 1, the action bytes and the salt exactly as presented (form 2: the kind 15 `(5, action_hash)` record holds them encrypted, section 19.2). Nothing else is required before stage 11; the Authorization, its path and the K2 inputs are written after stage 12 (section 10.7). |
| AR2 | Idempotent. The same bytes under an existing key succeed without a change. The archive never overwrites: different bytes under an existing key are a conflict. Because G and A1 run first, a conflict on the action bytes or the salt is impossible (equal `commitment_hash` fixes `action.hash`, and a different salt or different bytes would need a SHA-256 collision); envelopes can differ only by a second valid signature of the agent key over the same hash (G2 rules out malleated `S`), and the gate treats that conflict as success, keeping the stored record, which verifies equally. Any other conflict is an archive fault: `ErrArchiveUnavailable`, nothing signed. |
| AR3 | Failure, timeout or an archive the gate cannot reach: answer `ErrArchiveUnavailable` (HTTP 503 with a `Retry-After` header, section 18.3). The nonce is not consumed and nothing is signed, so the same request can be retried unchanged. |
| AR4 | No fallback: a gate with an archive configured MUST NOT issue an Authorization whose decision record is not durable, whatever its mode. |
| AR5 | Rejection marker. When a request whose decision record exists (stage 4a passed) is then refused with a verdict, the gate marks that record rejected with the error name exactly as listed in section 21 (for example `ErrExpired`, `ErrIssuedBeforeAnchor`, `ErrNonceUsed`), its `gate_id` and the gate clock at refusal. Verdicts are the sentinels of stage 4m rule M1, stage 4p and stages 5 to 12 (the list is in section 19.2, kind 5); an M0 or M2 refusal writes no decision record and so no marker (section 8.8). Operational failures (`ErrChainUnavailable`, `ErrArchiveUnavailable`, `ErrAnchorIntentUnavailable`, `ErrAnchorIntentRejected`, a signer error or timeout) say nothing about the decision and are not marked. The marker is archive metadata of the gate: not signed and not part of any message between parties; its archive record layout is section 19. |
| AR6 | States and idempotence. A record is in exactly one state: `pending` (no outcome recorded), `rejected` or `authorized`. Allowed transitions: `pending` to `rejected`, `pending` to `authorized`, `rejected` to `authorized` (a retry that passes, for example after `ErrNotYetValid` or `ErrPayloadUnavailable`). `authorized` is final. The marker write is atomic and conditional: it applies only if the record holds no Authorization, and is a no-op otherwise. Marking with a name already present is a no-op; a later refusal with another name adds that name; names are never removed or rewritten. The gate never writes a marker when its registry holds an Authorization for this `commitment_hash` (for example `ErrNonceUsed` on a same-commitment retry, retry rule above). So an authorized decision is never in state `rejected`; names marked before it was authorized stay as a history of refused attempts. |
| AR7 | Marker write failure is fail-safe. The gate still refuses with the original verdict sentinel (the verdict never depends on the marker), signs nothing and does not consume the nonce, exactly as before. It logs the failure at error level and raises a metric, and SHOULD retry the write later. The record stays `pending`, which no verifier reports as authorized (AR8). A marker failure never turns into an Authorization or a consumed nonce. |
| AR8 | Verifier report. `verify` and `replay` report the record state: `authorized` only with a SignedAuthorization for this `commitment_hash` that verifies (section 15.3); `rejected` with every marked error name when the record holds markers and no Authorization; `pending` otherwise. A `rejected` or `pending` record MUST NOT be reported as authorized or executed, and no receipt is accepted for it as evidence of anything (a gate issues none without an Authorization, section 14.3). |

Threat note (archive before authorize). Without AR4 an Authorization can
exist for a decision whose envelope and action bytes exist only in the gate's
registry, which prunes; once it does, `verify <ref>` and `replay <ref>` have
nothing to verify and the decision is unauditable. Writing first costs one
durable write per authorization and turns an archive outage into a
retryable refusal, never into an unverifiable action. The archive is trusted
for availability only: a record that differs from what the gate later reads
fails the verifier's own checks (signature, action hash). The write happens
after G, L and A (the `edictad` server decodes, checks the signature and the
allowlist and runs A before writing, then runs the remaining stages), so an
unauthenticated caller cannot fill the archive, and a caller who holds a
published envelope but not the committed action bytes and salt cannot store
wrong bytes under its key first and lock the real request out. A request that
fails stage 1 to 4 stores nothing; a request that
passes A and then fails a later stage leaves a record of a decision that
was never authorized, which is harmless (the record is the agent's own
signed decision, and the absent Authorization says it was not authorized).

Threat note (rejected records, AR5 to AR8). Refused decisions are kept as
an audit trail: an auditor sees what an agent tried and why the gate
refused it. The risk is that a reader takes such a record for an
authorized or executed decision; the marker names the refusal, and AR8
makes the Authorization, never the presence of a record, the only basis
for `authorized`. The marker is unsigned and the archive is trusted for
availability only, so a lying archive can drop or invent markers; it still
cannot make a record `authorized`, because that needs the gate's
signature. The conditional write keeps a refused retry that races a
successful one from marking an authorized record. A crash after stage 12
and before the Authorization reaches the archive can leave a record
`rejected` (from an earlier attempt) or `pending` while the registry holds
the Authorization; the gate repairs it from the registry at the next start
and on a same-commitment retry, and until then the report under-states,
never over-states, what was authorized. Retention and cleanup of rejected
records are not specified.

Threat note (sign before consume). Stages 1 to 11 write nothing to the
nonce registry (stage 4a writes only the idempotent archive record), so a
transient DA, chain, archive or signer failure never burns a nonce, and anyone holding
the envelope and the action bytes can retry. The Authorization exists only in
gate memory until stage 12 commits, and it leaves the gate only after the
commit is durable. A crash before the commit leaves nothing stored and the
nonce unused; the retry gets a fresh Authorization (possibly with another
`expires`). The first one never left the gate's trust boundary (its process
and its signer); with a remote signer it may still exist there, so after such
a crash two distinct valid Authorizations for one decision can exist. Both
carry the same `commitment_hash`, so executor dedupe (section 16, I5) still
allows at most one execution. A crash after the commit and before stage 13
is covered by the retry rule. Consuming the nonce first and then
authorizing could burn a nonce with no outcome; this order cannot.

Threat note (E1). If the registry is lost and recreated, every nonce is
"unused" again. Any commitment authorized against the old registry passed T1
at some `now_old < epoch`, so `issued_at <= now_old + skew_s <= epoch + skew_s`,
and E1 rejects it on the new registry. Assumption: the gate clock does not step
back across the recreation. Cost: commitments issued within `skew_s` seconds
after a new registry is created are refused once. Vectors: `anchor.json`
`epoch` (equality rejected, one second after accepted, saturation at
`2^64-1`). Gate implementations additionally keep a persisted clock watermark
and a prune cutoff inside the registry transaction, so a clock step forward,
a prune and a step back cannot make a pruned nonce usable again; those are
operational rules of the gate and have no wire format.

Threat note (L0, key roles; invariant 7). A key acts either as an agent key or
as a gate key, never both (and never as an executor or a principal key). Domain separation already makes a gate signature
useless as a commitment signature and vice versa (`edicta/v1/sig` versus
`edicta/v1/authorization-sig` and `edicta/v1/receipt-sig`, over hashes under
different tags; vectors `sig_under_authorization_sig_tag`,
`authorization_signed_by_agent_key`, `authorization_reuses_commitment_signature`),
so L0 is defence in depth: it keeps a compromised or misconfigured gate key
from also deciding, and keeps an audit reader from having to ask which role a
signature played. The gate also refuses to start with its own key in its
allowlist. No vector for L0 itself: the vector format has no gate key
configuration; gate tests cover it.

What happens after stage 13 is outside the gate: the integrator's executor
verifies the Authorization, executes the exact bytes once and may ask the gate
to notarize a rail reference (sections 14 and 16).

### 8.8 Mandate reference (stage 4m)

Runs at every gate, after stage 4 (A) and before 4p.

| Rule | Gate | Condition | Result |
|---|---|---|---|
| M0 | without a mandate | commitment with key 14 | `ErrMandateMismatch` |
| M1 | with a mandate | commitment without key 14 | `ErrMandateRefMissing` |
| M2 | with a mandate | key 14 differs from `mandate_hash` of the mandate in force (the hash the verdict will carry), compared in constant time | `ErrMandateMismatch` |
| | | otherwise | continue |

Before refusing under M0, M1 or M2 the gate runs the stored-retry check,
which a gate without a mandate needs as well (M0): it reads the nonce entry
of `(agent_pubkey, nonce)`; if the entry holds this `commitment_hash`, it
answers by the retry rule of section 8.7 (`ErrNonceUsed` with the stored
SignedAuthorization, handed out only after decoding it, verifying it under
the gate key and comparing its `commitment_hash` and `action_hash` with the
presented ones in constant time; a mismatch is `ErrActionMismatch` with no
Authorization) and writes nothing. With a mandate, policy 11.1 runs the same
check and also returns the stored verdict. Otherwise the gate refuses. After
an M1 refusal it runs stage 4a and writes the rejection marker. After an M0
or M2 refusal it writes nothing: no decision record (stage 4a is skipped),
no marker, no kind 15 record. No policy verdict is signed for any 4m
refusal: the gate never signs a verdict under a mandate the agent did not
commit to.

Reasoning. After a mandate version bump, in-flight decisions carry the old
hash and are refused; the agent re-signs under the new hash (same payload
reference, new nonce). The stored-retry check keeps the crash-liveness of a
decision that was already authorized before the bump.

Threat note (M0). The agent signed `mandate_ref`, which says "I act under
this mandate". A gate without a mandate (the mandate dropped from the
configuration, or a library gate) would otherwise authorize the decision
with no verdict, and every such decision would verify `valid` while the
principal's limits were never applied. M0 refuses it at the gate; the
verifier requires the `policy` check whenever the envelope has
`mandate_ref` (section 20.5), so an Authorization from a gate that skipped
M0 is never `valid` without an allow verdict. An agent that acts with no
mandate omits key 14.

Rationale (no record after M0 or M2). Such a decision was never
policy-evaluated: no verdict exists, and an archive record would imply that
it was evaluated. The typical cause is a benign mandate-version race. The
attempt stays visible in DA, because the decision blob is published before
authorization.

Threat note (no record after M0 or M2). The decision record takes its form
from the mandate in force (section 19.2), not from the mandate the agent
named. Under M0 or M2 the two differ: the agent may have committed under a
private mandate (its action bytes and salt meant to stay encrypted to that
mandate's auditors) while the gate has none, a public one, or a private one
with other auditors. A form 1 record would publish the action bytes and the
salt that unblinds the public `action_hash` in the shared archive; a form 2
record would encrypt them to auditors the principal never chose. This
happens in practice: a switch from private to public mode needs a new
`mandate_id` (policy 6.3), so every in-flight decision under the old mandate
meets M2. So nothing is written. Cost: the refusal leaves no audit trail in
the archive; the caller still receives the sentinel, and the agent re-signs
under the mandate in force. M1 keeps its record: a commitment without key 14
named no mandate, so the form of the mandate in force is the only one there
is.

### 8.9 Configuration

| Field | Rule |
|---|---|
| `FastMode` | bool; default false. Requires `PendingNamespaces` non-empty and an archive (`ErrInvalidConfig`), and a mandate (constructor check, `ErrInvalidConfig` with cause `fast_mode_without_mandate`: no mandate, no fast mode). |
| `FastWindowBlocks` | `1..1000`, default 100 (100 blocks is about 5 minutes at 3 s blocks, a per-network example). Upper bound of `anchor_deadline - h0`. |
| `MaxH0AgeBlocks` | `1..FastWindowBlocks - 1`, default 10. Upper bound of `head - h0` at authorization (V1-6). |
| `MinFastSlackBlocks` | `1..100`, default 3. Least `anchor_deadline - head` at authorization (section 13.3). |
| `MinPromiseSlackSeconds` | `1..600`, default 15. Least time left before the Fibre promise expires at authorization (section 13.1 F5). |
| `PendingNamespaces` | list of 29-byte namespaces, each passing S8. |
| `RebroadcastIntent` | bool, default true; applies to `da = 1` only (F6). For `da = 2` the broadcast check B5 always runs. |
| `RevealOnExecution` | list of action types (section 19.7). Default empty. Each MUST be in the action-type allowlist (C2; cause `reveal_on_execution`) and MUST be registered in the gate's compiled profile registry with `public_execution = true` (cause `reveal_not_public_execution`; a type no compiled profile registers is refused the same way). The registry is code shipped with the gate, like the extractor registry (policy section 5), not configuration: a profile document states `public_execution` (dca-agent 3.4: false; bank-send 3.5: true). The core imports no profile, so the integrator's build fills the registry and passes it to the gate constructor; this check therefore runs in the constructor (below), not in `ValidateBasic`. |

Cross-field rule: `MaxH0AgeBlocks + MinFastSlackBlocks <= FastWindowBlocks`,
so that a fresh `h0` can always pass (`ErrInvalidConfig`, cause
`age_plus_slack`). Defaults are applied before validation by a separate step
(project convention); validation (`ValidateBasic`) holds every stateless
check above, in table order, then the cross-field rule; the checks that
need a dependency run in the constructor, in this order: `RevealOnExecution`
against the profile registry (`reveal_not_public_execution`); FastMode
without a mandate (`fast_mode_without_mandate`); then, with `FastMode` on and
the mandate's `fast_mode_max_delay` present, `fast_mode_max_delay >=
MinFastSlackBlocks + 1`, else cause `fast_delay_below_slack`. The same check
runs when a later mandate version is adopted at runtime: the adoption is
refused with that cause and the version in force stays. The gate refuses the
whole version rather than clamping the bound, because the principal signed
that setting and a gate-chosen value would be a limit nobody signed: the
setting is invalid as a whole, so the fix is a new version from the
principal (fail closed; until then the old version's M2 refusals are loud). Vectors:
`spec/vectors/v1/gate.json` (top-level `profile_registry`; optional per-case
`allowlist` and `mandate_fast_mode_max_delay`).

Threat note (`RevealOnExecution`). A reveal publishes the action salt. For a
type executed on a public rail that hides nothing new (the transaction is
public and the receipt links it). For an off-chain type (the IBKR order)
the salt would make the low-entropy order bytes testable against the public
`action_hash`, which is exactly the dictionary search the salt exists to
stop. Taking the flag from compiled profiles, not from an operator list,
keeps a misconfiguration from doing that.

Threat note (`fast_delay_below_slack`). The window is at most
`fast_mode_max_delay` (section 13.3) and the slack needs `anchor_deadline >=
head + MinFastSlackBlocks`, so a bound below `MinFastSlackBlocks + 1`
refuses every pending reference whose head is past `h0` with
`ErrAnchorWindowClosed`, after the K-fast work. That is a liveness failure,
never a safety one, but a silent one; refusing at start makes it visible.

## 9. Payload blob and its hashes

The blob is the canonical CBOR encoding (same profile, arrays allowed) of:

```
{ 1: version      uint = 1,
  2: recipients   [ { 1: recipient_kid bstr 1..32,
                      2: enc           bstr 32,      ; HPKE encapsulated key (X25519)
                      3: wrapped_dek   bstr 48 } ... ],  ; 32-byte DEK + 16-byte tag
  3: aead_nonce   bstr 12,
  4: ciphertext   bstr }                              ; ChaCha20-Poly1305, includes its 16-byte tag
aead_plaintext = salt (32 bytes) || plaintext
```

DEK wrapping is HPKE base mode, X25519 / HKDF-SHA256 / ChaCha20-Poly1305
(RFC 9180). The exact construction is section 9.1; decoding, plaintext and
opening are sections 9.2 to 9.4.

| Definition | Statement | Inv. |
|---|---|---|
| `ciphertext_hash` | `H(blob)` over the exact bytes handed to the DA submit call, first byte to last: version, every recipient entry, nonce, ciphertext and tag. Bytes are hashed as received, never re-encoded. The gate never decodes the blob. | 2 |
| Excluded | Everything the DA layer adds: share framing and padding, namespace prefixes, sequence lengths, the 5-byte Fibre blob header, Fibre rows and parity, archive metadata. | 2 |
| `plaintext_hash` | `H(salt || plaintext)`, salt exactly 32 bytes and first in the AEAD plaintext. | 2 |
| `payload_size` | `len(blob)`, the same bytes as `ciphertext_hash`. Not the Fibre `PaymentPromise.blob_size`, which is the padded upload size. | 2 |

Threat notes: the fixed salt width means `salt || plaintext` splits only one
way. 256 random bits make a dictionary attack on a low-entropy plaintext
(for example "buy" or "sell") infeasible. `plaintext_hash` has no domain tag
by design; it is only ever compared with a hash recomputed from a
decrypted payload, never signed on its own.

Vectors (`v1/payload.json`): `ciphertext_hash_small_blob` (the blob of
`minimal_lmt`, dummy bytes that stage P only hashes), `plaintext_hash_basic`,
and the three payload rejects.
`blob_with_share_padding` models a producer that hashed share-framed bytes;
its framing is illustrative only (one share-version-1 sparse share: namespace,
info byte `0x03`, 4-byte big-endian sequence length, the 20-byte signer of
`minimal_lmt`, data, zero padding to 512 bytes).

### 9.1 Encryption (producer)

```
DEK         = 32 bytes from a CSPRNG, one per blob, never reused
aead_nonce  = 12 bytes from a CSPRNG
salt        = 32 bytes from a CSPRNG
plaintext   = canonical CBOR of the Payload (section 9.3)
ciphertext  = ChaCha20-Poly1305-Seal(key = DEK, nonce = aead_nonce,
                                     aad = tag("edicta/v1/payload"),         ; 18 bytes, 0x11 || ASCII
                                     pt  = salt || plaintext)                 ; RFC 8439, 16-byte tag appended
for each recipient i, in producer order, with X25519 public key pkR_i and label kid_i:
  enc_i, ctx_i  = SetupBaseS(pkR_i, info = tag("edicta/v1/payload-dek"))   ; 22 bytes, 0x15 || ASCII
  wrapped_dek_i = ctx_i.Seal(aad = uint8(len(kid_i)) || kid_i, pt = DEK)   ; sequence 0, 48 bytes
blob        = canonical CBOR { 1: 1, 2: [ {1: kid_i, 2: enc_i, 3: wrapped_dek_i} ... ], 3: aead_nonce, 4: ciphertext }
```

| Item | Value |
|---|---|
| HPKE suite | RFC 9180 mode_base (`0x00`); KEM DHKEM(X25519, HKDF-SHA256) `0x0020`; KDF HKDF-SHA256 `0x0001`; AEAD ChaCha20Poly1305 `0x0003` (the suite of RFC 9180 Appendix A.2). No PSK, no auth mode. |
| `enc` | The 32-byte serialized ephemeral X25519 public key (`SerializePublicKey`). |
| Recipients | 1..16 entries. `kid` is an opaque byte string of 1..32 bytes chosen by the producer; kids are pairwise distinct within one blob. Order is the producer's and carries no meaning; it is not sorted. |
| Size | A producer MUST NOT emit a blob longer than `2^27 - 5` bytes (the Fibre data maximum, section 10.2); `payload.ErrTooLarge`. Readers accept up to `2^27` (B0). |
| Randomness | `DEK`, `aead_nonce`, `salt` and every HPKE ephemeral key come from a CSPRNG. Test vectors fix them from labels (section 22); no production API may accept them from the caller. |

Reasoning and threat notes:
- One DEK, many wraps: the payload is encrypted once, so each recipient adds `89 + len(kid)`
  bytes (one more for a kid of 24 bytes or longer), not the payload size.
- The AEAD nonce is random although the DEK is single use: it costs nothing
  and still protects against an implementation bug that reuses a DEK.
- The HPKE `aad` binds each wrapped DEK to its kid: swapping kids between
  entries makes both fail to unwrap instead of silently opening under another
  label (vector `pb_kids_swapped`). The length byte makes the aad
  unambiguous.
- The recipient list is not in the payload AEAD's `aad`: `ciphertext_hash`
  in the signed commitment already covers every byte of the blob.
- Base mode, not auth mode: the payload is authenticated by the agent's
  Ed25519 signature over a commitment that carries `ciphertext_hash` and
  `plaintext_hash`. Auth mode would add a second long-term agent key. Anyone
  can build a blob for any recipient set; only the signed commitment makes it
  the agent's.
- Kids are public (threat model, section 1): meaningful labels reveal who can
  read each decision (auditor, counterparty) and link payloads. v1 guidance:
  use non-identifying labels when identities are sensitive. A reader that is
  not given a kid tries every entry (rule O4), so random per-blob kids work
  without a format change.
- ChaCha20-Poly1305 is not key-committing (multi-key collisions, Len, Grubbs
  and Ristenpart, USENIX Security 2021): a malicious producer can wrap DEK1 for
  one recipient and DEK2 for another such that one ciphertext opens under both
  to different bytes. The defence is rule O7: every recipient compares
  `H(aead_plaintext)` with the signed `plaintext_hash` before using the bytes.
  Vector `pb_key_commitment_two_deks` is such a blob.
- X25519 inputs: an `enc` whose shared secret is all zero (low-order point)
  MUST be rejected as an unwrap failure (RFC 9180 section 7.1.4; vector
  `pb_enc_low_order`).

### 9.2 Blob decoding (readers)

Readers (recipients, verifiers, replay tools) decode a blob with a sequential
parser of the fixed layout. Walk in byte order; the first failing rule
decides the sentinel. The gate never decodes the blob.

| Rule | Check | Sentinel | Vectors |
|---|---|---|---|
| B0 | `len(blob) <= 2^27`, before parsing | `blob.ErrTooLarge` | none (size only; Go unit test) |
| B1 | The top item is a map of exactly 4 pairs, keys `1, 2, 3, 4` in this order, each key a one-byte uint; every head in the blob is shortest form and of definite length; no major 1, 6 or 7 anywhere | `blob.ErrMalformed` | `pb_blob_truncated`, `pb_blob_nonminimal_version`, `pb_blob_nonminimal_nonce_len`, `pb_blob_unsorted_keys`, `pb_blob_extra_key`, `pb_blob_indefinite_array`, `pb_blob_float_version`, `pb_blob_version_tstr` |
| B2 | `version` is a uint; a uint other than `1` is `blob.ErrVersion` | `blob.ErrVersion` (`blob.ErrMalformed` if not a uint) | `pb_blob_version_0` |
| B3 | `recipients` is an array with 1..16 entries, checked at the array head | `blob.ErrRecipients` | `pb_recipients_0`, `pb_recipients_17` |
| B4 | Each entry is a map of exactly 3 pairs, keys `1, 2, 3` in order: `kid` bstr 1..32, `enc` bstr 32, `wrapped_dek` bstr 48 | `blob.ErrMalformed` | `pb_kid_empty`, `pb_kid_33_bytes`, `pb_kid_tstr`, `pb_enc_31_bytes`, `pb_wrapped_dek_49_bytes`, `pb_entry_missing_wrapped_dek` |
| B5 | `kid` values are pairwise distinct (bytewise), checked as each kid is read | `blob.ErrDuplicateKID` | `pb_duplicate_kid` |
| B6 | `aead_nonce` bstr 12; `ciphertext` bstr of at least 49 bytes (32 salt + 1 + 16 tag) | `blob.ErrMalformed` | `pb_nonce_11_bytes`, `pb_ciphertext_48_bytes` |
| B7 | No byte follows the top-level map | `blob.ErrMalformed` | `pb_blob_trailing_byte` |

Not rules, on purpose: entries are not sorted; `enc` is not validated as a
point at decode time (a bad point fails at O5). A string whose length exceeds
the remaining input is a truncation (B1). Given B0 to B7 the accepted set is
exactly the canonical encodings of the layout, so `encode(decode(x)) == x`
(fuzz property). A producer refuses 0 or more than 16 recipients and duplicate
kids with the same sentinels. The `payload.json` blob
`ciphertext_hash_small_blob` is dummy bytes in the shape of a blob whose
version field is 0: stage P hashes it, and a reader that decoded it stops at
B2 (checked by the Python checker).

Threat note: two readers that disagree on what a blob contains could be shown
different recipient lists or ciphertexts from the same `ciphertext_hash`.
A fixed layout with one encoding per blob removes that room.

### 9.3 Payload plaintext

`plaintext` is the canonical CBOR (section 3 profile) of:

```
Payload = { 1: version     uint = 1,
            2: model       Model,
            3: policy      Policy,
            4: context     Data,                 ; REQUIRED
            5: action      PayloadAction,        ; the cleartext action; O8 ties it to commitment key 8
            ; 6 unassigned
            7: metadata    Data (O) }
PayloadAction = { 3: type tstr 3..128 (media-type grammar, section 4.5), 4: data bstr 1..65536,
                  5: action_salt bstr 32 }                                                   ; 1, 2 unassigned
Model   = { 1: id tstr 1..128, 2: version tstr 1..64 (O), 3: digest bstr 32 (O) }
Policy  = { 1: id tstr 1..128, 2: version tstr 1..64 (O), 3: digest bstr 32 (O), 4: text bstr 1.. (O) }
Data    = { 1: media_type tstr, 2: data bstr }  ; both keys REQUIRED
```

| Field | Rule |
|---|---|
| `id`, `version` (model, policy) | Printable ASCII `0x20..0x7e`. |
| `digest` | Exactly 32 bytes; the producer's choice of hash (for example SHA-256 of model weights or policy text). Not checked by Edicta. |
| `media_type` | REQUIRED in `context` and in `metadata` whenever `metadata` is present. 1..64 bytes, lower case, matching `name "/" name` with `name = [a-z0-9][a-z0-9!#$&^_.+-]*` (RFC 6838 restricted-name characters, lower case only). Exactly one `/`, no parameters (`;`), no whitespace. |
| `context.data` | 0..n bytes, opaque to Edicta; interpreted per `media_type`. Empty is allowed because the field is required. |
| `metadata.data` | 1..n bytes (an optional field is absent, never empty). |
| `action.type` | Same length and grammar as the commitment's `action.type`. |
| `action.data` | The exact action bytes, 1..65536 bytes (`MaxActionSize`). Opaque to the core; O8 binds them to `action.hash`. |
| `action.action_salt` | Required, exactly 32 bytes: the salt of the commitment's `action.hash` (section 5.1). It is an envelope field next to the action bytes, not part of the opaque context. |
| Depth, entries | Payload 1; model, policy, context, action, metadata 2. At most 16 entries per map. |
| Size | No limit of its own; the blob bound (section 9.1) applies. |

Decoding, one schema for every payload:

| Rule | Statement | Sentinel |
|---|---|---|
| PV2 | A payload that is well-formed and canonical except that `version != 1` is refused. | `payload.ErrVersion` |
| PV3 | Any profile, schema, limit, charset or media type failure, including action key 5 missing, of another type or not exactly 32 bytes, or a re-encoding that differs from the input. | `payload.ErrMalformed` |

Input with several defects may yield either sentinel. Vectors:
`v1/payload.json` `open_reject` (`payload_v1_salt_missing`,
`payload_v1_salt_31`, `payload_v1_salt_tstr`, `payload_version_0`) and the
`pb_payload_*` rejects of `v1/payload_blob.json`.

Reasoning:
- Lower-case media types: RFC 6838 names are case-insensitive, so
  `Application/JSON` and `application/json` would be two byte strings for one
  type. Requiring lower case leaves one encoding per type, so replay tools can
  dispatch on bytes. Parameters are excluded for the same reason (order,
  quoting and case of parameter values); a type that needs a charset names it
  in its definition (for example `application/json` is UTF-8 by RFC 8259).
- `context` and `metadata` are opaque bytes with a required type rather than
  open CBOR maps: a text-keyed or free-form map would break the profile
  (uint keys, at most 16 entries, depth at most 4). Structure belongs to the
  media type; the core defines none (the dca-agent profile defines
  `application/vnd.edicta.dca.v0+cbor`).
- The payload carries the cleartext action bytes so a recipient can replay
  exactly what was authorized, and a context media type can be checked
  against the action (the dca-agent profile's DCA1..DCA5).
- The AEAD salt is not a CBOR field. It is the fixed 32-byte prefix of the
  AEAD plaintext (section 9), so `salt || plaintext` splits one way only. It
  is not the action salt: the AEAD salt hides `plaintext_hash`, the action
  salt hides `action_hash`, and neither is derived from the other (deriving
  the action salt from the payload key or the AEAD salt was rejected because
  it would make keyless execution checks in public mode impossible).
- The action salt is in the payload so that every party that opens it can
  run O8 on the salted hash.

### 9.4 Opening (recipients and verifiers)

`OpenPayload(envelope, blob, recipient key, optional kid)` runs, in this
order:

| Rule | Check | Sentinel | Vectors |
|---|---|---|---|
| O1 | The signed envelope decodes and its signature verifies (stages D, S, G; section 6, 7, 5) | stage D, S, G sentinels | `valid.json`, `reject.json` |
| O2 | P1 and P2 hold for the blob (section 8.5) | `ErrPayloadSizeMismatch`, `ErrPayloadHashMismatch` | `payload.json` |
| O3 | The blob decodes (section 9.2) | B0..B7 sentinels | `pb_*` decode rejects |
| O4 | Entry selection: with a kid, the entry with that kid, else `blob.ErrNoRecipient`. Without a kid, every entry in blob order; the first entry that unwraps (O5) is used and its DEK is final | `blob.ErrNoRecipient` | `pb_kid_absent` |
| O5 | HPKE `SetupBaseR(enc, skR, info)` and `Open(aad = uint8(len(kid)) \|\| kid, wrapped_dek)`; any failure, including an all-zero X25519 output; without a kid, failure of every entry | `blob.ErrUnwrap` | `pb_wrong_recipient_key`, `pb_wrong_recipient_key_try_all`, `pb_kids_swapped`, `pb_enc_swapped`, `pb_flipped_wrapped_dek`, `pb_flipped_enc`, `pb_enc_low_order`, `pb_hpke_info_*`, `pb_hpke_aad_kid_unprefixed` |
| O6 | ChaCha20-Poly1305 open of `ciphertext` with the DEK, `aead_nonce` and `aad = tag("edicta/v1/payload")` | `blob.ErrDecrypt` | `pb_flipped_ciphertext`, `pb_flipped_aead_tag`, `pb_flipped_aead_nonce`, `pb_aead_aad_*` |
| O7 | `H(aead_plaintext) == plaintext_hash`, over the full decrypted bytes as they are, **before any parsing** | `sdk.ErrPlaintextHashMismatch` | `pb_plaintext_hash_unsalted`, `pb_plaintext_hash_of_other_salt`, `pb_key_commitment_two_deks` |
| O8 | `aead_plaintext[32:]` decodes as a Payload (section 9.3, PV2, PV3); then `payload.action.type == c.action.type` (bytewise) and `ActionHash(payload.action.type, payload.action.action_salt, payload.action.data) == c.action.hash` (section 5.1) | `payload.ErrMalformed`, `payload.ErrVersion`, then `sdk.ErrPayloadMismatch` | `pb_payload_*`; `v1/payload.json` `payload_v1_minimal`, `payload_v1_wrong_salt`, `payload_v1_unsalted_commitment` |

**O7 is mandatory for every party that opens a payload** (the SDK, a
verifier, a replay tool, an auditor, a counterparty, or any other consumer):
it MUST compare `H(aead_plaintext)` with the signed `plaintext_hash` before
parsing, displaying or acting on any decrypted byte, and MUST discard the
bytes on mismatch. Reason: ChaCha20-Poly1305 is not key-committing, so a
malicious producer can wrap DEK1 for one recipient and DEK2 for another such
that one ciphertext passes O6 under both and yields two different plaintexts
(vector `pb_key_commitment_two_deks`). HPKE and the AEAD therefore do not
bind a recipient to *the* payload; only the signed `plaintext_hash` does. A
recipient that skips O7, or parses first, can be shown a decision that
no other recipient sees. O7 is what makes the scheme key-committing as a
whole, under SHA-256 collision resistance.

An O8 failure is a `payload` fail of the verifier (section 20.1): the agent's
own signed payload contradicts its own commitment, whatever any archive copy
holds. The comparison of the payload's salt with an archive copy runs after
O8 and never blames the agent (section 20.11).

O1 and O2 need the envelope; the `payload_blob.json` reject vectors exercise
O3 to O8 directly, given the commitment's `plaintext_hash`, `action.type` and
`action.hash`. `OpenPayload` checks no time, scope or anchor: replay happens after
expiry, and anchor checks belong to the verifier. A low-level open that stops
after O6 MUST be documented as not bound to any commitment.

The two hashes, exactly:

| Hash | Preimage | Not in the preimage |
|---|---|---|
| `ciphertext_hash` | Every byte of the blob as handed to the DA submit call: the CBOR map head, version, every recipient entry (kid, enc, wrapped_dek), `aead_nonce`, and `ciphertext` including its 16-byte tag. Hashed as received, never re-encoded. | DA framing of section 9 (share framing, padding, Fibre header, rows). |
| `plaintext_hash` | `salt \|\| plaintext`: exactly the bytes the AEAD returns at O6. No domain tag. A verifier hashes them as they are and never re-encodes. | The Poly1305 tag, `aead_nonce`, recipient entries, the blob's CBOR framing. |

### 9.5 Producer checks before signing

A producer (the SDK) MUST, before it signs a commitment:

| Rule | Check | On failure |
|---|---|---|
| W1 | The payload plaintext re-decodes under section 9.3, its `version` is 1, its `action_salt` is the salt the producer used for `action.hash`, and its `action` matches the commitment's key 8 as in O8 | refuse (`payload.ErrMalformed`, `sdk.ErrPayloadMismatch`) |
| W2 | `ciphertext_hash` and `payload_size` are computed over the exact bytes given to the publisher, and the publisher contract is "bytes unchanged" | refuse |
| W3 | The commitment passes stages D, S, G, T on the exact bytes it returns (the gate's own code) | the stage sentinel |
| W4 | The DA commitment recomputed locally from the blob equals the `payload_ref.commitment` the Recorder returned: `da = 2`: `CreateCommitment(NewV1Blob(namespace, blob, signer), RFC6962, 64)` (section 10.5). `da = 1`: the `da = 1` committer of section 10.4 (`fibre.NewBlob`), injected into the producer from the separate Fibre module; a producer built without it refuses unless the caller explicitly opted out for `da = 1`. Default: on for every `da`; the opt-out is explicit and per `da` | `sdk.ErrDACommitmentMismatch`; `sdk.ErrDACheckUnavailable` when no recompute exists and no opt-out was given |
| W5 | Independent inclusion check (below). Mandatory when the submitter is a different party; optional when submitter and producer are one operator | `sdk.ErrInclusionUnverified`, `sdk.ErrBlockTimeMismatch`, `sdk.ErrUnexpectedRef` |
| W6 | Bounded publication wait (below) | `sdk.ErrPublishTimeout` |

Threat note (W4, "anchor X, sign H(Y)" on the producer side). A Recorder that
anchors blob X but returns X's locator while the agent signs
`ciphertext_hash = H(Y)` (a bug, or a malicious or compromised hosted
Recorder) makes the agent's key sign a false statement: "my payload Y was
public at height H". The gate rejects at P2 or P3 (section 8.5) either way,
so gate safety does not depend on W4; W4 keeps the agent from attaching its
signature to a decision that cannot be authorized and that an auditor would read as
dishonest. The recompute is over bytes the producer already holds. With the
opt-out, the agent trusts its Recorder for this. For `da = 1` the recompute
also needs no download: the producer holds the bytes before upload, and the
Recorder computes the same commitment before submitting (section 10.4).

#### Rule W5: independent inclusion check

Before signing, the producer MUST verify, from sources not controlled by the
submitter, that block `payload_ref.height` contains a blob with
`payload_ref.namespace`, `.commitment` and `.signer`:

1. If the producer is configured with expected namespaces or submitter
   accounts, `payload_ref.namespace` and `payload_ref.signer` are among them
   (`sdk.ErrUnexpectedRef`).
2. The header of block `payload_ref.height` is verified by light-client rules
   against validator-set signatures, reached from a trust anchor (CometBFT
   light-client verification: more than 2/3 of the voting power at the target
   height signed its commit, and the trust rules hold for every skip from the
   anchor). Headers and commits come from consensus RPC providers configured
   by the producer, not controlled by the submitter, with at least one
   witness besides the primary.
3. A commitment proof for `payload_ref.commitment` verifies against that
   header's data root. The proof may come from any node, including the
   submitter's. Together with W4 this binds the blob bytes, `namespace` and
   `signer` to block `height`: W4 recomputes the commitment from them, and
   the proof shows that the subtree roots whose Merkle root is that
   commitment are in the data root.
4. The producer uses that header's time, floored to seconds, as `T_H` for its
   validity window, and it MUST equal the block time the submitter reported
   (`sdk.ErrBlockTimeMismatch`).

Any failure of 2 or 3, including an unreachable provider, is
`sdk.ErrInclusionUnverified`; the producer does not sign.

`da = 1`: there is no `signer` and no blob commitment proof
for a Fibre payload. The evidence equivalent to step 3 is the PFF tx at
`height` (section 10.4), proven against that header's data root by a tx
inclusion proof; a serving API and an offline verifier for that proof are
`UNVERIFIED` (section 10.7). Until they are settled, a `da = 1` producer
MUST have its submitter under the same operator and runs W5 at `SelfCheck`
level or omits it; a hosted `da = 1` submitter is not supported in v1.

Trust levels, in decreasing strength:

| Level | Header source | Assumption | Allowed |
|---|---|---|---|
| `Light` | Light-client verification as in step 2 | A trust anchor (height and hash) inside its trust period, which is below the chain's unbonding time; more than 2/3 of voting power honest at H; one honest provider among primary and witnesses (equivocation is detected only with an honest witness) | Always |
| `CrossCheck` | The header of H (hash, data root, time) from two or more independent providers that agree bytewise | Non-collusion of the providers; no signature is checked. Weaker: it MUST be identified as such in configuration and logs | As an interim substitute for `Light`, at either trust relation |
| `SelfCheck` | The operator's own node | The operator's own node is honest | Only when submitter and producer are under one operator |

When submitter and producer are under one operator, W5 MAY use the operator's
own node, or MAY be omitted; then the producer relies on its Recorder for
`height` and `T_H`. When the submitter is a
different party (a hosted relay, another operator), W5 MUST be performed at
level `Light` or `CrossCheck`, and a producer MUST refuse to start with
`SelfCheck` or without W5.

`CrossCheck` source identity (minimum). Independence is counted per
host, never per configured string. Each header provider URL is normalized
before any comparison, both between sources and against the submitter's
own node:

| Rule | Normalization |
|---|---|
| X1 | The URL is absolute; the scheme is compared lower-case and MUST be one the implementation supports. Unparsable, relative, or an unknown scheme: refuse to start |
| X2 | The host is compared lower-case, with one trailing dot removed (`a.example.` is `a.example`); an IPv6 literal is compared without brackets |
| X3 | The port is explicit: when absent, the scheme's default (`http`, `ws`: 80; `https`, `wss`: 443; a scheme without a default and without a port: refuse to start) |
| X4 | Path, query, fragment and user info are not part of the identity; in particular a trailing `/` and any other path are ignored |

The identity of a source is `scheme://host:port` after X1 to X4. A producer
MUST refuse to start (a configuration error) if two configured `CrossCheck`
sources have the same normalized host (X2), whatever their scheme, port or
path: two endpoints on one host are one provider, and silently counting or
silently dropping one of them would misstate the number of independent
sources. A source whose normalized host equals that of a node the submitter
controls (for the reference tools, the node configured for submission) is
submitter-controlled and does not count toward the two independent sources.
After this check, fewer than two independent sources is also a refusal to
start.

Threat note (source identity). The rule closes operator mistakes in which
one provider is listed twice under different spellings (`https://a` and
`https://A:443/`, `a.example.` and `a.example`), which would let one node
satisfy "two or more independent providers". It does not prove
independence: an IP address and its DNS name, two DNS names for one machine,
`localhost` versus `127.0.0.1` versus `::1`, or two hosts run by one company
still count as two. Independence stays an operator assertion, and the
level stays weaker than `Light` for that reason.

Facts the rule relies on (celestia-core `v0.42.3`, celestia-node `v0.31.4`
source read locally; `UNVERIFIED` that they are unchanged at the pinned
celestia-node `v0.34.2-mocha` and app `v10.x`):
- The header field `data_hash` is the data root of the extended square: the
  app supplies it through `types.NewData(txs, squareSize, hash)`, and
  `Data.Hash()` returns that value (celestia-core `types/block.go`).
- `CommitmentProof.Verify(dataRoot, commitment)` checks that the Merkle root
  of the proof's subtree roots equals `commitment`, the NMT proofs of those
  subtree roots to the row roots, and the row roots to `dataRoot`
  (celestia-node `blob/commitment_proof.go`). It does not take a namespace
  argument; the namespace binding comes from W4, because the subtree roots
  that hash to the recomputed commitment are NMT roots carrying the
  namespace.
- `UNVERIFIED`: that the stock celestia-core `light` client verifies headers
  of an app-v10 chain without changes.

Threat note (W5). W4 alone binds the bytes to a commitment the submitter
named; it says nothing about whether that commitment is on chain at the
claimed height, or about the block time. A submitter that lies about height
or time could otherwise make the agent sign `issued_at` values that K1
later rejects, or sign a decision that was never public. With W5 the agent
signs only after the chain of evidence bytes -> commitment (W4) -> data root
(proof) -> validator signatures (light client) is complete, and none of it
comes from the submitter. The gate's own anchor checks (K0, K1, P1 to P3) are
unchanged; a gate MAY use the same verifier for K0 and `T_H` instead of its
own node.

#### Rule W6: bounded publication wait

A producer bounds the wait for publication, including W4 and W5, by a
deadline of its own (`MaxPublishWait`). A payload not confirmed in time, or
on an ambiguous submitter error, or failing W5, is discarded unsigned. A
retry seals a new payload (new salt, DEK and AEAD nonce, hence a new blob and
commitment) under a new commitment nonce and publishes it again, at most a
configured number of times, then `sdk.ErrPublishTimeout`. A late anchor of a
discarded blob is not a decision: no signed commitment refers to it. A
producer re-evaluates its decision before a retry if its inputs may have gone
stale.

Threat note (W6). A submitter that censors or delays can only make a
decision late or absent; it cannot make the agent wait forever or sign a
decision whose publication was not confirmed. Re-issuing with a new nonce
instead of re-signing the late blob keeps "one decision, one nonce, one
published payload" and avoids two commitments over one payload.

Private mandate (policy 9.5). Under a mandate with `auditors` the agent MUST
include every auditor of the mandate among the payload's recipients, and
gives the action salt, outside the payload, only to the gate and the
executor: every payload recipient learns the action and its salt.

For a pending reference the producer rule is W5-P (section 12.2) in place of
W5.

## 10. payload_ref, Fibre and L1

### 10.1 Pins

| Repo | Tag | Commit | Why |
|---|---|---|---|
| celestiaorg/celestia-app | `v10.4.0-mocha` | `5187d2fb5eb8bc4b534c74724882943c54253ae9` | Latest v10 tag on 2026-10-03; contains `x/fibre`, `fibre/`, `x/blob`. Same commit as `v10.4.0-corto`. |
| celestiaorg/go-square | `v4.0.1` | `948e81207e45d7daa9b4c68a8a4931b9118eae9f` | Version required by the app pin's `go.mod`. Namespace and share commitment code. |
| celestiaorg/celestia-node | `v0.34.2-mocha` | `cd6cd46f00a572a7010fecc7e0dacf8a456982d2` | Latest node tag; pruning windows; Fibre and blob client APIs. |
| celestiaorg/nmt | `v0.24.5` | `a2ba47691cbda955ca24fb9fa97b2a12ceb2ff91` | The version the node pin resolves; NMT namespace proofs for the `da = 1` anchor lookup (section 10.4). SHA from the Go module proxy's origin record, 2026-10-06. |

The SHAs come from `git ls-remote` against GitHub on 2026-10-03; the tags are
lightweight, so each SHA is the tagged commit. `UNVERIFIED`: the pins are a
proposal pending confirmation.

`UNVERIFIED`: `v10` is a pre-release line. The latest non-pre-release app tag
is `v9.0.8`, which has no `x/fibre`. Fibre exists on the Mocha and Corto
testnets only. Mainnet parameters may differ.

Note: `celestia-node v0.34.2-mocha` imports `celestia-app/v10 v10.1.0-mocha`
(`fa5b523b7e3b2b83bd16bc072a45cbd3819fa369`). The files cited below for the
Fibre commitment, BlobID, params, protos, namespace validation and blob
header are byte-identical between `v10.1.0-mocha` and `v10.4.0-mocha`.

Replace set (decision of 2026-10-05): every Edicta module that imports
celestia-app uses the replace directives of celestia-node `v0.34.2-mocha`
verbatim. celestia-app `v10.4.0-mocha` itself pins newer forks (celestia-core
`v0.42.3` instead of `v0.42.0`, cosmos-sdk `v0.52.12` instead of `v0.52.8`,
store `v1.1.3-celestia.3`, api `v0.7.7`, an x/evidence fork). The Fibre
vectors are identical under both sets (generator run, 2026-10-05); any
runtime difference elsewhere is `UNVERIFIED`.

Sources below use these prefixes:
`APP = https://github.com/celestiaorg/celestia-app/blob/5187d2fb5eb8bc4b534c74724882943c54253ae9`,
`SQ = https://github.com/celestiaorg/go-square/blob/948e81207e45d7daa9b4c68a8a4931b9118eae9f`,
`NODE = https://github.com/celestiaorg/celestia-node/blob/cd6cd46f00a572a7010fecc7e0dacf8a456982d2`.

### 10.2 Fact table

| Fact | Value | Status | Source |
|---|---|---|---|
| Namespace size | 29 bytes = 1 version byte + 28-byte id | VERIFIED | `SQ/share/consts.go` (`NamespaceSize`, `NamespaceIDSize`) |
| Blob namespace rule | Version 0 only; id starts with 18 zero bytes; not reserved | VERIFIED | `SQ/share/consts.go` (`NamespaceVersionZeroPrefixSize`, `SupportedBlobNamespaceVersions`), `SQ/share/namespace.go` (`ValidateForBlob`, `validateID`, `IsReserved`) |
| Fibre uses the same namespace rule | `MsgPayForFibre` requires 29 bytes and `ValidateForBlob` | VERIFIED | `APP/x/fibre/types/msgs.go` |
| L1 share commitment | 32 bytes: RFC 6962 merkle root (`merkle.HashFromByteSlices`, SHA-256) over NMT subtree roots of the blob's shares, `SubtreeRootThreshold = 64` | VERIFIED | `SQ/inclusion/commitment.go` (`CreateCommitment`), `APP/x/blob/types/payforblob.go`, `APP/pkg/appconsts/app_consts.go` |
| PFB share versions | A PFB accepts share versions 0 and 1 only. Share v2 is the Fibre system blob, not user-submittable | VERIFIED | `APP/x/blob/types/payforblob.go` (`ValidateBasic`, line 121) |
| Share v1 signer | Exactly 20 bytes (`SignerSize`), the raw account address, written into the first share right after the 4-byte sequence length | VERIFIED | `SQ/share/consts.go` (`SignerSize`), `SQ/share/blob.go` (`NewBlob`, `NewV1Blob`), `SQ/share/split_sparse_shares.go`, `SQ/share/share_builder.go` (`WriteSigner`), `APP/specs/src/shares.md` ("Share Version 1") |
| Blob signer equals PFB signer | Enforced by the chain for share v1 in `ValidateBlobTxSkipCommitment`, called from CheckTx and ProcessProposal; the PFB `signer` is the tx signer (`cosmos.msg.v1.signer`) | VERIFIED | `APP/x/blob/types/blob_tx.go`, `APP/app/check_tx.go`, `APP/app/process_proposal.go`, `APP/proto/celestia/blob/v1/tx.proto` |
| Fibre commitment | 32 bytes, `SHA256(rowRoot || rlcOrigRoot)` from rsema1d encoding | VERIFIED | `APP/fibre/blob_id.go` (`CommitmentSize`), `APP/pkg/rsema1d/types.go` |
| Fibre BlobID | 33 bytes = blob version (1 byte) `||` commitment; only version 0 exists | VERIFIED | `APP/fibre/blob_id.go`, `APP/fibre/blob.go` (`BlobConfigForVersion`) |
| Fibre max blob size | `MaxBlobSize = 2^27` including a 5-byte header (version 1 byte, data size uint32), so max data is `2^27 - 5` | VERIFIED | `APP/fibre/protocol_params.go`, `APP/fibre/blob.go` |
| Fibre minimum size | No protocol minimum. Uploads are padded to whole rows; `min_upload_size` (default 262144) is a local server config, not a governance parameter | VERIFIED | `APP/fibre/server_config.go` (`MinUploadSize`) |
| L1 max blob size | Bounded by `MaxTxSize = 8 MiB` per PFB tx and by the square size (`GovMaxSquareSize` default 256) | VERIFIED (bound), exact usable maximum `UNVERIFIED` | `APP/pkg/appconsts/app_consts.go`, `APP/pkg/appconsts/initial_consts.go` |
| `shard_retention` | Default 4h, governance bounds 10m to 168h | VERIFIED | `APP/x/fibre/types/params.go`, `APP/x/fibre/README.md` |
| Shard prune time | `pruneAt = max(promise expiry, creation_timestamp + shard_retention)`, computed once at upload from the retention value at that moment | VERIFIED at pin | `APP/fibre/server_upload.go` (`shardPruneAt`), `APP/specs/src/fibre_server.md` |
| Unsettled promise is charged | A `PaymentPromise` handed to validators but never settled by a PFF (fewer than 2/3 signatures, a crash, a lost connection) can be settled by anyone holding it with `MsgPaymentPromiseTimeout`, once block time reaches `creation_timestamp + payment_promise_timeout` (default 1 h, bounds 10 min to 12 h) and while the promise is still fresh (`creation_timestamp` after `block time - withdrawal_delay`, default 24 h). Only the payer's promise signature is checked, no validator signatures. The escrow pays `PaymentAmount(blob_size)`, the same as for a PFF, and the promise is marked processed, so it can never anchor afterwards. A failed upload can therefore cost one fee and never creates an anchor | VERIFIED (code) | `APP/x/fibre/keeper/msg_server.go` (`PaymentPromiseTimeout`), `APP/x/fibre/keeper/keeper.go` (`validatePaymentPromiseStatefulInternal`), `APP/x/fibre/types/params.go`, `APP/x/fibre/types/gas.go` (`PaymentAmount`) |
| `height` for Fibre | The block height in which `MsgPayForFibre` was included (`SubmitResult.Height`). Not `PaymentPromise.height`, which selects the validator set | VERIFIED | `NODE/nodebuilder/fibre/types.go`, `APP/proto/celestia/fibre/v1/fibre.proto` |
| `height` for L1 blobs | The block height in which the PFB was included (`blob.Submit` returns it; `blob.Get(height, namespace, commitment)` reads it) | VERIFIED | `NODE/nodebuilder/blob/blob.go` |
| L1 blob retention | Pruned nodes keep `7d + 1h` (`StorageWindow`); light nodes sample 7d (CIP-036). Archival nodes keep everything | VERIFIED | `NODE/share/availability/window.go`, `NODE/nodebuilder/pruner/module.go` |
| Fibre fetch | `Download(BlobID)`; the client verifies rows against the commitment in the BlobID, never returns partial data, and returns exactly the submitted bytes (header and padding stripped); a download-only client (`fibre.NewClient(nil, cfg)`) needs no key | VERIFIED (code; Mocha probe 2026-10-05) | `NODE/nodebuilder/fibre/fibre.go`, `APP/fibre/README.md` |

### 10.3 Namespace rule (S8)

`namespace` is valid if and only if:
1. `namespace[0] == 0x00` (version 0), and
2. `namespace[1..18]` (18 bytes) are all zero, and
3. `namespace[19..27]` (the first 9 bytes of the 10-byte sub-id) are not all
   zero.

Rule 3 excludes the primary reserved range `0x00 || 0^27 || 0x00..0xff`
(Tx, PFB, PFF and padding namespaces). Secondary reserved namespaces have
version `0xff` and already fail rule 1. This matches `ValidateForBlob` at
the pin.

### 10.4 Fibre locator (`da = 1`)

- `commitment` is the 32-byte rsema1d commitment, not the 33-byte BlobID
  (vector `fibre_commitment_33_bytes`). The BlobID for a download is
  `0x00 || commitment`, because blob version 0 is the only version at the
  pin. `da = 1` means Fibre blob version 0. A future Fibre blob version gets
  a new `da` value; `da = 1` keeps its meaning.
- The anchor is the `MsgPayForFibre` tx at `height` whose `PaymentPromise`
  has the same `namespace` and `commitment` (lookup below).

Recompute (normative; celestia-app at the pin,
`APP/fibre/blob.go`, `APP/fibre/blob_id.go`, `APP/fibre/protocol_params.go`):

```
b   = fibre.NewBlob(copy_of(blob), fibre.DefaultBlobConfigV0())  ; blob = bytes covered by ciphertext_hash
c   = b.ID().Commitment()                                        ; b.ID() = 0x00 || c, 33 bytes
ok <=> c == payload_ref.commitment
```

| Fact (blob version 0) | Value | Status |
|---|---|---|
| Encoded input | 5-byte header (`0x00`, then the data length as uint32 big-endian) followed by the data | VERIFIED (code) |
| Rows | 4096 original rows, 12288 parity rows (16384 in total) | VERIFIED (code) |
| Row size | `ceil((len(blob) + 5) / 4096)` rounded up to a multiple of 64 | VERIFIED (code, vectors) |
| Upload size | `4096 * row_size`; this is `PaymentPromise.blob_size`, the size that is paid for (minimum 262144) | VERIFIED (code; live vector) |
| Commitment | `SHA-256(rowRoot \|\| rlcOrigRoot)` from rsema1d | VERIFIED (code) |
| Data size | 1 to `2^27 - 5` bytes; `NewBlob` refuses 0 and anything larger | VERIFIED (code, vectors) |
| Ownership | `NewBlob` takes ownership of its input and may reuse it as row storage, so callers pass a private copy | VERIFIED (code) |
| Determinism | Same bytes, same commitment, at `v10.1.0-mocha` and `v10.4.0-mocha` and under both candidate replace sets | VERIFIED (diff of the commitment code; the generator run under both sets, 2026-10-05) |

There is no second, independent implementation of rsema1d. The definition is
the upstream code at the pin, which is also what validators check shards
against before signing. Vectors: `spec/vectors/da/fibre_commit.json`,
produced by upstream code only (section 22), including the live Mocha blob
`fibre_live_mocha_popsmin1` whose commitment was read from the chain. A
second-language gate links the same upstream code or reproduces every vector
bit for bit; the Python checker checks the file structure and the size
arithmetic, not the commitments.

Fibre payload limit (normative). Every component that
handles `da = 1` has a configured cap `fibre_max_data_bytes`, default
16 MiB (16,777,216 bytes), allowed range 1 to `2^27 - 5`:

| Component | Rule | On failure |
|---|---|---|
| Recorder | Refuses a blob above its cap before committing, archiving or paying | `recorder.ErrTooLarge` (413) |
| Gate (with a `da = 1` committer) | C4 (section 8.3): `payload_size` above its cap, before any fetch | `ErrPayloadAboveCap` (413) |
| Committer | Refuses to encode above its own cap, which MUST be at least the gate's and the Recorder's cap in the same deployment (section 8.5) | `ErrDACommitmentMismatch` |
| Producer (SDK) | SHOULD use the cap of the Recorder and gate it targets, so that it never signs a decision the gate refuses by size | - |
| Verifier | MAY refuse to recompute above its own cap (default `2^27 - 5`, every valid blob); it then reports P3 as not checked, never as passed | - |

The 16 MiB default bounds the encode memory (about 200 MB per check) and
upload cost; S7 (`2^27`) stays the format limit for every `da`. Raising the
cap is a configuration change; the value is not on the wire.

Submission (normative for v1). A Recorder submits `da = 1` blobs only
through the operator's own node (section 2: chosen and controlled by the
operator, not necessarily self-hosted), holding the escrow account key in
that node's keyring. A node or relay controlled by someone else is not
supported for `da = 1` submission in v1. Reason: the node signs the
`PaymentPromise` with the escrow key and runs the upload; a third party would
hold the key that pays and could spend the escrow on blobs of its own.
`recorder.ErrSubmitMismatch` (section 21) and W4 catch a substituted commitment, not
that spending. The
gate's reads (anchor, retention, download) may still use other endpoints
under the rules of section 10.9.

Anchor lookup (rule K0 for `da = 1`). The gate proves the anchor from the PayForFibre
namespace of block `height` and never reads the whole block. Sources: the
gate's consensus endpoint for the header at `height` and for result codes; a
celestia-node bridge for the data availability header (DAH) and the namespace
data. `PFF_NS` is go-square `PayForFibreNamespace`, `0x00 || 0^27 || 0x05`
(VERIFIED, `SQ/share/consts.go` and the live vectors).

| Rule | Requirement | On failure |
|---|---|---|
| NA1 Header | The header at `height` is read from the consensus endpoint under HR1 (section 10.9): its height equals `height`. `data_hash` and `T_H` (K1, K2) come from this one header. A header returned by a bridge never stands in for it. | `ErrChainUnavailable` (HR3 and HR5 as for any header read) |
| NA2 DAH | The DAH (row roots and column roots) comes from a bridge (`header.GetByHeight(height)`, field `dah`; the returned header's height MUST equal `height`, HR1) or from any other source. It is accepted iff upstream `DataAvailabilityHeader.ValidateBasic` passes (as many row roots as column roots, each count from 2 to 1024) and `Hash()`, the RFC 6962 root over `row_roots \|\| column_roots`, equals `data_hash` of NA1. | `ErrChainUnavailable` |
| NA3 Namespace data | `share.GetNamespaceData(height, PFF_NS)` from a bridge. Accepted iff upstream `NamespaceData.Verify(dah, PFF_NS)` passes (celestia-node at the pin, nmt `v0.24.5`): with `R` the rows, ascending, whose row root's namespace range `[min, max]` contains `PFF_NS` (`RowsWithNamespace`; parity rows never qualify), the answer has exactly `len(R)` entries, and entry `j` is a complete NMT namespace proof against `row_roots[R[j]]`: an inclusion proof with the row's shares of the namespace, or an absence proof without shares. `VerifyNamespace` checks the leaf namespaces, the range and completeness (no leaf of the namespace left or right of the range). `R` empty with no entries is a valid proof that the block holds no PFF. The gate bounds the bytes it reads per answer (`fibre_anchor_read_max_bytes`, configuration, default 16 MiB); a larger answer fails. | `ErrChainUnavailable` |
| NA4 Reassembly | `S` = the shares of all entries, in order. If `S` is empty, `T` is empty. Otherwise `T = ParseTxs(S)` (go-square compact-share parsing), and splitting `T` again with `NewCompactShareSplitter(PFF_NS, 0)` MUST give exactly `S` (same count, every share byte-equal). | `ErrChainUnavailable` |
| NA5 Candidates | A tx of `T` is a candidate iff upstream `fibretypes.TryParseFibreTx` (`APP/x/fibre/types/classified_tx.go`) classifies it as a Fibre tx and its single `MsgPayForFibre` carries a `PaymentPromise` with `namespace == payload_ref.namespace`, `commitment == payload_ref.commitment`, `blob_version == 0`, `chain_id` equal to the gate's configured chain id, and `PaymentPromise.height <= height` (equality allowed). Any other tx of `T` is not a candidate, including one whose message or promise does not decode: at the gate that can only end in `ErrAnchorNotFound` (a refusal, the safe direction). An absence proof treats such a unit as "not proven" instead (section 20.8 AB4). | - |
| NA6 Code | The result code of a candidate `x` comes from the consensus endpoint's gRPC `cosmos.tx.v1beta1.Service/GetTx` with the hash `SHA-256(x)` (upper-case hex). It is used only if `tx_response.height == height` and `tx_response.txhash` is that hash (HR1). Settlement level `node-attested` (section 10.6.1). | Error, not found, or another height: `ErrChainUnavailable` |
| NA7 Selection | Candidates are taken in order of `creation_timestamp`, then of position in `T`. The anchor is the first whose code (NA6) is 0. A candidate whose code cannot be read stops the lookup if no candidate before it had code 0: it may be the anchor. | No candidate, or every candidate has a non-zero code: `ErrAnchorNotFound` |

`ErrAnchorNotFound` is answered only after NA1 to NA4 held, so "no anchor" is
a statement about the complete namespace data of the block whose header has
`data_hash`, not about a bridge's answer. Every other failure is operational
and retryable (`ErrChainUnavailable`, 503, nonce untouched; `valid_until`
bounds the retries). A gate whose configured DA is `fibre` MUST have at least
one bridge configured for NA2 and NA3 and refuses to start otherwise (a
configuration error, like a missing committer); a configured bridge that is
unreachable at request time gives `ErrChainUnavailable`. With several bridges
the gate MAY try the next one after a failure of NA2, NA3 or NA4: those
failures belong to the bridge's answer, never to the chain. The NA1 header,
the DAH and the namespace data MAY be cached per height once verified; `T`
depends on nothing else. The tx index of the node is needed for NA6 only.

| Fact behind NA1 to NA7 | Status |
|---|---|
| `data_hash` of a Celestia header is the DAH hash (`DataAvailabilityHeader.Hash`: RFC 6962 over the row roots, then the column roots) | VERIFIED (code `APP/pkg/da/data_availability_header.go`; live: at both vector heights the bridge's DAH hashes to the `data_hash` of the consensus node's `/header`) |
| `ValidateBasic` checks only the counts (equal, 2 to 1024); root lengths and a power-of-two width are not checked, and need not be: once the hash matches, the roots are the chain's | VERIFIED (code) |
| With unequal counts `Hash()` does not hash the concatenation (it allocates `2 * len(row_roots)` slots), so the count check must come first; an implementation that hashes `row_roots \|\| column_roots` directly would accept a shifted split (one column root moved into the row roots) against the same `data_hash` and then read the wrong row roots | VERIFIED (code; vector `dah_split_shifted`) |
| NMT completeness needs nmt `v0.24.3` or later: earlier versions skip the right-side check when the proof's nodes run out before the range start (GHSA-r9fq-g486-v8pg). celestia-node `v0.34.2-mocha` resolves `v0.24.5` | VERIFIED (code: the guard is in `proof.go` of `v0.24.3` to `v0.24.5`, absent in `v0.24.2`) |
| The PayForFibre shares of a block are exactly what `NewCompactShareSplitter(PFF_NS, 0)` makes of its txs (one sequence, canonical reserved bytes, zero padding), so NA4 accepts real blocks | VERIFIED (live: Mocha heights 1,402,819 and 1,439,696). `UNVERIFIED` as a protocol guarantee: that the square builder at the pin never lays out this namespace differently |
| `ParseTxs` alone drops a cut last unit, stops at zero bytes inside the sequence, and checks neither the share count, the reserved bytes of continuation shares nor a second sequence start, all without an error | VERIFIED (code `SQ/share/parse_compact_shares.go`; vectors `reassembly`) |
| Because splitting is injective, any parser that returns `T` for `S = split(T)` gives the same NA4 verdict as `ParseTxs`, except on a zero-length unit, which `ParseTxs` reads as the end of the data; a second implementation mirrors that | VERIFIED (code; the Python checker's own parser and splitter agree on every vector) |
| The order of `T` equals the relative order of those txs in the block's `data.txs` | `UNVERIFIED` (expected from square construction). NA7 uses the order only to break a tie of equal timestamps between promises for one blob |
| gRPC `GetTx` answers for a PayForFibre tx with its height and code; it needs the node's tx index (`tx_index.indexer = "kv"`) | VERIFIED (live, `grpc-mocha.pops.one`, both vector heights, 2026-10-06) |
| The node-reported index of a PFF (CometBFT `/tx` `index`) is its position in `data.txs` | VERIFIED (one live sample, height 1,402,819: index 1 of 2) |
| A PFF included with code 0 at `height` has `PaymentPromise.height <= height`: the keeper reads x/staking `HistoricalInfo` at the promise height (`validateValidatorSignatures`), which is written in BeginBlock of that height, so above the current block it does not exist and the tx fails; equality is possible. The keeper makes no explicit comparison | VERIFIED (code, celestia-app-fibre snapshot `v6.0.0-20260127170033-157017cbe077`, `x/fibre/keeper/msg_server.go`). `UNVERIFIED` at the pin |
| Whether a PFF can be included with a non-zero code, and whether its system blob is then in the square | Yes, through an ante failure in FinalizeBlock only: ProcessProposal runs the ante handler and the message of every PFF and rejects the block if either fails (`APP/app/process_proposal.go`), but a non-Fibre tx placed earlier in the same block can drain the PFF's fee payer, so the PFF fails `DeductFeeDecorator` in FinalizeBlock (no escrow debit, no `ProcessedPayment`). Its system blob is in the square, which is built from every tx before execution (`ClassifyTxs`). VERIFIED (code at the pin, task 045 research). Message-level failures (escrow, expiry, replay, height window) cannot be included under more than 2/3 honest voting power. NA7 handles either answer |

From the anchor the gate takes `PaymentPromise.creation_timestamp` for K2
(section 12.2) and `T_H` from the NA1 header. It MAY also check that
`PaymentPromise.blob_size` equals the upload size of `payload_size` and run
the certificate rule of section 10.6.1 on the anchor's bytes from `T`; P3
already implies the first, and inclusion with code 0 implies that the chain
accepted the second.

The Recorder reads its anchor back with the same procedure (one shared
function in the Go code, as for the certificate rule), with its own node as
the consensus endpoint, and archives exactly the DAH and namespace data it
verified (section 10.7).

Threat note (lookup). The bridge is untrusted. NA2 to NA4 make everything it
returns self-checking against `data_hash`, which comes from the header the
gate already trusts for `T_H` (section 10.9). A bridge can withhold or garble
an answer, which gives `ErrChainUnavailable`, but it cannot add a PFF, drop
one or reorder the namespace without breaking an NMT proof or the DAH hash,
and a cut or padded sequence fails NA4 even where `ParseTxs` would not
complain. Completeness matters twice: it makes `ErrAnchorNotFound` a proof of
absence instead of a bridge's word, and it shows every earlier candidate, so
nobody can hide the PFF with the earliest `creation_timestamp` and move K2's
`start` later. What is not proven: code 0 (NA6) is the consensus node's word,
as before (`node-attested`), and a node can hide a code-0 result by answering
"not found", which is a retryable refusal, never an Authorization. The header
is trusted from the node (or from the W5 light verifier), as in section 10.9:
a node that serves a false header together with a matching false DAH and
namespace data defeats NA1 to NA4, as it would have defeated the block scan.
Requiring code 0 keeps a PFF that the chain rejected in execution from
serving as evidence; matching `chain_id` keeps a promise signed for another
chain from matching, although inclusion on this chain already implies it.
Cost: the namespace data grows with the PFFs in the block, not with the block
(live: 6.9 KB for one PFF in a 4 x 4 square, 15.4 KB for four PFFs in a
64 x 64 square; the task 017 probe read about 74 times less than the whole
1.1 MB block it compared with), plus the DAH (90 bytes per root: 1.5 KB and
23.5 KB in the vectors, about 185 KB at the 512 x 512 bound).

Threat note (`ShareProof`, not used on this path). celestia-app
`pkg/proof.ShareProof.Validate` (the type of `NewTxInclusionProof`, CometBFT
`/tx?prove=true` and `prove_shares_v2`) checks the Merkle proof of each row
root against the data root and each share range against its row root, but
not that the Merkle proof of row `i` has index `start_row + i`, nor that its
total is the number of DAH roots (`4k` for a `k x k` square), nor that the
row is an original row (`< k`). A prover can present a column root, or a row
at another position, as "row `start_row`", and the shares it proves are then
not the contiguous range the proof claims. `ShareProof` also verifies with
`VerifyInclusion`, which has no completeness, so it cannot show that no other
PFF is in the namespace. VERIFIED (code `APP/pkg/proof/row_proof.go`,
`APP/pkg/proof/share_proof.go`). Edicta takes no position or absence claim
from a `ShareProof`. A component that checks one anyway (the optional
`anchor_tx_proof`, section 19.2) MUST, given a DAH that passed NA2, also
require `row_roots[i] == dah.row_roots[start_row + i]`, `index ==
start_row + i` and `total == 4k` for every row proof, and `end_row < k`.

### 10.5 celestia_blob locator (`da = 2`)

Rule (normative): a `celestia_blob` payload MUST be published
as one L1 blob with **share version 1**, whose embedded signer is
`payload_ref.signer`, in namespace `payload_ref.namespace`, paid by a
`MsgPayForBlobs` included at `height`, with share commitment
`payload_ref.commitment`. Share version 0 is not accepted: the same bytes as
a share-version-0 blob have a different share commitment, so the recompute
below fails and the verifier rejects.

Verified at the pins:

| Fact | Source |
|---|---|
| User PFBs accept share versions 0 and 1 (`ValidateBasic`) | [`APP/x/blob/types/payforblob.go#L121`](https://github.com/celestiaorg/celestia-app/blob/5187d2fb5eb8bc4b534c74724882943c54253ae9/x/blob/types/payforblob.go#L121) |
| Constructor: `share.NewV1Blob(ns Namespace, data []byte, signer []byte) (*Blob, error)`; `NewBlob` rejects a v1 signer whose length is not `SignerSize` | [`SQ/share/blob.go#L75`](https://github.com/celestiaorg/go-square/blob/948e81207e45d7daa9b4c68a8a4931b9118eae9f/share/blob.go#L75), [`#L43`](https://github.com/celestiaorg/go-square/blob/948e81207e45d7daa9b4c68a8a4931b9118eae9f/share/blob.go#L43) |
| `SignerSize = 20` | [`SQ/share/consts.go#L83`](https://github.com/celestiaorg/go-square/blob/948e81207e45d7daa9b4c68a8a4931b9118eae9f/share/consts.go#L83) |
| The signer is written into the first share after the sequence length | [`SQ/share/split_sparse_shares.go#L48`](https://github.com/celestiaorg/go-square/blob/948e81207e45d7daa9b4c68a8a4931b9118eae9f/share/split_sparse_shares.go#L48), [`SQ/share/share_builder.go#L177`](https://github.com/celestiaorg/go-square/blob/948e81207e45d7daa9b4c68a8a4931b9118eae9f/share/share_builder.go#L177), [`APP/specs/src/shares.md#L53`](https://github.com/celestiaorg/celestia-app/blob/5187d2fb5eb8bc4b534c74724882943c54253ae9/specs/src/shares.md#L53) |
| The chain enforces blob signer == PFB signer for share v1 (`ErrInvalidBlobSigner`), where the PFB signer is `sdk.AccAddressFromBech32(msg.signer)` | [`APP/x/blob/types/blob_tx.go#L106`](https://github.com/celestiaorg/celestia-app/blob/5187d2fb5eb8bc4b534c74724882943c54253ae9/x/blob/types/blob_tx.go#L106) |
| That check runs in CheckTx and ProcessProposal (`ValidateBlobTx` and `ValidateBlobTxSkipCommitment`), and `ValidateBlobTx` recomputes every share commitment from the blob including its signer | [`APP/app/check_tx.go#L78`](https://github.com/celestiaorg/celestia-app/blob/5187d2fb5eb8bc4b534c74724882943c54253ae9/app/check_tx.go#L78), [`APP/app/process_proposal.go#L188`](https://github.com/celestiaorg/celestia-app/blob/5187d2fb5eb8bc4b534c74724882943c54253ae9/app/process_proposal.go#L188), [`#L301`](https://github.com/celestiaorg/celestia-app/blob/5187d2fb5eb8bc4b534c74724882943c54253ae9/app/process_proposal.go#L301), [`APP/x/blob/types/blob_tx.go#L39`](https://github.com/celestiaorg/celestia-app/blob/5187d2fb5eb8bc4b534c74724882943c54253ae9/x/blob/types/blob_tx.go#L39) |
| The PFB `signer` is the account that signs the tx | [`APP/proto/celestia/blob/v1/tx.proto#L30`](https://github.com/celestiaorg/celestia-app/blob/5187d2fb5eb8bc4b534c74724882943c54253ae9/proto/celestia/blob/v1/tx.proto#L30) (`cosmos.msg.v1.signer`) |
| Client-side constructor applies the same rule | [`APP/x/blob/types/payforblob.go#L53`](https://github.com/celestiaorg/celestia-app/blob/5187d2fb5eb8bc4b534c74724882943c54253ae9/x/blob/types/payforblob.go#L53) (`ValidateBlobShareVersion`) |

`signer` encoding: the raw 20-byte account address, the bytes that bech32
`celestia1...` encodes. It is not the bech32 text (vector
`signer_bech32_tstr`). A 32-byte address (for example a module or ICA
account) cannot sign a share-version-1 blob and cannot appear in the locator
(vector `signer_32_bytes`). The Recorder's PFB account MUST therefore be an
ordinary 20-byte account.

Recompute (go-square at the pin,
[`SQ/inclusion/commitment.go#L20`](https://github.com/celestiaorg/go-square/blob/948e81207e45d7daa9b4c68a8a4931b9118eae9f/inclusion/commitment.go#L20)):

```
ns  = share.NewNamespaceFromBytes(payload_ref.namespace)          ; 29 bytes, S8 holds
b   = share.NewV1Blob(ns, blob, payload_ref.signer)               ; blob = bytes covered by ciphertext_hash
c   = inclusion.CreateCommitment(b, RFC6962_SHA256_Root, 64)
ok <=> c == payload_ref.commitment
```

- `RFC6962_SHA256_Root` is the RFC 6962 binary Merkle root: leaf
  `SHA256(0x00 || x)`, inner `SHA256(0x01 || left || right)`, split at the
  largest power of two strictly below the leaf count, empty input
  `SHA256("")`. The app passes cometbft `merkle.HashFromByteSlices`, which
  computes exactly this
  ([`APP/x/blob/types/payforblob.go#L58`](https://github.com/celestiaorg/celestia-app/blob/5187d2fb5eb8bc4b534c74724882943c54253ae9/x/blob/types/payforblob.go#L58)).
  go-square does not export one, so an implementation supplies it.
- `64` is `SubtreeRootThreshold`, a constant, not chain state
  ([`APP/pkg/appconsts/app_consts.go#L30`](https://github.com/celestiaorg/celestia-app/blob/5187d2fb5eb8bc4b534c74724882943c54253ae9/pkg/appconsts/app_consts.go#L30)).
- go-square alone is sufficient; no celestia-app import is needed.
- The anchor is the PFB tx at `height` whose `signer` decodes to
  `payload_ref.signer` and whose `namespaces[i]`, `share_commitments[i]` and
  `share_versions[i]` equal `namespace`, `commitment` and `1` for some
  index `i`.

Threat note: what the signer binding adds, and what it does not.

- Adds: the share commitment becomes recomputable from data the verifier has
  (`namespace`, `signer`, blob), so archive bytes can be tied to the anchor
  without trusting the archive.
- Adds: binding to an L1 account. Because the chain rejects a v1 blob whose
  embedded signer differs from the PFB signer, a blob with commitment
  `payload_ref.commitment` can only have been paid for by `signer`. Another
  account that re-posts the same bytes gets a different commitment, so it
  cannot produce or front-run the anchor of a given commitment.
- Does not authenticate the agent. The agent is authenticated only by the
  Ed25519 signature over the commitment (G0 to G2). `signer` is chosen by the
  agent like any other field. Nothing in v1 ties `signer` to `agent_pubkey`
  or to a Recorder allowlist; a gate that wants "only our Recorder" must
  check `signer` against configuration (section 8.7).
- Does not prove the Recorder behaved correctly. A compromised Recorder key
  can anchor any bytes under its own account.
- Names the submitter, not who decided. `signer` is the account of whoever
  submitted the blob (section 1, blob submitter): the operator's Recorder,
  or, with a third-party relay, the relay. It is never evidence of which
  agent decided; only the agent signature is. A consumer that wants "only
  our submitter" checks `signer` against configuration (W5 step 1 for a
  producer, a gate-side check for a gate).
- Holds only as long as more than 2/3 of voting power is honest. The signer
  rule is checked in CheckTx and ProcessProposal, not re-executed in
  FinalizeBlock, the same assumption as for share commitments in general.
- Privacy: `signer` is public and links every `celestia_blob` decision
  anchored by the same account. The namespace already links them, so this
  adds little.
- Fibre (`da = 1`) has no `signer`: the rsema1d commitment does not include
  a signer, and the PFF signer appears only in the share-version-2 system
  blob. Binding a Fibre anchor to an account would need a new `da` value.

### 10.6 What the PFF anchor proves, and what it does not

`MsgPayForFibre` carries the `PaymentPromise` (chain id, valset height,
namespace, padded `blob_size`, blob version, commitment, creation timestamp,
escrow signer key and signature) and validator signatures over
`RawBytesMessageSignBytes(chain_id, "fibre/pp:v0", stripped_promise)` with
the validators' ed25519 consensus keys (`APP/specs/src/fibre_server.md`,
`APP/fibre/payment_promise.go`). A validator signs only after verifying its
assigned shards and their row proofs against the commitment.

Inclusion of the PFF at `height` proves: validators holding more than 2/3 of
the voting power at `PaymentPromise.height` attested that they hold their
shards of the blob with this commitment, and that this happened no later
than block `height`. That is the "public at decision time" property, given
`issued_at` is after `height`.

It does not prove:
- that the blob is the agent's payload. That link is `ciphertext_hash` in the
  signed commitment, checked against the bytes (P2);
- that the archive copy is the published blob. A verifier that reads from the
  archive and wants to tie the bytes to the anchor MUST recompute the DA
  commitment from the bytes (rsema1d for Fibre; share-version-1 commitment
  with `signer` for L1, section 10.5) and compare it with
  `payload_ref.commitment`. The hash alone proves integrity
  against the commitment, not publication;
- retention beyond `pruneAt`.

Threat assumptions: validator signatures are verified in CheckTx and
ProcessProposal only, not in FinalizeBlock (`APP/x/fibre/README.md`), so a
verifier that trusts inclusion relies on more than 2/3 of voting power being
honest, as for blob share commitments. `UNVERIFIED`: the exact semantics a
validator signature attests (custody of assigned shards versus a stronger
availability claim) and whether a PFF inclusion proof format for light
clients exists at the pin.

#### 10.6.1 Certificate rule for verifiers (`da = 1`)

A verifier (the `verify` and `replay` tools, an auditor) that re-checks the
availability certificate without the chain, for example after the chain
pruned the validator history (about 8 h, below), applies these rules to the
archived PFF tx. They mirror the keeper at the pin
(`APP/x/fibre/keeper/msg_server.go` `validateValidatorSignatures`,
`APP/fibre/payment_promise.go`, `APP/fibre/validator/signature_set.go`;
VERIFIED, code), so that a verifier never rejects what the chain accepted for
a reason the chain does not have, and never accepts less. Any failure is a
verification failure; the verifier reports the first rule that failed. For
`verify` and `replay` that failure makes `anchor` `unchecked` with reason
`source_corrupt`, and never `fail`. The archived
certificate and proofs are the archive's answer, and a failure shows that
this copy does not prove the anchor (20.1). The gate and the Recorder still
refuse on any failure.

| Rule | Check |
|---|---|
| CV1 | The archived tx parses as a Fibre tx (`TryParseFibreTx`) with exactly one `MsgPayForFibre`. |
| CV2 | Binding: `promise.namespace == payload_ref.namespace`, `promise.commitment == payload_ref.commitment`, `promise.blob_version == 0`, `promise.chain_id` equals the expected chain id, `promise.height <= payload_ref.height` (equality allowed; see the fact under NA5, section 10.4; for a pending reference `promise.height == h0`, section 13.1 F2 and section 20.6), and `promise.blob_size == U`, the upload size of section 10.4 computed from the committed `payload_size` (the blob length P1 checks), never from the archived blob or from the promise itself: `rows = ceil((payload_size + 5) / 4096)`, `row_size = 64 * ceil(rows / 64)`, `U = 4096 * row_size`, in exact integer arithmetic (`ceil(a / b) = floor((a + b - 1) / b)`). So `U >= 262144`: `payload_size` 1 and 262139 give 262144, 262140 gives 524288, and `2^27 - 5` gives `2^27`. |
| CV3 | Promise well-formed and owner-signed, as `PaymentPromise.Validate`: `signer_public_key` is a 33-byte compressed secp256k1 key, `chain_id` is 1..20 bytes, `blob_size > 0`, `creation_timestamp` is not zero, `height > 0`, the owner signature is 64 bytes (`r \|\| s`) and verifies over `sign_bytes` below. |
| CV4 | Validator list `V`: `HistoricalInfo.valset` of x/staking at `promise.height` (the `HistoricalInfo` header's height MUST be `promise.height`), each entry with its Ed25519 consensus key and power `tokens` (the integer token amount, not the consensus power), in the stored order: the keeper walks the list as stored and does not re-sort it. The stored order is the one SDK `NewHistoricalInfo` writes: consensus power `floor(tokens / 10^6)` descending, then consensus address (the first 20 bytes of `SHA-256(pubkey)`) ascending, which is the order of the set CometBFT `NewValidatorSet` builds over consensus powers. `V` MUST be in that order; a list in any other order is rejected, and the check is made in CV7, where that set is built. The order is positional: signature `i` belongs to `V[i]`. `V` is rejected as a whole, before any signature is checked, if the keeper would reject it: a consensus key that is not 32 bytes, or a list on which `NewValidatorSet` over `(key, tokens)` fails (two entries with the same address, a power `<= 0`, a power or a total above `MaxTotalVotingPower = MaxInt64 / 8`). VERIFIED (code: keeper `validateValidatorSignatures`, SDK `NewHistoricalInfo` and `ValidatorsByVotingPower`). |
| CV5 | `len(validator_signatures) <= len(V)`. |
| CV6 | Quorum, exactly as the chain: `required = floor(2 * total / 3)` with `total` the sum of `V`'s powers. Walk `i = 0, 1, ...`; skip empty entries; a non-empty entry MUST verify as an Ed25519 signature by `V[i]` over `sign_bytes` (the Go `crypto/ed25519.Verify` equation, as rule G1) or the certificate is rejected; add `V[i]`'s power once; as soon as the sum is `>= required`, accept and stop (entries after that point are not checked, as on chain). If the walk ends below `required`, reject. |
| CV7 | `V` is the chain's list in the chain's order: the header at `promise.height` has `height == promise.height` and `chain_id == promise.chain_id`; CometBFT `NewValidatorSet` over `V` with power `floor(tokens / 10^6)` for each key succeeds, its `ValidatorSet.Hash()` equals that header's `next_validators_hash`, and for every `i` the key of its `i`-th validator equals the key of `V[i]` (the stored order of CV4). Otherwise CV7 fails. No other header and no archived CometBFT set stands in for it. The header is tied to the chain by the header trust rules of section 10.6.2. |
| CV8 | Anchor (settlement), level `node-attested` (below). The archived anchor proof (section 19.2): its DAH passes NA2 against `data_hash` of the archived header at the anchor height (trusted by section 10.6.2), its namespace data passes NA3 and NA4 (section 10.4), the archived PFF tx is byte-equal to a tx of `T` and is a candidate for `payload_ref` (NA5), and the archived system blob equals `NewV2Blob(namespace, 0, commitment, pff_signer)` of that tx. The archived result of the PFF tx at that height has code 0. The optional `anchor_tx_proof` is not part of CV8 (section 10.4, threat note on `ShareProof`). |

Sign bytes (byte-exact; `APP/fibre/payment_promise.go` `SignBytes`,
celestia-core `types.RawBytesMessageSignBytes`):

```
ts        = 0x01 || u64be(unix_seconds + 62135596800) || u32be(nanoseconds) || 0xffff
            ; Go time.Time.MarshalBinary of creation_timestamp in UTC, 15 bytes
stripped  = signer_public_key (33) || namespace (29) || u32be(blob_size)
            || commitment (32) || u32be(blob_version) || u64be(promise.height) || ts
request   = protobuf SignRawBytesRequest { 1: chain_id, 2: stripped, 3: "fibre/pp:v0" }
            ; fields in ascending order, none empty
sign_bytes = "COMET::RAW_BYTES::SIGN" || uvarint(len(request)) || request
```

The owner (CV3, secp256k1 over `SHA-256(sign_bytes)` as the Cosmos SDK
`secp256k1.PubKey.VerifySignature` does) and every validator (CV6, Ed25519
over `sign_bytes` directly) sign the same bytes.

Facts and open points:
- The threshold is the chain's, `signed >= floor(2 * total / 3)`, computed
  over token amounts. It accepts exactly two thirds, and through the floor
  slightly less, so it is not the strict "more than 2/3" of CometBFT
  commits. VERIFIED (code). Decided for v1: every component applies the
  network rule (CV6) and never rejects what the network accepted; none
  adds `3 * signed > 2 * total` as a condition (one rule, below). Whether the network rule
  should be strict is an open question with the Fibre team.
- Token amounts versus consensus power: the list is ordered by consensus
  power `floor(tokens / 10^6)` (CV4), the same order as the CometBFT set,
  but the keeper counts the quorum in tokens. The CometBFT set carries only
  the consensus power, so it fixes the order and the bucket of each
  validator but not its tokens: that is why the archive keeps the
  `HistoricalInfo` set (section 10.7) and CV7 only cross-checks it. The
  power reduction is `10^6` on Celestia: VERIFIED (live Mocha data,
  2026-10-06, task 016 vectors). Rounding inside a bucket can change a
  verdict only at the threshold edge; see the threat note on token
  precision below.
- Which header commits to `V`: `HistoricalInfo(h)` is written in BeginBlock
  of `h` from the validators of the previous EndBlock, which CometBFT
  applies one height later, so `V` is expected to equal the set behind
  `next_validators_hash` of the header at `promise.height` (the same as
  `validators_hash` of `promise.height + 1`). VERIFIED (live Mocha data,
  2026-10-06, task 016 vectors): `next_validators_hash` at `h` equals
  `validators_hash` at `h + 1`, and both match the `HistoricalInfo` set.
  A verifier does not accept `validators_hash` of `promise.height + 1` in its
  place (CV7): CometBFT makes it equal to `next_validators_hash` of
  `promise.height` (celestia-core v0.42.0, `state/validation.go` and the
  light client's `VerifyAdjacent`; VERIFIED, code), so once the next header
  must chain to the promise header it can never match where the promise
  header failed, and without that binding it would let a header of any
  height vouch for `V`.
- The header inside `HistoricalInfo` is partial: it has no `version`,
  `last_block_id` or `validators_hash` (VERIFIED, live Mocha data,
  2026-10-06), so its hash is not the block hash and it is never a trust
  anchor. CV7 uses the archived signed header at `promise.height`, tied to
  the chain by section 10.6.2.
- The chain itself can re-check the certificate only while x/staking keeps
  `HistoricalInfo` (`historical_entries` = 10000 blocks, about 7 h 56 min at
  2.855 s per block; VERIFIED, probe). After that only the archive can.

One threshold rule (normative). The gate (whenever it checks a
certificate: the optional check after K0 in section 10.4, and K-fast F4,
section 13.1), the
Recorder (when it checks the certificate of a PFF it submits) and the
verifier MUST apply the same rule: accept iff CV6 accepts, and warn iff
`3 * signed <= 2 * total` (`cert_quorum_warning`, below). Given the same
PFF tx and validator set, all three MUST produce the same verdict and the
same warning. The warning never changes a verdict. In the Go code the rule
is one shared function that all three call, never a copy, so a change of
the network threshold is made in one place; a change of the rule itself is
a spec change. The gate and the Recorder surface the warning in logs and
metrics; no v1 wire field carries it.

Threat note (one rule). If the components disagreed, the gate could
authorize a decision whose certificate the verifier later reports invalid,
or the reverse, and the audit trail would contradict the Authorization. A
stricter rule in one component would refuse what the network settled and
lose liveness exactly at the two-thirds edge; the warning makes that edge
visible instead. A looser rule would accept certificates the chain
rejects; where inclusion with code 0 is checked the chain has already
decided, so the risk is in the verifier after pruning, which CV6 closes.
`UNVERIFIED`: whether the Fibre client at the pin stops collecting
signatures at the same `floor(2 * total / 3)` test, or at a different
target, when it builds the certificate for the Recorder.

Verifier report for `da = 1` (normative). Besides the
verdict, `verify` and `replay` report:

| Field | Value |
|---|---|
| `cert_signed_power` | Sum of the token powers of every non-empty entry that verifies, walking the whole list (not only up to the CV6 stop point). An entry after the stop point that fails is reported as a warning and does not change the verdict, because the chain never checked it. |
| `cert_total_power` | `total` of CV6. |
| `cert_signed_share` | `cert_signed_power / cert_total_power`, informational, printed with at least four decimals; comparisons use the integers. |
| `cert_quorum_warning` | `WARN` iff `3 * cert_signed_power <= 2 * cert_total_power`: the certificate passed the network rule but not the classic BFT "more than 2/3". The verdict stays valid. |
| `cert_token_precision` | `robust` iff CV6 gives the same verdict for every assignment of tokens that keeps each validator's consensus power (each `tokens` anywhere in `[10^6 * p, 10^6 * p + 10^6 - 1]`): the walk accepts with the lowest tokens for signers and the highest for the rest, or rejects with the opposite. Otherwise `bucket-dependent` (a warning; the verdict stays the one computed from the archived tokens). |
| `cert_valset_header` | The header that committed to `V` in CV7: `next_validators_hash` at `promise.height`. |
| `settlement` | `node-attested` in v1 (below); `failed` if CV8 fails. Not part of "anchored" (section 10.6.3). |
| `anchor_tx_result` | `code 0, node-reported, not part of the claim`, exact text, whenever CV8 passed: the archived `tx_code`, level `node-attested`. Informational; never listed under `assumptions` and never called proven (section 10.6.3). |
| `anchor_candidates_earlier` | The number of other candidates in `T` (NA5) whose `creation_timestamp` is earlier than the archived anchor's. Their result codes are not archived, so the verifier cannot tell whether the gate's NA7 picked one of them; a non-zero value is a warning that K2 replay rests on the `promise_created` the gate recorded, which replay checks against the creation times of these candidates (section 19.2). It never changes the verdict. |
| `header_trust` | Section 10.6.2: the trusted header's height and hash, and the cross-check result. |

Settlement level `node-attested`. Settlement means the PFF executed with
code 0 at `height`, so the escrow paid and the promise is on chain. The
verifier establishes it from three parts: the certificate (CV1 to CV7,
cryptographic given the validator set), the PFF tx in block `height` (the
anchor proof, cryptographic given the header), and code 0, which is only
what the Recorder's node reported when the archive was written. A verifier
MUST report it as `node-attested` and MUST NOT call it proven. Settlement is
not part of "anchored" (section 10.6.3): the claim is inclusion, binding and
certificate, and no proven settlement level is planned for v1 (human
decision, 2026-10-10).
Threat note: a node that lies about code 0 can make a PFF that failed in
execution look settled. The certificate and the anchor proof still show that
validators attested the blob and that the PFF was in block `height`; what
is not proven is the payment. Such a PFF can exist only through an ante
failure, with its system blob in the square and the shards kept by the same
time rule (section 10.4, facts; section 10.6.3), so the lie hides an unpaid
escrow, not a missing publication.

Threat note (token precision). No header commits to exact token amounts:
`validators_hash` commits to the keys and to `floor(tokens / 10^6)`. Whoever
can write the archive can shift a validator's tokens inside its `10^6`
bucket without breaking CV7, and at exactly the threshold edge that can turn
a rejected certificate into an accepted one, or the reverse. The archived
`HistoricalInfo` is therefore trusted for token precision only as far as the
`validators_hash` binding reaches. Mitigations: `cert_token_precision`
reports every verdict that depends on in-bucket precision, so an auditor
knows exactly when the verdict rests on archive integrity; the gate and the
Recorder check the certificate while the chain still serves
`HistoricalInfo` (about 8 h), so a forged set cannot change their verdict;
and an operator who needs the archived set beyond that SHOULD keep a
second, independently administered copy of the evidence record (or of its
`historical_info` bytes), against which a verifier compares byte for byte.
Any shift outside a bucket fails CV7.
Threat note (CV4 list conditions, CV7 binding and order). The archive
is trusted for availability only, so the `HistoricalInfo` list may be
forged. A list that repeats a validator would let one signature count once
per copy: a validator with share `p` repeated `k >= 2(1 - p) / p` times
reaches the requirement alone (four copies at 34%). The chain cannot accept
such a list (`NewValidatorSet` panics, which fails the tx), so neither may a
verifier; the same holds for zero power, an overflowing total and a bad key.
A CV7 that compares keys through a map, or accepts a header from another
height or chain, would let such a list, or the set of another epoch whose
keys may have been retired or leaked, pass as the chain's. Hashing the set
`NewValidatorSet` builds binds the size, the multiplicity and the powers of
`V` to one field of one header. That hash does not bind the order, because
`NewValidatorSet` sorts; the walk is positional, so a list with two
validators swapped hashes the same and moves each signature to another
validator. With `A` 34%, `B` and `C` 33% and signatures `[sA, sC, garbage]`
over the stored order `[A, B, C]` the chain rejects (index 1 is not `B`'s
signature); over the forged order `[A, C, B]` the walk accepts at index 1
and never looks at the garbage. The counted power is still that of genuine,
distinct signers, so no attestation is inflated, but the verifier would
accept a certificate the chain rejects. Comparing `V` position by position
with the sorted set (CV7) closes this. Vectors:
`spec/vectors/da/fibre_cert.json` (`boundary` cases `duplicate_signer`,
`zero_power`, `total_above_max`, `bad_key_length`; `valset` cases,
including `valset_out_of_order`).

Threat note (CV). The certificate is what turns "a tx was included" into
"validators holding the required stake attested custody of shards of this
blob". Inclusion already implies it under the honest-majority assumption,
because the chain checks it in CheckTx and ProcessProposal, not in
FinalizeBlock. CV lets a verifier check it without trusting the proposer and
the 2/3 that accepted the block, given a validator set it trusts through CV7.
It does not prove that validators still hold the shards (retention ends at
`pruneAt`), nor that the blob is the agent's payload (that is P2 and P3).

### 10.6.2 Header trust for verifiers (both `da`)

The verifier works from the archive and needs headers it can trust: at
`payload_ref.height` (`T_H`, `data_hash`, the inclusion proofs) and, for
`da = 1`, at `promise.height`. Archived headers are untrusted (the archive is trusted
for availability only). v1 ties them to the chain with a trusted header and
the hash chain, without signatures:

| Rule | Requirement |
|---|---|
| HT1 Trusted header | The auditor supplies a trusted header file: one header at height `T` with its hash, obtained out of band. `T` MUST be at least the highest height the verifier needs (`payload_ref.height`, or `promise.height` if that is higher; no header at `promise.height + 1` is needed, other than as a link of the HT3 chain; for a pending reference `max(anchor_deadline, H)`, and `anchor_deadline + 1` for an AB5 results proof, section 20.6). A file with `T` below that is refused: forward verification from an older header is out of scope. CV2 rejects `promise.height > payload_ref.height`, so for an included reference that can verify this is `payload_ref.height`. The trusted header may instead be an explicit or an agreed checkpoint (section 20.4), and with the execution check `T` MUST also be at least the execution height (EX5). |
| HT2 Hash of the trusted header | The verifier recomputes the header hash (CometBFT `Header.Hash()`, the Merkle root of the header fields) and it MUST equal the hash in the file. |
| HT3 Backward chain | For each `k` from `T` down to the lowest needed height, the header at `k - 1` is accepted iff its recomputed hash equals `last_block_id.hash` of the accepted header at `k`. Headers between come from the archive, a file or any online source; they need no trust, because the chain checks them. Any break: the header trust fails. OH6 (section 20.4) refines this for online sources: an online header that does not link is a fault of its source (`unchecked` if no source links). An archived header that does not link is `unchecked` too, with reason `chain_mismatch` (20.1). |
| HT4 No signatures | Commit signatures are not checked in v1: the trust comes from the trusted header and SHA-256 collision resistance, not from a validator set. |
| HT5 Archived headers | An archived header at a needed height is used only if its hash equals the one reached by HT3. |
| HT6 Cross-check (optional) | The verifier MAY additionally read the header at `T` (or at `payload_ref.height`) from one or more configured endpoints, under the at-height rules (section 10.9: the response echoes the height), and compare hashes. A mismatch fails the header trust (`header_trust` is `unchecked` with the reason of OH7, never `fail`). An unreachable endpoint is reported as `cross-check: not done`, never as a pass. |
| HT7 Verdict | Without a trusted header (a file, or a checkpoint of section 20.4), or if HT1 to HT3 fail, the verifier MUST NOT report the anchor as valid: it reports `header_trust: none` or the failed rule, and the overall verdict is not valid. The report always carries `T`, the trusted hash and the cross-check result. |

Two needed heights (`da = 1`). Let `H = payload_ref.height` and `P = promise.height`; `P <= H` (CV2), and a verifier rejects `P > H` before it walks HT3. The verifier checks the header at `H` and the header at `P` through HT3 and HT5 separately: the archived `header` is used only if its hash equals the one HT3 reached at `H`, and the archived `promise_header` only if its hash equals the one reached at `P`. If `P == H`, both archived headers MUST have that same hash. One never stands in for the other: `T_H` and `data_hash` (K1, K2, NA2, CV8) come only from the header at `H`, `next_validators_hash` (CV7) only from the header at `P`, and an implementation that keeps the needed hashes in one map keyed by height MUST NOT let one entry replace the other (keep them in two fields, each checked).

Threat note (two headers). The archive is trusted for availability only, so either header may be forged. If at `P == H` the promise header's hash replaced the anchor header's, the genuine promise header would pass header trust while a forged anchor header (any `data_hash` with a matching forged anchor proof, any `T_H`) fed CV8, K1 and K2 unchecked, and the verifier would report a valid anchor that the chain never had. `P > H` cannot occur on chain; rejecting it also keeps a verifier from accepting a trusted header above `H` only to vouch for a promise header.

Header hash on Mocha: VERIFIED on live data (2026-10-07). An independent implementation of upstream CometBFT
`Header.Hash()` (the Merkle root of the 14 fields in upstream order) over the
`/header` JSON of `mocha-5` blocks 1,442,606 and 1,460,000 (block version 11,
app 10, celestia-core reporting CometBFT `0.38.17`) gives `commit.block_id.hash`
and the next header's `last_block_id.hash`. The source of celestia-core at
the pin was not read; a header version other than 11 is not covered.

Threat note (HT). The whole anchor proof rests on the trusted header: an
auditor who takes it from the party being audited proves nothing. With a
correct header the backward chain is as strong as SHA-256; no assumption
about validator honesty enters, except the one already in the certificate
(CV) and in inclusion. Cost: `T - H` headers (about 1,260 per hour of
blocks). A light client that verifies forward from an older trusted header
(signature bisection) would remove the need for `T >= H` and is planned
after v1.

### 10.6.3 Anchored: what a verifier proves (both `da`)

Spec revision `v1.0.2` (clarification, human decision of 2026-10-10). The
word "anchored" (an `anchor` pass, `publication: anchored`, the `Proven:`
line of 20.9) means that the inclusion of the anchor in block `H` of the
trusted chain is proven from the archived evidence against the header at `H`
that passed header trust (section 10.6.2). `H` is `payload_ref.height`, or
for a pending reference the evidence's `height` (section 20.6). It never
rests on a node's word, and it never includes the anchor tx's result code.
v1.0 verifiers additionally require `tx_code == 0` (CV8); this requirement
is removed in v1.1.

| `da` | Anchored means | Rules |
|---|---|---|
| 2 | The share-version-1 blob with `payload_ref.namespace`, `payload_ref.commitment` and `payload_ref.signer` is in the square of block `H`: its commitment proof (evidence key 11) verifies against the data root (`data_hash`) of the header at `H`. | 10.5, 10.7 |
| 1 | (a) Inclusion of the PFF tx: the archived anchor proof is an NMT proof of the complete `PFF_NS` range against `data_hash` of the header at `H` (NA2; NA3 with completeness), the txs are parsed from the proven shares (NA4), the archived PFF tx is byte-equal to one of them and is selected by its promise's commitment (an NA5 candidate for `payload_ref`), and the system blob equals `NewV2Blob` of that tx (the inclusion part of CV8). (b) Binding: CV2 (namespace, commitment, blob version, chain id, `blob_size`, `promise.height <= H`). (c) Certificate: CV3 to CV7, offline, against the archived `historical_info` at `promise.height`, with the promise header at `promise.height` tied to the trusted chain (CV7; section 10.6.2, two needed heights). | 10.4, 10.6.1 |

Promise height (`da = 1`). `promise.height <= H` is CV2 for an included
reference. For a pending reference CV2 requires `promise.height == h0`
(section 20.6), and `H < h0` makes the evidence `source_corrupt` (20.6). The
x/fibre height window, `H - promise.height <= payment_promise_height_window`
(and `promise.height <= H + 1`), is the keeper's rule.

Assumption (included references, human decision of 2026-10-10). For an
included reference the window is not checked by any verifier rule; it
follows from inclusion. Every PFF of a committed block passed the window
check in ProcessProposal, and a block is committed only if validators
holding more than 2/3 of the voting power accepted it, the honest-majority
assumption that header trust (10.6.2), the anchor and the certificate
already rest on. The call path at the pin (VERIFIED, code at `5187d2f`, task
045 research and re-read 2026-10-10):

| Step | Pinned code |
|---|---|
| ProcessProposal executes the messages of every PFF tx, after its ante handler, on the proposal branch whose block height is the proposed one, and rejects the whole block if they fail | `APP/app/process_proposal.go` `ProcessProposalHandler`, the `if isPFF` branch (lines 162 to 166: `executeTxMsgs`, then `return reject()` on error) |
| The messages run through the app's message router on a cached branch; an out-of-gas panic becomes an error, so it rejects too | `APP/app/pff_execution.go` `executeTxMsgs` |
| The `MsgPayForFibre` handler runs the stateful promise check | `APP/x/fibre/keeper/msg_server.go` `msgServer.PayForFibre` (line 139, `ValidatePaymentPromiseStateful`) |
| The window: `ctx.BlockHeight() - promise.height > PaymentPromiseHeightWindow` is refused, and so is `promise.height > ctx.BlockHeight() + 1` | `APP/x/fibre/keeper/keeper.go` `validatePaymentPromiseStatefulInternal` (lines 418 to 429, non-timeout path) |

The window parameter is not archived (format 1 has no field for it, no
header binds it, and its only bound is `!= 0`), so no offline check exists;
one would need a format addition and would close no path that the
honest-majority assumption leaves open. What inclusion implies is that the
window held on the proposal branch; whether FinalizeBlock could then still
fail the message (a parameter change earlier in the same block) does not
matter here, since the code is not part of the claim. If a later app version moves
the check out of ProcessProposal (for example to FinalizeBlock only) or
removes it, inclusion no longer implies the window, and this assumption
must be revisited before the pins move (section 23.2, PC1).

Pending references are not covered by this argument for the decision the
gate signs: the gate checks the window at authorization against the
chain's current parameter. K-fast reads `payment_promise_height_window` at
the head `h` (F3, F5) and caps the window with it (13.3: `window = min(...,
payment_promise_height_window(h))`, `anchor_deadline = h0 + window`); a
parameter of 0 gives `window = 0`, refused with `ErrAnchorWindowClosed` (F5
(2)). So the gate never signs `anchor_deadline > h0 +
payment_promise_height_window(h)`. Coverage: vectors `v1/anchor.json`
`window` cases `window_chain_min` (the chain's window is the smallest bound)
and `window_chain_zero` (window 0 refused); Go tests `gate/fast_test.go`
(the `anchor.json` window runner and the case `chain window zero`) and
`gate/fast_edge_test.go` (`ChainWindow` in the deadline cases). The
verifier also has `H <= D <= h0 + 1000` (20.6, AM2), and the evidence itself
is an included PFF, so the assumption above covers its `H`. Threat note
(parameter change between `h` and `H`): a governance change that lowers the
window after the gate signed makes the chain refuse a late PFF; the anchor
then does not land, which is `anchor_absent` (the safe direction for the
verifier: no false `valid`), and the fast-mode risk the principal accepted
through `fast_mode_max_delay`.

Result code: not part of the claim.

- `da = 2`. The blob's shares are in the square whatever the PFB's execution
  result: ProcessProposal checks the blob tx and its ante handler, and the
  square is built from the txs before execution. The absence proof (AB6)
  reads no code either, so presence and absence read the same fact.
  `UNVERIFIED` (human to confirm): no case exists where shares in the square
  with a failed PFB do not count as published.
- `da = 1`. Validators keep their shards whatever the PFF's result: a
  validator fixes `pruneAt = max(creation_timestamp + ShardRetention,
  creation_timestamp + PaymentPromiseTimeout)` at upload, before any PFF
  exists, and deletes only by a wall-clock prune loop; nothing in the Fibre
  server reads PFF results (`APP/fibre/server_upload.go` `shardPruneAt`,
  `APP/fibre/server_prune.go`, `APP/fibre/store.go`). VERIFIED (code at the
  pin, task 045 research). `UNVERIFIED`: that no component outside
  celestia-app (a celestia-node bridge, a validator sidecar) prunes shards
  on the PFF's result. A non-zero code (possible only through an ante
  failure, section 10.4 facts) means the escrow did not pay, not that the
  blob was unavailable.
- What v1.0.x still checks. CV8 requires the archived `tx_code = 0`
  (evidence key 12 admits only 0, section 19.2), as the gate's NA6 and NA7
  require code 0 before K0 passes. The requirement stays in every `v1.0.N`
  revision: dropping it would turn an `unchecked` into a pass, a relaxation
  that needs a minor revision (section 0). It is node-attested and is not
  part of "anchored". A `da = 1` report prints it as `anchor_tx_result:
  code 0, node-reported, not part of the claim` (section 10.6.1), in both
  modes. The evidence of `da = 2` carries no code, and a `da = 2` report has
  no such field.
- Absence (spec revision `v1.0.3`, security). Inclusion is what "anchored"
  means, so a PFF candidate included inside the window is never read as
  absence, whatever its code: AB5 classifies its height as present unpaid
  when every candidate's code is proven non-zero, and `anchor` is then
  `unchecked` with reason `anchor_unpaid` ("anchor included, non-zero result
  code; not confirmable by v1.0 verifiers"), never `fail` (sections 20.6,
  20.8). Presence keeps failing on CV8 in v1.0: a format 1 evidence record
  cannot carry a non-zero code (key 12 is `= 0`; a record with another value
  fails strict decoding and stays `source_corrupt`), and the gate never
  authorizes a strict reference on one (NA6, NA7). With CV8's code
  requirement removed in v1.1, such an anchor can become `valid` there; that
  is a relaxation and is not part of any `v1.0.N`.

Threat note (anchored). The adversary is a party that writes the archive and
also controls the node a code was read from. Inclusion, binding and the
certificate are checked against the trusted chain, so it cannot fake them.
It can write `tx_code`, the only node-attested field of the evidence, and
only as 0. Because the code is not part of the claim, a false code cannot
turn into a false `valid`: a PFF whose fee payment failed still anchors a
blob that more than 2/3 of the stake attested and whose shards the
validators keep by the time rule. What that party can hide is an unpaid
escrow, which `anchor_tx_result` marks as node-reported.

### 10.7 What must be archived for later verification

The byte layout of these items is archive record format 1 (section 19);
where each item lives is listed there. Contents and
reasons:

| Item | `da` | Level | Why |
|---|---|---|---|
| The blob bytes, written before the anchor tx is submitted | both | MUST | Fibre prunes after `pruneAt` (about 4 h); L1 pruned nodes after 7d + 1h. P2 and P3 tie the bytes to the commitment. |
| The signed envelope and the action bytes, written by the gate before it signs (stage 4a, rules AR1 to AR4); the SignedAuthorization, written after stage 12 (a crash between the two is repaired from the registry at the next start); for a refused decision, the rejection marker with the error name (AR5 to AR8) | both | MUST | The object being verified, and which path the gate used (section 15). Writing the decision first means no Authorization exists for a decision the archive lacks. |
| The PFF tx bytes exactly as included, and its index in block `height` as the node reports it (CometBFT `/tx` `index`; informational, no check reads it) | 1 | MUST | Carries the `PaymentPromise` and the positional certificate (section 10.6.1). About 5.3 KB at 83 validators. |
| The anchor proof: the DAH of the header at `height` and the namespace data of `PFF_NS` at `height`, exactly as NA2 to NA4 verified them (section 10.4), in the form of section 19.2 | 1 | MUST | CV8: proves that the PFF tx, and with it namespace and commitment, was in block `height`, and shows every other candidate of that block. Self-contained: it is checked against the archived header alone. |
| A `ShareProof` of the PFF tx against `data_hash` | 1 | MAY | Not used by CV8; see the threat note on `ShareProof` (section 10.4) before relying on one. |
| The commitment proof of the share-version-1 blob against the data root of the header at `height` | 2 | MUST | Proves that namespace, commitment and, through the commitment, `signer` were in block `height`: the inclusion evidence for `da = 2`. |
| The PFB tx bytes exactly as included, its index in block `height` and its inclusion proof against `data_hash` | 2 | SHOULD | Adds the fee payer's tx, which no check uses: the commitment proof above already binds the blob to `height`, and the chain rejects a share-version-1 blob whose signer is not the PFB signer (section 10.5). |
| The signed header (header and commit) of block `height` | both | MUST | Root of the inclusion proof, `T_H` for K1 and K2. |
| For PFF: the x/staking `HistoricalInfo` validator set at `PaymentPromise.height` (consensus keys and token amounts) | 1 | MUST | CV4 and CV6 need the keeper's order and powers. The chain keeps it only for `historical_entries` blocks (about 8 h), after which nobody can re-check the certificate without the archive. |
| For PFF: the signed header at `PaymentPromise.height` | 1 | MUST | CV7: its `next_validators_hash` ties the `HistoricalInfo` set to the chain. CV7 reads no CometBFT validator set and no header at `promise.height + 1`, so neither is archived: the CometBFT set is rebuilt from the `HistoricalInfo` set (consensus powers) and bound by this header's `next_validators_hash`. |
| The retention inputs the gate used: `shard_retention` latest and at `height`, and which source gave the at-height value (section 12.2, RS rules), next to the Authorization (section 19.2, K2 inputs) | 1 | MUST | K2 replay; the at-height value cannot be read back reliably later. |
| The result of the anchor tx (code 0) as the node reported it | 1 | MUST | CV8, settlement `node-attested` (section 10.6.1); not part of "anchored" (section 10.6.3). |
| The results of all txs of block `height` and the header at `height + 1`, for a proof of code 0 against `last_results_hash` | 1 | MAY | No check reads them, and no proven settlement level is planned for v1 (section 10.6.3; SHOULD before `v1.0.2`). Format 1 has no field for them in the evidence record (section 19.8). |
| The share-version-2 system blob | 1 | MUST | Checked for equality with `NewV2Blob` of the archived PFF (CV8). |
| For a pending reference: the anchor intent (kind 13), written before the reference is returned and before the anchor tx is broadcast (section 11.3) | both | MUST | K-fast reads it (section 13); with `anchor_absent` the verifier names its signer (section 20.10). |

Headers the verifier needs between the trusted header and `height` (section
10.6.2) need not be archived: the hash chain checks them from any source.

The Recorder MUST write the blob before submitting and the remaining MUST
items, other than the gate's decision record and Authorization, before
returning `payload_ref` to the producer, so a signed
commitment never exists without them. For `da = 1` this is also before the
`historical_entries` horizon, which is hours away at that point.

No tx inclusion proof is needed: the anchor proof is the bridge's namespace
data plus the DAH, both verified before they are archived. If the encoded
anchor proof is larger than an opaque field allows (`2^22` bytes; a block
with roughly 750 or more PFFs), the
Recorder cannot archive it: it answers `recorder.ErrArchiveUnavailable` and
returns no `payload_ref`; the producer can publish a new blob (a fresh salt
gives a new commitment and a new anchor). A later archive format lifts the
limit.

Threat note (archived anchor proof). The anchor proof is no more trusted
than the rest of the archive; a verifier re-runs NA2 to NA4 on it against
the header it trusts by section 10.6.2, so a forged proof fails CV8 instead
of passing.

Recompute on read (verification after Fibre or L1 pruning). The archive is
trusted for availability only. A verifier that reads the blob from the
archive MUST, besides P1 and P2 (`payload_size`, `ciphertext_hash`),
recompute the DA commitment from the archived bytes and compare it with
`payload_ref.commitment` before treating the anchor as covering those bytes:

| `da` | Recompute | Inputs taken from |
|---|---|---|
| 1 (fibre) | `fibre.NewBlob(blob, DefaultBlobConfigV0()).ID().Commitment()` (section 10.4) | archived blob only |
| 2 (celestia_blob) | `CreateCommitment(NewV1Blob(namespace, blob, signer), RFC6962, 64)` (section 10.5) | archived blob, `payload_ref.namespace`, `payload_ref.signer` |

Nothing beyond the blob needs to be archived for the recompute: blob version
0 is fixed by `da = 1`, share version 1 by section 10.5, and the signer is in
the signed commitment. A mismatch means the archived bytes are not the
anchored blob; the verifier rejects (fail-closed). The gate applies the same
recompute as rule P3 (section 8.5).

### 10.8 Startup compatibility check

Fibre is on a pre-release line and changes between tags. Any component that
handles `da = 1` (gate, Recorder, verifier, SDK with the Fibre committer)
MUST, before it serves or signs, run the checks below, and MUST refuse to
start if one fails. There is no override; a failure is a configuration
error, not a sentinel.

| Check | Requirement |
|---|---|
| SC1 Build pin | The linked celestia-app module is exactly the pinned version (section 10.1, read from the build information). Also the linked nmt module: `v0.24.5`, the version celestia-node `v0.34.2-mocha` resolves (NA3 needs the completeness fix of `v0.24.3`). |
| SC2 Known answers | The `da = 1` committer reproduces the commitments of `fibre_commit.json` it embeds: at least `fibre_live_mocha_popsmin1`, `fibre_size_262139`, `fibre_size_262140` and one row size above 128. |
| SC3 Chain | The node's chain id is in the configured `da = 1` chain allowlist, and the app version in the latest header is 10. The allowlist is configuration; its default, and the only value validated for v1, is `["mocha-5"]`. Adding a chain (for example Arabica or Corto) is an operator decision after checking that the pins and `fibre_commit.json` hold there. |
| SC4 Parameters | x/fibre `Params` is readable and `shard_retention` is within the governance bounds (10 min to 168 h). |
| SC5 Retention source and at-height reads | The retention store is bound to this chain id and gets its first sample; the canary runs (section 12.2, RS2; section 10.9). A failing canary disables only the direct at-height read, never the start: the gate then runs in observations-only mode for retention and MUST log the mode and the reason at startup at warning level (and again whenever a later canary changes it). |
| SC6 Bridges | A bridge used as a download fallback is enabled only after its compatibility is verified, by version (BV) or by a capability probe (BP), below. Otherwise the fallback is disabled and the gate logs the reason at warning level; this is never a refusal to start, because the fallback is optional. A version or capability declared in operator configuration is never accepted in place of BV or BP. The fallback is never trusted for P3, which the gate computes itself on every answer. A bridge used for the anchor proof (NA2, NA3) is not gated on its version, because its answers are verified with the pinned code; the gate logs the version at startup if it can read it, at warning level if it differs from the pin. At the pin `node.Info` needs an admin token, so with a read token its permission error is the normal case: it is logged as "version unknown", never a refusal. A gate whose configured DA is `fibre` with no bridge configured for the anchor proof refuses to start. |

An app version change seen at runtime (an upgrade) stops `da = 1` service
(`ErrChainUnavailable`) until a restart has re-run the checks.

Threat note (SC). The commitment, the sign bytes and the parameters are
upstream definitions that a new tag may change; the vectors are the only
independent memory of what the network did at the pin. Refusing to start on
any difference turns a silent divergence (accepting bytes the network never
committed, rejecting every anchor) into a visible configuration error.

Bridge fallback compatibility (normative). Facts at the
pin (celestia-node `v0.34.2-mocha`, go-jsonrpc `v0.10.2`; VERIFIED in code,
not probed live): the only method that returns the node version is
`node.Info`, tagged `perm:"admin"`; its `api_version` is set from build
flags (UNVERIFIED: the exact string a release build of the pinned tag
reports). No `public` or `read` method returns a version. An admin token
also mints tokens of any permission (`node.AuthNew`), so a gate SHOULD NOT
hold one. Read methods need a token: without one the server grants only
`public`. The fallback uses exactly one method, `fibre.Download(BlobID)`
(`perm:"read"`), whose result is `GetBlobResult`, JSON `{"data": <base64>}`.
The pinned client decodes it with `encoding/json`, which ignores unknown
members and leaves `data` empty when it is missing, so a renamed field
looks like an empty blob, not like an error.

| Rule | Requirement |
|---|---|
| BV By version | `node.Info` answers and its `api_version` equals the pinned celestia-node version exactly. Permitted, NOT RECOMMENDED: it needs an admin token. A permission error, an empty or different version, or no answer fails BV; the gate MAY then run BP. |
| BP1 Probe blob | The gate finds one blob that is anchored and still retained: a `MsgPayForFibre` candidate (NA5) in the PayForFibre namespace data at a height `h` with `head - probe_window <= h <= head - canary_offset`, read and verified through NA1 to NA4 (the namespace data from the anchor-proof bridge), with result code 0 (NA6), whose promise `creation_timestamp + shard_retention` is at least `probe_margin` after the gate clock. The newest such candidate is used. `probe_window` (default 600 blocks) and `probe_margin` (default 600 s) are gate configuration; the defaults are UNVERIFIED for Mocha traffic. No candidate in the window: inconclusive (BP5). |
| BP2 Method | The gate calls `fibre.Download` with the probe blob's BlobID (`0x00 \|\| promise.commitment`) on the fallback bridge, with the same token, transport and size cap the fallback uses (cap from `promise.blob_size`). |
| BP3 Shape | The raw JSON-RPC `result` is a JSON object with exactly one member, `data`, holding a standard base64 string (no other members, no `null`). It is decoded from the raw bytes, not through the struct decoder. An error answer, a missing or extra member, a non-string `data` or invalid base64 fails BP3. |
| BP4 Content | The decoded bytes pass P3 with the gate's `da = 1` committer against the probe blob's commitment. |
| BP5 Outcome | BP1 to BP4 pass: the fallback is enabled and the gate logs the probe height and BlobID. A failure of BP2 to BP4 (HTTP 401, a missing-permission error, method not found `-32601`, wrong parameters `-32602` or `-32700`, a shape or P3 failure): incompatible, fallback disabled, warning. No probe blob, a timeout or a transport error: inconclusive, fallback disabled, warning. The gate MAY repeat the probe, at most every `canary_interval`, and enables the fallback only after a pass; a later failure does not disable a fallback that passed, because every answer is checked by P3 anyway. |

Rationale (bridge fallback). Integrity never depends on the bridge: every
fallback answer is checked by the gate's own DA-commitment recompute (P3,
section 8.5), so a lying, outdated or malicious bridge can cost
availability (the gate falls back to the archive) but cannot make the gate
accept other bytes. The version or capability check is about compatibility
only: it finds a bridge whose API or encoding changed at startup, where the
operator sees it, instead of near the end of the retention window, when the
fallback is the last DA source. A configured version proves nothing about
the node that answers, hence never a substitute. Threat assumptions: the
bridge is untrusted; BP shows that it served one retained blob correctly
once, nothing about later answers; BP spends one blob download of bridge
bandwidth per run.

### 10.9 At-height reads (all modules, both `da`)

Facts: on 2026-10-05 the public QuickNode Mocha endpoint answered x/fibre
queries pinned to a past height with the latest state and no response
height (VERIFIED, probe). Per the human, it drops the height for every
module, not only x/fibre; the gate cannot tell such an endpoint from an
honest one by a normal answer. Every read "at height `h`" by a gate,
Recorder or verifier is therefore suspect until checked. Two classes:

- State reads: a Cosmos gRPC or REST query whose height travels in request
  metadata (`x-cosmos-block-height`), for example x/fibre `Params` at `h`.
- Block reads: a request whose height is an argument and whose response is
  an object that names its own height: a header, a block, block results, a
  commit, a validator set at `h`, `HistoricalInfo(h)`, a celestia-node
  `header.GetByHeight(h)`, `blob.Get(h, namespace, commitment)` and its
  proof, `share.GetNamespaceData(h, namespace)`. This covers the
  `celestia_blob` path (K0 and `T_H` for `da = 2`) as much as `da = 1`.
- Not a read at a height: gRPC `GetTx(hash)` (NA6, section 10.4). It asks by
  hash; the answer names a height, which HR1 compares with the expected one.
  A mismatch fails that read only and does not mark the endpoint
  height-ignoring under HR3: the request carried no height, and the tx index
  keeps one result per hash, so if the same tx bytes were included twice an
  honest node reports the later inclusion (`UNVERIFIED` for the pin: that a
  tx that failed before its sequence was consumed can be included again).

| Rule | Requirement |
|---|---|
| HR1 Echo | A response is used only if it carries the requested height and that height equals `h`: for a state read the response header `x-cosmos-block-height`; for a block read the height inside the returned object (`header.height`, `block.header.height`, the results' height, `HistoricalInfo.header.height`). A response without a height (for example `blob.Get`) is used only through HR2. Missing or different: the response is discarded as a failure of that endpoint. |
| HR2 Binding | Where the content can be tied to the header at `h`, it MUST be, and the header itself MUST pass HR1: txs to its `data_hash`; a DAH to its `data_hash` (NA2); namespace data to the row roots of that DAH (NA3); a blob or its share commitment to its data root through the inclusion proof; a validator set to `validators_hash` or `next_validators_hash`. Result codes (NA6) have no binding in v1 (`node-attested`). A block read that passes HR1 and HR2 does not depend on whether the endpoint honours heights. |
| HR3 Canary per endpoint | The RS2 canary (section 12.2) is a property of the endpoint, not of a module: a canary that does not pass marks the consensus endpoint height-ignoring for every state read, whatever the module. Block reads are checked by HR1 and HR2 on every response. A block or header read on a consensus endpoint whose returned height is missing or differs from the requested one also marks that endpoint height-ignoring for state reads (retention goes to observations-only mode, HR4) until a later canary on it passes (Honoured). Bridge (celestia-node) endpoints do no state reads, so they have their own canary: read the header at `head - canary_offset` (RS2) and compare its height with the requested one: equal is Honoured, a header at another height is Ignoring, anything else (error, not found, timeout) is Inconclusive. The bridge result is logged (warning level unless Honoured, again on every change) and MUST NOT drive the retention mode; a bridge HR1 mismatch discards that response only. |
| HR4 On failure, retention | The x/fibre retention at `height` comes only from the gate's own observations (RS4 to RS6): observations-only mode, logged at startup and on every change (SC5). A height the observations do not cover gives `ErrRetentionUnavailable`. |
| HR5 On failure, other reads | Any other read at a height that fails HR1 or HR2 on every configured source gives nothing: the check that needed it is not evaluated from latest state or from another height. The gate answers `ErrChainUnavailable` (503, nonce untouched), never `ErrAnchorNotFound`, never a K1 or K2 verdict from the wrong block. It MAY instead use a source that does not depend on the endpoint honouring heights: a header verified by the W5 light verifier (section 9.5), or a block read from another endpoint that passes HR1 and HR2. A state read other than x/fibre `Params` from a height-ignoring endpoint MUST NOT be used; v1 defines no other. A header or block read that answers "not found" for a height the chain must have (at or below a head the gate has observed on any configured source) is a failed at-height read under this rule, on both `da` paths (K0 and `T_H`): `ErrChainUnavailable`, never `ErrAnchorNotFound`. A pruned or trailing backend answers "not found" for blocks that exist, so the answer says nothing about the chain. A height above every observed head gives `ErrChainUnavailable` too (retryable, nonce untouched; `valid_until` bounds the retries). `ErrAnchorNotFound` is given only after the block at `height` was read and passed HR1 and HR2 and holds no anchor (for `da = 1`: after NA1 to NA4 held and NA7 found no anchor, section 10.4). |

The Recorder applies HR1, HR2 and HR5 to its read-back (an HR failure is
`recorder.ErrNodeUnavailable`); the verifier applies them to HT6
(section 10.6.2).

Threat note (HR). A height-ignoring endpoint answers "latest" for "at `h`".
For retention that silently replaces the at-height half of `r` (RS1); for a
block read it would make a gate find no anchor, or the wrong block time.
HR1 detects it whenever the object names its height, HR2 makes the content
self-checking against the header, and HR5 turns any remaining doubt into a
retryable refusal instead of a verdict. What HR does not cover: an endpoint
that echoes the requested height and serves a consistent but false header.
The header is trusted from the node (own node recommended), or from the W5
light verifier; that is the same assumption as K1 and K2 (section 12.2).

## 11. Pending reference

### 11.1 Meaning

A pending reference (`payload_ref.anchor = 2`) says: the payload blob is
durable in the archive and its availability evidence exists, the anchor tx
is signed and archived as an anchor intent (kind 13), and the anchor is
expected on L1 at a height in `[h0, anchor_deadline]`, where `h0 =
payload_ref.height` and `anchor_deadline` is stated by the gate in the
Authorization (section 15).

| `da` | `h0` | Anchor intent (`tx` of kind 13) |
|---|---|---|
| 1 (Fibre) | `PaymentPromise.height` of the upload: the height whose validator set signs the certificate | the signed `MsgPayForFibre` tx carrying the promise and the validator signatures |
| 2 (celestia_blob) | the chain head the Recorder read before it built and archived the PFB | the signed tx holding one `MsgPayForBlobs` for the blob, without the blob |

`h0` is inside the agent-signed commitment, so neither the gate nor the
Recorder can change it after the agent signed.

On chain, the anchor of a Fibre pending reference lands at `H >= h0`: the
keeper verifies the certificate against `HistoricalInfo` at
`promise.height`, which does not exist above the current block (section
10.4, the fact under NA5), and it refuses `H - promise.height >
payment_promise_height_window` (section 13.1, F5). For `da = 2`, `h0` was the
head when the tx was built, so any inclusion is at `H > h0`.

Pending references are accepted only by a gate in fast mode, which needs a
mandate (section 8.9); a strict gate, or one without a mandate, refuses them
with `ErrAnchorPending` (C5a). An agent whose
payload is already anchored signs an included reference and gets a strict
Authorization at any gate.

### 11.2 Producer rule W5-P (pending references)

W5 (independent inclusion check, section 9.5) applies to included references. For a
pending reference the agent, before signing, MUST verify the anchor intent
the way the gate does (section 13, F2 to F4 for `da = 1`, B2 for `da = 2`)
against an endpoint independent of the Recorder when the Recorder is another
party, and MUST check that `payload_ref.height` equals `h0` of that intent.
For `da = 2` the agent cannot check mempool acceptance independently of the
gate; the gate does it (B5).

Threat note. Without W5-P, a dishonest Recorder could hand the agent a
reference to an intent that never verifies; the gate would refuse it
(K-fast), so the risk is liveness, not safety. W5-P matters for the
agent's own record: it signs only a reference it has checked.

### 11.3 Recorder (normative points)

The Recorder MUST write the payload record (kind 1) and then the anchor
intent (kind 13) durably before it returns a pending reference and before it
broadcasts the anchor tx; the intent's `created_at` for `da = 1` is
`floor(PaymentPromise.creation_timestamp)`. After broadcast it continues its
confirmation loop and writes the evidence record (kind 2, `height = H`)
when the anchor lands. It MUST NOT write a second, different intent under
the same `(da, commitment, ref_height)` (archive identity, section 19);
after a refused PFB it re-intents at a new `h0`, which needs a new
commitment.

`UNVERIFIED`: whether celestia-node's Fibre service at the pin exposes the
upload without the submit; otherwise the Recorder uses the celestia-app
Fibre client library directly (research item of task 035).
## 12. MaxTTL, retention, reference time and the archive

### 12.1 MaxTTL (stage S)

```
MaxTTL(da) = min(3600, floor(retention(da) / 4))
retention(1 fibre)         = params.fibre_retention_s   ; x/fibre shard_retention, read at check time
retention(2 celestia_blob) = params.blob_retention_s    ; default 14400 in v1
```

| Point | Rule and reasoning |
|---|---|
| Hard cap | TTL never exceeds 1 h, default TTL 15 min (SDK default). |
| Factor 4 | Leaves room for the time between the Fibre `creation_timestamp` (start of retention) and `issued_at`: upload, PFF inclusion, archive write, signing. With 4h retention and 1h TTL, any `issued_at` within 3h of the promise creation keeps the shards alive until `valid_until`. Rule K2 (section 12.2) checks this per commitment instead of assuming it. |
| Read at check time | The gate passes the current `shard_retention` as `params`. If governance lowers it, commitments with a TTL above the new MaxTTL fail with `ErrTTLTooLong` (vector `ttl_ok_at_4h_rejected_at_10m`). Fail-closed: only liveness is lost. Governance changes are visible days ahead and the default TTL is 15 min. |
| Floor division | `floor(601 / 4) = 150` (vectors `ttl_max_at_601s_retention`, `ttl_floor_division`). |
| Retention lowered after upload | At the pin, `pruneAt` is fixed when the shard is stored, so lowering retention does not shorten the life of shards already stored. The check-time rule is therefore stricter than needed today; it stays because server behaviour may change and a server may prune early or lose data. |
| `celestia_blob` | Real retention is 7d + 1h on pruned nodes (section 10.2), so MaxTTL is 1h with any realistic value. v1 keeps the conservative default `blob_retention_s = 14400`; this is a local constant, not a chain parameter. |

### 12.2 Reference time `T_ref`, rules K1 and K2

MaxTTL bounds `valid_until - issued_at`, but `issued_at` is chosen by the
agent: nothing in the commitment alone stops an agent from anchoring a
payload, waiting hours, and then signing, at which point the DA layer may
prune the payload before `valid_until`; nor from signing before the payload
was public at all. The gate MUST therefore relate the commitment's times to
the reference block.

Definitions. All values are Unix seconds. Arithmetic is exact; an
implementation in unsigned 64-bit integers MUST saturate on addition, which
yields the same verdicts because every left-hand side below is under
`2^63 + 600` (rule S2 bounds `issued_at` and `valid_until`).

```
T_ref  = header time of block payload_ref.height, truncated to whole seconds (floor)
         ; both reference forms, both da. Included: T_H, the anchor block. Pending: the block at h0.
r      = da = 1: min(fibre_retention_s(latest), fibre_retention_s(at height))
         da = 2: blob_retention_s
start  = da = 1, included: min(T_ref, floor(PaymentPromise.creation_timestamp))
         da = 1, pending:  min(T_ref, created_at of the anchor intent)   ; = floor(promise.creation_timestamp) by F2
         da = 2:           T_ref
margin = min(600, floor(r / 8))          ; 600 at 4h; 75 at the 10 min governance minimum
```

For an included reference `T_ref = T_H`. The policy clock is `T_ref` (policy
8.1). The verifier reads `T_ref` from a header at `payload_ref.height` that
passed header trust. For a pending reference, "at height" below means at
`h0`.

| Rule | Exact inequality | On failure |
|---|---|---|
| K1 | `issued_at + skew_s >= T_ref` | Reject with `ErrIssuedBeforeAnchor` (package `commitment`). |
| K2 | `valid_until + margin <= start + r` | Not a rejection, except that an unreadable at-height retention is (`ErrRetentionUnavailable`, below). The gate MUST NOT accept the payload on the DA path (`path = 1`); it uses the archive path, where the bytes must pass P1, P2 and P3, and if the archive does not return them the result is `ErrAnchorTooOld`. A gate without a committer for the `da` refuses that path (`ErrArchiveRecomputeUnsupported`, section 8.5). |

Unreadable inputs:
- `fibre_retention_s` at `height` cannot be established (`da = 1`) by the
  rules RS1 to RS6 below: the gate MUST reject with `ErrRetentionUnavailable`
  and MUST NOT substitute the latest value. Reason: if governance lowered
  retention after the upload and the node misreports or cannot serve
  history, the latest value is the only input left, and `r` would silently
  lose its at-height half; rejecting keeps the rule "minimum of both" exact.
  The nonce is untouched, so the envelope can be retried once a source
  covers `height` (vector `k2_fibre_at_height_unreadable`).
- `creation_timestamp` unknown (`da = 1`): K2 is false, so the archive path
  is the only one (with a `da = 1` committer), or
  `ErrArchiveRecomputeUnsupported` (without one). Fail-closed either way.

Retention at `height` (normative). Facts: on 2026-10-05
the public QuickNode Mocha endpoint answered x/fibre queries with the latest
value for any requested height, including heights whose state does not
exist, and sent no response height header; P-OPS and nodes.guru, one of
them on the same binary, honoured the height and echoed it (VERIFIED,
probe; the cause is in front of the QuickNode node). The client cannot tell
from a normal answer which kind of endpoint it talks to, so the gate uses:

| Rule | Requirement |
|---|---|
| RS1 | The latest value is never used as the value at `height`, unless one of the sources below establishes it for `height`. |
| RS2 Canary | At start and at least every `canary_interval` (default 600 s, at most 3600 s), the gate runs the canary on each consensus endpoint it uses for state reads. Canary heights are configuration, per chain id, and logged at startup: (a) the recent height `h_r = head - canary_offset`, where `head` is the latest height the same endpoint reports just before, and `canary_offset` (default 10) MUST be at least 1 and greater than `lag` (RS4) and MUST stay inside the state the node retains; (b) `h_pre`, the last height before x/fibre was activated, optional. Defaults are keyed by chain id, read from the same endpoint: `mocha-5` has `h_pre = 1,082,619`; every other chain has no `h_pre` unless configured (absent on a chain that has x/fibre from genesis). A configured `h_pre` MUST NOT be applied to another chain id. The `h_r` query is a state query whose module is present at every height of every chain (bank `Params`), pinned to `h_r`; if `h_pre` is configured, the gate also queries x/fibre `Params` pinned to `h_pre`, and runs that query even when the `h_r` query fails (Ignoring takes precedence, so its result still matters). If `h_pre` is configured but not below `h_r`, the `h_pre` query is not run and the outcome is Inconclusive, not Honoured. Outcomes, decided only from success or failure and the response header `x-cosmos-block-height`, never from error codes or messages: **Ignoring** if the `h_r` query succeeds without the header or with a value other than `h_r`, or if the `h_pre` query succeeds (any response message, empty included, whatever its header). **Honoured** if the `h_r` query succeeds with the header equal to `h_r` and the `h_pre` query, if configured, fails (any error). **Inconclusive** in every other case (the `h_r` query fails and the `h_pre` query, if run, fails too; the head cannot be read; `h_pre` not below `h_r`; timeout, cancellation). Ignoring takes precedence over Inconclusive. Only Honoured passes; Inconclusive counts as not passed. |
| RS3 Direct read | A read of x/fibre `Params` pinned to `height` establishes the value only if: the canary passed at start; the response carries the response header `x-cosmos-block-height` equal to `height`; and a canary on the same connection right after the read passes. Otherwise the direct source gives nothing for this check (it is not a rejection by itself). While the canary fails, the gate is in observations-only mode (section 10.9, HR4). |
| RS4 Samples | The gate samples the latest `shard_retention` at start, periodically (default every 30 s), on every `da = 1` check, and on demand when `height` is above the newest sample. A sample reads the chain head `a`, then the latest params, then the head `b`, and records that the value was in force at some height in `[a - lag, b + lag]` (both ends saturating), where `lag` is configured (0 for an own node, more for a load-balanced endpoint whose backends may trail each other). Both ends are widened because behind a load balancer the three reads may hit different backends: the params backend may trail the one that answered `a` or be ahead of the one that answered `b`. Without the upper widening a retention increase could be recorded below the height where it took effect, and the gate could take a too high value at `height` (K2, invariant 4). Threat assumption: any two backends behind the endpoint differ by at most `lag` blocks; a larger spread breaks this rule silently, so `lag` MUST be set from the provider's stated or observed spread. Samples are persisted durably in the gate's registry, bound to the chain id, before they are used, and never rewritten. |
| RS5 Segments | Consecutive samples with the same value form a run; consecutive runs form a segment. A new segment starts when the next sample is more than `max_gap_blocks` (default 100) above the last one or more than `max_gap_s` (default 300) later on the gate clock, or when heights or the clock go backwards. A restart that keeps within both gaps continues the segment; otherwise only heights strictly inside the downtime are uncovered. Runs MAY be pruned once older than 8 days (above the 168 h governance maximum). |
| RS6 Value at `height` | From samples: `height` is covered iff some segment has `first.FirstTo <= height <= last.LastFrom`; a run `r` of that segment may be in force at `height` iff `prev(r).LastFrom <= height <= next(r).FirstTo` (a missing neighbour uses `r.FirstTo`, `r.LastFrom` instead); the value is the minimum over those runs. The value at `height` is the minimum over RS3 and RS6 when both give one, either one when only one does, and `ErrRetentionUnavailable` when neither does. |

Threat notes (RS):
- Canary (RS2). The `h_r` query catches an endpoint that drops the request
  height: it answers from the latest state and sends no header, or sends the
  latest height, which is above `h_r` because `canary_offset >= 1`. The
  `h_pre` query catches an endpoint that echoes the requested height but
  answers from other state: no honest node holds x/fibre params at `h_pre`
  (a pruned node has no state there; an archival node at the pin has no
  x/fibre store at that version and the query fails). Verified from the
  pinned celestia-app and cosmos-sdk code, not from a live probe: on an
  archival node `rootmulti.CacheMultiStoreWithVersion` finds x/fibre absent
  from that version's commit info and keeps a typed-nil store, the first
  read on it panics, and the panic is recovered into a gRPC error; no path
  returns zero-value params with success. On a chain where x/fibre existed
  at the configured `h_pre`, an honest archival node succeeds and is
  Ignoring, which is why `h_pre` is keyed by chain id. The `h_r` query uses
  bank, not x/fibre, so it means the same on a chain without x/fibre and at
  any height. A proxy that copies the request height into the response
  header passes the `h_r` step and is caught only by `h_pre`, so a chain
  without `h_pre`, or with `h_pre` not below `h_r`, cannot catch it; the
  latter is Inconclusive rather than silently Honoured. Error codes and messages are not used because
  they do not separate node from transport: an honest pruned node answers
  `codes.Unknown`, and grpc-go itself produces `codes.Internal` for a proxy's
  HTTP 400 or a reset stream. An endpoint that echoes but ignores heights
  and has no `h_pre` configured passes the canary; the next note bounds
  that case. `canary_offset > lag` keeps `h_r` at or below the head of every
  backend behind a load balancer, so an honest one does not answer "height
  in the future"; an offset beyond the node's retained state makes every
  canary Inconclusive (fail-closed, observations-only mode). The default
  offset 10 is inside retained state with default pruning (verified from
  code): the cosmos-sdk default `pruning = "default"` keeps 362880 recent
  heights (interval 10), celestia-app's default app config does not change
  it, and its `MinRetainBlocks = 3000` covers CometBFT blocks only, not
  application state. An operator who sets custom keep-recent below the
  offset, or `pruning = "everything"`, gets an Inconclusive or flapping
  canary, which fails closed and is never Ignoring.
- Any non-monotone pair of changes between two samples is missed, not only
  a change and its revert (for example 4 h to 2 h to 3 h: both neighbouring
  runs are above 2 h): the gate may then take a too high value at `height`.
  One change between samples is covered, because both neighbouring runs
  count. Sampling every 30 s against
  governance voting periods makes this unlikely; the residual risk is
  accepted, and the later source is the history of executed
  parameter changes (governance events), which needs no state at height.
- A source that echoes the height but still answers from other state passes
  RS3. The canary and the minimum with the samples limit the damage to a
  too low value at most when the samples cover `height`; when they do not,
  the gate trusts that node (v1: the operator's own node or a provider the
  operator chose).
- `lag` covers a load balancer whose backends are at different heights: a
  sample from a trailing backend is attributed to a range that includes its
  height.
- Samples are evidence from the gate's own observation, not chain proofs; a
  verifier replaying K2 later uses the archived retention inputs (section
  10.7).

Path selection (normative):

| K2 | `da` | DA path (`path = 1`) | Archive path (`path = 2`) |
|---|---|---|---|
| holds | 2 | first choice; P1, P2, P3 local | fall back if the DA path fails; P1, P2, P3 |
| holds | 1 | first choice; P1, P2, P3 local with the `da = 1` committer (delegated without one, section 8.5) | with the committer: fall back if the DA path fails; P1, P2, P3. Without: refused before fetching, `ErrArchiveRecomputeUnsupported` |
| fails | 2 | MUST NOT be used | only path; P1, P2, P3; blob missing gives `ErrAnchorTooOld` |
| fails | 1 | MUST NOT be used | with the committer: only path; P1, P2, P3; blob missing gives `ErrAnchorTooOld`. Without: refused before fetching, `ErrArchiveRecomputeUnsupported` |

Reasoning for each definition:
- `T_ref` uses the block header time, which is CometBFT BFT time, fixed when
  the block is committed (`UNVERIFIED` for the pinned celestia-core). Floor
  makes K1 at most one second more lenient, which `skew_s` already covers,
  and makes `start` for `da = 2` earlier, which is the conservative side.
- `start` for `da = 1` uses `min(T_ref, creation_timestamp)` because Fibre
  computes `pruneAt = max(promise expiry, creation_timestamp + retention)`
  from the promise, which is created before inclusion (section 10.2); for a
  pending reference the intent's `created_at` is that same creation time
  (F2).
  `creation_timestamp` is a `google.protobuf.Timestamp`
  (`APP/proto/celestia/fibre/v1/fibre.proto`, field 7); floor to seconds is
  the conservative side.
- `r` for `da = 1` takes the minimum of the latest and the at-height value:
  `pruneAt` is fixed at upload with the retention in force then, and the
  latest value covers a server that applies a lowered retention early. S14
  (MaxTTL) uses the latest value only.
- `margin` covers Fibre server clock drift, the gate's own skew and slack for
  early pruning, and scales down with very short retention.
- K2 uses `valid_until`, the only expiry (invariant 4): the window covers the
  whole signed validity, and every Authorization ends no later.
- At defaults (`r = 14400`, margin 600) K2 fails only if the agent signs more
  than 3h35m after `start` with a 15 min TTL, or more than 2h50m after with a
  1h TTL.

Threat notes:
- K1 enforces the meaning of `issued_at` in section 4.1 ("after the anchor tx
  was included", or after the anchor intent was archived): a decision
  signed before its payload was public is not a pre-committed decision.
  `skew_s` tolerates a fast agent clock only.
- K2 makes `path = 1` mean "the DA layer was expected to serve the payload for
  the whole validity window". Without K2 a gate could report DA availability
  for a commitment whose payload the DA layer prunes before `valid_until`.
- Both rules trust the node for `T_ref`, `creation_timestamp` and the retention
  parameters, read under section 10.9. The operator's own node is
  recommended (self-check); a public endpoint is allowed, and the operator
  docs list the providers that passed the canary (P-OPS, nodes.guru). A gate MAY
  instead take K0 and `T_ref` for `da = 2` from the W5 verifier (section 9.5),
  which removes the trust in its node for those two inputs.
- Vectors: `v1/anchor.json`: `k1` (equality accepted, one second earlier
  rejected, `skew_s = 0`, a `2^64-1` block time, both reference forms),
  `k2` (the pending forms, `start = min(T_ref, created_at)`), `k2_included`
  (at the limit and one second over for both `da`, unknown
  `creation_timestamp`, unreadable at-height retention, retention lowered
  and raised since `height`, the governance minimum, the margin floor and
  cap, saturation), `epoch` (rule E1, section 8.7). Each case carries the
  expected values, verdict and route.

The PFF is proven from the PayForFibre namespace data of block `height`
(section 10.4, NA1 to NA7); x/fibre params at a past height are served by
honest nodes and are not by the QuickNode public endpoint (RS rules above).
Still `UNVERIFIED`: header time final at commit for the pinned celestia-core.

Fibre servers keep unsettled shards until `max(promise expiry, creation +
retention)` (section 10.2 `pruneAt`): retention is fixed at upload and
pruning is by wall clock only, whatever the promise's settlement. VERIFIED
(code at the pin, task 045 research; section 10.6.3). `UNVERIFIED`: that no
component outside celestia-app prunes earlier. If one does, the archive path
still serves the payload, and fast mode requires an archive.

### 12.3 The archive

| Point | Rule and reasoning |
|---|---|
| When it is used | When K2 fails, or when the DA path fails for any reason, for both `da` values when the gate has the committer for that `da` (section 8.5). |
| What is checked | P1, P2 and P3 on the full archived blob. The archive is trusted for availability only. |
| Recorder duty | The Recorder writes the archive synchronously before submitting the anchor tx, so the archive copy exists whenever a valid commitment exists. Archive unavailable: `recorder.ErrArchiveUnavailable` (503), nothing submitted; after a submit the write is retried by resubmitting the same bytes, which pays nothing again (PR8). |
| Gate duty | The gate writes the decision record (envelope, action bytes) before it signs and the Authorization after it commits the nonce (section 8.7, stage 4a, AR1 to AR4), and marks a record it then refuses as rejected with the error name (AR5 to AR8). Archive unavailable: `ErrArchiveUnavailable` (503, `Retry-After`), nonce not consumed. |
| Residual risk | If the archive loses or withholds the blob after the DA layer pruned it, the gate rejects (`ErrAnchorTooOld` when K2 failed, otherwise `ErrPayloadUnavailable`), and later `verify` or `replay` cannot recover the payload. Mitigations later: archive replication, archive health check before signing. |
| Record format | Section 19: deterministic CBOR records, write-once, keyed by `(da, commitment)` for payloads and evidence, `(da, commitment, ref_height)` for anchor intents, and `commitment_hash` for decisions, Authorizations, reveals and rejection markers. |
| `da = 1` and the archive | Accepted by a gate with the `da = 1` committer, which every gate configured for `fibre` has (section 8.5). With 4 h retention the archive is the only source a few hours after the anchor, so for `da = 1` it is part of normal operation, not a rare fallback. |

## 13. Stage K-fast

Replaces stage 6 (K) for a pending reference. Inputs: the verified
commitment, the archive, the chain, the mandate (if any). First failure wins.
Every read at a height follows the at-height rules of section 10.9 (HR1 to HR5).

### 13.1 Fibre (`da = 1`)

| # | Check | On failure |
|---|---|---|
| F1 | The intent record for `(1, payload_ref.commitment, h0)` is read from the archive and decodes (kind 13). | `ErrAnchorIntentUnavailable` (503) |
| F2 | `tx` parses with upstream `TryParseFibreTx` as exactly one `MsgPayForFibre`. Its promise passes CV2 (section 10.6.1) with `promise.height == h0` in place of `promise.height <= payload_ref.height` (namespace, commitment, `blob_version = 0`, the gate's `chain_id`, `blob_size` by the CV2 upload-size arithmetic from `payload_size`) and CV3 (well-formed, owner-signed). The record's `namespace` equals `payload_ref.namespace` and its `created_at` equals `floor(promise.creation_timestamp)`. | `ErrAnchorIntentInvalid` (422) |
| F3 | Header at `h0` from the consensus endpoint (NA1 with `h0`): `T_ref` and the header needed by CV7. `HistoricalInfo` at `h0` (CV4 rules). The head `h` is read; `h >= h0` (a head below `h0` means the endpoint is behind). | `ErrChainUnavailable` (503) |
| F4 | Certificate: CV4 to CV7 against the validator set at `h0`, with the network quorum rule of section 10.6.1. | `ErrCertInvalid` (422) |
| F5 | In this order: (1) age, `h - h0 <= MaxH0AgeBlocks`; (2) `window >= 1` (13.3); (3) slack, `anchor_deadline >= h + MinFastSlackBlocks` with `anchor_deadline` of 13.3; (4) promise slack, `T(h) + MinPromiseSlackSeconds < creation_timestamp + payment_promise_timeout` (section 10.2), parameters read at `h`. A failure of (3) or (4) is **provisional**: F6 decides it. | `ErrH0TooOld` (410) for (1); `ErrAnchorWindowClosed` (410) for (2) |
| F6 | Lookup `GetTx(SHA-256(tx))` on the gate's node, with `RebroadcastIntent` or after a provisional F5 failure (lookup only, never a broadcast, when `RebroadcastIntent` is off): included with code 0 at `h0 <= H <= anchor_deadline`: done, and a provisional F5 failure is waived; included elsewhere or with a nonzero code: `ErrAnchorWindowClosed`; not found after a provisional F5 failure: `ErrAnchorWindowClosed`; not found otherwise: `BroadcastTxSync(tx)`, and accepted or already known: done. | `ErrAnchorWindowClosed` (410); `ErrAnchorIntentRejected` (503) for a refused broadcast |

F5, window origin. The x/fibre keeper refuses a PFF whose promise is too
old with `currentHeight - promise.height > PaymentPromiseHeightWindow`
(default 1000), so the chain accepts inclusion at `H <= h0 +
payment_promise_height_window`. VERIFIED (code at the pin `5187d2f`,
`APP/x/fibre/keeper/keeper.go` `validatePaymentPromiseStatefulInternal`;
earlier also in local checkouts `f08d07c` and celestia-app-fibre
`b515db4`). ProcessProposal runs this check for every PFF in a proposed
block (section 10.6.3). The same code allows `promise.height <=
currentHeight + 1`; the certificate check against `HistoricalInfo` at
`promise.height` is what keeps `H >= h0` (section 11.1).

### 13.2 celestia_blob (`da = 2`)

| # | Check | On failure |
|---|---|---|
| B1 | The intent record for `(2, payload_ref.commitment, h0)` is read and decodes. | `ErrAnchorIntentUnavailable` (503) |
| B2 | `tx` decodes as a Cosmos `TxRaw` whose body holds exactly one message, a `MsgPayForBlobs` with, at one index `i`, `namespaces[i] = payload_ref.namespace`, `share_commitments[i] = payload_ref.commitment`, `share_versions[i] = 1`; its `signer` decodes to `payload_ref.signer`; `timeout_height` is 0 or `> h0`; `auth_info` has at least one signer and `signatures` at least one entry. The record's `namespace` and `signer` equal the reference's. | `ErrAnchorIntentInvalid` (422) |
| B3 | Header at `h0` (as F3): `T_ref`. Head `h >= h0`. | `ErrChainUnavailable` (503) |
| B4 | In this order: (1) age, `h - h0 <= MaxH0AgeBlocks`; (2) `window >= 1`; (3) slack, `anchor_deadline >= h + MinFastSlackBlocks` (13.3), after the lowering to `timeout_height`. A failure of (3) is **provisional**: B5 decides it. | `ErrH0TooOld` (410) for (1); `ErrAnchorWindowClosed` (410) for (2) |
| B5 | Mandatory. `GetTx(SHA-256(tx))`: found with code 0 at `h0 <= H <= anchor_deadline`: done, and a provisional B4 failure is waived; found elsewhere or with a nonzero code: `ErrAnchorWindowClosed`; not found after a provisional B4 failure: `ErrAnchorWindowClosed`; not found otherwise: `BroadcastTxSync(BlobTx{tx, [NewV1Blob(namespace, blob, signer)]})` with the archived blob (read under the stage P fetch budget); accepted or already known: done. This is the only check that the tx is valid (signature, fee, sequence): the gate relies on its own node's CheckTx. | `ErrAnchorWindowClosed` (410); `ErrAnchorIntentRejected` (503) |

`UNVERIFIED`: the exact "already in cache" result of CometBFT
`BroadcastTxSync` at the pin (`ErrTxInCache`); the gate treats it as
accepted.

### 13.3 Window and deadline

All values in blocks.

```
window          = min( FastWindowBlocks,
                       mandate.fast_mode_max_delay,
                       payment_promise_height_window(h) if da = 1 )
anchor_deadline = h0 + window
                  lowered to timeout_height when da = 2 and 0 < timeout_height < h0 + window
slack           : anchor_deadline >= h + MinFastSlackBlocks       ; h = the head read in F3 or B3
```

A mandate is always configured in K-fast (C5a, section 8.9). `window >= 1` is
required; a `window` of 0 (only possible when the chain's
`payment_promise_height_window` read at `h` is 0) is `ErrAnchorWindowClosed`
(F5, B4 for symmetry). Otherwise the gate would sign `anchor_deadline = h0`,
which the verifier fails under AM2 (section 20.5) and which K2 input key 9
(`1..1000`) cannot encode.

The slack is checked after the deadline is computed and lowered. It implies
`h - h0 <= window` (`anchor_deadline >= h + 1` and `anchor_deadline <= h0 +
window`). A slack
failure, and for Fibre a promise-slack failure (F5 (4)), is provisional: the
lookup of F6 or B5 runs, and a tx already included with code 0 in `[h0,
anchor_deadline]` waives it (K-fast is done: the anchor has landed in the
window); otherwise `ErrAnchorWindowClosed`.

With a mandate whose key 16 is absent, stage 4p has already denied
(`ErrFastModeNotAllowed`, policy P15), so K-fast never runs without a
mandate bound. `anchor_deadline` is recorded for stage Z and in the K2
inputs (`fast_window = anchor_deadline - h0`, section 19.2).

### 13.4 Then

K1 and K2 on `T_ref` (section 12.2); P; T'; 10p on `T_ref`; Z with `mode =
2` and `anchor_deadline`; N as for an included reference. A gate's sweep MAY list fast-mode entries
whose deadline passed without an evidence record and raise an operator
alert (`anchor_missing`); it never changes an answer or a record.

Threat notes:
- The gate attests availability evidence it checked; it cannot guarantee
  inclusion. A tx accepted by its node can still be evicted or outbid, and a
  Fibre promise can expire before settlement. The deadline makes that
  provable afterwards (`anchor_absent`).
- The gate's own node lying about mempool acceptance is equivalent to the
  gate lying; v1 requires the operator's own node for B5 and F6, as for
  Fibre submission.
- K-fast is idempotent: the intent is content-addressed by what the
  commitment names; a crash before stage 12 leaves nothing stored and a
  retry re-runs it.
- Slack: `MinFastSlackBlocks` and `MinPromiseSlackSeconds` are the gate's
  margin for mempool latency. No fast-mode Authorization is signed whose
  anchor cannot still land in `[h0, anchor_deadline]`, unless it already
  landed there (the waiver reads the chain, not a claim).
- F6 and B5 broadcast before stages P, T' and 10p, so a later refusal or
  deny still lands the payload's anchor and spends the Recorder's fee.
  Accepted: the payload is meant to be public, and the broadcast never
  creates an Authorization.

## 14. Receipt (gate notarization)

A receipt maps one authorized decision to a rail reference that an
allowlisted executor claims, for example the IBKR order id or an EVM
transaction hash. It is optional, signed by the gate, carries the executor's
key and its signed claim, is issued at most once per authorized decision, and
is the only place where a rail reference appears (invariant 6, rule H4).

**A receipt attests that a known executor claimed `rail_ref`, and that the
gate recorded the claim; it is not proof of execution.** It proves that the
holder of `executor_pubkey` signed the claim for this decision, that the gate
accepted that key from its executor allowlist at `recorded_at`, and that the
gate holds no other receipt for it. It does not prove that the rail executed anything, that
`rail_ref` exists at the rail, or what the rail did with it. Execution
evidence is the rail's own record (a broker statement, a transaction in a
block), which a verifier can look up by `rail_ref` or by the idempotency key
(section 16).

### 14.1 Wire format

```
Receipt       = { 1: version         uint = 1,
                  2: commitment_hash bstr 32,
                  3: gate_id         tstr 1..64, ID charset,
                  4: gate_pubkey     bstr 32,
                  ; 5 unassigned
                  6: rail_ref        tstr 1..128, ID charset,
                  ; 7 unassigned (the path is in the Authorization)
                  8: recorded_at        uint 1..2^63-1,
                  9: executor_pubkey    bstr 32,
                  10: executor_signature bstr 64 }
SignedReceipt = { 1: Receipt, 2: signature bstr 64 }
```

| Key | Name | Type | Limit | Semantics |
|---|---|---|---|---|
| 1 | `version` | uint | `= 1` | Receipt format version; same versioning rules as the commitment (section 0). |
| 2 | `commitment_hash` | bstr | exactly 32 | `commitment_hash` of the authorized commitment (section 5). Binds agent, nonce, scope, action and payload. |
| 3 | `gate_id` | tstr | 1..64, ID charset | The gate's own id; equals `scope.gate_id` of that commitment. |
| 4 | `gate_pubkey` | bstr | exactly 32 | The gate's Ed25519 key (the same key that signs its Authorizations). MUST pass G0. |
| 5 | - | - | - | Unassigned. Present means `ErrUnknownKey`. |
| 6 | `rail_ref` | tstr | 1..128, ID charset | Opaque, supplied by the integrator. Decoding enforces only the type, length and ID charset; its shape is a profile matter (the dca-agent profile: the IBKR `order_id`; an EVM integrator: the transaction hash in lowercase hex). A verifier MUST NOT reject a receipt because `rail_ref` lacks some rail's usual shape. |
| 7 | - | - | - | Unassigned (the payload path is in the Authorization, section 15). Present means `ErrUnknownKey`. |
| 8 | `recorded_at` | uint | `1..2^63-1` | Gate clock (Unix seconds) when the gate recorded the executor's claim. The gate never observes execution. |
| 9 | `executor_pubkey` | bstr | exactly 32 | The Ed25519 key of the executor that made the claim; in the gate's executor allowlist when recorded. MUST pass G0 and MUST differ from `gate_pubkey`. |
| 10 | `executor_signature` | bstr | exactly 64 | The executor's signature over `record_message(commitment_hash, gate_id, rail_ref)` (section 14.3), as presented to `Record`. |

All keys are required; there are no optional fields. The CBOR profile is
section 3 (keys one byte each, strictly ascending; shortest heads; definite
lengths; no floats, tags or simple values). Limits: SignedReceipt bytes
`<= 512` (`MaxReceiptSize`), checked before parsing (`ErrTooLarge`); the
largest SignedReceipt that passes every rule below is 452 bytes.

```
receipt_canon  = canonical CBOR of Receipt (SignedReceipt key 1 value)
receipt_hash   = H( 0x11 || "edicta/v1/receipt" || receipt_canon )     ; 32 bytes
signed_message = 0x15 || "edicta/v1/receipt-sig" || receipt_hash       ; 54 bytes
signature      = Ed25519-Sign(gate_sk, signed_message)                 ; 64 bytes
SignedReceipt  = canonical CBOR of { 1: <receipt_canon spliced verbatim>, 2: signature }
```

### 14.2 Verification

`VerifyReceipt(bytes)` runs, in this order:

| Stage | Rules | Check | Sentinels |
|---|---|---|---|
| D | D0 to D21 | As for the envelope (section 6), with the receipt schema above and the 512-byte limit in place of D0 and D14 | stage D sentinels |
| S | R1 | `version == 1` | `ErrUnsupportedVersion` |
| S | R2 | `version`, `recorded_at` `<= 2^63-1` | `ErrIntRange` |
| S | R5 | `recorded_at != 0` | `ErrZeroValue` |
| S | R6 | `executor_pubkey != gate_pubkey` | `ErrKeyRole` |
| G | G0, G2, G1 | Section 5, with `gate_pubkey` for `agent_pubkey`, `receipt_hash` for `commitment_hash` and `TagReceiptSig` for `TagSig` | `ErrInvalidPublicKey`, `ErrSignatureInvalid` |
| G | G0, G2, G1 | On `executor_pubkey` and `executor_signature` over `record_message(commitment_hash, gate_id, rail_ref)` (section 14.3), with the receipt's own fields, signed directly | `ErrInvalidPublicKey`, `ErrSignatureInvalid` |

`VerifyReceipt` proves only that the holder of `gate_pubkey` signed these
bytes. A verifier MUST additionally check, out of band:
- `gate_pubkey` is the key it has on record for `gate_id`;
- `commitment_hash` is the hash of a commitment that itself verifies, with
  `scope.gate_id == gate_id`;
- if it cares which executor claimed the reference, that `executor_pubkey` is
  an executor it knows for this gate.

A verifier MAY flag a `recorded_at` long after the commitment's `valid_until`;
it is not a validity rule, because the integrator may report late.

### 14.3 Record request and issuing (gate `Record`)

An executor asks the gate to record a rail reference with a signed request.
`Record` is a privileged operation: the gate accepts it only under a key from
its executor allowlist.

```
TagRecordRequest = "edicta/v1/record-request"              ; 24 bytes, tag(t) = 0x18 || ASCII
record_message   = 0x18 || "edicta/v1/record-request"      ; 25 bytes
                   || commitment_hash                      ; 32 bytes
                   || uint8(len(gate_id)) || gate_id       ; 1 + 1..64 bytes (ASCII, the gate's own id)
                   || uint8(len(rail_ref)) || rail_ref     ; 1 + 1..128 bytes (ASCII)
executor_sig     = Ed25519-Sign(executor_sk, record_message)            ; 64 bytes
Record(envelope, rail_ref, executor_pubkey, executor_sig)
```

`record_message` is 61 to 251 bytes. Layout reasoning:
- The tag first, with its length byte, as for every Edicta preimage. Its
  length 24 is unique among hashed and signed tags, so the first byte alone
  separates this message from every commitment, receipt, action and
  Authorization preimage and every other signed message (H3).
- `commitment_hash` is fixed at 32 bytes, so it needs no length. It binds the
  claim to one decision.
- `gate_id` binds the executor's signature directly to one gate, so a claim
  signed for one gate cannot be presented to another, even by a holder of
  the executor key's signature, and without relying on how the commitment
  was scoped. The gate fills in its own id when it verifies; the executor
  never sends it. It is variable (1..64), so it carries a one-byte length.
- `rail_ref` is variable (1..128), so it carries a one-byte length too. Each
  variable field is length-prefixed, so `gate_id || rail_ref` splits one way
  only (a gate id ending in characters that also start a rail reference
  cannot shift the boundary), and the message is self-delimiting.
- Both lengths fit one byte (`<= 128`), so there is no width or endianness
  choice, as for `tag(t)`.
- The message is signed directly (no hash first): it is at most 251 bytes,
  Ed25519 hashes internally, and there is no hash for anyone else to sign.
- No nonce or timestamp: a replayed request can only repeat the same claim
  for the same decision, which `Record` answers with the stored receipt.

Executor keys (rules K-E1 to K-E3):
- K-E1: an executor key is a raw Ed25519 public key (RFC 8032) that passes
  G0. Signatures are verified as in G2 and G1 (cofactorless).
- K-E2: the gate holds an executor allowlist (`ExecutorKeys`), configured out
  of band. The gate MUST refuse to start if any entry fails G0, equals any
  gate key, or equals any key in its agent allowlist.
- K-E3: an executor key is never a gate key or an agent key (invariant 7
  extended to three disjoint roles). The gate also checks this per request
  against the commitment's own `agent_pubkey` and its gate keys.

`Record` runs, in this order:

| # | Rule | Check | Sentinel |
|---|---|---|---|
| 1 | D | The envelope decodes (stage D); the gate computes `commitment_hash` | stage D sentinels |
| 2 | RQ1 | `rail_ref` is 1..128 bytes of the ID charset | `ErrFieldSize`, `ErrInvalidString` |
| 3 | RQ2 | G0 on `executor_pubkey`, then G2 and G1 for `executor_sig` over `record_message(commitment_hash, own gate_id, rail_ref)` | `ErrInvalidPublicKey`, `ErrSignatureInvalid` |
| 4 | RQ3 | `executor_pubkey` is in the executor allowlist | `ErrExecutorNotAllowed` |
| 5 | RQ4 | `executor_pubkey` differs from the commitment's `agent_pubkey` and from every gate key | `ErrKeyRole` |
| 6 | RQ5 | The registry entry for `(agent_pubkey, nonce)` exists and holds this `commitment_hash`; otherwise (never authorized, another commitment, pruned) | `ErrNotAuthorized` |
| 7 | RQ6 | The entry has no receipt; otherwise the gate returns the stored receipt | `ErrReceiptExists` |
| 8 | - | Build the receipt with `recorded_at` = gate clock, `executor_pubkey`, `executor_signature`; sign it; attach it atomically, only if the entry still has no receipt | (operational) |

Signature before allowlist, as for agents (L after G): the gate never answers
an unsigned request with "this key is or is not an executor". The gate does
not re-verify the commitment's signature or time: equality with a stored
`commitment_hash` already proves this is a commitment it authorized.

A crash between signing and attaching leaves no receipt; a retry signs a new
one (its `recorded_at` may differ). Only the stored receipt is ever returned,
so at most one receipt per decision leaves the gate.

Vectors: `v1/record_request.json`: 5 valid (both executors, `rail_ref` of 1 and
128 characters, a hex transaction hash) and 19 rejects for RQ1 to RQ4,
including a request signed for another gate
(registry steps RQ5, RQ6 are stateful; gate tests cover them).

### 14.4 Worked example (vector `receipt_minimal_lmt`, gate `gate1`, executor `executor1`)

```
record_message   18 6564696374612f76312f7265636f72642d72657175657374
                 2024a4ac8a2366f3c3658fcbbd4e4e2429e2698cbfa32a63b69ee0e9f3d366fe
                 0c 676174652d70617065722d31                                 ; "gate-paper-1"
                 0a 31333730303933323339                                     ; "1370093239", 81 bytes
executor_sig     e038249bf04ce3b65c59773a2e4ec1eff087a862e4f092da2001ea312b904d2d
                 b76e1abb09f8e0499170a33c7a4680cda85e7c804eac26315126aa68e2e3e500
receipt_canon    a8 01 01 02 58 20 2024...66fe 03 6c "gate-paper-1" 04 58 20 fc51...8025
                 06 6a "1370093239" 08 1a 6ac07dfe 09 58 20 ec17...e2bf 0a 58 40 e038...e500   ; 207 bytes
receipt_hash     5e63721f1881d39e87364e2fe53c090bee3251a70b56e16c5f694dbcf3b0604e
signed_message   15 6564696374612f76312f726563656970742d736967 || receipt_hash
signature        47257367eaaaee96c2c8de7a72188b1ef989e8b38723af5dff35394cd2598636
                 995277bf6ac367c169a509b8e2dd266456cb0173026c201330058d7e90806b07
```

### 14.5 Threat notes

- Why signed: a rail's own record is often private to the account holder.
  Without a signature, anyone could place a fabricated
  `commitment_hash -> rail_ref` mapping in an archive or report. With it, a
  fabricated mapping needs the gate key.
- Why both sign: the executor's signature says who claimed `rail_ref`, and a
  verifier can check it without trusting the gate; the gate's signature and
  its registry make the mapping unique (at most one receipt per decision),
  so it cannot equivocate. Without the executor signature, anyone holding the
  envelope (which is not secret) could record a bogus `rail_ref` first and own
  the decision's only receipt.
- What it still does not prove: that the claim is true. An allowlisted
  executor that is compromised or dishonest can claim any `rail_ref`, and if
  it is first, that claim is the receipt. Execution evidence stays at the
  rail.
- Separate signature tags: the gate signs `TagReceiptSig || receipt_hash` and
  `TagAuthorizationSig || authorization_hash`, an agent signs
  `TagSig || commitment_hash`. The signed messages differ in tag and length
  (54, 60 and 46 bytes), and the hashes are under different tags (rule H3),
  so no signature verifies as another kind (vectors
  `receipt_reuses_commitment_signature`, `receipt_reuses_authorization_signature`,
  `receipt_signed_under_commitment_sig_tag`,
  `receipt_signed_under_authorization_sig_tag`). Key roles are also kept
  apart by configuration (rule L0).
- G0 on `gate_pubkey`: with a small-order key every message verifies (vector
  `receipt_gate_pubkey_identity`), so a forged receipt would pass any
  verifier that skipped G0.
- Privacy: the receipt reveals `rail_ref` next to `commitment_hash`. Receipts
  are published only as the operator chooses.

Vectors: `v1/receipt.json`: 6 valid (`minimal_lmt`, a `da = 1` commitment, a
128-character `rail_ref`, a 64-character hex `rail_ref` for a JSON action,
`recorded_at = 2^63-1`, a claim by `executor2`) and 48 rejects covering every
rule above, including the unassigned keys 5 and 7, versions 0 and 2, an
Authorization fed to the receipt decoder, and the executor key and signature.

## 15. Authorization (gate output)

The Authorization is the gate's signed statement that one commitment passed
every check of section 8.7 at this gate, for exactly one action (type, salt
and bytes), until `expires`, with the publication guarantee its `mode`
states. The integrator's executor verifies it before acting (section 16).

### 15.1 Wire format

```
Authorization       = { 1: version         uint = 1,
                        2: commitment_hash bstr 32,
                        3: action_hash     bstr 32,
                        4: gate_id         tstr 1..64, ID charset,
                        5: expires         uint 1..2^63-1, Unix seconds,
                        6: path            uint enum (1 = da, 2 = archive),
                        7: mode            uint enum (1 = strict, 2 = fast),
                        ? 8: anchor_deadline uint 1..2^63-1 }
SignedAuthorization = { 1: Authorization, 2: signature bstr 64 }
```

| Key | Name | Type | Limit | Semantics | Inv. |
|---|---|---|---|---|---|
| 1 | `version` | uint | `= 1` | Format version; section 0 rules. | 6 |
| 2 | `commitment_hash` | bstr | exactly 32 | The authorized commitment (section 5). The executor's idempotency key. | 1, 5 |
| 3 | `action_hash` | bstr | exactly 32 | Equals the commitment's `action.hash`: `ActionHash(type, salt, bytes)` (section 5.1). The type is inside it, so the Authorization does not carry the type. | 3 |
| 4 | `gate_id` | tstr | 1..64, ID charset | The issuing gate; equals the commitment's `scope.gate_id`. | scope |
| 5 | `expires` | uint | `1..2^63-1` | Last moment of use, exclusive with skew: `expires = min(valid_until, authorized_at + MaxAuthorizationTTL)`. Never later than `valid_until`. | 4 |
| 6 | `path` | uint enum | `1 = da`, `2 = archive` | Where the gate accepted the payload from (section 8.5), the gate's availability statement made at authorization time. `2` means DA retrievability during the validity window was not shown; publication is still proven by the anchor. Executors may ignore it. | 2 |
| 7 | `mode` | uint enum | `1 = strict`, `2 = fast` | Required. `1` iff the commitment's reference is included, `2` iff it is pending. The gate derives it from the commitment, never from a request field or path. | 9 |
| 8 | `anchor_deadline` | uint | `1..2^63-1` | Present iff `mode = 2`. The absolute L1 height by which the anchor must be included: the anchor must land at a height in `[h0, anchor_deadline]`. Computed by K-fast (section 13.3). It is a height, not a tx hash or rail reference (invariant 6). | 2, 9 |

There is no agent key, no signature of the agent, no action type, no salt, no
`authorized_at`, no `h0` (the commitment holds it) and no rail reference: the
executor needs only the bound, and the registry keeps `authorized_at`. The
gate key is not a field: the executor pins `gate_id -> gate_pubkey` out of
band, exactly like a receipt verifier. A required `mode` gives one encoding
per mode, and invariant 9 wants the mode stated, not implied.

### 15.2 Tags and exact bytes

```
auth_canon          = canonical CBOR of Authorization (SignedAuthorization key 1 value)
authorization_hash  = H( 0x17 || "edicta/v1/authorization" || auth_canon )        ; 32 bytes
signed_message      = 0x1b || "edicta/v1/authorization-sig" || authorization_hash  ; 60 bytes
signature           = Ed25519-Sign(gate_sk, signed_message)                       ; 64 bytes
SignedAuthorization = canonical CBOR of { 1: <auth_canon spliced verbatim>, 2: signature }
```

The CBOR profile is section 3 (keys `1..8`, one byte each, strictly
ascending; shortest heads; definite lengths; no floats, tags or simple
values). SignedAuthorization bytes `<= 256` (`MaxAuthorizationSize`), checked
before parsing (`ErrTooLarge`); the largest one that passes every rule below
is 233 bytes (vector `auth_v1_max_size`). Signed-message lengths are 46
(agent), 54 (receipt) and 60 (Authorization) bytes: all different, and every
hash is under a distinct tag (H3).

### 15.3 Verification (executor side)

`VerifyAuthorization(bytes, check)`, where `check` is what the executor knows
on its own: the pinned `gate_pubkey`, the expected `gate_id`, the
`action_type` it executes, the exact `action_bytes` it is about to execute,
the `action_salt` presented with them, its clock `now` and its `skew_s`
(0..300). Pure: no I/O. In this order:

| Stage | Rule | Check | Sentinel |
|---|---|---|---|
| D | D0 to D21 | As for the envelope (section 6), with the Authorization schema and the 256-byte limit in place of D0 and D14. Key 8 is not defined when `mode == 1` (D15) and required when `mode == 2` (D17); `mode` (key 7) precedes key 8 in canonical order, so this is decided in one pass, as D15 and D17 do for `signer` and `da`. For any other `mode` value key 8 is optional at stage D and Q5 refuses the value | stage D sentinels; `ErrUnknownKey` (deadline with `mode = 1`), `ErrMissingField` (`mode = 2` without deadline, or `mode` absent) |
| S | Q1 | `version == 1` | `ErrUnsupportedVersion` |
| S | Q2 | `version`, `expires`, `path`, `mode`, `anchor_deadline` `<= 2^63-1` | `ErrIntRange` |
| S | Q3 | `path in {1, 2}` | `ErrInvalidEnum` |
| S | Q5 | `mode in {1, 2}` | `ErrInvalidEnum` |
| S | Q4 | `expires != 0` | `ErrZeroValue` |
| S | Q6 | `anchor_deadline != 0` when present | `ErrZeroValue` |
| G | G0, G2, G1 | Section 5, with the **pinned** `gate_pubkey` for `agent_pubkey`, `authorization_hash` for `commitment_hash` and `TagAuthorizationSig` for `TagSig` | `ErrInvalidPublicKey`, `ErrSignatureInvalid` |
| X | X1 | `gate_id == check.gate_id` | `ErrScopeMismatch` |
| X | X2 | `1 <= len(action_bytes) <= 65536` | `ErrActionSize` |
| X | X2s | `check.action_salt` is present and exactly 32 bytes | `ErrMissingField` (absent), `ErrFieldSize` (other length) |
| X | X3 | `ActionHash(check.action_type, check.action_salt, action_bytes) == action_hash`, constant-time | `ErrActionMismatch` (wrong bytes, wrong type or wrong salt) |
| X | X4 | `now + skew_s < expires` | `ErrExpired` |

The stage order is normative, as in section 6.5: D, then Q1, Q2, Q3, Q5, Q4,
Q6, then G, then X1, X2, X2s, X3, X4. X3 is where "exact bytes" is enforced
at the executor: it hashes the bytes it holds, with the salt it was given,
under the type it executes, so other bytes, the same bytes under another type
or salt, or bytes of another decision all fail.

The executor's input is the SignedAuthorization, the action type, the exact
action bytes and the salt; the integrator carries the salt next to the bytes
from the agent, and the executor never derives it. A missing salt is a
separate error from a wrong one because it is an integration fault; the
salt's presence is not secret, so the distinction leaks nothing.

An executor MAY refuse `mode = 2` by configuration; the profile defines the
sentinel (`ErrFastModeRefused`, profile documents). The default accepts fast
mode: fast mode exists only under a mandate whose principal stated
`fast_mode_max_delay` (C5a, policy P15), and an executor default must not
silently override that consent; refusing is the explicit strict-only
setting. An executor that accepts `mode = 2` logs `mode` and
`anchor_deadline`, and MAY keep them in its dedupe record; the source of
truth is the gate-signed Authorization (one per nonce, archived as kind 4,
reached by `commitment_hash`). The receipt does not carry them.

### 15.4 Worked example (vector `auth_minimal_lmt_da`, signer `gate1`)

`minimal_lmt`, authorized at `now = 1791000060` with `MaxAuthorizationTTL =
300`, so `expires = min(1791000900, 1791000360) = 1791000360`; DA path;
included reference, so `mode = 1` and no deadline.

```
auth_canon          a7 01 01 02 58 20 2024...66fe 03 58 20 c219...0d0f
                    04 6c "gate-paper-1" 05 1a 6ac07f28 06 01 07 01            ; 97 bytes
authorization_hash  939c9f592e250c6a6aef540f9e4d4d017e26436ea04683c1cc9a4bfd95fd69b9
signed_message      1b 6564696374612f76312f617574686f72697a6174696f6e2d736967 || authorization_hash
signature           7dcb3bbc984852600abedb931d5d2ac58f0e64bbf16615d702a5ba381d8175a0
                    23b4316a3e539630a9b61486dc9b5a57205f00da03916cffcc3498efad19b501
SignedAuthorization a2 01 <auth_canon> 02 58 40 <signature>                     ; 166 bytes
```

### 15.5 Threat notes

- Bearer token. Anyone who holds the SignedAuthorization, the action bytes
  and the salt can present them to an executor until `expires`; the gate
  issues one Authorization per nonce but cannot stop it being presented
  twice. At most once execution therefore needs the executor's dedupe
  (section 16, I5). `MaxAuthorizationTTL` bounds how long a leaked
  Authorization is usable and how long the executor must keep its dedupe
  record.
- Never longer than the decision: `expires <= valid_until` (invariant 4), and
  K2 covers `valid_until`, so the payload stays retrievable for as long as an
  Authorization can be used. `anchor_deadline` cannot extend the decision.
- Mode confusion: `mode` is signed, and the verifier checks it against the
  commitment's reference form (section 20.5); an Authorization that says
  `strict` for a pending reference is a gate-signed contradiction.
- Fast mode. A fast-mode Authorization is a bearer token exactly like a
  strict one. What differs is the publication guarantee: "available (Fibre:
  validators' custody certificate; blob: accepted by the gate's node) before
  the action, anchored no later than `anchor_deadline`". An executor that
  needs "anchored before the action" refuses `mode = 2`.
- Acting after the deadline: an executor that accepts `mode = 2` SHOULD act
  only while its own chain head is below `anchor_deadline`; one without a
  chain head source relies on `expires` (profile rule, profiles T1a/X1a). No
  core sentinel is mandated.
- Replay across gates and actions: `gate_id` is in both the commitment and the
  Authorization, and the executor pins its gate; `action_hash` binds type,
  salt and bytes (vectors `authorization_foreign_gate_id`,
  `authorization_action_other_type`, `authorization_action_other_order`,
  `exec_v1_wrong_salt`).
- Signature confusion: an agent key cannot produce an Authorization the
  executor accepts (pinned key, vector `authorization_signed_by_agent_key`),
  and no commitment or receipt signature verifies as one (different tags and
  hashes; vectors `authorization_reuses_commitment_signature`,
  `authorization_signed_under_commitment_sig_tag`,
  `authorization_signed_under_receipt_sig_tag`). G0 on the pinned key: vector
  `authorization_pinned_key_identity`.
- Why the Authorization is not the receipt: it exists before any rail
  reference does, and it is what the executor needs; the receipt is an
  optional record made afterwards.
- Gate key compromise: whoever holds the gate key can sign an Authorization
  for any bytes, committed or not, and every executor that pins that key
  accepts it. The gate key is as sensitive as the rail credentials it guards.
  Key rotation and revocation are out of scope for v1.
- Clock: X4 subtracts the skew on the executor's side (`now + skew_s <
  expires`), so an executor clock up to `skew_s` slow still stops at the true
  `expires`; a clock slower than that extends use. Assumption: executor clock
  within `skew_s` of true time.

Vectors: `v1/authorization.json`: 12 valid (both paths, `expires` capped by
`valid_until`, a `da = 1` commitment, a JSON action, a 65536-byte action, a
128-byte type, both modes, a deadline lowered to the PFB's `timeout_height`,
the 233-byte maximum) and 60 rejects covering every rule above.

## 16. Integrator contract

The core guarantees, given the gate key is secret and executors pin it:
- An Authorization exists only for a commitment that passed invariants 1 to 6
  at this gate, for exactly one action (type and bytes), until
  `expires <= valid_until`.
- At most one Authorization per `(agent_pubkey, nonce)` per registry lifetime
  (rule E1 covers registry loss).
- Anyone holding the Authorization, the action bytes and the gate key can
  check this offline; with the envelope and the payload, a recipient can
  replay the decision and see the exact authorized action (O8).
- At most one receipt per authorized decision.

The core does not guarantee, and depends on the integrator for:
- that anything is executed only with an Authorization;
- at-most-once execution;
- any semantic bound (notional, price, account, instrument), the
  well-formedness or safety of the action bytes for the rail, and that a
  receipt's `rail_ref` is true;
- confidentiality of the action bytes and their salt wherever it hands them
  on (section 5.1).

### 16.1 Executor rules (normative)

An executor is whatever holds the rail credentials and acts on an action: a
signer that signs only authorized transactions, a contract that verifies the
Authorization, or middleware in front of a broker API. A conforming executor:

| Rule | Requirement |
|---|---|
| I1 | Pins `gate_id -> gate_pubkey` out of band, and the action type(s) it executes. It never takes the key, the gate id or the type from the Authorization, the caller or the agent. |
| I2 | Calls `VerifyAuthorization` (section 15.3) with its pinned key and gate id, its type, **the exact bytes it is about to execute** and the salt presented with them, its clock and skew, and refuses on any error. |
| I3 | Executes exactly the authorized bytes: it parses those bytes as they are with the profile's strict decoder and acts on the result of that parse. It never builds the rail request from a struct supplied by the caller or the agent, and never re-encodes its own struct to compare it with the bytes. Where the rail needs another encoding (for example a broker's JSON API), the mapping from the parsed bytes is fixed by the profile, field for field. |
| I4 | Checks the domain the bytes name (account, chain id, contract, as the profile defines) against its own, and refuses a mismatch. |
| I5 | Dedupes by `commitment_hash`: records it as in flight atomically before or with the send, refuses a second execution of the same `commitment_hash`, and keeps the record at least until `expires + skew_s`. After a crash it resolves an in-flight record by looking the action up at the rail (by the idempotency key), never by sending again. |
| I6 | Does not start a send once `now + skew_s >= expires`; a send started before may complete. |
| I7 | Optionally reports the rail reference to the gate after the rail acknowledged the action: a record request signed with its own executor key, which the gate operator has put in the executor allowlist (section 14.3). The executor key is used for nothing else. |

Amendment to I5. A profile MAY allow re-sending
byte-identical signed rail requests when the rail guarantees at-most-once
inclusion of those bytes (for example an account sequence) and the profile
bounds the window (for example a timeout height derived from `expires` at
signing time). Such a resend is the same send, not a second execution, and
I6 does not forbid it as a new start. Before the first send the executor
records the exact signed bytes durably; every resend uses those bytes, and
none is built after the first. After the window the record goes to the
operator; the executor never builds a second request for the same
`commitment_hash`. The profile states the window, which side of it bounds
inclusion in wall-clock time, and the resend conditions (bank-send profile,
section 4).

Threat note (I5 amendment): a fresh request after a lost send (new sequence,
new signature) could execute twice if the first one lands late. Resending
the identical bytes cannot: the rail accepts them at most once, and the
window makes inclusion impossible after it closes.

Threat note (I3): every translation between "what was authorized" and "what
is sent" is a place where the two can differ. Parsing the authorized bytes
directly leaves only the profile's decoder and its documented field mapping;
re-encoding a struct from elsewhere would let a caller authorize one order and
execute another that "looks the same".

Threat note (enforcement gap): the gate cannot see whether an executor runs
these rules. An integrator that executes without them has no Edicta
protection, whatever the gate does. Audits of an integration check that the
rail credentials are reachable only through a conforming executor.

### 16.2 Profile requirements (normative for profile documents)

Cross-domain binding is the profile's job; the core provides only `gate_id`
and the gate's action-type allowlist. A profile document MUST:
1. define its action type, lower case, with the version in the name
   (`application/vnd.<org>.<format>.v<N>+<encoding>`); an incompatible change
   gets a new type;
2. define a strict decoder under which one byte string has exactly one
   meaning, and say which encodings it refuses;
3. make the action format **self-identify its domain**: the bytes name where
   they may execute (EVM: `chain_id` in the transaction, plus the contract;
   dca-agent profile: the IBKR account in the order), and the executor checks
   it (I4);
4. state the executor's checks beyond I1 to I7 (validation, risk limits), the
   field mapping to the rail's API (I3), and the idempotency key derivation
   (16.3);
5. list which rail facts it relies on and mark unverified ones.

### 16.3 Idempotency key (non-normative guidance)

Use `commitment_hash`, as 64 lowercase hex characters, as the rail's
idempotency key wherever the rail has one (client order id, request id,
idempotency header). The same decision then always maps to the same key, so a
resend after a crash is a duplicate at the rail, and anyone with the rail's
records can link an action to its public decision. If the rail limits the key
length or charset, the profile defines the derivation (for example the
dca-agent profile's IBKR `cOID`); truncation weakens the collision bound and
belongs in the profile, not in an executor's code.

## 17. Publish request (agent to Recorder)

A Recorder spends its operator's fees on every blob it submits, so it accepts
a blob only in a request signed by an allowlisted agent key, and applies
per-agent quotas before any fee is spent. The request authenticates the
agent to the Recorder; it is not part of the decision, and nothing in a
commitment, Authorization or receipt refers to it.

### 17.1 Message

```
TagPublishRequest = "edicta/v1/publish-request"            ; 25 bytes, tag(t) = 0x19 || ASCII
publish_message   = 0x19 || "edicta/v1/publish-request"    ; 26 bytes
                    || uint8(len(gate_id)) || gate_id       ; 1 + 1..64 bytes, ID charset, the server's own id
                    || uint8(len(agent_id)) || agent_id     ; 1 + 1..64 bytes, ID charset
                    || u64be(requested_at)                  ; 8 bytes, Unix seconds, 1..2^63-1
                    || SHA-256(blob)                        ; 32 bytes
signature         = Ed25519-Sign(agent_sk, publish_message) ; 64 bytes
```

`publish_message` is 70 to 196 bytes. It is signed directly, as the record
request is (section 14.3). `gate_id` is the id of the server that runs the
Recorder (`edictad` runs gate and Recorder under one `gate_id`); the agent
learns it out of band (configuration, or the server's health endpoint) and
the server fills in its own when it verifies, so it is not on the wire.
Layout reasoning:
- The tag first, with its length byte; length 25 is unique among hashed and
  signed tags, so the first byte separates a publish request from every
  other Edicta preimage and signed message (H3). An agent key signs only two
  kinds of message, `TagSig || commitment_hash` (46 bytes, first byte
  `0x0d`) and this one (first byte `0x19`), so neither verifies as the other
  (vector `pr_sig_under_commitment_tag`).
- `gate_id` binds the request to one server, so a captured request cannot
  spend another operator's fees. It is variable and carries a one-byte
  length, as `agent_id` does, so `gate_id || agent_id || requested_at`
  splits one way only.
- `agent_id` names the allowlist entry whose key must verify.
- `requested_at` is fixed-width big-endian; it gives the request a short
  life (PR5: `skew_s + 300` seconds either side of the server clock).
- The blob is bound by its SHA-256, which is the commitment's
  `ciphertext_hash` of the blob the agent will later sign, so the Recorder
  can log which decision a fee paid for without reading the blob.

### 17.2 Wire

Transport is HTTP with `application/cbor` bodies, `POST /v1/publish`. Both
bodies use the CBOR profile of section 3 with uint keys `1..4`, all required:

```
PublishRequest  = { 1: blob bstr 1..max_blob_bytes, 2: agent_id tstr 1..64 ID charset,
                    3: requested_at uint, 4: signature bstr 64 }
PublishResponse = { 1: payload_ref bstr,          ; canonical PayloadRef map, the exact bytes of commitment key 10
                    2: block_time uint,           ; T_H as the submitter reports it
                    3: retention_start uint }     ; 0 for da = 2
```

`payload_ref` is carried as a byte string holding its canonical encoding, so
the producer splices it into the commitment without re-encoding. Everything
in the response is a claim of the submitter: the producer checks it with W4
and W5 (section 9.5) before signing.

### 17.3 Checks (Recorder side)

In this order; the first failing rule decides:

| Rule | Check | Sentinel |
|---|---|---|
| PR1 | Request bytes `<= max_blob_bytes + 256` before parsing; strict decoding (section 6 rules with this schema); `len(blob) <= max_blob_bytes` | `ErrTooLarge`, stage D sentinels |
| PR2 | `requested_at` in `1..2^63-1` | `ErrZeroValue`, `ErrIntRange` |
| PR3 | `agent_id` is in the agent allowlist, and its key passes G0, G2 and G1 (cofactorless) for `signature` over `publish_message`. An unknown `agent_id` and a bad signature give the same sentinel, so the endpoint is no allowlist oracle | `edictaapi.ErrPublishSignature` |
| PR4 | The allowlisted key is not a gate key (L0) | `ErrAgentKeyIsGateKey` |
| PR5 | `abs(now - requested_at) <= skew_s + 300` | `edictaapi.ErrPublishStale` |
| PR6 | Completed-blob cache, by `SHA-256(blob)`. (a) If this server has a completed publication of the same blob, the request is answered with the stored PublishResponse (same `payload_ref`, `block_time`, `retention_start`). (b) If another request for the same blob is being processed right now, this one waits for it and, if that one completes, gets the same answer; if it fails, this request continues at PR7 as if no entry existed. Completed entries are kept at least `2 * (skew_s + 300)` seconds after the publication, so every request that can still pass PR5 for that blob finds them. Requests answered under (a) or (b) are not charged | (none: answered from the record) |
| PR7 | Per-`agent_id` quota (blobs per hour, bytes per day) allows the request, and is charged for it; checked before anything is submitted. The quota counts **requests that reach this rule, not spend**: a retry of a blob whose earlier submission has an unresolved outcome (it answered `recorder.ErrOutcomeUnknown`, `recorder.ErrNodeUnavailable` after the submit, or a deadline) is charged again, although it never submits again (PR8) | `edictaapi.ErrQuotaExceeded` |
| PR8 | Unresolved submissions, by `SHA-256(blob)`. If an earlier submission of the same blob has an unresolved outcome and is still held (section 21, `recorder.ErrNodeUnavailable`), the Recorder does not submit again: it resumes the search for that submission and answers the PublishResponse if found, otherwise retryable `recorder.ErrOutcomeUnknown`. Unresolved submissions are held at least `2 * (skew_s + 300)` seconds, like completed ones. Otherwise it submits | `recorder.ErrOutcomeUnknown` |

Then the Recorder publishes the blob unchanged (or finds the earlier
submission, PR8), records the response under `SHA-256(blob)` and answers
with it. Signature before staleness and quota, as for agents at the gate (L
after G): an unsigned request learns nothing about the allowlist or the
quotas.

Threat notes:
- Replay. A captured request is valid only at the server whose `gate_id` it
  names (PR3), and only for `skew_s + 300` seconds either side of
  `requested_at` (PR5). Inside that window PR6 answers it from the dedupe
  record, or PR8 finds the earlier submission: no second submission, no
  second fee, the same `payload_ref`. A replay that reaches PR7 is charged
  to the agent's quota, which bounds how much Recorder work a captured
  request can cause. It publishes
  only bytes the agent chose and creates no decision.
- Dedupe key. `SHA-256(blob)` per server: the server has one namespace and
  one signer account, so the share commitment of a given blob is fixed and
  returning the stored `payload_ref` is exact. Two agents that publish the
  same bytes get the same `payload_ref`; that is harmless, because each
  signs its own commitment. A re-issued decision (W6) is a new blob with a
  new hash and is never deduplicated against the late one.
- A dedupe record lost in a restart costs at most one extra submission of the
  same bytes, which gives the same commitment (and one extra fee).
- Fee of a failed `da = 1` upload. The upload hands the signed
  `PaymentPromise` to validators before any signature set exists. A promise
  that never settles through a PFF (fewer than 2/3 signatures, a crash, a
  timeout) can still be charged once by anyone holding it, through
  `MsgPaymentPromiseTimeout` after the promise timeout (section 10.2,
  "Unsettled promise is charged"). So a failed upload is not free: it may
  cost one fee and never creates an anchor, and every new upload attempt
  signs a new promise that may be charged once. Operators size the escrow
  and quotas with this in mind; "nothing was submitted" in section 21 means
  that no promise left the Recorder.
- The Recorder is untrusted for integrity (section 1): the request protects
  the operator's fees, not the agent. The agent's protection is W4 to W6.
- Quotas held in memory reset on restart; a restart therefore restores a
  quota early. Accepted for v1.
- What the quota counts. v1 has one quota and it counts requests that reach
  PR7, not fees spent. Only completed answers (PR6) are free. A retry
  of an unresolved blob spends no fee (PR8 never submits it twice) but is
  charged, because it costs the Recorder node reads (the search resumes from
  where the last one stopped) and because an agent that keeps retrying must
  not hold Recorder capacity for free: unresolved entries count toward the
  Recorder's limit on unresolved submissions (`recorder.ErrTooManyPending`).
  Consequence for clients: retrying `recorder.ErrOutcomeUnknown` with the
  same blob uses quota; after a few such answers a client SHOULD discard the
  blob and seal a new payload (W6) instead. A separate request-rate limit and
  spend quota are possible later and are not part of v1.

Vectors: `spec/vectors/api/publish_request.json` (section 22).

## 18. HTTP API

`edictad` (gate plus optional Recorder) serves the operations of sections 8.7,
14.3 and 17 over HTTP, so agents and executors in any language need only an
HTTP client and the CBOR profile of section 3. The bodies are the existing
canonical encodings, carried as byte strings and never re-encoded.

### 18.1 Transport rules

| Rule | Value |
|---|---|
| Content type | Requests with a body and every response body: `application/cbor`. A request with another `Content-Type` gets 415 `edictaapi.ErrMediaType`. |
| Encoding | Canonical CBOR, section 3 profile; wrapper maps with uint keys, all listed keys required unless marked optional. Arrays appear only in the health response. Booleans are uint `0`/`1`. An unknown wrapper key is `ErrUnknownKey` (400). |
| Embedded objects | An envelope, SignedAuthorization, SignedReceipt or PayloadRef travels as a `bstr` holding its exact canonical bytes. Servers and clients splice and parse them with their own decoders; they never re-encode them. |
| Versioning | Paths start with `/v1/`. An incompatible change gets `/v2/`. There are no other paths and no aliases. |
| Size | Each endpoint's request limit (18.2) is checked before parsing: `ErrTooLarge` (413). |
| Authentication | `/v1/publish` by the agent signature (section 17); `/v1/record` by the executor signature (section 14.3); optionally, per endpoint class, a bearer token in `Authorization: Bearer` (`edictaapi.ErrTokenInvalid`, 401). `/v1/health` is unauthenticated and carries no secrets. Tokens over plain HTTP to a non-loopback address are refused by configuration. |
| Order of checks | Route (404), method (405), media type (415), token (401), size (413), wrapper decoding (400), then the operation's own stage order (sections 8.7, 14.3, 17). |

### 18.2 Endpoints

| Method, path | Request | 200 response | Request limit |
|---|---|---|---|
| `POST /v1/publish` | `PublishRequest` (section 17.2) | `PublishResponse` (section 17.2) | `max_blob_bytes + 256` |
| `POST /v1/authorize` | `{1: envelope bstr, 2: action bstr, 3: action_salt bstr 32}` | `{1: signed_authorization bstr}` | `2176 + 65536 + 35 + 24 = 67771` bytes |
| `POST /v1/record` | `{1: envelope bstr, 2: rail_ref tstr, 3: executor_pubkey bstr 32, 4: executor_signature bstr 64}` | `{1: signed_receipt bstr}` | `2560` bytes |
| `GET /v1/health` | no body | `Health` (below) | - |

`/v1/authorize` runs section 8.7 on the envelope, the action bytes and the
salt as given and answers the SignedAuthorization of stage 13. All three
keys are required: wrapper decoding (400) refuses a missing key 3 with
`ErrMissingField`, a key 3 that is not a bstr with `ErrWrongType` and a
length other than 32 with `ErrFieldSize`; stage A0s judges presence only for
library callers that pass the salt separately. A wrong salt is 422
`ErrActionMismatch` (A1). `/v1/record` runs section
14.3 with the server's own `gate_id`. `/v1/publish` with the Recorder
disabled answers 404 `edictaapi.ErrPublishDisabled`.

```
Health = { 1: status          uint (1 ok, 2 degraded),
           2: chain_id        tstr 1..50,
           3: head_height     uint,
           4: head_time       uint, Unix seconds,
           5: gate_id         tstr 1..64, ID charset,
           6: gate_pubkey     bstr 32,
           7: recorder_signer bstr 20      (O, absent when the Recorder is disabled),
           8: namespace       bstr 29      (O, absent when the Recorder is disabled),
           9: allowed_da      [ uint ] 1..2 entries, ascending }
```

Health is informational. An agent or executor MUST NOT take a gate key, a
signer or a namespace from it as trusted configuration (I1, section 16.1, pins the
gate key out of band); it may compare them with its configuration.

### 18.3 Errors

Every non-200 response has the body

```
Error = { 1: code      tstr,                  ; the sentinel name, exactly as section 21 writes it
          2: message   tstr,                  ; human-readable, not normative, no secrets
          3: retryable uint (0 or 1),
          4: stored    bstr (O) }             ; 409 only, see below
```

`code` is stable: it is the sentinel's name as written in section 21 (bare
for packages `commitment` and `gate`, prefixed with the package otherwise,
for example `edictaapi.ErrPublishStale`). No two sentinels share a code. A
client maps a code back to its sentinel (Go: `errors.Is` works across the
API); an unknown code is treated as `edictaapi.ErrInternal`.

Status semantics:

| Status | Meaning | `retryable` |
|---|---|---|
| 400 | The request is malformed or fails a static rule; the same bytes always fail | 0 |
| 401 | Not authenticated (token, or the publish signature) | 0 |
| 403 | Authenticated but not permitted (key, scope, allowlist, role, type or DA not allowed) | 0 |
| 404, 405, 415 | Wrong route, method or media type | 0 |
| 409 | The operation already happened for this nonce or decision; `stored` may carry its result | 0 |
| 410 | Too late, permanently (expired, anchor too old, stale publish request) | 0 |
| 413 | Above a size limit | 0 |
| 422 | Well-formed but inconsistent with the committed or stored data | 0 |
| 425 | Too early: retry later, the same request may succeed (not yet valid, anchor not yet visible) | 1 |
| 429 | Quota exceeded; a `Retry-After` header gives the seconds to wait | 1 |
| 500 | Unmapped server error; `message` redacted | 0 |
| 502 | The chain shows something the Recorder did not submit | 0 |
| 503 | A dependency is unavailable or the outcome is unknown; nothing was consumed. `ErrArchiveUnavailable` MUST and every other 503 MAY carry a `Retry-After` header (seconds) | 1 |
| 504 | The server's deadline passed; nothing was consumed, or a retry is deduplicated | 1 |

`retryable = 1` means: the same request, unchanged, may succeed later, and
retrying is safe (the gate writes nothing to the registry before stage 12
and its archive write is idempotent, the Recorder
deduplicates by blob hash, `Record` returns the stored receipt). A client
MUST NOT retry a request answered with `retryable = 0` unchanged.

409 and `stored`:
- `ErrNonceUsed` carries `stored` = the stored SignedAuthorization **only if**
  the retry rule of section 8.7 holds (same `commitment_hash`, and the
  presented action bytes and salt hash to the stored `action_hash`); otherwise key 4
  is absent. A caller that receives `stored` verifies it with
  `VerifyAuthorization` like any Authorization; it is the same answer the
  first request got.
- `ErrReceiptExists` always carries `stored` = the stored SignedReceipt.
- No other code carries key 4.

Mapping (normative). The server maps the error returned by the operation to
the first row below whose sentinel it matches (Go: `errors.Is`, in table
order). Order matters where one sentinel also matches another:
`ErrAnchorTooOld` matches `ErrPayloadUnavailable` too (section 8.5), so it is
listed first. A sentinel that wraps no other sentinel is matched after the
codes of its status that come before it in the table.

| Status | Codes, in match order |
|---|---|
| 410 | `ErrAnchorTooOld`, `ErrExpired`, `edictaapi.ErrPublishStale`, `ErrH0TooOld`, `ErrAnchorWindowClosed` |
| 400 | `ErrMalformed`, `ErrTrailingData`, `ErrFloat`, `ErrSimpleValue`, `ErrTag`, `ErrIndefiniteLength`, `ErrNonMinimalInt`, `ErrNestingTooDeep`, `ErrUnsortedMap`, `ErrDuplicateKey`, `ErrKeyType`, `ErrInvalidString`, `ErrUnknownKey`, `ErrWrongType`, `ErrMissingField`, `ErrFieldSize`, `ErrNonCanonical`, `ErrUnsupportedVersion`, `ErrIntRange`, `ErrInvalidEnum`, `ErrZeroValue`, `ErrPayloadTooLarge`, `ErrInvalidNamespace`, `ErrTimeOrder`, `ErrActionSize` |
| 401 | `edictaapi.ErrTokenInvalid`, `edictaapi.ErrPublishSignature` |
| 403 | `ErrInvalidPublicKey`, `ErrSignatureInvalid`, `ErrScopeMismatch`, `ErrActionTypeNotAllowed`, `ErrDANotAllowed`, `ErrAgentKeyIsGateKey`, `ErrAgentNotAllowed`, `ErrAgentKeyMismatch`, `ErrExecutorNotAllowed`, `ErrKeyRole`, `ErrAnchorPending`, `ErrNamespaceNotAllowed`, `ErrMandateRefMissing`, `ErrMandateMismatch` |
| 404 | `edictaapi.ErrRouteNotFound`, `edictaapi.ErrPublishDisabled` |
| 405 | `edictaapi.ErrMethodNotAllowed` |
| 409 | `ErrNonceUsed`, `ErrReceiptExists`, `ErrBeforeRegistryEpoch` |
| 413 | `ErrTooLarge`, `recorder.ErrTooLarge`, `ErrPayloadAboveCap` |
| 415 | `edictaapi.ErrMediaType` |
| 422 | `ErrActionMismatch`, `ErrPayloadSizeMismatch`, `ErrPayloadHashMismatch`, `ErrDACommitmentMismatch`, `ErrArchiveRecomputeUnsupported`, `ErrIssuedBeforeAnchor`, `ErrTTLTooLong`, `ErrNotAuthorized`, `ErrAnchorIntentInvalid`, `ErrCertInvalid` |
| 425 | `ErrNotYetValid`, `ErrAnchorNotFound` |
| 429 | `edictaapi.ErrQuotaExceeded` |
| 502 | `recorder.ErrSignerMismatch`, `recorder.ErrSubmitMismatch` |
| 503 | `ErrPayloadUnavailable`, `ErrRetentionUnavailable`, `ErrChainUnavailable`, `ErrAllowlistUnavailable`, `ErrRegistryUnavailable`, `ErrClockRegression`, `ErrClosed`, `recorder.ErrOutcomeUnknown`, `recorder.ErrNodeUnavailable`, `recorder.ErrTooManyPending`, `recorder.ErrNotVisible`, `ErrArchiveUnavailable`, `recorder.ErrArchiveUnavailable`, `recorder.ErrEscrowInsufficient`, `ErrAnchorIntentUnavailable`, `ErrAnchorIntentRejected` |
| 504 | `edictaapi.ErrDeadline` |
| 500 | `edictaapi.ErrInternal` (anything else) |

Deadlines (normative). `edictaapi.ErrDeadline` means only that the
server's own per-request handler deadline fired. A timeout inside an
operation is reported by that operation's sentinel, and the table order
(every 503 row before 504) makes it win even when the handler deadline fired
at the same time or the error wraps a context deadline:
- a Recorder submit that timed out: `recorder.ErrOutcomeUnknown` (503; the
  blob may have been broadcast, PR8 applies to a retry);
- a Recorder read of the node (head, search, read-back) that timed out:
  `recorder.ErrNodeUnavailable` (503);
- a gate dependency timeout that the gate reports as an unavailable
  sentinel (`ErrChainUnavailable` and others) stays 503.
An error that wraps a context deadline but matches no section 21 sentinel is
504 `edictaapi.ErrDeadline` only if the handler's deadline has fired;
otherwise it is 500 `edictaapi.ErrInternal`. Threat note: a Recorder timeout
reported as 504 would hide that a fee may have been spent and that a retry
is held by PR8; 503 with the Recorder code says exactly that.

The mapping is the whole contract: two servers report the same code and
status for the same failure because the operations' stage orders (sections
6.5, 8.7, 14.3, 17.3) decide which sentinel occurs, and this table decides
how it is reported. The full table, and the section 21 names that never
cross the API (client-side SDK checks, payload opening, profile sentinels,
removed names), are in `spec/vectors/api/errors.json`. A gate with a mandate
also reports the policy codes and the error body key 5 of `spec/policy-v1.md`
section 12.3, each matched after every code above of its status.

Threat notes:
- No oracle: an unknown agent and a bad signature give the same code
  (`ErrAgentNotAllowed` comes only after a valid signature, section 8.7; at
  `/v1/publish` both are `edictaapi.ErrPublishSignature`). `stored` is
  returned only under the retry rule, so a caller without the committed
  bytes learns nothing about a used nonce.
- `retryable` is advice the server derives from the sentinel, never from
  the client. A 503 at `/v1/authorize` means no nonce was consumed and no
  Authorization left the gate (section 8.7, sign before consume); at most
  the idempotent decision record of stage 4a exists, so a retry cannot
  produce a second Authorization. The K-fast 503s
  (`ErrAnchorIntentUnavailable`, `ErrAnchorIntentRejected`) carry a
  `Retry-After` header like every other 503.
- `message` is for operators. It MUST NOT contain tokens, keys or request
  bodies; for 500 it is a fixed redacted text.

## 19. Archive records (format 1)

The archive store (a directory, an object store, a database) is
implementation-defined; the bytes of each record are not. A Recorder, a gate,
a verifier in another language and an auditor's tool read each other's
records, so the record layout is fixed here, in the CBOR style of the rest of
v1. Records are never signed and never hashed into a commitment, an
Authorization or a receipt: the archive is trusted for availability only
(section 12.3), and every reader re-checks what it uses.

### 19.1 Encoding and strict decoding

Profile: section 3 rules 2 to 7 (shortest heads, definite lengths, uint keys
in `1..23` strictly ascending, optional fields absent when unset, required
fields always present, text in the charsets below), restricted further:

| Point | Rule |
|---|---|
| Data items | Major 0, 2, 3 and 5 only. No arrays, negative integers, tags, floats or simple values. |
| Nesting | Depth at most 2 (the record is depth 1, the K2 inputs map depth 2). |
| Entries | At most 24 per map. |
| Record size | At most `MaxRecordSize = 2^27 + 4096` bytes before parsing; per kind at most: payload `2^27 + 4096`, evidence `2^25`, Authorization 512, rejection 256, anchor intent 65,600, absence proof `2^24`, private blob 69,760, decision 69,632, execution reveal 640; policy kinds as `spec/policy-v1.md` section 12.1. |
| Opaque Celestia objects | Each 1 to `2^22` bytes (4 MiB), unless a kind states otherwise (kind 14). |

Every record is a map with two common keys:

| Key | Name | Type | Rule |
|---|---|---|---|
| 1 | `format` | uint | `= 1`. Archive record format, independent of the wire `version`. Kind numbers are scoped per archive format: a kind number names a layout only together with the format value, so the kinds of the superseded `v0` drafts' format 0 say nothing about format 1. |
| 2 | `kind` | uint enum | 1 payload, 2 evidence, 4 Authorization, 5 rejection, 7 to 12 the policy records of `spec/policy-v1.md` section 12, 13 anchor intent, 14 absence proof, 15 private blob, 17 decision, 18 execution reveal. 3 and 6 are not assigned; 16 is reserved (section 4.6). |

Strict decoding, in this order; the first failure decides, and a reader
reports every failure as `archive.ErrCorrupt` wrapping the cause named here
(the vectors list the cause):

1. Size above `MaxRecordSize`: `ErrTooLarge`, before parsing.
2. Generic well-formedness as section 6.2 with the limits above (`ErrMalformed`,
   `ErrTrailingData`, `ErrFloat`, `ErrSimpleValue`, `ErrTag`,
   `ErrIndefiniteLength`, `ErrNonMinimalInt`, `ErrNestingTooDeep`,
   `ErrTooLarge` for entries, `ErrUnsortedMap`, `ErrDuplicateKey`,
   `ErrKeyType`, `ErrInvalidString` for UTF-8).
3. The record is a map (`ErrWrongType`). Then `format` and then `kind`, each
   missing (`ErrMissingField`) or not a uint (`ErrWrongType`); then
   `format != 1` (`ErrUnsupportedVersion`: a record of the superseded format 0
   is refused here, never misread); then `kind` outside 1, 2, 4, 5, 7 to 15,
   17, 18 (`ErrInvalidEnum`).
4. Size above the cap of the kind: `ErrTooLarge`.
5. Schema, per key in encoded order: a key the kind does not define, or does
   not define for the record's `da` or `form` (or, for `anchor_tx_index` and
   `anchor_tx_proof`, without `anchor_tx`): `ErrUnknownKey`; wrong major
   type: `ErrWrongType`; length outside the limit: `ErrFieldSize`;
   characters outside the charset: `ErrInvalidString`. The same, recursively,
   for the K2 inputs map.
6. A required field absent (in key order): `ErrMissingField`.
7. Values: any uint above `2^63 - 1`, `tx_code != 0`, or `fast_window` above
   1000: `ErrIntRange`; `da` outside `{1, 2}`, `retention_source` outside `{1,
   2, 3}`, `form` outside `{1, 2}`, `plaintext_kind` outside `{1, ..., 5}`, or a
   marker name that is not a verdict (19.2): `ErrInvalidEnum`; zero where the
   field is `> 0`: `ErrZeroValue`; a namespace failing rule S8:
   `ErrInvalidNamespace`. Per-kind conditions (key presence by `form`, key 9
   of the K2 inputs by the Authorization's `mode`, the kind 15 envelope limit
   by `plaintext_kind`, kind 14 keys 10 and 11 together) are given with the
   kinds.
8. Nested messages: `envelope` passes strict decoding of section 6 (stage D)
   and its commitment has `version = 1` (`ErrUnsupportedVersion`: a decision of
   the superseded drafts is refused, not misread); `signed_authorization`
   passes the decoding of section 15 and its stage S rules (Q1 to Q6);
   `signed_receipt` passes stages D and S of section 14.2. Their own sentinels
   are the cause.
9. Re-encoding the decoded record gives the input bytes (`ErrNonCanonical`;
   unreachable when 1 to 8 are implemented exactly, kept as a guard).

A corrupt record is never read as absent and never as another record: the
gate's archive source reports it as an operational error, not
`gate.ErrBlobNotFound`, and `verify` names the corrupt item.

### 19.2 Record kinds

Presence: R required; O optional; R1 or R2 required for that `da` and not
defined for the other; O1 optional for `da = 1`, not defined for `da = 2`.

Payload (kind 1). Written by the Recorder before it submits the anchor tx.

| Key | Name | Type | Limit | Presence | Semantics |
|---|---|---|---|---|---|
| 3 | `da` | uint enum | `{1, 2}` | R | As `payload_ref.da`. |
| 4 | `commitment` | bstr | 32 | R | `payload_ref.commitment`. |
| 5 | `namespace` | bstr | 29, S8 | R2 | The share commitment covers it (section 10.5). Not defined for `da = 1`: the Fibre commitment does not cover it, and the anchor's namespace is in the evidence record. |
| 6 | `signer` | bstr | 20 | R2 | Covered by the share commitment, as `namespace`. |
| 7 | `blob` | bstr | `1..2^27` | R | The exact blob bytes (`ciphertext_hash` preimage). |
| 8 | `intent_height` | uint | `> 0` | R | Chain head when the Recorder archived the blob, before submitting: the lower bound of the search for an earlier submission of the same blob after a crash (section 17.3, PR8). |

Evidence (kind 2). Written by the Recorder after it has read the anchor back,
before it returns `payload_ref` (section 10.7).

| Key | Name | Type | Limit | Presence | Semantics |
|---|---|---|---|---|---|
| 3 | `da` | uint enum | `{1, 2}` | R | |
| 4 | `commitment` | bstr | 32 | R | |
| 5 | `namespace` | bstr | 29, S8 | R | Namespace of the anchor (PaymentPromise or blob). |
| 6 | `height` | uint | `> 0` | R | `payload_ref.height`. |
| 7 | `header` | bstr | opaque | R | Signed header (header and commit) of block `height`. |
| 8 | `anchor_tx` | bstr | opaque | R1, O for `da = 2` | The anchor tx (PFF, or PFB) exactly as in block `height`. |
| 9 | `anchor_tx_index` | uint | | with `anchor_tx` | Its index in the block's txs. For `da = 1` as the node reports it; informational, no check reads it. |
| 10 | `anchor_tx_proof` | bstr | opaque | O, only with `anchor_tx` | Its inclusion proof against `data_hash` (section 10.7: SHOULD for `da = 2`; MAY for `da = 1`, not used by CV8). |
| 11 | `blob_proof` | bstr | opaque | R2 | Commitment proof of the share-version-1 blob against the data root of `header`. |
| 12 | `tx_code` | uint | `= 0` | R1 | The PFF result code as the node reported it (CV8, `node-attested`). Only code 0 is archived: any other code means no anchor. |
| 13 | `system_blob` | bstr | opaque | R1 | The share-version-2 system blob. |
| 14 | `system_blob_proof` | bstr | opaque | R1 | The CV8 inclusion evidence: the anchor proof (DAH and PayForFibre namespace data at `height`), in the form below. |
| 15 | `promise_height` | uint | `> 0` | R1 | `PaymentPromise.height`. |
| 16 | `promise_header` | bstr | opaque | R1 | Signed header at `promise_height` (CV7). |
| 17 | `historical_info` | bstr | opaque | R1 | x/staking `HistoricalInfo` at `promise_height` (CV4, CV6). |

Encodings of the opaque fields. A reader decodes them with upstream code at
the pins of section 10.1 and checks each against the header it hangs from
(section 10.6.2, HT5; HR2), so a wrong encoding fails verification, never
passes it.

| Field | Encoding | Status |
|---|---|---|
| `header`, `promise_header` | protobuf `tendermint.types.SignedHeader` (celestia-core at the pin) | `UNVERIFIED`: proto package name and field set at celestia-core `v0.42.x` |
| `historical_info` | protobuf `cosmos.staking.v1beta1.HistoricalInfo` (the `hist` field of the x/staking `HistoricalInfo` query response at the pin's cosmos-sdk fork), `valset` in the stored order (CV4); its embedded header is partial and never a trust anchor (section 10.6.1) | Message VERIFIED (code, cosmos-sdk `v0.50` proto: `header`, `valset`); at the fork `UNVERIFIED` |
| `anchor_tx` | Raw bytes of the element of the block's `data.txs` | VERIFIED (definition) |
| `anchor_tx_proof` | protobuf `celestia.core.v1.proof.ShareProof`, as `pkg/proof.NewTxInclusionProof` returns it | VERIFIED (code, `APP/pkg/proof/proof.go`) |
| `system_blob_proof` | Anchor proof, deterministic CBOR (below) | VERIFIED (vectors `spec/vectors/da/fibre_anchor.json`, `archive_proof`, live Mocha data) |
| `blob_proof` | JSON of celestia-node `blob.CommitmentProof` (`MarshalJSON`, the CometBFT JSON encoder), the form the node API returns; verified with `CommitmentProof.Verify(data_root, commitment)` | VERIFIED (code: celestia-node `v0.34.2-mocha` `blob/commitment_proof.go` has no protobuf form) |
| `system_blob` | protobuf `BlobProto` of go-square `v4` `share.Blob.Marshal`; MUST equal `NewV2Blob(namespace, 0, commitment, pff_signer)`, where `pff_signer` is the 20-byte signer of the archived PFF; upstream `TryParseFibreTx` returns this blob with the tx (`FibreTx.SystemBlob`) | VERIFIED (code, go-square `v4.0.1` `share/blob.go`; vectors `fibre_anchor.json` `system_blob_hex`, from `FibreTx.SystemBlob`) |

Anchor proof (`system_blob_proof`, `da = 1`). A deterministic CBOR map under
the profile of section 19.1 (shortest heads, definite lengths, keys
ascending, no other key, no tag, float or simple value; re-encoding gives the
same bytes); its first byte is `0xa3`, and any other first byte fails CV8.
The record itself still decodes: the field is opaque to section 19.1.

| Key | Name | Type | Rule |
|---|---|---|---|
| 1 | `form` | uint | `= 1`. |
| 2 | `dah` | bstr | protobuf `celestia.core.v1.da.DataAvailabilityHeader` (`row_roots`, field 1, and `column_roots`, field 2, both repeated bytes; celestia-app at the pin, `DataAvailabilityHeader.ToProto`): the DAH of `header`. |
| 3 | `namespace_data` | bstr | celestia-node `shwap.NamespaceData.WriteTo` of the namespace data of `PFF_NS` at `height`: per row, in row order, a uvarint length followed by protobuf `shwap.RowNamespaceData` (`shares`, field 1, each a `Share` with `data` in field 1; `proof`, field 2, nmt `proof.pb.Proof`), nothing after the last row. Never empty in an evidence record, which needs a PFF. |

A reader decodes `dah` with `DataAvailabilityHeaderFromProto` (which runs
`ValidateBasic`) and `namespace_data` with `NamespaceData.ReadFrom` (a
partial row is an error), and then applies NA2 to NA5 of section 10.4
against `data_hash` of `header` (CV8). The protobuf parts are upstream
encodings and need not be canonical: identity (AW2) does not cover them,
and every byte is re-checked through the DAH hash and the NMT proofs. The
CBOR envelope fixes the layout independently of protobuf libraries and
leaves room for another form. Sizes in the vectors: 8,379 and 38,964 bytes.

Key 18 of the evidence record is unassigned. The validator set needed to
re-check the certificate after the chain stops serving it (x/staking keeps
`HistoricalInfo` for about 8 h, section 10.6.1) is the `HistoricalInfo` set
at `promise.height`, archived as key 17 with its binding header as key 16.
The CometBFT set behind `next_validators_hash` carries only consensus powers,
not the token amounts CV6 needs, and CV7 rebuilds it from key 17, so it is
not archived (section 10.7).

Authorization (kind 4). Written after stage 12, or later from the registry by
the gate's repair (section 8.7, threat note on rejected records).

| Key | Name | Type | Limit | Presence | Semantics |
|---|---|---|---|---|---|
| 3 | `signed_authorization` | bstr | `1..256`, section 15 decoding and stage S | R | The SignedAuthorization exactly as the registry holds it. |
| 4 | `authorized_at` | uint | `> 0` | R | The gate clock at stage 10 (`T'`), as the registry keeps it (section 15.1). |
| 5 | `k2` | map | K2 inputs, below | O | The inputs of rule K2 (section 12.2) as the gate used them. Absent when the record was repaired from the registry, which does not keep them; `replay` then reports K2 as not replayable. |

K2 inputs (Authorization key 5), conditions on its own `da`:

| Key | Name | Type | Presence | Semantics |
|---|---|---|---|---|
| 1 | `da` | uint enum `{1, 2}` | R | Equals the decision's `payload_ref.da` (a reader that finds otherwise reports the record corrupt). |
| 2 | `checked_at` | uint `> 0` | R | The gate clock read once at stage 1 (`now`). |
| 3 | `block_time` | uint `> 0` | R | `T_ref` (section 12.2): `T_H` for an included reference, the header time at `h0` for a pending one. |
| 4 | `blob_retention_s` | uint `> 0` | R2 | `r` for `da = 2`. |
| 5 | `retention_latest_s` | uint `> 0` | R1 | `fibre_retention_s(latest)`. |
| 6 | `retention_at_height_s` | uint `> 0` | R1 | `fibre_retention_s(at height)` (always known when an Authorization exists: otherwise the gate refused with `ErrRetentionUnavailable`). |
| 7 | `retention_source` | uint enum | R1 | Where the at-height value came from: 1 the direct read (RS3), 2 the observations (RS6), 3 both (the minimum was taken). |
| 8 | `promise_created` | uint `> 0` | O1 | `floor(PaymentPromise.creation_timestamp)` (for a pending reference the intent's `created_at`); absent when unknown (then K2 is false). |
| 9 | `fast_window` | uint `1..1000` | R iff the Authorization has `mode = 2`; else not defined | `anchor_deadline - h0` as the gate computed it (section 13.3). |

Replay recomputes `r`, `start`, `margin` and K2 from these fields and the
decision; a K2 that fails with `path = 1` in the Authorization is reported as
an inconsistency of the gate. Every inconsistency in this section makes
`retention_replay` `unchecked`, with reason `replay_inconsistent`, and never
`fail`. The K2 inputs are unsigned archive data, so a gate error and an
altered record look the same (20.1). Missing inputs give
`replay_inputs_missing`. With key 9, replay also checks the deadline (section
20.7).

For `da = 1` replay first checks `promise_created` against the archived
evidence. The gate's NA7 takes the earliest
candidate with code 0, which need not be the PFF the Recorder archived:
another promise for the same blob in the same block, paid by anyone, may be
earlier and also settled. Hence:

- Present: consistent iff it equals `floor(creation_timestamp)` of a
  candidate of `T` (NA5 on the anchor proof) whose `creation_timestamp` is at
  or before the archived anchor's. With `anchor_candidates_earlier = 0` this
  is equality with the archived anchor's value. Any other value, in particular one later than the archived anchor's (NA7 would have
  reached the archived anchor first), is an inconsistency of the gate.
- Absent: the gate did not know the creation time, so K2 was false for it
  (section 12.2) and the archive path was the only one. Consistent iff the
  Authorization's path is 2 (archive); with `path = 1` it is an
  inconsistency of the gate. An implementation that reads absence as 0 MUST
  NOT compare that 0 with any candidate.

Threat note (replay of `promise_created`). Requiring equality with the
archived anchor would report an honest gate as inconsistent whenever an
earlier candidate settled; accepting any value at or before it would let a
gate record an invented earlier time. Matching a candidate that the
complete namespace data shows closes both. Code 0 of the earlier candidates
is not archived, so replay cannot tell whether the gate's choice was the
earliest settled one, only that it was a real, not later, candidate.

Rejection marker (kind 5). Written by the gate per AR5 to AR7.

| Key | Name | Type | Limit | Presence | Semantics |
|---|---|---|---|---|---|
| 3 | `commitment_hash` | bstr | 32 | R | The refused decision. |
| 4 | `error` | tstr | 4..64, `Err` followed by ASCII letters and digits, and one of the verdicts below | R | The refusal, by its section 21 name without package. |
| 5 | `gate_id` | tstr | 1..64, ID charset | R | The refusing gate (equals the decision's `scope.gate_id`, since stage 4a runs after C1). |
| 6 | `rejected_at` | uint | `> 0` | R | The gate clock at the refusal. |

Verdicts (the sentinels of stages 4m and 5 to 12 in section 8.7):
`ErrActionMismatch` (stage 5, retry rule condition 2), `ErrAnchorNotFound`,
`ErrAnchorTooOld`, `ErrArchiveRecomputeUnsupported`,
`ErrDACommitmentMismatch`, `ErrExpired`, `ErrIssuedBeforeAnchor`,
`ErrNonceUsed`, `ErrNotYetValid`, `ErrPayloadHashMismatch`,
`ErrPayloadSizeMismatch`, `ErrPayloadUnavailable`,
`ErrRetentionUnavailable`, `ErrMandateRefMissing` (stage 4m, M1),
`ErrAnchorIntentInvalid`, `ErrCertInvalid`, `ErrH0TooOld`,
`ErrAnchorWindowClosed` (stage 6, K-fast), and the policy deny names of
`spec/policy-v1.md` section 12.3 (with `ErrFastModeNotAllowed` and, in
private mode only, `ErrDenied`). For an error that matches several (for
example `ErrAnchorTooOld`, which also matches `ErrPayloadUnavailable`) the
most specific one is written. Operational failures are never written (AR5);
a decoder rejects them. A new verdict sentinel extends this list in a new
revision.

Not markers: the stage 1 refusals (`ErrAnchorPending`,
`ErrNamespaceNotAllowed` and every stage D to C sentinel; no decision record
exists then), the stage A refusals (A0, A0s, A1, before stage 4a), and the
operational 503s, among them `ErrAnchorIntentUnavailable` and
`ErrAnchorIntentRejected` (AR5).

Anchor intent, absence proof, private blob, decision and execution reveal
(kinds 13, 14, 15, 17, 18):

| Kind | Name | Fields (key: name, type) | Logical key | Path | Cap (bytes) | Identity (AW2) | Writer |
|---|---|---|---|---|---|---|---|
| 13 | `anchor_intent` | 3: `da` uint {1, 2}; 4: `commitment` bstr 32; 5: `namespace` bstr 29; 6: `ref_height` uint > 0; 7: `tx` bstr 1..65536; 8: `signer` bstr 20 (R iff `da = 2`, else not defined); 9: `created_at` uint > 0 (Fibre: `floor(creation_timestamp)`; blob: the Recorder clock) | `(da, commitment, ref_height)` | `intent/<da>/<commitment hex>/<ref_height>` | 65,600 | whole record | Recorder, before broadcast |
| 14 | `absence_proof` | 3: `da` uint {1, 2}; 4: `commitment` bstr 32; 5: `namespace` bstr 29; 6: `height` uint > 0; 7: `header` bstr `1..2^22` (SignedHeader at `height`); 8: `dah` bstr `1..2^22` (proto DAH); 9: `namespace_data` bstr `0..2^24` (shwap `NamespaceData.WriteTo` of `NS`, section 20.8; empty when no row holds `NS`); ? 10: `results` bstr `1..2^22` (block results of `height`: the JSON `result` object of CometBFT `/block_results?height=<height>`, of which only `txs_results[]` `code`, `data`, `gas_wanted`, `gas_used` are read (AB5); `da = 1` only, present iff a candidate exists); ? 11: `next_header` bstr `1..2^22` (SignedHeader at `height + 1`; present iff 10 is) | `(da, commitment, height)` | `absence/<da>/<commitment hex>/<height>` | 16,777,216 | the key (first write stays) | an auditor's tool or a gate sweep after the deadline; never required for `valid` |
| 15 | `private_blob` | 3: `plaintext_kind` uint {1 mandate, 2 bucket, 3 closed_set, 4 private_part, 5 action}; 4: `hash` bstr 32; 5: `envelope` bstr `1..65536` for plaintext kinds 1 to 4 (`ErrFieldSize` above), `1..69632` for kind 5 (policy 9.5) | `(plaintext_kind, hash)` | `private/<plaintext_kind>/<hash hex>` | 69,760 | the key (first write stays) | gate (adoption, stage 4a, stage 13) |
| 17 | `decision` | 3: `envelope` bstr `1..2176` (strict decoding, `version = 1`); 4: `form` uint {1 public, 2 private}; 5: `action` bstr `1..65536`, exactly as presented (R iff `form = 1`, else not defined); 6: `action_salt` bstr 32, exactly as presented (R iff `form = 1`, else not defined) | `commitment_hash` (from `envelope`) | `decision/<commitment_hash hex>` | 69,632 | whole record | gate, stage 4a (also after an M1 refusal or a 4p deny; never after an M0 or M2 refusal) |
| 18 | `execution_reveal` | 3: `signed_receipt` bstr `1..512` (section 14.2 stages D and S); 4: `action_salt` bstr 32 | `commitment_hash` (receipt key 2) | `reveal/<commitment_hash hex>` | 640 | whole record | gate, after `Record` attached the receipt (19.7) |

Heights in paths are decimal without leading zeros. Encodings of `header`,
`dah`, `namespace_data`: as for the evidence record above (the same
`UNVERIFIED` status for the protobuf package names at the pin). `results` is JSON as the table says. A
writer MAY drop every field the results proof of AB5 ignores; the reader
reads only `txs_results[]` `code`, `data`, `gas_wanted`, `gas_used`.

Kind 15 plaintext kind 5 (`action`): plaintext = `action_salt (32) ||
action_bytes`; `hash` = the commitment's `action_hash`. A reader with a key
recomputes `H(tag("edicta/v1/action") || uint8(len(type)) || type ||
plaintext)` with `type` from the kind 17 envelope, which is exactly
`ActionHash` because the plaintext is the tail of its preimage; a mismatch is
corrupt. The larger envelope limit fits a 65,536-byte action plus the two
salts, the AEAD tag and 16 recipient entries, which 65,536 does not.

Kind 17 reader rules, after section 19.1: the envelope decodes and has
`version = 1` (otherwise corrupt, cause `ErrUnsupportedVersion`); `form`
outside `{1, 2}` is `ErrInvalidEnum`; keys 5 and 6 with `form = 2` are
`ErrUnknownKey`, absent with `form = 1` `ErrMissingField`; `action_salt` of
another length is `ErrFieldSize`. Kind 3 is not assigned in format 1: a
record that claims it is corrupt (`ErrInvalidEnum`).

Kind 18 reader rules: the receipt decodes (section 14.2 D, S); its key is the
receipt's `commitment_hash`. Its signatures are checked by the verifier
(section 20.11), not at decoding, as for every signed nested object.

Preconditions (AW4): none for 13, 14, 15. Kind 17 with `form = 2` needs the
kind 15 `(5, action_hash)` record durable first. Kind 18 needs the kind 17
record of its `commitment_hash`. The preconditions on "the decision record"
(an Authorization, a marker; policy kinds 8, 9) are met by kind 17. A reader recomputes the key from fields 3 to 6 (13, 14),
3 and 4 (15), the envelope (17) or the receipt (18), and reports a mismatch
as corrupt.

Form (kind 17). `form = 2` iff the mandate in force at stage 4a has
`auditors`; otherwise `form = 1`. The gate never writes `form = 1` in
private mode. The form follows the mandate in force only when the agent
named that mandate or none: after an M0 or M2 refusal (the commitment names
a mandate other than the one in force, or names one at a gate without a
mandate) no kind 17 or kind 15 record is written (section 8.8), because
either form could reveal or misdirect the action of a decision committed
under another, possibly private, mandate. Form 1 holds the salt in clear (public
mode: the salt hides nothing the bytes beside it do not show).

Identity reasoning. Kind 13 is the whole record: two different intents
under one key would let the gate and the verifier see different txs for one
reference. Kind 14 is the key, not the whole record: protobuf parts need not
be canonical and two honest tools may
serialize one proof differently; every proof is re-verified, so the first
durable one serves. Kind 15 is the key: two envelopes of one plaintext differ
in their randomness and open to the same bytes, which the reader checks by
hash. Kind 17 is the whole record. Kind 18 is the whole record:
the gate writes it from its stored receipt, so a second, different record
for one decision would show two receipts, which the gate never issues.
### 19.3 Keys

The store derives the key from the record; a writer never supplies a key
that the record does not determine, and a store whose API takes a key MUST
check it against the record. A reader MUST check that a record read under a
key carries that key (payload and evidence: `da`, `commitment`; decision:
`commitment_hash` recomputed from `envelope`; Authorization: its
`commitment_hash`; marker: `commitment_hash` and `error`; anchor intent and
absence proof: fields 3 to 6; private blob: fields 3 and 4; reveal: the
receipt's `commitment_hash`), and otherwise reports it corrupt.

| Kind | Logical key | Canonical path (RECOMMENDED for file and object stores) |
|---|---|---|
| Payload | `(da, payload_ref.commitment)` | `payload/<da>/<commitment hex>` |
| Evidence | `(da, payload_ref.commitment)` | `evidence/<da>/<commitment hex>` |
| Decision (kind 17) | `commitment_hash` | `decision/<commitment_hash hex>` |
| Authorization | `commitment_hash` | `authorization/<commitment_hash hex>` |
| Rejection | `(commitment_hash, error)` | `rejection/<commitment_hash hex>/<error>` |
| Anchor intent | `(da, commitment, ref_height)` | `intent/<da>/<commitment hex>/<ref_height>` |
| Absence proof | `(da, commitment, height)` | `absence/<da>/<commitment hex>/<height>` |
| Private blob | `(plaintext_kind, hash)` | `private/<plaintext_kind>/<hash hex>` |
| Execution reveal | `commitment_hash` | `reveal/<commitment_hash hex>` |

Policy kinds 7 to 12: keys and paths in `spec/policy-v1.md` section 12.1
(`mandate/<hex>`, `policy-allow/<hex>`, `policy-deny/<hex>/<reason>`,
`policy-bucket/<hex>`, `policy-closed/<hex>`, `policy-successor/<hex>`).

`da` is decimal, hex is lower case. Every path component is ASCII from a
fixed charset, so no escaping is needed.

`(da, commitment)` and not the full `payload_ref`: the payload is archived
before the anchor exists, so its height is unknown then. For `da = 2` the key
fixes namespace, signer and blob (the share commitment covers them); for
`da = 1` it fixes the blob only, so one archive holds one anchor per Fibre
blob. Payload blobs carry a fresh salt, DEK and nonce (section 9.1), so two
publications of the same bytes are a replay that PR6 answers from the first.

### 19.4 Write rules

| Rule | Requirement |
|---|---|
| AW1 Write-once | A stored record is never overwritten or deleted (retention and cleanup are not specified). A write is atomic: the record is either fully present or absent, also after a crash (for files: temp file, fsync, rename, fsync of the directory). |
| AW2 Identity | A write of a record whose key is already stored compares identities: equal, the write succeeds and the stored record stays unchanged; different, `archive.ErrConflict` and nothing is written. Identity per kind: payload, every field except `intent_height`; evidence, `da`, `commitment`, `namespace`, `height`; decision, the whole record; Authorization, `signed_authorization`; rejection, the key (`commitment_hash`, `error`); anchor intent, the whole record; absence proof and private blob, the key (the first write stays); execution reveal, the whole record. |
| AW3 DA check | Before storing a payload, the store recomputes the DA commitment from `blob` (and, for `da = 2`, `namespace` and `signer`) with the committer for `da` (sections 10.4, 10.5) and compares it with `commitment`. Mismatch: `gate.ErrDACommitmentMismatch`, nothing written. A store has a committer for every `da` it accepts; a payload for any other `da` is refused with `gate.ErrArchiveRecomputeUnsupported`, nothing written. |
| AW4 Order | Evidence needs the payload record of its key; an Authorization, a marker or an execution reveal needs the decision record of its `commitment_hash`; a decision record with `form = 2` needs the private blob `(5, action_hash)`. Otherwise `archive.ErrNotFound`, nothing written. An Authorization with K2 inputs whose `da` differs from the decision's `payload_ref.da` is refused with `archive.ErrCorrupt`, nothing written, before the identity comparison of AW2 (so also when a consistent Authorization is already stored): a reader would report the stored record corrupt (19.2). |
| AW5 Conditional marker | A marker write and an Authorization write for the same `commitment_hash` are serialized. If an Authorization record exists, the marker write succeeds without writing (AR6). |

Callers:

| Writer | On `archive.ErrConflict` |
|---|---|
| Recorder, payload | Cannot occur after AW3 except by a SHA-256 collision; treated as an archive fault (`recorder.ErrArchiveUnavailable`). |
| Recorder, evidence | Another anchor of the same blob is archived. The Recorder reads the archived evidence before it submits (as it resumes a search under PR8) and answers from it when it is valid, so it never pays for a second anchor; a conflict after a submit is `recorder.ErrArchiveUnavailable`, and the Recorder MUST NOT return a `payload_ref` whose evidence is not the archived one. |
| Gate, decision | AR2: the envelopes differ only by a second valid agent signature over the same hash; the gate treats it as success and keeps the stored record. |
| Gate, Authorization | Two valid Authorizations exist for one commitment (sign-before-consume threat note, remote signer after a crash). The registry's is authoritative for the gate; the gate logs at error level and raises a metric. The answer to the caller does not change. |

Threat note (AW). First-write-wins on non-identity fields is deliberate: the
earliest `intent_height` is the conservative start of a search; header and
proof bytes of one anchor can differ between reads (a commit seen locally
versus the canonical commit in the next block) and every copy is re-checked
by the verifier, so the first durable copy serves; the repair writes an
Authorization without K2 inputs, and a copy with them adds nothing the
verifier depends on. Identity fields are the ones a different value of which
would change a verdict: the blob, the anchor, the decision, the
Authorization. A party with write access to the archive can store garbage
first and so deny service (every later write conflicts); write access is the
operator's, and the gate writes only after G, L and A (section 8.7), so an
unauthenticated caller cannot squat a decision key.

### 19.5 Record state (AR6 to AR8)

The state of a decision is derived from the records present under its
`commitment_hash`, never stored (the decision record is kind 17):

| State | Records |
|---|---|
| absent | No decision record. |
| `pending` | Decision record, no Authorization record, no marker. |
| `rejected` | Decision record, at least one marker, no Authorization record. |
| `authorized` | Decision record and Authorization record. |

Transitions (by writes): `pending` to `rejected` (first marker), `rejected` to
`rejected` (a marker with another name), `pending` or `rejected` to
`authorized`. `authorized` is final: AW5 suppresses later markers, and
markers written before stay as the history of refused attempts. Marker names
are reported ordered by `rejected_at`, then by name.

`verify` and `replay` report `authorized` only if the Authorization record
decodes, its signature verifies under a configured gate key, its
`commitment_hash` is the decision's and its `action_hash` equals the
decision's `action.hash` (section 15.3); otherwise they report the
Authorization record as invalid and MUST NOT report the decision as
authorized or executed (AR8).

### 19.6 Gate archive source

The gate's `BlobSource` over the archive reads the payload record under
`(ref.da, ref.commitment)`: none, `gate.ErrBlobNotFound`; unreadable or
corrupt, an operational error, which the gate reports as
`ErrArchiveUnavailable` (section 8.7, stage 9). It returns at most `maxSize + 1` bytes of
`blob` and bounds its read of the record accordingly. It does not compare
`namespace` or `signer` with `ref`: the gate's P3 recompute with `ref`
(section 8.5) does, and fails with `ErrDACommitmentMismatch` on any
difference.

### 19.7 Writers

Recorder: kind 1, then kind 13, before returning a pending reference or
broadcasting (section 11.3); kind 2 when the anchor lands. Gate: kind 17 at
stage 4a (in private form the kind 15 `(5, action_hash)` envelope first), kind
4 after stage 12, kind 5 per AR5 to AR7, and the policy records of policy
12.2; in private mode kind 15 replaces kinds 7, 10, 11 (policy 12.2). Kind 14:
written by `edicta-verify absence <ref>` into a local or shared archive copy;
never written by the Recorder.

Reveal on execution (kind 18). The gate writes it in `Record` (section 14.3),
after step 8 attached the receipt, iff the decision's record is kind 17 with
`form = 2` and `action.type` is in `RevealOnExecution` (section 8.9, which
admits only types with a compiled `public_execution = true` profile); it takes
the salt from the nonce entry (RQ5 already requires that entry, so the salt is
there whenever a receipt can be issued) and the receipt it stored. The gate's
repair rewrites it from the entry like the other records. A failed write does
not change the answer to the executor. Nothing else reveals a salt: a denied
or never-receipted decision keeps its salt encrypted. Threat note: an
allowlisted executor that requests a receipt without executing makes the gate
reveal the salt of an action that never ran; that executor already holds the
action bytes and the salt, so no new trust is placed in it (section 14.5: a
receipt is the executor's claim).

### 19.8 Not in format 1

- The header at `height + 1` and the results of block `height` for the
  evidence record (section 10.7, MAY): no check needs them, because
  "anchored" is inclusion (section 10.6.3). (Kind 14 carries them for an
  absence proof only.)
- The validator set at `height`: no commit signatures are checked (HT4).
- The CometBFT validator set at `promise.height` (former evidence key 18):
  CV7 rebuilds it from `historical_info`.
- The Recorder's own retention readings: the K2 inputs that matter are the
  gate's, in the Authorization record.

A new field is a new `format` value, because strict decoding rejects unknown
keys; a reader of a later format keeps reading format 1.

Vectors: `spec/vectors/archive/records.json` and `state.json` (kinds 1, 2, 4,
5, 17; section 22) and `spec/vectors/v1/archive.json` (kinds 13, 14, 15, 17,
18 and kind 4 with K2 input key 9). Must-reject records too large to embed
are in `reject_large`: the record is `record_prefix_hex` followed by the
`affine-7-3` pattern of the given size, with `record_size` and
`record_sha256_hex` of the whole (in `v1/archive.json`: the base case, the
field replaced and the placeholder recipe). A reject with several defects
lists them in `defects`, the expected cause first; its cause follows the
stage order of 19.1. `state.json` `reads` places records in a store without
the write checks and reads them back with the reader checks.

## 20. Verifier

This section adds no wire bytes, tags or gate checks. It defines what
`verify` and `replay` report: the checks and the verdict (20.1), the
execution check (20.2), HTTP archive reads (20.3), online header sources
(20.4), and the rules for the Authorization's mode, pending references,
absence proofs and the action record (20.5 to 20.11).

### 20.1 Report checks and verdict

The report is a list of named checks, each `pass`, `fail` or `unchecked`. A
`fail` and an `unchecked` carry the reason. The names and the verdict rule
are normative, so that two verifiers print the same checklist.

| Check | What passes it |
|---|---|
| `decision` | The decision record is present, is kind 17, decodes (section 19.1) and carries its key (20.11). |
| `envelope` | Stages D, S and G of the signed envelope (sections 6 to 8.1). |
| `action` | The action bytes and salt, from the decision record, a private blob or a reveal, hash to `action.hash` (section 5.1, 20.11). |
| `authorization` | The record state, the Authorization check of section 19.5 (AR8), and AM1, AM2 (20.5). |
| `payload` | P1 to P3 on the archived blob (sections 8.5, 10.7). |
| `anchor` | The inclusion evidence of the archived anchor, checked against the header at `payload_ref.height` (sections 10.4, 10.5, 10.6.1); for a pending reference against the header at the anchor height inside the window, or the absence proof (20.6). |
| `anchor_time` | K1 against `T_ref` (section 12.2): `T_H` of that header, or the header time at `h0` for a pending reference. |
| `header_trust` | HT1 to HT7 (section 10.6.2), with an online checkpoint per 20.4. |
| `receipt` | Section 14.2 and its out-of-band checks against the decision. Present only when a receipt is given. |
| `retention_replay` | K2 replay (section 19.2, 20.7). `replay` only. |
| `execution` | Section 20.2. Present only when the execution check is requested. |
| `policy` | `spec/policy-v1.md` section 13. Present when `RequirePolicy` is set, when a `policy_allow` record exists for an authorized decision, or when the Authorization has `mode = 2` (20.5), and then required. |

Report field `gate_integrity`, always present: `ok`,
`violated` (reason `gate_equivocation` or `gate_signed_inconsistent_private_part`,
with the gate-signed evidence), `not_checked` or `unchecked` (with a reason), per
`spec/policy-v1.md` section 13.4. It is not a check: it says whether the
gate contradicted itself, not whether the decision is valid. After a policy
walk it is `ok` only when the walk checked
every link back to genesis, the start of the counter's history; a walk that
took its step cap first, whether the cap is the default or set by the
auditor, is `unchecked` with reason `policy_walk_truncated`, never `ok`.
After a walk the field carries `walk` (`spec/policy-v1.md` section 13.4):
the step cap, the steps taken, the walked seq range, the chain length and
why the walk ended, and the text output prints it as "last N of M verdicts
checked". Only `violated` changes the verdict; `unchecked` and
`not_checked` never do, because the decision's own checks already ran.

Verdict, first match wins: `invalid` if any check is `fail`; then
`unchecked` if `gate_integrity` is `violated`; then `unchecked` if the record state is `unknown` (no decision record); then
`not_authorized` if the record state is not `authorized`; then `unchecked`
if any check is `unchecked`, or if any of `decision`, `envelope`, `action`,
`authorization`, `payload`, `anchor`, `anchor_time`, `header_trust` is
missing or not `pass`; otherwise `valid`. When the execution check is
requested, `execution` joins that required list. A check that never ran cannot
pass by being absent.

Exit codes of the CLI: 0 `valid`, 1 `invalid`, 2 `unchecked` (the
INCONCLUSIVE outcome of 20.2.1), 3 `not_authorized`, 4 for usage,
configuration and I/O errors, which give no verdict, and 5: `unchecked`
with `gate_integrity` `violated`. Precedence: 4, then 1, then 5, then 3, then 2, then 0, so an
`invalid` decision at an equivocating gate exits 1. Whenever `gate_integrity`
is `violated`, the text output starts with the line `GATE INTEGRITY VIOLATED
(<reason>)`, whatever the exit code, and JSON always carries the field. The output prints the reason of every check that is not
`pass`. For an `unchecked` caused by a source, it names the source and
suggests another one (EO2).

General rule (no exceptions). `invalid` is issued only about the decision or the action,
and only from verified data. Every source problem gives at most `unchecked`.
Sources include the archive, a header or checkpoint source, a tx or results
source, and a receipt file, and their problems include a disagreement between
sources. A hostile source can never cause `valid` or `invalid`. The archive is
a source: it is trusted for availability only, and it only delivers bytes.
The boundary is this. Archived data that verifies (it hashes to the
commitment, carries a valid signature of the party it claims, or is proven
against a trusted header) and that itself proves a violation gives `fail`.
The execution check states the rule in detail (20.2.1).

Archive cases (they follow the general rule):

- A decision, payload or evidence record that is absent in every checked
  copy is `unchecked` (`decision_unavailable`, `payload_unavailable`,
  `evidence_unavailable`). The state of an absent decision is `unknown`, and
  the verdict is `unchecked`, not `not_authorized`. `payload_unavailable`
  signals a retention failure of the operator. An external accountability
  policy can use it, and it is not a verdict on the decision.
- Bytes that fail a check a genuine copy passes are `unchecked`
  (`source_corrupt`, try another copy). These checks are strict decoding
  (19.1), the key check (19.3), the action hash, P1 to P3, a signature that
  the commitment hash does not cover (the agent's in the envelope, the
  gate's in an Authorization or receipt), the `da = 2` commitment proof, the
  Fibre rules CV1 to CV8 (10.6.1), the anchor proof, and an absence proof
  (20.8).
- An archived header at a needed height that does not link to the trusted
  chain is `unchecked` (`chain_mismatch`; HT3, HT5, OH6). So is evidence for
  another height than `payload_ref.height` of an included reference
  (`source_corrupt`); for a pending reference see 20.6.
- An absent Authorization record still leaves the state `pending`
  (`not_authorized`), and an absent marker still turns `rejected` into
  `pending`. Neither is `valid` or `invalid`.
- An archive that cannot be read at all (an I/O fault, HA2) gives no
  verdict.

`fail` cases, a closed list:

- `envelope`: the commitment hashes to the reference and breaks stage D or
  S, or G0 on its `agent_pubkey`. Every copy has these bytes.
- `anchor_time`: K1 against `T_H` of a header that passed header trust.
  Without one, `anchor_time` is `unchecked` (`blocked`), whatever the
  untrusted header says.
- `authorization`: an Authorization whose gate signature verifies and that
  contradicts the decision (AR8, section 15.3), including AM1 and AM2 (20.5).
- `payload`: a payload whose bytes pass P1 to P3 and that a recipient opens
  (9.4) with an O-rule failure, for example O8 (the payload's action or
  action salt does not give the committed `action.hash`).
- `receipt`: a receipt whose gate signature verifies, that belongs to this
  decision, and that breaks a receipt rule.
- `execution`: EO1 (20.2.1).
- `policy`: verified data proving the allow broke the mandate: a per-action
  rule, facts that differ from the re-extraction, or a rule broken on the
  gate-signed state (`spec/policy-v1.md` section 13.4); `mandate_ref_mismatch`
  (the agent-signed `mandate_ref` differs from the allow verdict's
  `mandate_hash`); `ErrFastModeNotAllowed` and `fast_mode_delay` (policy 13.2
  step 4, from the gate-signed Authorization and the principal-signed
  mandate).
- `anchor`: `anchor_absent`, absence proven for every height of `[h0,
  anchor_deadline]` (20.6, 20.8), from the agent-signed reference, the
  gate-signed deadline and proofs against trusted headers. A height with a
  PFF candidate for the reference is never absent, whatever its result code
  (since spec revision `v1.0.3`).

Every other non-`pass` outcome is `unchecked`.

#### 20.1.1 Reasons

Every `unchecked` check carries exactly one machine-readable `reason` from
this enum. Every `fail` carries the rule or sentinel that failed. The text
output prints the reason, the meaning, the source it names (EO2), and the
advice. The enum is closed: 44 reasons in this revision (`anchor_unpaid`
added by spec revision `v1.0.3`). A new reason is a revision change.

| Reason | On checks | Meaning | Advice |
|---|---|---|---|
| `decision_unavailable` | `decision`, `action` | No decision record for the reference in any checked archive copy; on `action`, a form 2 decision whose kind 15 `(5, action_hash)` record is absent (20.11). | Another archive copy. |
| `payload_unavailable` | `payload` | The payload record is missing in every checked copy. It signals a retention failure of the operator and can feed an external accountability policy. It is not a verdict on the decision. | Another archive copy. |
| `evidence_unavailable` | `anchor` | The evidence record is missing in every checked copy. | Another archive copy. |
| `source_corrupt` | `decision`, `envelope`, `action`, `authorization`, `payload`, `anchor`, `receipt`, `policy`, `gate_integrity` | Bytes from a source fail a check that a genuine copy passes: strict decoding, the key check, a hash or DA commitment against the commitment, a signature that the commitment hash does not cover, or an archived proof (da = 2 commitment proof, Fibre CV1 to CV8, anchor proof, absence proof). | Another copy. |
| `chain_mismatch` | `header_trust`, `anchor` | An archived header at a needed height does not link to the trusted chain (HT3, HT5, OH6), or the archived evidence names another height than the decision. | Another archive copy, or check the trusted header. |
| `da_unsupported` | `anchor` | The verifier has no anchor verifier for payload_ref.da. | A verifier build that supports this da. |
| `no_trusted_header` | `header_trust` | No trusted header file, explicit checkpoint or checkpoint source was given. | Supply a trusted header. |
| `header_above_checkpoint` | `header_trust`, `execution` | The checkpoint height T is below a needed height (OH4, EX5 (a)). | Retry later or with a newer checkpoint. |
| `header_not_linking` | `header_trust`, `execution` | An online header at a needed height does not link to the trusted chain, and no source gives one that does (OH6, EX5 (b)). | Another header source. |
| `header_source_unavailable` | `header_trust` | No header or checkpoint source answered. | Another header source. |
| `checkpoint_quorum` | `header_trust` | Fewer than quorum distinct sources agree on the checkpoint (OH5). | More checkpoint sources. |
| `header_disagreement` | `header_trust`, `execution` | header disagreement with trusted chain: possible bad trusted header, hostile source, or fork (OH5, OH7, HT6, EX5 (d)). | Check the trusted header against an independent source. |
| `blocked` | `anchor`, `anchor_time`, `header_trust`, `execution`, `retention_replay`, `policy` | The check needs another check that did not pass; the report names that check. | Fix the named check. |
| `receipt_mismatch` | `receipt` | A receipt that verifies but is not this decision's: another commitment_hash or gate_id, or a gate key that is not on record for gate_id. | The receipt of this decision. |
| `replay_inputs_missing` | `retention_replay` | The Authorization record carries no K2 inputs (repaired from the registry). | Another archive copy. |
| `replay_inconsistent` | `retention_replay` | K2 recomputed from the recorded inputs disagrees with the Authorization's path, promise_created matches no candidate, or `anchor_deadline - h0` exceeds `fast_window` (20.7). The K2 inputs are unsigned archive data, so a gate error and an altered record look the same. | Another archive copy. |
| `timeout` | `any` | The run deadline cut the check short. | Retry with a longer --timeout. |
| `no_checker` | `execution` | No execution checker for action.type. | A verifier with the profile. |
| `chain_config` | `execution` | BX0: the checker is configured for another chain. | Configure the action's chain. |
| `tx_not_found` | `execution` | BX1: no tx source knows the transaction. | Another tx source. |
| `tx_source_unavailable` | `execution` | BX1: the tx sources failed. | Another tx source. |
| `tx_hash_mismatch` | `execution` | BX2: the served bytes do not hash to rail_ref. | Another tx source. |
| `tx_proof_invalid` | `execution` | BX6: the inclusion proof does not verify. | Another tx source. |
| `result_unproven` | `execution` | The result code is not proven: no inclusion proof, or no source served block_results (RP1, RP2). It is attested by one source or confirmed only by agreeing sources, and neither gives pass (EX9). | A tx source that serves inclusion proofs and a source that serves block_results. |
| `results_root_mismatch` | `execution` | RP4: the results do not hash to last_results_hash. | Another results source. |
| `result_index_unbound` | `execution` | RP5: nothing binds the tx's index in the results. | A source that serves the block's txs (/block). |
| `result_header_unreachable` | `execution` | RP4: the header at height + 1 is not trusted. | Retry later or with a newer checkpoint. |
| `code_unproven` | `execution` | A nonzero code that no result proof verifies (EX9). | A source that serves block_results. |
| `height_unproven` | `execution` | A height at or below the anchor without a proof (EX4). | A tx source that serves inclusion proofs. |
| `cross_disagree` | `execution` | Tx sources disagree and nothing verifies either (EX6). | Another tx source. |
| `chain_unbound` | `execution` | BX4: another chain id without proven inclusion. | A tx source that serves inclusion proofs. |
| `policy_verdict_unavailable` | `policy` | No policy_allow record for an authorized decision while the policy check is required (RequirePolicy, or a fast-mode Authorization, 20.5). | Another archive copy. |
| `policy_mandate_unavailable` | `policy` | The mandate record named by the verdict is missing. | Another archive copy. |
| `policy_principal_untrusted` | `policy` | The mandate verifies, but its principal is not among the trusted principal keys. | Pin the principal key, if it is the intended one. |
| `policy_no_extractor` | `policy` | The verifier has no extractor for action.type with the extractor ID the verdict names. | A verifier with that extractor. |
| `state_history_unavailable` | `policy`, `gate_integrity` | A closed set, a needed bucket, or a verdict or mandate the walk needs is missing. | Another archive copy. |
| `gate_equivocation` | `gate_integrity` only | Gate-signed verdicts contradict each other (fork, broken link, self-inconsistent transition, seq gap, version decrease or mandate change in one chain). The agent may be honest; the gate is at fault. Exit code 5. | Investigate the gate; the attached verdicts are the evidence. |
| `policy_walk_truncated` | `gate_integrity` only | The policy walk took its step cap (default or explicit) before it reached genesis, with no finding. The older part of the gate's chain was not read, so `gate_integrity` is never `ok` here. The report gives the walked seq range and the step count. The `policy` check, the verdict and the exit code do not change. | Raise `--max-walk-steps` above the target's seq. |
| `gate_signed_inconsistent_private_part` | `gate_integrity` only | A PrivatePart that hashes to the gate-signed `private_hash` breaks the presence rule of its verdict (`spec/policy-v1.md` section 13.4). The gate signed a hash of contents it could not have produced honestly; the agent is not at fault. Exit code 5, unless the verifier's own facts deny, which is a `policy` fail (exit 1). | Investigate the gate; the PrivatePart and the verdict are the evidence. |
| `anchor_pending` | `anchor` | Pending reference, no usable evidence, and the trusted header is below `anchor_deadline` (or `anchor_deadline + 1` when a results proof is needed): not decidable yet. | Retry later or with a newer checkpoint. |
| `absence_unproven` | `anchor` | Pending reference, no evidence inside the window, and the absence proofs for `[h0, anchor_deadline]` are missing, incomplete or fail. Names the first height not proven. | Another archive copy or `--absence-source`. |
| `anchor_unpaid` | `anchor` | Anchor included, non-zero result code; not confirmable by v1.0 verifiers. Pending reference, no evidence inside the window, and an absence proof (AB5) shows a PFF candidate for the reference at a height of `[h0, anchor_deadline]` whose result code is proven non-zero, with no height showing one with code 0. The payload was published (inclusion); the escrow did not pay; v1.0 requires code 0 for presence (CV8). Names the first such height. Spec revision `v1.0.3`. | None in v1.0 (a v1.1 verifier confirms inclusion without the code). If a paid anchor may sit at a height not proven, another archive copy or `--absence-source`. |
| `policy_private` | `policy`, `gate_integrity`, `action`, `execution` | The record needed is a private blob (kind 15) and no configured auditor key opens it. Names the first record. On `action` and `execution`: a form 2 decision record (20.11) without a reveal that applies. | An auditor key of the mandate. |
| `principal_scheme_unsupported` | `policy` | The verifier build lacks the principal signature scheme the mandate names. | A verifier build with that scheme. |

Vectors: `spec/vectors/verifier/reasons.json` holds the enum and one case
per reason, as overrides of a valid, authorized decision with references to
concrete bytes where a vector has them. It also lists the `fail` boundary
cases. The execution reasons point at `execution_outcomes.json`. The enum of
spec revision `v1.0.3` is that file's 43 reasons plus the reasons of
`verifier/reasons_v1.0.3.json` (`anchor_unpaid`, with its case); the frozen
file stays byte-identical.

### 20.2 Execution check (core, rail-agnostic)

The core knows no rail. It hands the authorized action and the receipt's
`rail_ref` to a checker registered for the action type, and it judges only
the facts the checker returns. Profiles define checkers. The bank-send one is
`spec/profiles/bank-send-v0.md` section 3.4.

Checker input: `commitment_hash`, `action.type`, the authorized action bytes
from the decision record (the bytes stage A matched, never re-encoded), and
`rail_ref` from a receipt that passed `receipt`. Checker output, on success:

| Fact | Meaning |
|---|---|
| `height` | The block that holds the rail transaction, as the source that served it reports it. |
| `header_hash` | The hash of the header at `height` that the checker used. It is a header that passed header trust (EX5). |
| `inclusion` | `proven` (an inclusion proof of the transaction bytes verified against that header's data root) or `node-attested` (the tx source said so). |
| `outcome` | `success` or `failure`: the rail's result as the tx source reported it. |
| `result` | What binds `outcome`: `proven` (a result proof against the trusted chain, F7), `cross-confirmed` (F6: sources agree, reported only) or `node-attested` (one source said so). Only `proven` binds it. |
| `cross_check` | `pass`, `mismatch`, `unavailable` or `off` (EX6). |
| `sources` | Every tx source asked, with its role and result (EX10). |

#### 20.2.1 Outcome rule

The execution check is tri-state, and the general rule of 20.1 holds for it. `pass` leads to the
verdict `valid` (if every other check passes), `fail` to `invalid`, and
`unchecked` to `unchecked`. `unchecked` is the INCONCLUSIVE outcome, exit code 2. Report and JSON names do not change, and a text
output MAY print `INCONCLUSIVE` for it.

A fact is *verified* when it holds no matter which source supplied it:

- F1: the action bytes, bound by `action.hash` with the salt (stage A, 20.11);
- F2: `rail_ref`, bound by the gate's signature over the receipt (section 14);
- F3: transaction bytes whose SHA-256 equals `rail_ref`. F2 and SHA-256 fix
  them, so every source that serves them serves the same bytes;
- F4: a header that passed header trust (section 10.6.2 with 20.4), and with
  it the chain id of the trusted chain;
- F5: a fact that a verified inclusion proof binds to F4. With
  `inclusion = proven`, the F3 bytes are in block `height` of the trusted
  chain, which also binds `height`;
- F7: a result that a verified result proof binds to F4 (`result = proven`;
  the bank-send rules are RP1 to RP6 of its section 3.4). It needs F5.

One more fact is *confirmed* but not verified:

- F6: `cross_check = pass` (EX6). The used source and every configured cross
  source agree on `height`, the bytes and the result. Agreement between
  sources is not verified data. F6 is reported only: it supports neither a
  `fail` nor a `pass`.

| Rule | Requirement |
|---|---|
| EO1 Fail | `fail` only for a violation of the decision or action proven from verified facts (F1 to F5, F7). The core's cases are EX4 under F5 and EX9 under F7. The profile lists its own cases (bank-send: a malformed `rail_ref`, a malformed `TxRaw` or the wrong body in F3 bytes, and a chain id other than the action's under F5). |
| EO2 Unchecked | Every source problem is `unchecked`, never `fail`. That covers a tx source that does not know the transaction or fails, bytes that do not hash to `rail_ref`, a proof that does not verify, a header at `height` that does not link or that `T` does not reach, results that do not recompute to `last_results_hash`, a height or result that is not verified, and sources that disagree with each other, including header sources (EX5 (d)). Such a finding shows a bad source, not a bad execution. The reason MUST name the source (its normalized host, OH3) and the rule. It SHOULD suggest retrying with another source. The verifier tries configured alternates on its own (EX10). |
| EO3 Pass | `pass` only if every fact the check relies on is verified: the bytes (F3), the action they carry (F1 and the profile's body rule), the chain (F4), `height` (F5, so `inclusion = proven`) and `outcome = success` (F7, so `result = proven`). There is no exception. A result that one source attests (`node-attested`) or that sources agree on (`cross-confirmed`) never gives `pass`. |
| EO4 Precedence | A proven violation wins. If any `fail` finding holds, the check is `fail` with the first one in rule order, even if another fact is unverified. Otherwise any unverified fact makes it `unchecked`. Otherwise it is `pass`. A source that contradicts a verified fact is reported, and it does not change the outcome. |

Invariant, with no exceptions. A hostile source can never cause `valid` or
`invalid`, and at most causes `unchecked`. This holds for every tx source
(primary, alternate, cross), every results source, every header source
(headers walk, checkpoint, cross-check), and every disagreement between
them. Why, for this check: a `fail` rests only on F1 to F5 and F7, which no
source can change, because they need a gate signature, SHA-256 or a
verified proof against the trusted header. A `pass` rests on the same facts.
Any number of colluding sources, however distinct their hosts and node
ids, can at most cause `unchecked`. Limits:

- The trust root of 20.4 is trusted by definition: the header file, the
  explicit checkpoint, or the agreed checkpoint sources up to `quorum`. With
  `quorum = 1` that root is one operator (threat note OH). A dishonest root
  is outside every rule here.

Vectors: `spec/vectors/verifier/execution_outcomes.json` gives one case per
cause of `unchecked` and of `fail`, the passing cases, and the live result
proof of the bank-send checker (section 3.4 of the profile). The `cause` of
an `unchecked` case there is its reason in the enum of 20.1.1.

| Rule | Requirement |
|---|---|
| EX1 Request | The check runs only when requested. When requested, `execution` is a required check (20.1). |
| EX2 Preconditions | It runs only if `receipt` passed, the record state is `authorized` (AR8: no receipt is evidence for any other state), and no other check is `fail`. Otherwise `execution` is `unchecked`, with the reason. A missing receipt is `unchecked`, never `pass`. |
| EX3 Checker | No checker for `action.type`: `unchecked`. The checker classifies each finding by 20.2.1. It returns facts, a `fail` error, or an `unchecked` error that names the source. The profile lists the class of each of its errors. A checker that cannot tell whether a finding is bound MUST return `unchecked`. |
| EX4 After the anchor | `height > payload_ref.height`, strictly. If the height is at or below the anchor height: `fail` when the height is verified (`inclusion = proven`, F5), otherwise `unchecked`, because the height is then only the claim of one or more sources. Why `fail`: a gate signs an Authorization only after block `payload_ref.height` exists (strict mode: the anchor is in it, section 8.7; fast mode: it is `h0`, at or below the head `h` the gate read, section 13), and the executor acts only on an Authorization. An honest execution therefore lands in a later block. A transaction at or below that height was made before the gate could have authorized it. |
| EX5 Header | The header at `height` MUST pass header trust (section 10.6.2 with 20.4) under the same trusted header as the anchor before the checker compares anything with it (the chain id, the data root). So `T >= height`, and `header_hash` equals the hash HT3 reached at `height`. Outcomes: (a) `T < height`, after the optional wait of OH4: `unchecked`. (b) A header at `height` that an online source serves and that does not link is that source's fault (OH6): `unchecked`, naming the source. The checker never gets such a header (EX10 sets the candidate aside). (c) A `header_hash` from the checker that differs from the hash HT3 reached: `unchecked`, because the checker read a header that is not on the trusted chain. (d) A cross-check mismatch at `height` (OH7) is a disagreement between sources. Nothing tells whether the trusted header, the cross source or a fork is at fault, and none of them says anything about the decision. `header_trust` and `execution` are `unchecked` with the distinct reason "header disagreement with trusted chain: possible bad trusted header, hostile source, or fork", and the verdict is `unchecked` (exit 2). It is never `fail`. |
| EX6 Cross-check | The checker reports each cross source as `agree`, `disagree` or `fault` (the profile defines them). The aggregate `cross_check` is `off` if none is configured, `mismatch` if any disagrees, `unavailable` if none disagrees and any is at fault, and `pass` if all agree, which needs at least one. `cross_check = pass` is reported and never gives the check `pass` (EO3). `mismatch` is `unchecked`: the answers contradict each other, one side lies, and nothing tells which. It names the disagreeing sources. The exception: when `height` and the result are verified (F5 and F7), a disagreeing cross source contradicts verified facts. It is reported, and the outcome does not change (EO4). `unavailable` and `off` never count as `pass`. |
| EX7 Proven | The report sets `proven_execution` only if `inclusion = proven` and EX5 passed. It says that the transaction bytes are in block `height` of the trusted chain. It says nothing about the result, whose binding is reported in `result` and `cross_check`. |
| EX8 Late | If the block time of `height` is after the Authorization's `expires`, the report carries the warning `execution_after_expires`. The verdict does not change: a rail can include a transaction after the Authorization expired, if it was signed while the Authorization was valid (bank-send profile 4.3, threat note on a halt). |
| EX9 Result | `outcome = failure`: `fail` if the result is verified (`result = proven`, F7), otherwise `unchecked`. `outcome = success`: `pass` needs `result = proven`, which needs `inclusion = proven`. Otherwise `unchecked` with the reason `result_unproven`, or the profile's result-proof reason, and the hint to configure a tx source that serves inclusion proofs and a source that serves `block_results`. `result = cross-confirmed` (F6) is no exception: agreement is not verified data. A profile defines its result proof (bank-send: RP1 to RP6, from `last_results_hash` of the trusted header at `height + 1`). |
| EX10 Sources and alternates | A checker reads its tx sources in configuration order: the primary, then the configured alternates. If a candidate's answer fails for an EO2 reason that rests on that answer (the transaction is not found, the source is unavailable, the bytes do not hash to `rail_ref`, a proof does not verify, the header at its `height` does not reach the trusted chain), the verifier MUST set the candidate aside, record why, and try the next alternate. The first usable answer is used. If an answer's bytes hash to `rail_ref` but fail the profile's byte rules, that is `fail` (EO1), and the check stops. Every source would serve the same bytes (F3). Cross sources are only compared with the used answer (EX6), and their agreement is reported only. They are never promoted to primary, because their independence is counted against the used source. If no candidate is usable, the check is `unchecked`. It names every candidate with its reason, and the reported cause is the last candidate's. Tx sources are distinct by OH3 among themselves and from the headers source. The report lists every source asked: name, role (`primary`, `alternate`, `cross`), result (`used`, `set_aside`, `agree`, `disagree`, `fault`) and reason. |

The report carries `execution` with the facts above, the `rail_ref`, the
block time of `height` and, for `unchecked`, the named sources. Errors of
this check are verifier or profile package errors. They are not section 21
sentinels, and they never cross the gate API.

Threat note (EX). The receipt is the executor's claim, notarized by the
gate (section 14). EX turns it into a statement about the chain: the claimed
transaction exists, is the authorized action, came after the anchor and
succeeded.
- What is trusted: the trust root of 20.4 and SHA-256. No tx source,
  results source or block source is trusted for anything that changes the
  outcome, and neither is the independence of sources that agree.
- A lying tx or results source can make the check `unchecked`, and nothing
  more. It can claim not to know the transaction, serve other bytes, send a
  bad proof, serve wrong results, or claim a false height or code.
- Fabricated height. Without a proof, `height`, and with it the ordering
  after the anchor (EX4), is only the source's claim. A source can put a
  transaction that landed before the anchor into a later block, or a later
  one at or below the anchor. The ordering counts for `fail` and for `pass`
  only under F5.
- The result proof (F7) needs the header at `height + 1` from the trusted
  chain, so a transaction in the newest block can be checked only once the
  next block exists and `T` reaches it.
- Not covered: a second execution of the same decision. EX checks the one
  transaction the receipt names. An executor that signs a second transaction
  with the same body (another `timeout_height` or fee) is not detected here.
  The executor rules (section 16) and the rail's sequence numbers are the
  defence.
- Without a receipt there is no `rail_ref`, and the check is `unchecked`.
  Edicta defines no search of the rail by `commitment_hash`.

### 20.3 HTTP archive read convention

A read-only archive over HTTP serves the records of section 19 under their
canonical paths (section 19.3). Any static file server over a format 1 file
tree conforms, if it meets HA2.

| Rule | Requirement |
|---|---|
| HA1 URL | A record is at `<base>/<path>`. `<base>` is an `http` or `https` URL without query, fragment or user info, with trailing slashes removed. `<path>` is the canonical path of 19.3, byte for byte: `payload/<da>/<commitment hex>`, `evidence/<da>/<commitment hex>`, `decision/<commitment_hash hex>`, `authorization/<commitment_hash hex>`, `rejection/<commitment_hash hex>/<error>`, `intent/...`, `absence/...`, `private/...`, `reveal/<commitment_hash hex>`, and the policy paths of 19.3. `da` is decimal without leading zeros, hex is lower case, and `<error>` is one of the marker verdicts of 19.2. No escaping is needed. |
| HA2 Status | `GET`. `200`: the body is the record bytes, verbatim. `404` and `410`: the record is absent (`archive.ErrNotFound`). Anything else is an archive fault, never absent: another status (including `403` and `429`), a redirect (redirects are not followed), a transport error, a timeout, a body cut short. A client MAY retry a fault and SHOULD honour `Retry-After`. It ignores `Content-Type`. |
| HA3 Size | The client reads at most the cap of the kind it asked for, plus one byte (section 19.1). A longer body is corrupt (`archive.ErrCorrupt` with cause `ErrTooLarge`). |
| HA4 Reader checks | Every body passes strict decoding (19.1) and the key check (19.3: the record carries the key it was asked under), exactly as a local read does. A body that fails is corrupt, never absent and never another record. The client does no DA recompute; the verifier does (P3, section 10.7). |
| HA5 State | The record state (19.5) is derived from reads only: decision, then Authorization, then, if the Authorization is absent, one read per marker verdict of 19.2. The state is known only if each read the derivation needs answered `200` or `404`. A fault on any of these reads, or on any later record read, is an archive I/O error: the verification stops without a verdict (exit 4), and it is never reported as `pending`, `rejected` or absent. |
| HA6 Server | A conforming server is read-only. It answers `GET` and `HEAD` only (`405` otherwise). It serves only paths that parse as a canonical key (HA1) and answers `404` for anything else: other kinds, upper-case hex, `..`, dot files, empty segments, trailing slashes. It lists no directories and follows no link out of the tree. It returns the stored bytes verbatim. It SHOULD send `Content-Type: application/cbor`. It MAY mark a `200` as immutable (records are write-once, AW1). It MUST NOT let a `404` be cached (`Cache-Control: no-store`), because an absent Authorization or marker can appear later. |

Threat note (HA). The archive is trusted for availability only, and HTTP adds
no trust. A server can withhold a record (a `404`): a hidden decision,
payload or evidence record makes its check `unchecked` (20.1, reasons
`decision_unavailable`, `payload_unavailable`, `evidence_unavailable`), a hidden Authorization
gives `not_authorized`, and a hidden marker turns `rejected` into `pending`. A
server that answers with faults gives no verdict. None of these gives
`valid`. A server can
serve altered bytes: strict decoding, the key check, P1 to P3 and the
signatures turn that into `unchecked` with reason `source_corrupt`, unless the bytes verify and prove a violation themselves (20.1). TLS keeps an on-path party from
withholding or reading records. Integrity does not depend on it. Privacy: the
decision record holds the action bytes in clear, and the archive's operator
decides who may read them. The demo binds its server to `127.0.0.1`.
Pitfall: object stores that hide whether a key exists answer `403` for an
absent object. Under HA2 that is a fault, so `verify` stops without a verdict. Configure the store to answer `404` for absent objects
(for S3, grant list permission or serve through a CDN that maps the error).

### 20.4 Online header sources and checkpoint

HT1 needs a trusted header at a height `T` at least the highest height the
verifier needs: `payload_ref.height`, and with the execution check also the
execution `height` (EX5). That header comes from one of three sources, in
this precedence:

1. a trusted header file (HT1 as before);
2. an explicit checkpoint `T:HASH` obtained out of band, for example from an
   explorer;
3. an agreed checkpoint from online sources (OH3 to OH5).

The report names the mode (`file`, `explicit`, `agreed`).

| Rule | Requirement |
|---|---|
| OH1 Source | An online header source is a CometBFT RPC base URL. Reads: `/status` (latest height, `node_info.id`, network), `/header?height=h`, and optionally `/blockchain?minHeight=a&maxHeight=b` (at most 20 headers per call). The verifier builds the protobuf `Header` from the JSON and recomputes its hash (HT2). It never uses a hash the source reports. |
| OH2 At-height | Each header read is a block read (section 10.9): `header.height` MUST equal the requested height (HR1). The chain id of every header MUST equal that of the trusted header, and the configured chain id if one is configured. A header that fails this is a fault of that source. |
| OH3 Distinct sources | Checkpoint sources count once per normalized host (scheme and port ignored, lower case, one trailing dot dropped) and once per `/status` `node_info.id`: two host names that report the same node id count as one source. A source the verifier knows to be the gate's or the Recorder's own endpoint MUST NOT be counted. |
| OH4 Checkpoint height | `T` = the minimum of the latest heights reported by the sources that answered `/status`. If `T` is below the highest needed height, the verifier MAY wait for the chain and retry within its timeout (not waiting is fail-safe). If it does not wait, or if time runs out, the check that needs the height is `unchecked`. For `payload_ref.height` or `promise.height` that check is `header_trust`. For the execution `height` it is `execution` (EX5 (a)), and `header_trust` is not affected. |
| OH5 Agreement | The verifier reads the header at `T` from every source and recomputes each hash. If two answering sources give different hashes, `header_trust` is `unchecked` with the reason "header disagreement with trusted chain: possible bad trusted header, hostile source, or fork". A disagreement between sources is a source problem, not a finding about the decision (20.1). If fewer than `quorum` distinct sources (OH3) answer with the agreed hash, `header_trust` is `unchecked`, never `pass`. `quorum` is configuration, at least 1. The default is 1: one RPC operator is enough for the green line, and the report names it. |
| OH6 Chain links | Headers between `T` and the lowest needed height come from the configured header source, behind a preference for the archived headers. At a needed height (`payload_ref.height`, and for `da = 1` `promise.height`) the archived header is offered first. It is accepted only if it links (HT3, HT5). If it does not link, `header_trust` is `unchecked` with reason `chain_mismatch`: the archive presents a header that the trusted chain does not have, which is a problem of the archive copy, not a finding about the decision. An online header that does not link is a fault of its source. The verifier MAY ask another configured source for that height. If no source gives a linking header, `header_trust` is `unchecked` and names the source. |
| OH7 Cross-check | Cross-check sources (HT6) read the header at `T` and at every needed height, the execution `height` included, and compare recomputed hashes with the trusted chain. A mismatch makes `header_trust` `unchecked` with the distinct reason "header disagreement with trusted chain: possible bad trusted header, hostile source, or fork", whatever the `quorum`. The verifier cannot tell whether the trusted header, the cross source or a fork is at fault, and none of them proves anything about the decision. At the execution `height`, `execution` is `unchecked` too (EX5 (d)). An unreachable source is `unavailable`, never `pass`. Cross-check sources follow OH3 among themselves and against the checkpoint sources. A host that already counted for the checkpoint is not a cross-check. |
| OH8 Report | `header_trust` reports the mode, `T`, the trusted hash, the agreeing sources by normalized host, their number and the quorum, the cross-check result per source, and the source of every needed header (`archive` or the online source's host). |

Threat note (OH). With an agreed checkpoint the trust moves from the auditor's
own file to the agreeing operators. HT4 checks no signatures, so one
dishonest source can serve a whole fabricated chain whose hashes link, from a
fabricated `T` down to a header that matches a forged archive. With
`quorum = 1`, a single operator lying in the same way as the archive's
writer is enough to print `valid`. Mitigations:
- the report names the operator;
- `quorum` above 1;
- cross-check sources: one honest source among them turns the lie into
  `unchecked` with the header-disagreement reason;
- an explicit checkpoint from an independent kind of source, such as an
  explorer's indexer;
- excluding the gate's own endpoints (OH3).

Distinct host names do not mean distinct operators. On 2026-10-07 two
host names of one Mocha provider reported one node, which the node-id rule
catches. One operator can still run several nodes, and no rule catches that.
A light client that verifies validator signatures forward from an older
trusted header removes this assumption and is planned. OH6 keeps one
lying source from turning a valid decision into `invalid`: a header that does
not link is that source's fault, unlike an archived header, which is evidence.
OH5 and OH7 turn a contradiction between sources into
`unchecked`, with a reason that stands out in the report. A contradiction
must never pass, and it is never `invalid` either: the verifier cannot tell
which side is honest, and a fork or a bad trusted header looks the same. A
hostile cross-check source can therefore hold back `valid`, and it can never
cause `invalid`.

### 20.5 Authorization record: mode and deadline

`authorized` (section 19.5, AR8) also requires, from the Authorization's
signed bytes and the verified envelope:

| Rule | Check | On failure |
|---|---|---|
| AM1 | `mode = 1` iff the reference is included, `mode = 2` iff pending | `authorization` fail |
| AM2 | `mode = 2`: `h0 < anchor_deadline <= h0 + 1000` (no gate configuration allows more) | `authorization` fail |

These are gate-signed contradictions with the agent-signed decision, so
they are `fail` under the general rule of 20.1.

Fast mode needs consent, so an Authorization with `mode = 2` makes the
`policy` check required for the decision (as `RequirePolicy` does, policy
13.1): without a `policy_allow` record it is `unchecked`
(`policy_verdict_unavailable`) and the decision is never `valid`. This is
the verifier side of "fast mode only with consent" (invariant 9).

The same holds for a verified envelope with `mandate_ref` (key 14), in
either mode: the agent signed that a mandate applies, so the `policy` check
is required, and without a `policy_allow` record the decision is `unchecked`
(`policy_verdict_unavailable`, exit 2), never `valid`. This is the verifier
side of M0 (section 8.8): a gate that authorized such a decision without a
mandate is caught even when the auditor did not set `RequirePolicy`. Vector:
`policy/verify.json` `mandate_ref_without_verdict`.

### 20.6 The `anchor` check for a pending reference

`h0 = payload_ref.height`; `D = anchor_deadline` of the verified
Authorization. Without an `authorized` record the window is undefined and
`anchor` is `unchecked` (`blocked`, naming `authorization`); the verdict is
`not_authorized` or `unchecked` by 20.1 anyway. The same holds when the
`authorization` check fails AM1 or AM2: there may be no deadline (AM1) or one
out of range (AM2), and a deadline the verifier has just rejected is not
verified data. The verdict is already `invalid` by that
fail, so nothing is hidden.

Evidence (kind 2) for a pending reference names the anchor height `H` in its
`height` field. It is checked with the rules for `payload_ref.height =
H` (section 10.4 NA1 to NA7 and CV1 to CV8 for `da = 1`, with
`promise.height == h0` in CV2; section 10.5 for `da = 2`), against a header
at `H` that passed header trust.

| Situation | `anchor` | Report |
|---|---|---|
| Evidence verifies, `h0 <= H <= D` | pass | `mode: fast`, `h0`, `anchor_height: H`, `anchor_deadline: D`, `publication: anchored` (inclusion proven, 10.6.3), assumptions (20.9) |
| Evidence verifies, `H < h0` | unchecked `source_corrupt` | a PFF cannot precede its reference height (section 11.1) |
| Evidence verifies, `H > D`, an absence proof shows a height of `[h0, D]` present unpaid (AB5) and none present with code 0 | unchecked `anchor_unpaid` | the late `H` is reported; `unpaid_height`; `publication: unknown` |
| Evidence verifies, `H > D`, absence over `[h0, D]` proven | **fail** `anchor_absent` | the late `H` is reported; `publication: failed`; attribution (20.10) |
| Evidence verifies, `H > D`, absence not proven | unchecked `absence_unproven` | names the first height not proven |
| No evidence (or evidence that does not verify), trusted header `T < D` (or `T < D + 1` when an AB5 results proof is needed) | unchecked `anchor_pending` | retry later with a newer checkpoint |
| No usable evidence, an absence proof shows a height of `[h0, D]` present unpaid (AB5) and none present with code 0 | unchecked `anchor_unpaid` | `unpaid_height` (the first such height); `publication: unknown` |
| No usable evidence, absence proven for every height of `[h0, D]` | **fail** `anchor_absent` | `publication: failed`; attribution |
| No usable evidence, a height of `[h0, D]` not proven absent | unchecked `absence_unproven` | names the first height not proven; advice `--absence-source` or another archive copy |

Evidence that does not verify is a source problem (`source_corrupt`, as
in 20.1) and the verifier goes on with the rows for "no usable evidence". An
absence proof that shows the anchor present at some `h` in the window
(AB5 with a proven code 0, AB6) is used as evidence at `H = h`; if the
verifier cannot build the full evidence from it, the result is
`evidence_unavailable`.

Order of the window results (spec revision `v1.0.3`). With no usable
evidence: a height present (code 0) decides first (as above); then a height
present unpaid (`anchor_unpaid`, naming the first one), even when other
heights are not proven; then absence at every height (`anchor_absent`);
otherwise `absence_unproven`. The `anchor_pending` row still decides before
`anchor_unpaid` while the results proof of the deadline height waits for the
header at `D + 1`: that height may hold a candidate with code 0. With late
evidence (`H > D`) a present-unpaid height
decides before the two absence rows. Threat note: an unpaid candidate is an
included PFF whose system blob is in the square and whose shards the
validators keep (10.6.3), so the reference was published inside the window;
reading it as absence would accuse an honest agent (a false `invalid`), and
counting it as anchored would rest presence on a code that v1.0 requires to
be 0 (CV8). `unchecked` is the only outcome left that is false in neither
direction.

`anchor_time` (K1) uses `T_ref` from the header at `h0`. `header_trust` must
reach `max(D, H)` (and `D + 1` for an AB5 results proof); HT3 gives every
header of the window from one backward chain.

The bound holds for every kind of header trust: a trusted header file, an
explicit or agreed checkpoint (20.4), or any other trust an implementation
adds. Each must name its height `T`. A trust that cannot name `T` cannot show
`T >= max(D, H)`, so `header_trust` is `unchecked` (HT1, HT7), never `pass`
(spec revision `v1.0.4`, clarification). Threat note: a trust kind that
skipped the bound would let `pass` rest on a header below `D`, where a later
block of the window is not yet fixed; the bound is what makes the window, and
so the anchor height chosen in it, final.

For an included reference the `anchor` check is the one of 20.1.

### 20.7 `retention_replay`

Recomputes K2 with `block_time = T_ref` (K2 input key 3). When K2 input key
9 (`fast_window`) is present, also checks `anchor_deadline - h0 <=
fast_window`; a mismatch is `replay_inconsistent` (unsigned inputs, as in
section 19.2).

### 20.8 Absence proof

For one height `h`, a proof that the anchor of `(da, namespace, commitment[,
signer])` is not included at `h`:

```
AbsenceProof(h) = { header(h) SignedHeader, dah(h), namespace_data(h, NS), [ results(h), header(h + 1) ] }
NS = PFF_NS (0x00 || 0^27 || 0x05) for da = 1; payload_ref.namespace for da = 2
```

Verification. The first failing rule decides; a failure is a source problem
(`absence_unproven`), never `fail`.

| # | Rule |
|---|---|
| AB1 | `header(h)` has height `h` and its recomputed hash equals the hash header trust reached at `h` (HT3, one chain from `T >= D` serving every height of the window). |
| AB2 | `dah(h)` passes `ValidateBasic` and its `Hash()` equals `data_hash` of `header(h)` (NA2). |
| AB3 | `namespace_data` passes `NamespaceData.Verify(dah, NS)` (NA3, nmt `v0.24.5`, completeness included): with `R` the original rows whose root range contains `NS`, exactly `len(R)` entries, each a complete NMT namespace proof against `row_roots[R[j]]`. `R` empty with no entries is a valid proof. The row selection assumes the pinned namespace layout (`da = 1`: Fibre txs in `PFF_NS`); at another app version AB3 can pass while proving nothing about the anchor, so AB4 never gives absent there. |
| AB4 (`da = 1`) | `S` = all shares of the entries, in order. At an app version other than the pinned one AB4 never gives absent, `S` empty included: with the trusted `header(h)` carrying another `version.app`, `S` empty makes the height **not proven**. `S` empty at the pinned version: **absent at `h`**. Else NA4 reassembly (`ParseTxs`; re-split equals `S`). Every unit MUST decode as CV1 reads a PFF tx (`TxRaw`, `TxBody` with exactly one message, type URL `/celestia.fibre.v1.MsgPayForFibre`, `MsgPayForFibre`, `PaymentPromise` with a 29-byte namespace and a 32-byte commitment); a unit that does not, whether or not upstream `TryParseFibreTx` classifies it as Fibre, makes the height **not proven**, at any app version. Then NA5 candidates with `promise.height <= h` (same namespace, commitment, `blob_version = 0`, expected `chain_id`). No candidate: **absent at `h`** when the trusted `header(h)` has `version.app` equal to the pinned `appconsts.Version` (10); at any other app version, not proven. Threat note (undecodable units, other app versions): at the pinned version every `PFF_NS` unit is a Fibre tx that `ClassifyTxs` accepted (section 23.1), so a unit this decoder refuses means another encoding (a chain upgrade) or a decoder stricter than upstream; reading it as "not a candidate" could hide the real anchor and give a false `anchor_absent`, the direction that is not fail-safe. For the same reason neither an empty `S` nor units without a candidate prove anything at another app version: AB3 selects rows by the pinned layout (Fibre txs as compact shares in `PFF_NS`), and an upgrade that moves Fibre txs to another namespace or changes the square layout would leave `S` empty while the real anchor is in the block, a false `anchor_absent`. The gate's NA5 may still skip such a unit: there it can only lead to `ErrAnchorNotFound` or another refusal, the safe direction. Threat note: a candidate with `promise.height < h0` (another party re-anchoring the same blob inside the window under an older promise) is a candidate like any other; if it settles, `anchor_absent` is unreachable for the window. Safe direction: the blob is then published. |
| AB5 (`da = 1`, candidates) | A height with a candidate is never absent, whatever the candidates' result codes (spec revision `v1.0.3`): an included PFF publishes the payload (10.6.3). AB5 only tells which presence it is, from the codes, each proven: `results(h)` hash to `last_results_hash` of `header(h + 1)`, which header trust ties to the chain, and the result at the candidate's index gives its code. Results proof: read `txs_results[]` of `results(h)` and only its `code` (number), `data` (base64), `gas_wanted`, `gas_used` (decimal strings, int64); the leaf of result `i` is the protobuf of `ExecTxResult` with only field 1 `code` (varint uint32), 2 `data` (bytes), 5 `gas_wanted`, 6 `gas_used` (varint int64, a negative value as 64-bit two's complement), in this order, a zero or empty field omitted (gogoproto `Marshal` of the deterministic fields of CometBFT `types.NewResults`); the root is CometBFT `merkle.HashFromByteSlices` (RFC 6962) over the leaves and MUST equal `last_results_hash` of `header(h + 1)` (the state after block `h` stores the hash of block `h`'s results, and the header of `h + 1` carries it). These are the rules RP1, RP3, RP4 of the bank-send profile, restated so that the core does not depend on a profile. With `n` results and `p` units reassembled from `PFF_NS` at `h` (AB4), `n >= p >= 1` MUST hold, else the height is not proven. When the trusted `header(h)` has `version.app` equal to the pinned `appconsts.Version` (10), the index is bound by the tail rule only: with `j` the candidate's position among the `p` units, the index is `n - p + j`; there is no uniform-code path at the pinned version. For any other app version only uniform codes apply, and only in the safe direction: every result code 0 proves the anchor **present at `h`**; any other pattern (all nonzero, or mixed) is not proven. Threat note: a block of another app version may follow other square rules, so it can never yield "absent" (fail-closed against a false `anchor_absent`); "every code 0" is safe whatever the index, because the root fixes every result. Why the tail rule binds: go-square `Construct` refuses a normal or blob tx after a Fibre tx (`validateTxOrdering`), so the Fibre txs are the last `p'` elements of `data.txs`; it appends each Fibre tx, in block order, as one unit of the `PFF_NS` compact sequence, so `p' = p` and the order is the same; the block has one result per tx (celestia-core `FinalizeBlock`, VERIFIED in the bank-send rail facts). The proof needs neither `data.txs` nor a square rebuild. Threat note: a wrong binding is not fail-safe, so the rule is limited to the pinned app version: up to `v1.0.2` it could read another tx's nonzero code and give a false `anchor_absent`; since `v1.0.3` a candidate height is never absent, and a wrong binding can only swap present (code 0) and present unpaid, which still decides between the evidence path and `anchor_unpaid` in v1.0; it is VERIFIED at the pins by code and on live Mocha blocks (section 23.1). Assumption: the block was accepted by validators running `ProcessProposal` of the pinned app (the >2/3 honest assumption of section 1), which refuses any block whose `data.txs` do not rebuild the square under these rules. A candidate with proven code 0: the anchor **is present at `h`**. Every candidate's code proven and none 0: **present unpaid at `h`** (up to `v1.0.2`: absent; never absent since `v1.0.3`). Otherwise (a candidate whose code is not proven, and none with proven code 0): not proven, and still never absent. Threat note (`v1.0.3`, unpaid candidates): a PFF can be included with a non-zero code through an ante failure in FinalizeBlock (an earlier tx in the block drains its fee payer, section 10.4 facts); its system blob is in the square and the validators keep its shards (10.6.3). Reading it as absent gave `anchor_absent` against an honest agent whose payload was published, a false `invalid`. The code only says whether the escrow paid; a present-unpaid height gives `anchor_unpaid` (20.6). |
| AB6 (`da = 2`) | `S` empty: **absent at `h`**. Else `ParseBlobs(S)` (go-square sparse shares). For each blob of share version 1, `CreateCommitment(blob, RFC 6962 root, 64)`; a blob whose commitment equals `payload_ref.commitment` and whose signer equals `payload_ref.signer` **is present at `h`**; none: **absent at `h`**. Shares that do not parse: not proven. |

Absence over the window: absent at every `h` in `[h0, D]`. Then and only
then `anchor` fails with `anchor_absent`. Only AB4 (no candidate) and AB6
(no matching blob) give absent at a height; no rule gives absent at a height
where a candidate, a matching blob or a unit that does not decode was found.

Sources. Kind 14 records of any archive copy, or online sources
(`--absence-source <bridge>` plus the configured header sources). Every
proof is verified against the trusted chain, so no source needs trust.

Cost. Per height: the DAH (1.5 KB to 185 KB), the namespace data (`da = 1`:
nothing when no row holds `PFF_NS`, about 7 KB per PFF otherwise; `da = 2`:
the namespace's shares at that height), and `D - h0 + 1` headers. At the
default window of 100 blocks this is a few MB on Mocha.

Threat note. Every byte of a proof is checked against a header tied to the
trusted chain, and NMT completeness turns "no share of `NS` in these rows"
into a proof. A hostile source can withhold (`absence_unproven`); a verifying
proof of absence for a block that holds the anchor would need a SHA-256 or
NMT break. The verdict is about the decision: its signed reference promised
an anchor by a gate-signed deadline and the chain shows none. That is
verified data, so `invalid` satisfies the general rule of 20.1.

### 20.9 Assumptions printed for a valid fast-mode decision

```
mode: fast. The gate authorized before the L1 anchor. The anchor landed at height H (window h0..deadline, in blocks).
Proven: payload bytes match the commitment; anchored on L1 no later than T_H (anchor inclusion proven); policy evaluated on T_ref (header h0).
Informational: anchor tx result: code 0, node-reported, not part of the claim   (da = 1 only)
Attested by the gate (not proven): the availability evidence was verified before the Authorization
  (Fibre: validators' custody certificate; celestia_blob: the signed anchor tx accepted by the gate's node).
```

"Anchored" is defined in section 10.6.3: inclusion of the anchor in block
`H` of the trusted chain, proven from the evidence against the header at
`H` (for `da = 1` with the binding and the certificate). The anchor tx's
result code is not part of the claim. For `da = 1` the report prints the
archived `tx_code` as the informational line above and as the JSON field
`anchor_tx_result` with the exact text `code 0, node-reported, not part of
the claim` (section 10.6.1); it is not an assumption of the verdict and is
not listed under `assumptions`. For `da = 2` the evidence carries no code
and the line is absent. (Spec revision `v1.0.2` replaces the line
`Assumptions: anchor tx result: node-attested` of E2, which was never part
of a tagged revision.)

### 20.10 Report fields and attribution

Report fields, present for every decision: `version`; `mode`
(`strict` or `fast`, from the verified Authorization); for `fast`: `h0`,
`anchor_deadline`, `anchor_height` (when evidence verified, or an absence
proof shows the anchor present at `H`), `publication` (`anchored`, `failed`
with `anchor_absent`, or `unknown`) and `assumptions`; for `da = 1`, in
either mode, whenever CV8 passed: `anchor_tx_result` (section 10.6.1,
informational). When an absence proof
(AB5, AB6) shows the anchor present at `H` but the full evidence is not
available (`evidence_unavailable`), the report gives `anchor_height: H` and
`publication: unknown`. With `anchor_unpaid` (spec revision `v1.0.3`) the
`anchor` check carries `unpaid_height` (the first height of the window that
AB5 shows present unpaid), the report gives `publication: unknown`, and
`anchor_height` only when late evidence verified (20.6); there is no
attribution, because nothing was proven absent.

With `anchor_absent` the report names the **intent signer**: the address
that signed the anchor intent tx, taken from chain data, never from a gate
or Recorder claim: the `signer` of the `MsgPayForFibre`
(`da = 1`) or of the `MsgPayForBlobs` (`da = 2`, equal to
`payload_ref.signer`, which the agent signed), read from the archived intent
whose binding to the reference passes F2 or B2. In fast mode this is usually
the gate operator's Recorder key. The report also states that the gate issued
a fast-mode Authorization with this deadline (signed data). Without an intent
record that passes F2 or B2, `da = 1` reports the signer as `unknown`; `da =
2` reports `payload_ref.signer`. The attribution is information only: the
verdict stays about the decision.

### 20.11 Decision record, the action check and the reveal

`decision` (20.1): the record under `decision/<commitment_hash hex>` MUST
be kind 17 (section 19.2). A record of another kind or format, or a kind 17
record whose envelope does not have `version = 1`, is `unchecked`
(`source_corrupt`).

`action` (20.1), first match:

| Situation | `action` | Bytes used by later checks |
|---|---|---|
| Form 1 | `ActionHash(c.action.type, key 6, key 5) == c.action.hash`: pass; else `unchecked` (`source_corrupt`) | key 5 |
| Form 2, a configured auditor key opens kind 15 `(5, c.action.hash)` (policy 9.5) | the reader recomputes `H(tag("edicta/v1/action") \|\| uint8(len(type)) \|\| type \|\| plaintext)` with `type = c.action.type`; equal to `c.action.hash`: pass; else, or an envelope failure with a listed key: `unchecked` (`source_corrupt`) | `plaintext[32:]` |
| Form 2, kind 15 `(5, c.action.hash)` absent in every checked copy | `unchecked` (`decision_unavailable`, naming the kind 15 record) | none |
| Form 2, no configured key opens kind 15, and the reveal path below gives bytes `A'` | pass | `A'` |
| Form 2, the reveal path runs and `ActionHash(c.action.type, salt, A') != c.action.hash` | `unchecked` (`source_corrupt`, naming the kind 18 record): a wrong salt and a tx that is not the action cannot be told apart | none |
| Form 2, otherwise | `unchecked` (`policy_private`) | none |

No `fail` comes from a missing or unopened action record. Checks that
consume the action bytes (`execution` F1 of 20.2, the `policy` facts
re-extraction of policy 13.2 step 3) are `unchecked` (`policy_private`) when
`action` is; for any other `action` outcome they follow 20.1 and 20.2.

Reveal path (private mode, public-rail profiles). It runs only when all of
these hold: the execution check is requested (20.2); a kind 18 record of
this `commitment_hash` exists in a checked copy and decodes; its receipt
passes section 14.2 and the out-of-band checks there (gate key on record for
`gate_id`, `commitment_hash` of this decision); the execution checker of
`action.type` belongs to a profile with `public_execution = true`. The
checker looks up the receipt's `rail_ref`, keeps only tx bytes that hash to
it (bank-send BX2), and returns `A' = ActionFromTx(tx, chain_id)` with its
configured `chain_id` (the profile's reconstruction). Then the table above
decides; on pass the execution check runs on `A'` as the authorized action.
The revealed salt is unsigned archive data, but it is self-verifying: bytes
that hash to the agent-signed `action_hash` with it are the committed
action (SHA-256 second-preimage resistance), so a hostile archive or tx
source can only make the result `unchecked`.

Salt equality. When the verifier has opened the payload and O8 passed
(section 9.4), and it also holds an archive copy of the
salt that passed its own hash check (kind 17 key 6, kind 15 `(5, ...)`
opened, or kind 18), it compares the two salts bytewise. Any difference is
`action` `unchecked` (`source_corrupt`, naming the archive record): a source
problem, never an agent violation. Given both hash checks pass, a
difference needs a SHA-256 collision; the rule is defence in depth.

Order. O8 runs first and alone decides `payload`: an O8 failure is a
`payload` fail (section 9.4) whatever any archive copy holds, and the salt
comparison runs only after O8 passed, so a hostile archive copy can never
turn the agent's own contradiction into a source problem, nor a source
problem into an agent violation. Vector: `v1/verify.json`
`payload_o8_fails_before_salt_compare`.

Report: `action_source` (`decision_record`, `private_blob`, `reveal`, or
absent when `action` did not pass).

Threat notes:
- A form 2 record holds nothing of the action; the salt and the bytes are
  only inside kind 15 `(5, ...)`, encrypted to the mandate's auditors. A
  record of the other form than the mandate's is a privacy loss for that
  record, never a verification change: the verifier reads whichever form it
  finds. The gate never writes a record for a decision whose `mandate_ref`
  names another mandate than the one in force (section 8.8, M0 and M2), so
  that case cannot arise from an honest gate.
- On a public rail in private mode the on-chain tx gives the bytes but not
  the salt; without a reveal it cannot be tied to `action_hash`, so the
  keyless verifier stays `unchecked` (`policy_private`). Denied or never
  executed decisions are never revealed, so their actions stay hidden (no
  limit probing, policy 9.6).

## 21. Sentinel errors

Names are identical in Go (`commitment.ErrX`) and in the Python checker
(`Reject.sentinel == "ErrX"`). Every sentinel below except `ErrNonCanonical`
and `ErrInvalidParams` has at least one must-reject vector.

| Stage | Sentinel | Rules |
|---|---|---|
| D | `ErrTooLarge` | D0, D9, D14 |
| D | `ErrMalformed` | D1 |
| D | `ErrTrailingData` | D2 |
| D | `ErrFloat` | D3 |
| D | `ErrSimpleValue` | D4 |
| D | `ErrTag` | D5 |
| D | `ErrIndefiniteLength` | D6 |
| D | `ErrNonMinimalInt` | D7 |
| D | `ErrNestingTooDeep` | D8 |
| D | `ErrUnsortedMap` | D10 |
| D | `ErrDuplicateKey` | D11 |
| D | `ErrKeyType` | D12 |
| D | `ErrInvalidString` | D13, D19 |
| D | `ErrUnknownKey` | D15 |
| D | `ErrWrongType` | D16 |
| D | `ErrMissingField` | D17 |
| D | `ErrFieldSize` | D18 |
| D | `ErrNonCanonical` | D21 (fuzz only) |
| S | `ErrUnsupportedVersion` | S1; Q1 (Authorization), R1 (receipt), the version of a nested envelope (section 19.1 step 8, kind 17) |
| S | `ErrIntRange` | S2 |
| S | `ErrInvalidEnum` | S3, V1-3 (`anchor`), Authorization `mode` |
| S | `ErrZeroValue` | S6 |
| S | `ErrPayloadTooLarge` | S7 |
| S | `ErrInvalidNamespace` | S8 |
| S | `ErrTimeOrder` | S12 |
| S | `ErrTTLTooLong` | S14 |
| S | `ErrKeyRole` | R6 (receipt), RQ4 (`Record`): one key in two of the roles agent, gate, executor |
| S | `ErrInvalidParams` | `Params.Validate` (Go unit tests only) |
| G | `ErrInvalidPublicKey` | G0 |
| G | `ErrSignatureInvalid` | G1, G2 |
| T | `ErrNotYetValid` | T1 |
| T | `ErrExpired` | T2 |
| C | `ErrScopeMismatch` | C1 |
| C | `ErrActionTypeNotAllowed` | C2 |
| A | `ErrActionSize` | A0 |
| A | `ErrMissingField`, `ErrFieldSize` | A0s, X2s: the action salt absent, or not exactly 32 bytes (the stage D names, reused) |
| A | `ErrActionMismatch` | A1, X3: the action bytes or the salt do not give `action.hash` |
| P | `ErrPayloadSizeMismatch` | P1 |
| P | `ErrPayloadHashMismatch` | P2 |

Names never to be reused for another meaning (they belonged to the
superseded drafts): `ErrUnsupportedActionKind`, `ErrUnsupportedRail`,
`ErrUnsupportedOrderType`, `ErrLimitPrice`, `ErrAccountMismatch`,
`ErrChainIDRule`, `ErrDeadlineRange`, `ErrPriceBound`,
`ErrNotionalExceeded`, `ErrVersionNotAccepted`. Order and account rules have
profile sentinels (`ibkrorder.ErrMalformed`, `ibkrorder.ErrInvalid`,
`ibkr.ErrAccountMismatch`, `ibkr.ErrRiskLimit`).

The Authorization and receipt decoders and verifiers (sections 14 and 15)
reuse the stage D, S, G, C, A and T sentinels above; they define no new ones.

Gate sentinels (stateful, section 8.7). A second gate implementation MUST use
the same names so that operators, tests and the verifier agree on the reason.
Package is where the Go sentinel lives.

| Stage | Sentinel | Package | Rules | Vectors |
|---|---|---|---|---|
| E | `ErrBeforeRegistryEpoch` | `gate` | E1 | `v1/anchor.json` `epoch` |
| L | `ErrAgentKeyIsGateKey` | `gate` | L0 | none (gate configuration) |
| L | `ErrAgentNotAllowed` | `gate` | L1 | none (stateful) |
| L | `ErrAgentKeyMismatch` | `gate` | L2 | none (stateful) |
| N0, N | `ErrNonceUsed` | `gate` | N1 | none (stateful) |
| K | `ErrAnchorNotFound` | `gate` | K0 (for `da = 1`: no PFF with result code 0 among the txs of the PayForFibre namespace of block `height`, proven complete by NA1 to NA4, section 10.4) | none (stateful) |
| K1 | `ErrIssuedBeforeAnchor` | `commitment` | K1 | `v1/anchor.json` `k1` |
| K2 | `ErrRetentionUnavailable` | `gate` | K2: `fibre_retention_s` at `height` not established by RS3 or RS6 (`da = 1`, section 12.2) | `v1/anchor.json` `k2_fibre_at_height_unreadable` |
| P | `ErrDACommitmentMismatch` | `gate` | P3 | `da/blob_commit.json` `reject`, `da/fibre_commit.json` `reject` (Go only) |
| P | `ErrArchiveRecomputeUnsupported` | `gate` | P3, K2 path selection: the archive path is needed and the gate has no DA committer for this `da` (only a library gate without the `da = 1` committer) | `v1/anchor.json` `k2_included` (`da = 1`, K2 false, gate without the committer) |
| P | `ErrAnchorTooOld` | `gate` | K2 failed and the archive did not return the blob; also matches `ErrPayloadUnavailable` | none (stateful) |
| P | `ErrPayloadUnavailable` | `gate` | No path returned the blob | none (stateful) |
| Record | `ErrExecutorNotAllowed` | `gate` | Section 14.3 RQ3: the request's executor key is not in the executor allowlist | `v1/record_request.json` |
| Record | `ErrNotAuthorized` | `gate` | Section 14.3: no Authorization is stored for this commitment (never authorized, another commitment holds the nonce, or the entry was pruned) | none (stateful) |
| Record | `ErrReceiptExists` | `gate` | Section 14.3: a receipt is already stored; returned with the stored receipt | none (stateful) |

SDK sentinels (payload blob and opening, sections 9.1 to 9.5). The
prefix is the Go package; vectors write them as `pkg.ErrName`.

| Sentinel | Rules | Vectors |
|---|---|---|
| `blob.ErrTooLarge` | B0 | none (size only) |
| `blob.ErrMalformed` | B1, B2 (not a uint), B4, B6, B7 | `v1/payload_blob.json` decode rejects |
| `blob.ErrVersion` | B2 | `pb_blob_version_0` |
| `blob.ErrRecipients` | B3; producer with 0 or more than 16 recipients | `pb_recipients_0`, `pb_recipients_17` |
| `blob.ErrDuplicateKID` | B5; producer with a repeated kid | `pb_duplicate_kid` |
| `blob.ErrNoRecipient` | O4 | `pb_kid_absent` |
| `blob.ErrUnwrap` | O5 | `v1/payload_blob.json` open rejects |
| `blob.ErrDecrypt` | O6 | `v1/payload_blob.json` open rejects |
| `payload.ErrMalformed` | PV3, O8, W1 | `pb_payload_*`, `v1/payload.json` `payload_v1_salt_*` |
| `payload.ErrVersion` | PV2, O8 | `pb_payload_version_0`, `v1/payload.json` `payload_version_0` |
| `payload.ErrTooLarge` | Section 9.1 size (producer) | none (size only) |
| `sdk.ErrPlaintextHashMismatch` | O7 | `pb_plaintext_hash_*`, `pb_key_commitment_two_deks` |
| `sdk.ErrPayloadMismatch` | O8 | `pb_payload_action_differs`, `pb_payload_action_type_differs`, `v1/payload.json` `payload_v1_wrong_salt`, `payload_v1_unsalted_commitment` |
| `sdk.ErrDACommitmentMismatch` | W4 | none (needs a Recorder fake; SDK e2e test) |
| `sdk.ErrDACheckUnavailable` | W4 | none (configuration) |
| `sdk.ErrInclusionUnverified` | W5 | none (needs a chain fake; SDK tests) |
| `sdk.ErrBlockTimeMismatch` | W5 step 4 | none (SDK tests) |
| `sdk.ErrUnexpectedRef` | W5 step 1 | none (SDK tests) |
| `sdk.ErrPublishTimeout` | W6 | none (SDK tests) |

Pending references, fast mode, mandate reference (package `gate` unless
noted; statuses in section 18.3):

| Sentinel | Stage | Meaning | Vectors |
|---|---|---|---|
| `ErrAnchorPending` | 1 (C5a) | pending reference at a gate whose `FastMode` is off or that has no mandate | `api/errors.json` examples |
| `ErrNamespaceNotAllowed` | 1 (C5b) | pending reference whose namespace is not in `PendingNamespaces` | none (gate configuration) |
| `ErrMandateRefMissing` | 4m (M1) | mandate configured, commitment without key 14 | `v1/archive.json` markers |
| `ErrMandateMismatch` | 4m (M0, M2) | key 14 present at a gate without a mandate (M0), or differs from the hash of the mandate in force (M2); writes no decision record and no marker | `v1/stage4m.json`; `api/errors.json` `authorize_mandate_ref_without_mandate`; `v1/archive.json` reject `rejection_mandate_mismatch_not_a_marker` |
| `ErrAnchorIntentUnavailable` | 6 (F1, B1) | no intent record for `(da, commitment, h0)` yet, or the archive failed (operational) | none (stateful) |
| `ErrAnchorIntentInvalid` | 6 (F2, B2) | the intent does not decode, names other values than the reference, or is not a PFF/PFB for exactly this blob | none (stateful) |
| `ErrCertInvalid` | 6 (F4) | the Fibre certificate fails CV4 to CV7 | `da/fibre_cert.json` |
| `ErrH0TooOld` | 6 (F5, B4) | `head - h0 > MaxH0AgeBlocks` | `v1/anchor.json` `h0_too_old` |
| `ErrAnchorWindowClosed` | 6 (F5, F6, B4, B5) | `window = 0`; `anchor_deadline < head + MinFastSlackBlocks`, or the Fibre promise expires within `MinPromiseSlackSeconds`, and the tx is not already included with code 0 in `[h0, anchor_deadline]`; or the intent is already included outside the window or with a nonzero code | `v1/anchor.json` `window_*` |
| `ErrAnchorIntentRejected` | 6 (F6, B5) | the gate's node refused the (re)broadcast (operational) | none (stateful) |
| `ErrInvalidConfig` | gate start | a configuration fails `ValidateBasic` (section 8.9), with its cause: among others `fast_mode_without_mandate`, `age_plus_slack`, `fast_delay_below_slack` (also refuses a runtime mandate adoption), the range checks, a `RevealOnExecution` type outside the allowlist (`reveal_on_execution`) or without a compiled `public_execution = true` profile (`reveal_not_public_execution`) | `v1/gate.json` |
| `policy.ErrFastModeNotAllowed` | 4p (P15) | policy section 8.2 | `policy/verify.json` |
| `ErrFastModeRefused` (profile packages) | executor | an executor whose profile refuses fast mode got `mode = 2` | profile documents |

Verifier fail rules are not gate sentinels: `anchor_absent` (`anchor`),
`mandate_ref_mismatch` and `fast_mode_delay` (`policy`), AM1 and AM2
(`authorization`), section 20.1.

Gate sentinel `ErrDANotAllowed` (package `gate`, stage C, rule C3; no
vector, gate configuration).

Gate sentinel `ErrPayloadAboveCap` (package `gate`, stage C, rule C4: `da = 1` `payload_size` above the gate's Fibre payload
limit, section 10.4; no vector, gate configuration). It is not
`ErrPayloadTooLarge`: that name is S7 and both are reported as bare codes.

Publish-request sentinels (section 17; package `edictaapi`). The stage D and
S sentinels of the request wrapper are the core ones above.

| Sentinel | Rules | Vectors |
|---|---|---|
| `edictaapi.ErrPublishSignature` | PR3: unknown `agent_id`, key check, `S < L` or signature equation (including a message signed for another `gate_id`) | `api/publish_request.json` stage G |
| `ErrAgentKeyIsGateKey` (package `gate`) | PR4 | `pr_gate_key` |
| `edictaapi.ErrPublishStale` | PR5 | `pr_stale_past`, `pr_stale_future` |
| `edictaapi.ErrQuotaExceeded` | PR7 | none (stateful) |
| `edictaapi.ErrPublishDisabled` | the Recorder is disabled on this server | none (configuration) |

Operational errors that a second implementation may name differently (chain
or registry unavailable, clock regression, signer failure or timeout) are not
part of this spec, except where they cross the HTTP API (section 18). Those
have stable names, because the API reports them as codes:

| Sentinel | Meaning | Section 18 status |
|---|---|---|
| `ErrChainUnavailable` (package `gate`) | Chain data (headers, anchors, parameters) could not be read | 503 |
| `ErrAllowlistUnavailable` (package `gate`) | The agent allowlist could not be read | 503 |
| `ErrRegistryUnavailable` (package `gate`) | The nonce registry could not be read or written | 503 |
| `ErrClockRegression` (package `gate`) | The gate clock is before the registry watermark | 503 |
| `ErrClosed` (package `gate`) | The gate is shutting down | 503 |
| `ErrArchiveUnavailable` (package `gate`) | Operational. The decision record could not be written durably before signing (section 8.7, stage 4a, AR3), or the archive payload record on the archive path is unreadable or corrupt (stage 9, section 19.6); nothing signed, nonce not consumed, no rejection marker | 503 |
| `recorder.ErrTooLarge` | The blob is above the Recorder's own limit | 413 |
| `recorder.ErrOutcomeUnknown` | A submission may or may not have reached the chain; a retry of the same blob does not submit again while the outcome is unresolved (PR8), and is charged quota (PR7) | 503 |
| `recorder.ErrNotVisible` | The anchor was not visible on the read node in time | 503 |
| `recorder.ErrSignerMismatch` | The node shows the anchored blob under another signer or share version | 502 |
| `recorder.ErrNodeUnavailable` | The Recorder's read node failed for a reason other than "not found". Before a submit (the head): nothing was submitted and the blob is not held. After a submit (the search for the blob, or reading back its header or blob): the submission is kept, and a retry of the same blob resumes the search and does not submit again while the outcome is unresolved (PR8) | 503 |
| `recorder.ErrTooManyPending` | Too many blobs have an unresolved submission outcome; new publishes wait until they resolve | 503 |
| `recorder.ErrArchiveUnavailable` | The archive write failed. Before a submit (the blob): nothing was submitted. After a submit (the evidence): the submission is kept, and a retry of the same blob resumes and pays nothing again (PR8) | 503 |
| `recorder.ErrEscrowInsufficient` | `da = 1`: the escrow account cannot pay for this upload; nothing was submitted. The Recorder never deposits by itself; the same request may succeed after the operator tops up | 503 |
| `recorder.ErrSubmitMismatch` | `da = 1`: the node reported a BlobID other than `0x00 \|\| commitment` the Recorder computed; nothing is returned to the agent, and a fee may have been spent | 502 |
| `edictaapi.ErrTokenInvalid` | Missing or wrong bearer token on an endpoint that requires one | 401 |
| `edictaapi.ErrRouteNotFound` | No such path | 404 |
| `edictaapi.ErrMethodNotAllowed` | Wrong HTTP method for the path | 405 |
| `edictaapi.ErrMediaType` | Request `Content-Type` is not `application/cbor` | 415 |
| `edictaapi.ErrDeadline` | The server's own per-request handler deadline passed, and the operation's error matches no other sentinel (section 18.3) | 504 |
| `edictaapi.ErrInternal` | Anything unmapped; message redacted | 500 |

The gate does not execute, so there is no execution error among its
sentinels.

## 22. Test vectors

Location `spec/vectors/`. Every live file carries `"format"` and, unless it
is a pure input file, `"revision"`: the revision of its last content change.
Files of `spec/vectors/historical/v0/` belong to the superseded drafts; no
checker reads them and they never change.

Generators and checkers (Python 3.11+, stdlib plus `cryptography`;
hand-written strict CBOR in `cbor_strict.py`), all in `spec/vectors/check/`:

| Script | Does |
|---|---|
| `gen_vectors.py` | Writes the core set: `v1/valid.json`, `reject.json`, `authorization.json`, `receipt.json`, `record_request.json`, `payload.json`, `limits.json`, `anchor.json`, `action.json`, `gate.json`, and `keys.json`; `v1/payload_blob.json` through `gen_payload_blob.py`. Rules module `edicta.py` (with `edicta_payload.py`, `edicta_publish.py`). |
| `check_vectors.py [--core-only]` | Checks the core set with its own implementation, written apart from the generator (literal tag bytes, own preimages), then runs every other checker below, then prints one line with the revision of every live vector file. Exit 0 when everything passes. |
| `gen_archive.py` / `check_archive.py` | `archive/records.json`, `archive/state.json` (rules module `archive.py`). |
| `gen_archive_v1.py` / `check_archive_v1.py` | `v1/archive.json`, `v1/verify.json`, `v1/stage4m.json`. |
| `gen_absence.py` / `check_absence.py` | `da/absence.json`. |
| `gen_v1_0_3.py` / `check_v1_0_3.py` | The files of spec revision `v1.0.3`: `da/absence_v1.0.3.json`, `v1/verify_v1.0.3.json`, `verifier/reasons_v1.0.3.json`. The checker also validates `SUPERSEDED.json` and runs `da/absence.json`, `v1/verify.json` and the merged reason enum under the `v1.0.3` rules, skipping a frozen case only through `SUPERSEDED.json` and asserting that every listed case no longer holds under those rules. |
| `gen_api_vectors.py` / `check_api_vectors.py` | `api/publish_request.json`. |
| `gen_api_errors.py` / `check_api_errors.py` | `api/errors.json`; the checker also parses sections 21 and 18.3 of this document. |
| `gen_verifier_reasons.py` / `check_verifier_reasons.py` | `verifier/reasons.json`. |
| `gen_execution_outcomes.py` / `check_execution_outcomes.py` | `verifier/execution_outcomes.json`. |
| `check_fibre_commit.py`, `check_fibre_cert.py`, `check_fibre_anchor.py` | The `da/` files produced by the Go tools of `spec/vectors/tools/`. |
| `gen_policy.py` / `check_policy.py`, `gen_principal.py` / `check_principal.py` | `policy/*.json`, `principal/*.json` (`spec/policy-v1.md` section 15). |
| `gen_profile_*.py` / `check_profile_*.py`, `gen_bank_send_action_from_tx.py` / `check_bank_send_action_from_tx.py` | `profiles/` (profile documents, section "Vectors"). |

No live checker imports a module of the superseded drafts, and
`check_vectors.py` refuses any live vector file or checker module that holds
one of their protocol tags (`edicta/v0/` followed by a tag name of section
2). Test derivation labels that only share the prefix (the validator key
seeds of `da/fibre_cert.json`, the `v1/payload_blob.json` derivation below)
are not tags and stay as they are. Likewise the files produced by the Go
tools and `verifier/execution_outcomes.json` keep the file label `format:
edicta-vectors/v0` (`da/fibre_commit.json`, `da/fibre_cert.json`,
`da/fibre_anchor.json`, `da/blob_commit.json`): a label of the vector file
layout, which did not change, not a dependency on the `v0` drafts.

```
python3 -m venv .venv && .venv/bin/pip install -r spec/vectors/check/requirements.txt
.venv/bin/python spec/vectors/check/check_vectors.py     # exit 0 when every set passes
```

`ed25519_point.py` is the checker's own RFC 8032 point decoding and
small-order test for G0, because OpenSSL does not enforce G0, and its own
cofactorless equation for G1, which the checker cross-checks against OpenSSL
on every signature.

JSON conventions: every uint (including enums, `now` and params) is a decimal
string; byte strings are lowercase hex; text strings are JSON strings
(ASCII-escaped); optional fields are absent when unset; input field names are
the names in sections 4, 14 and 15. Actions longer than 1024 bytes are given
as `action_pattern` (defined in the file's `patterns`: `affine-7-3`, byte `i`
is `(7*i + 3) mod 256`), `action_size` and `action_sha256_hex` instead of
`action_hex`. Action salts are `SHA-256("action-salt/" || label)`, the label
being the case id unless the file says otherwise; every case that presents
an action carries `action_salt_hex`.

| File | Contents |
|---|---|
| `keys.json` | `agent1` = RFC 8032 section 7.1 TEST 1, `agent2` = TEST 2, `gate1` = TEST 3 (the gate's key: it signs Authorizations and receipts): seed, public key, RFC known-answer signature. |
| `v1/valid.json` | Top-level `params`, `gate` (`gate_id`, `action_types`) and `patterns`. Each case: `input`, `commitment_cbor_hex`, `commitment_hash_hex`, `signer`, `signed_message_hex`, `signature_hex`, `envelope_hex`, `now`, optional `params`, `action_type`, the action bytes, `action_salt_hex`, `action_preimage_prefix_hex` (`tag \|\| uint8(len(type)) \|\| type`; the salt and the bytes follow), `action_hash_hex`, and `placeholders` (values that are not real chain data). 22 cases, among them `minimal_lmt` (section 4 worked example), the integer-width and limit cases, the included and pending references of both `da`, the `*_mandate_ref` cases (fast mode needs a mandate) and `v1_maximal`. |
| `v1/reject.json` | Same top-level fields. Each case: `id`, `stage`, `rule`, `description`, `envelope_hex`, `now`, optional `params`, `gate`, and exactly one `expect_error`. Stage S, G, T, C and A cases also carry `input`, `commitment_cbor_hex` and `commitment_hash_hex`; stage A cases carry the presented `action_type`, action bytes and salt and `committed_preimage_hex`. Every stage D to A rule, the reserved and unassigned keys, `version_0` and `version_2` (`ErrUnsupportedVersion`), `anchor` values, `mandate_ref` sizes, signer presence by `da` and form, and signatures under the tags of the superseded drafts (`ErrSignatureInvalid`). |
| `v1/action.json` | Section 5.1. `action_v1_minimal`, `action_v1_max` (preimage and hash); rejects with `committed_action_hash_hex`: wrong salt, unsalted preimage, salt after the bytes (`ErrActionMismatch`), salt missing (`ErrMissingField`), 31 and 33 bytes (`ErrFieldSize`). |
| `v1/payload.json` | Section 9. `ciphertext_hash_small_blob` (dummy bytes that stage P only hashes), `plaintext_hash_basic`, `payload_v1_minimal` (a sealed payload, O1 to O8); stage P rejects; `open_reject` on the AEAD plaintext: salt missing, 31 bytes, tstr, `payload_version_0` (`payload.ErrMalformed`, `payload.ErrVersion`), wrong salt and unsalted commitment (`sdk.ErrPayloadMismatch`). |
| `v1/payload_blob.json` | Section 9. `suite`, `derivation` (below), `params`, `gate`, `hpke_kat` (RFC 9180 Appendix A.2.1), `recipient_keys`. `cases`: `payload` (section 9.3 names; `context.data`, `action.data` and `action.action_salt` hex), `plaintext_cbor_hex`, `salt_hex`, `plaintext_hash_hex`, `dek_hex`, `aead_nonce_hex`, recipients, `blob_hex`, `ciphertext_hash_hex`, the commitment the payload belongs to. `reject`: `decode`, `open` and `plaintext` rejects (B0 to B7, O4 to O8). |
| `v1/authorization.json` | Top-level `max_authorization_ttl_s`, `gate`, `patterns`. `cases`: `commitment_ref`, `authorized_at`, `signer`, `input` (section 15 names, `mode` and `anchor_deadline` included), `authorization_cbor_hex`, `authorization_hash_hex`, `signed_message_hex`, `signature_hex`, `signed_authorization_hex`, and `check` (what the executor knows: `gate_pubkey_hex`, `gate_id`, `action_type`, the action bytes, `action_salt_hex`, `now`, `skew_s`). Strict and fast cases (`auth_v1_fast_fibre`, `auth_v1_fast_blob_timeout_lowered`), the maximal Authorization. `reject`: stage D, S, G and X cases (Q1 to Q6, X1 to X3, X2s), among them mode and deadline presence, `authorization_version_0`, and the executor salt rules (`exec_v1_salt_missing`, `exec_v1_salt_31`, `exec_v1_wrong_salt`). |
| `v1/record_request.json` | Section 14.3. Top-level `gate` (`gate_id`, `gate_pubkey_hex`, `executor_keys`) and `keys` (`executor1` = RFC 8032 section 7.1 TEST SHA(abc); `executor2` from a fixed label). `cases` and `reject` (RQ1 to RQ4). |
| `v1/receipt.json` | Section 14. `cases`: `input`, `commitment_ref`, `signer`, `receipt_cbor_hex`, `receipt_hash_hex`, `signed_message_hex`, `signature_hex`, `signed_receipt_hex`. `reject`: stage D, S and G cases, `receipt_version_0` among them. |
| `v1/limits.json` | Maximal and over-limit envelopes and Authorizations under the caps. |
| `v1/anchor.json` | Section 12.2 and 13.3: `k1` and `k2` on `T_ref` for both reference forms and both `da`; `k2_included` (the retention cases: margins, saturation, governance minimum, retention lowered and raised, unreadable at height); `epoch`; `window` (inputs and `expect`: `anchor_deadline`, `ErrH0TooOld`, `ErrAnchorWindowClosed` or `ErrChainUnavailable`). |
| `v1/gate.json` | Section 8.9 configuration: `defaults`, `allowlist`, `profile_registry` (action type to `public_execution`, the compiled registry restated) and cases with `config`, `mandate`, optional `allowlist` (overrides the top-level one) and `mandate_fast_mode_max_delay`, and `expect` (`ok`, or `ErrInvalidConfig` with its cause). |
| `v1/archive.json` | Section 19: kinds 13, 14 (synthetic proof parts; the record layer does not verify them), 15 (the bytes of `policy/private.json`), 17 (both forms), 18, Authorization records with K2 input key 9, rejection markers. `reject` (per-kind presence, sizes, `kind_3_unassigned`, `kind_6_reserved`, `kind_16_reserved`, `kind_19_undefined`, `format_0_decision`), `reject_large`, `reads` (key mismatches). |
| `v1/verify.json` | Section 20.5 to 20.11 on synthetic records: `cases` (fast-mode anchor, absence, AM1 and AM2, replay with `fast_window`) and `action_cases` (both forms, private blob, reveal, salt comparison, `payload_o8_fails_before_salt_compare`, `decision_record_corrupt`). Evidence and absence are given as verification results per height; their bytes are in `da/absence.json` and the `da/` evidence vectors. |
| `v1/stage4m.json` | Section 8.8: per gate mandate (none, public, private; the one the agent named or another) and per commitment (with or without `mandate_ref`), the stage 4m rule, the result, and the archive writes after it in order (kind 15 action, kind 17 form, kind 5 marker). M0 and M2 write nothing. |
| `archive/records.json`, `archive/state.json` | Section 19: kinds 1, 2, 4, 5, 17 in format 1, rejects (among them `rec_format_0`, `rec_format_2`, `rec_kind_3`, `rec_kind_6`, `rec_kind_19`, and the evidence record with the unassigned key 18), the write scenarios of 19.4 and the record state of 19.5. Opaque Celestia fields are stand-ins (`placeholder`), except the live `da = 1` records. |
| `api/publish_request.json` | Section 17: `tag`, `server`, `cases`, `reject` (stages D, S, G, PR), `response`. |
| `api/errors.json` | Section 18: `statuses`, `errors` in match order (`code`, `status`, `retryable`, `stored`, `endpoints`, `rules`), `not_api_visible` (every other name of section 21 with its reason), `examples` with refs into the core vectors. |
| `da/blob_commit.json` | `da = 2` share commitments computed by upstream code only (go-square `v4.0.1`), by `spec/vectors/tools/dacommit-gen`. Checked by Go only (Python has no NMT); the Python checker checks the blob descriptions. Inputs to the DA layer, no Edicta bytes, so its format stays `edicta-vectors/v0`. |
| `da/fibre_commit.json`, `da/fibre_cert.json`, `da/fibre_anchor.json` | Section 10.4 and 10.6.1: Fibre commitment, certificate (CV1 to CV8) and anchor lookup (NA2 to NA7, the anchor proof of section 19.2), live Mocha data, produced by the Go tools of `spec/vectors/tools/`. Celestia data only; their revisions name the draft that last changed them. |
| `da/absence.json` | Section 20.8: live Mocha cases (`live`, `mocha-5`, kind 14 records built from read-only captures) and synthetic chains; `live_tail_rule` (section 23.1). Capture tool `spec/vectors/tools/absence-gen` (not run by `check_vectors.py`). |
| `verifier/reasons.json` | Section 20.1.1: the 43 reasons of `v1.0`, one case per reason, the `fail` boundary cases. |
| `verifier/reasons_v1.0.3.json` | Spec revision `v1.0.3`: `extends` names `verifier/reasons.json`; the added reason `anchor_unpaid` and its case. The enum of the revision is the union (44). |
| `da/absence_v1.0.3.json` | Spec revision `v1.0.3`, section 20.8: the superseded cases `fibre_candidate_nonzero_code` and `window_three_heights_proven` on byte-identical inputs with the per-height result `present_unpaid` and the window result `present_unpaid` (`unpaid_height`); `window_unpaid_with_unproven_height` and `window_paid_after_unpaid` (order of the window results), on records of `da/absence.json`. |
| `v1/verify_v1.0.3.json` | Spec revision `v1.0.3`, section 20.6, in the layout of `v1/verify.json` `cases`, on the records named by `records_from`: an in-window unpaid candidate without evidence (`anchor_unpaid`), with a height not proven, after which a paid one decides (`evidence_unavailable`), with late evidence (`anchor_unpaid`, never `anchor_absent`), and with the deadline's results proof still waiting (`anchor_pending`). |
| `SUPERSEDED.json` | Frozen cases whose expectation a `security` revision changed (section 0): `file`, `case`, `revision` (the changelog entry), `type`, `replaced_by`. Checkers and tests of the current revision skip a frozen case only through this list. |
| `verifier/execution_outcomes.json`, `verifier/live/` | Section 20.2: one case per cause of `unchecked` and `fail`, the passing cases, and the live result proof of the bank-send checker. |
| `policy/*.json`, `principal/*.json` | `spec/policy-v1.md` section 15. |
| `profiles/dca-agent/`, `profiles/bank-send/` | Profile documents, section "Vectors". |

`v1/payload_blob.json` derivation (test only): recipient keys are
`DeriveKeyPair(SHA-256("edicta/v0 test recipient|" + name))` (RFC 9180
section 7.1.3); the HPKE ephemeral key of recipient `i` (0-based) in case `id`
is `DeriveKeyPair(SHA-256("edicta/v0 test ephemeral|" + id + "|" + i)).sk`;
`DEK = SHA-256("edicta/v0 test dek|" + id)`, `aead_nonce = SHA-256("edicta/v0
test aead nonce|" + id)[0:12]`, `salt = SHA-256("edicta/v0 test payload salt|"
+ id)`. These labels are test derivation strings, not protocol tags; they
keep their old spelling so that the derived keys stay the same. The Python
generator passes `skE` into Encap explicitly. Go's `crypto/hpke` cannot take
an ephemeral key, so Go checks the open direction, the byte-exact blob
encoding from the listed components, and the RFC 9180 `hpke_kat`; Python
checks the seal direction as well. The Python HPKE (`hpke_base.py`) is
hand-written over `cryptography` primitives and runs the full RFC 9180 A.2.1
set (`hpke_rfc9180_a2_1.json`) before any `payload_blob.json` check.

How an implementation uses them:
- valid: `encode(input) == commitment_cbor_hex`; hash, signed message,
  signature and envelope match; `DecodeSigned(envelope)` round-trips to
  `input`; `ActionHash(action_type, action_salt, action bytes) ==
  action_hash_hex` and equals `input.action.hash`; `VerifyForGate(envelope,
  now, gate, params)` succeeds; `CheckAction(c, action bytes, action_salt)`
  succeeds.
- reject, stages D to C: `VerifyForGate` fails with `expect_error`.
- reject, stage A: `VerifyForGate` succeeds, `CheckAction(c, action bytes,
  action_salt)` fails with `expect_error`.
- payload rejects: `CheckPayload` with the claimed size and hash fails with
  `expect_error`.
- Authorizations: `EncodeAuthorization(input) == authorization_cbor_hex`;
  hash, signed message, signature and signed Authorization match;
  `VerifyAuthorization(signed_authorization, check)` succeeds and round-trips
  to `input`; `input` agrees with the referenced commitment (its hash, its
  `action.hash`, its `gate_id`, the mode of its reference, and `expires =
  min(valid_until, authorized_at + max_authorization_ttl_s)`). Rejects:
  `VerifyAuthorization(bytes, check)` fails with `expect_error`.
- record requests: `RecordMessage(commitment_hash, gate.gate_id, rail_ref) ==
  record_message_hex`; the signature verifies; the stateless `Record` checks
  (RQ1 to RQ4) accept every case and reject every `reject` case with
  `expect_error`.
- receipts: `EncodeReceipt(input) == receipt_cbor_hex`; hash, signed message,
  signature and signed receipt match; `VerifyReceipt(signed_receipt)`
  succeeds and round-trips to `input`. Rejects: `VerifyReceipt` fails with
  `expect_error`.
- anchor: `CheckAnchorTime` (K1), `RetentionMargin` and `WithinRetention`
  (K2) and the epoch rule give the stated verdicts; the gate's path selection
  gives `route` or `expect_error`; the K-fast window gives `anchor_deadline`
  or the sentinel.
- `v1/payload_blob.json`: `payload.Encode(payload) == plaintext_cbor_hex`;
  blob encoding of the listed components equals `blob_hex`; every recipient
  key opens the blob (with and without its kid) to `salt || plaintext`;
  `plaintext_hash`, `ciphertext_hash`, `payload_size` match;
  `OpenPayload(envelope, blob, key)` returns `payload`. Rejects fail with
  `expect_error`.
- archive: `encode(input) == record bytes`; strict decoding returns `input`;
  the store files the record under `key`; every reject fails decoding with
  `archive.ErrCorrupt` (and SHOULD wrap `cause`); a store replaying each
  scenario gives each `expect`.
- `da/blob_commit.json`: the gate's `DACommitter` for `da = 2` accepts every
  case and rejects every `reject` case with `ErrDACommitmentMismatch`
  (`cd spec/vectors/tools/dacommit-gen && go run . -check`; it needs network
  access the first time to download modules, and is never run by `go test`
  of the main module).
- `da/fibre_commit.json`, `da/fibre_anchor.json`: as their files state
  (`fibrecommit-gen`, `fibreanchor-gen`, `-check`).
- current revision (`v1.0.3`): an implementation runs every case of every
  frozen file except those `SUPERSEDED.json` lists, and runs the listed
  `replaced_by` cases instead; it never skips a case on its own. `v1.0.3`
  absence windows give `present_unpaid` where AB5 proves every candidate's
  code non-zero, and the verifier maps that to `anchor` `unchecked`
  `anchor_unpaid` with `unpaid_height`.

Stage D vectors whose defect is inside the commitment are signed over
`tag || <malformed commitment bytes>`, so the encoding defect is the only
defect. Stage S, T, C and A vectors are correctly signed.

## 23. `UNVERIFIED` items

For a Celestia protocol engineer to confirm. Each item is marked in place;
this list is the index. Section 23.2 lists the VERIFIED facts to re-check before any pin
moves.

| Item | Section | How to settle |
|---|---|---|
| The pins are a proposal; app `v10` is a pre-release line; runtime differences between the two replace sets | 10.1 | confirm the pins |
| Exact usable maximum blob size of a PFB | 10.2 | read the square builder at the pin |
| The square builder never lays out `PFF_NS` differently (NA4) as a protocol guarantee | 10.4 | read go-square at the pin |
| The order of anchor candidates equals their order in `data.txs` | 10.4 | read square construction |
| Fibre keeper check details at the pin (not only the snapshot) | 10.4 | read the pin |
| No case exists where shares of a share-version-1 blob in the square with a failed PFB do not count as published | 10.6.3 | human to confirm |
| No component outside celestia-app (celestia-node bridge, validator sidecar) prunes Fibre shards on the PFF's result | 10.6.3 | read celestia-node at the pin |
| What a validator signature in the certificate attests (custody versus availability) | 10.6 | Fibre design |
| Whether the Fibre client stops collecting signatures at the same quorum test as CV6 | 10.6.1 | read the client at the pin |
| The version string of `node.Info`; the probe defaults for Mocha traffic | 10.8 | live check |
| Re-inclusion of a tx that failed before its sequence was consumed | 10.9 | read the ante handler |
| W5 inputs: a serving API and an offline verifier for the tx inclusion proof (`da = 1`); unchanged facts at celestia-node `v0.34.2-mocha`; the stock light client on an app-v10 chain | 9.5 | task 035 research |
| celestia-node Fibre service exposes the upload without the submit | 11.3 | task 035 research |
| Header time final at commit (BFT time) for the pinned celestia-core | 12.2 | read the pin |
| CometBFT `BroadcastTxSync` "already in cache" result at the pin | 13.2 | task 035 research |
| Protobuf package names of `SignedHeader`, DAH, block results at the pin | 19.2 | read the pin |
| libsodium and ZIP-215 behaviour against specific releases | 5 | library tests |
| Keplr `signArbitrary` limits and exact sign document; MetaMask acceptance of a domain without `chainId` | policy 6.2 | live checks, task 032 |

### 23.1 Verified: the tail rule (2026-10-09)

The tail rule of AB5 (section 20.8), formerly freeze-blocking. VERIFIED by code at
go-square `v4.0.1` (commit `948e812`) and celestia-app `v10.4.0-mocha`
(commit `5187d2f`, the pin), and on live Mocha blocks.

- Fibre txs are the tail of `data.txs`: celestia-app
  `app/process_proposal.go:210` classifies the block's `req.Txs` in block
  order with `x/fibre/types/classified_tx.go:20` `ClassifyTxs` (a tx is Fibre
  iff `TryParseFibreTx`, line 46, finds exactly one message of type
  `/celestia.fibre.v1.MsgPayForFibre`; a BlobTx is never Fibre), builds the
  square with go-square `Construct` (line 215) and refuses the block unless the
  DAH hash equals the proposed data root (line 245). go-square
  `square.go:23` `validateTxOrdering` refuses any blob or normal tx after a
  Fibre tx (lines 42 to 55), so the Fibre txs are the last `p'` elements.
- One `PFF_NS` unit per Fibre tx, in block order: `square.go:86`
  `populateBuilder` calls `builder.go:187` `AppendFibreTx` in tx order, which
  appends the raw tx bytes to `PayForFibreTxs` (line 209); `Export` writes each
  of them with one `WriteTx` into the compact splitter of `PayForFibreNamespace`
  (`builder.go:282` to 287), and `WriteSquare` (`square.go:238`) places that
  sequence. So `p' = p` and the order is the same.
- No other writer of `PFF_NS`: the only compact writer of the namespace is the
  one above; every sparse blob carries its own namespace. User blobs: a BlobTx
  passes `ValidateBlobTxWithCache` (`process_proposal.go:188`), which runs
  `x/blob/types/blob_tx.go:94` `ValidateBlobs` -> `payforblob.go:174`
  `ValidateBlobNamespace` (reserved refused, line 175). Fibre system blobs
  (share version 2) take the namespace of the payment promise
  (`classified_tx.go:101` `SystemBlob`), and `validatePayForFibreTxShape`
  (`app/check_tx.go:178`, called at `process_proposal.go:127`) runs
  `PaymentPromise.ValidateBasic` (`x/fibre/types/msgs.go:52`), which requires
  `ValidateForBlob` (line 70; go-square `share/namespace.go:152`, reserved
  refused at 157). `PFF_NS` is primary reserved (`share/consts.go:133`).
  Namespace padding takes the namespace of the blob before it, so it is never
  reserved either.
- Every executed MsgPayForFibre is in `PFF_NS`: the SDK decoder and
  `TryParseFibreTx` read the same `TxRaw`/`TxBody`; a tx with a
  MsgPayForFibre and any other message is refused at `check_tx.go:185`, and a
  malformed one makes `ClassifyTxs` fail, which refuses the block.
- Live (read-only, Mocha `mocha-5`, all blocks `version.app = 10`): height
  1,197,863 (`data.txs`: a normal tx with code 4, two blob txs, three Fibre
  txs) and height 1,439,495 (two blob txs, eight Fibre txs). At both, the last
  `p` elements of `/block` `data.txs` are byte-equal to the `PFF_NS` units in
  order, `ClassifyTxs` marks exactly them, and `pkg/da.ConstructEDS(data.txs,
  10, -1)` rebuilds a DAH whose hash equals `data_hash`. Recorded in
  `da/absence.json` `live_tail_rule` (checked offline); the case
  `fibre_present_live` shows the rule deciding a live height where the codes
  are not uniform and binding by position alone would give a false absence.
  Survey: `tx_search` returned 8,948 MsgPayForFibre txs in 8,303 blocks;
  in the 598 blocks with two or more, the PFF indexes are contiguous, and in
  the 532 of those that hold other txs, `ClassifyTxs` over `/block`
  `data.txs` puts every Fibre tx after every other tx (two of them also hold
  a normal tx: 1,197,863 and 1,199,544).

Since the rule holds, kind 14 does not carry `data.txs` and AB5 needs no
square rebuild.

### 23.2 Re-pin checklist

Facts VERIFIED by code at the pins (section 10.1) on which a check outcome
or a stated assumption depends. Before any pin moves, each item is
re-verified at the new commit; an item that no longer holds is a spec
change (section 0), decided before the re-pin.

| # | Re-verify at the new pin | Depends on it | If it no longer holds |
|---|---|---|---|
| PC1 | ProcessProposal still executes the messages of every PFF tx and rejects the block on failure (`app/process_proposal.go` `ProcessProposalHandler`, `if isPFF` branch), and the `MsgPayForFibre` handler still runs the height window check (`x/fibre/keeper/msg_server.go` `PayForFibre` -> `keeper.go` `validatePaymentPromiseStatefulInternal`). | The included-reference window assumption (10.6.3, promise height); the "non-zero code only through an ante failure" fact (10.4) | If the check moves to FinalizeBlock only, or disappears, inclusion no longer implies the window: revisit 10.6.3 before re-pinning. |
| PC2 | The tail rule of AB5: Fibre txs are the tail of `data.txs`, one `PFF_NS` unit per Fibre tx in block order (section 23.1). | AB5 index binding (20.8) | AB5 gives no "absent" at the new app version until re-verified. |
| PC3 | Shard retention is fixed at upload by time only and no Fibre server path reads PFF results (`fibre/server_upload.go` `shardPruneAt`, `fibre/server_prune.go`). | "Result code not part of the claim" for `da = 1` (10.6.3) | Revisit 10.6.3 before re-pinning. |
| PC4 | The keeper's certificate rules CV3 to CV7 (`validateValidatorSignatures`, `payment_promise.go`, `signature_set.go`) and the quorum `floor(2 * total / 3)`. | CV1 to CV7 (10.6.1), the one-threshold rule | Spec change before re-pinning. |
