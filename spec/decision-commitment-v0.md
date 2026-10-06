# DecisionCommitment v0

Edicta — verifiable decision layer for autonomous agents.

Status: revision `v0-draft.19` (2026-10-06). Working draft, subject to change.
Wire version: `version = 0`. Domain tags: `edicta/v0/...`.

The core knows no rail, broker or chain. An action is an opaque byte string
bound to the commitment by its type and a tagged hash. Rail-specific formats,
checks and identifiers live in profiles; the first one is the dca-agent
profile (`spec/profiles/dca-agent-v0.md`: IBKR order action, DCA context,
IBKR client order id, executor rules); the second is the bank-send profile
(`spec/profiles/bank-send-v0.md`: Cosmos `MsgSend` action, price-trigger
context, transaction body rule, executor rules).

Keywords MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.
Items marked `UNVERIFIED` are facts about Celestia or Fibre that a Celestia
protocol engineer must confirm. Everything else is normative for v0.

## 0. Versioning of this document

| Change | Rule |
|---|---|
| Editorial (wording, examples, sources) | No version change. |
| Any change to wire bytes, hash preimage, signed bytes, limits, or the outcome of any check, while in draft | Bump the draft revision (`v0-draft.N`), regenerate every vector, record it in the changelog (section 0.1). |
| Any such change after v0 is frozen | New wire `version` (1) and new tags (`edicta/v1/...`). A v0 verifier MUST reject `version != 0` (`ErrUnsupportedVersion`). |

The domain tags carry the version, so a v0 signature can never verify as a v1
signature even if the byte layout were identical.

### 0.1 Changelog

| Revision | Date | Change | Wire bytes | Vectors |
|---|---|---|---|---|
| `v0-draft.1` | 2026-10-03 | First complete draft. | - | Initial set. |
| `v0-draft.2` | 2026-10-03 | `celestia_blob` payloads MUST use share version 0. **Superseded by `v0-draft.3`.** | Unchanged | Regenerated; byte-identical. |
| `v0-draft.3` | 2026-10-03 | (1) `celestia_blob` (`da = 2`) payloads MUST be L1 blobs with share version 1; new `payload_ref` key 5 `signer` (bstr, exactly 20 bytes), required for `da = 2` and not defined for `da = 1` (sections 4.5, 6.3, 10.5). Replaces the draft.2 share-version-0 rule. (2) New rule G0: `agent_pubkey` MUST be a canonical encoding of a curve point that is not of small order; sentinel `ErrInvalidPublicKey` (stage G, section 5). Fixes a forgery with small-order keys. (3) Section 10.4: a new Fibre blob version gets a new `da` value. (4) Illustrative share framing in `blob_with_share_padding` is now share version 1. | Changed: every `da = 2` commitment carries key 5 | Regenerated. |
| `v0-draft.4` | 2026-10-03 | (1) Rule G1 pins the verification equation: cofactorless, accept iff `encode([S]B - [k]A) == R` bytewise (with G2 `S < L`). This is what Go `crypto/ed25519` and OpenSSL already do, so no conforming draft.3 verifier changes outcome; it rules out cofactored verifiers. (2) Section 6.4: the fuzz test is named `FuzzDecode`. | Unchanged | Regenerated; existing vectors byte-identical; one new must-reject vector `sig_torsion_r`. |
| `v0-draft.5` | 2026-10-03 | Gate rules. (1) Section 11: the anchor-time comparison is now MUST: rules K1 (`issued_at + skew_s >= T_H`, `ErrIssuedBeforeAnchor`) and K2 (`valid_until + margin <= start + r`, routing), with exact definitions of `T_H`, `r`, `start` and `margin`. (2) Rule P3 (section 8.5): the DA commitment recomputed from the bytes MUST equal `payload_ref.commitment`, per path and per `da`; `da = 1` is never accepted from the archive in v0 (`ErrArchiveRecomputeUnsupported`). (3) Section 8.7: stateful gate stages, their order and the registry-epoch rule E1. (4) Section 12: gate sentinels. (5) Section 14: the receipt (`edicta/v0/receipt` since draft.7), byte-exact, signed by the gate. (6) Section 15: the client order id per rail (IBKR: `cOID` = lowercase hex of `commitment_hash`). | Commitment bytes unchanged; new receipt wire format | Existing files byte-identical except `keys.json`, which gains `gate1`. New: `receipt.json`, `anchor.json`, `client_order_id.json`, `da_blob.json` (upstream go-square, Go only). |
| `v0-draft.6` | 2026-10-03 | Review of draft.5. (1) Receipts are signed under a separate receipt-signature tag (`TagReceiptSig`; `signed_message` was 53 bytes under the pre-draft.7 tag names), not `TagSig`. (2) K2: if `fibre_retention_s` at `height` cannot be read, the gate MUST reject with `ErrRetentionUnavailable` and never substitute the latest value. (3) New rule L0: the gate rejects a commitment whose `agent_pubkey` equals any gate key (`ErrAgentKeyIsGateKey`). (4) `valid.json` marks the placeholder `payload_ref.commitment` of each case (`placeholders`). (5) Section 15.2: IBKR brokerage-session limits on lookup coverage. (6) Status: the tag prefix (pre-draft.7 product name) is a placeholder; all tags are renamed once before the v0 freeze. | Receipt signed bytes changed; commitment bytes unchanged | `receipt.json` regenerated (signatures changed, receipt bytes and hashes unchanged, one new reject); `anchor.json` `k2_fibre_at_height_unreadable` now expects `ErrRetentionUnavailable`; `valid.json` gains `placeholders` only; `reject.json`, `payload.json`, `keys.json`, `da_blob.json` byte-identical. |
| `v0-draft.7` | 2026-10-03 | Product renamed to Edicta. (1) Every domain tag moves to the `edicta/v0/` prefix: `TagCommitment` = `edicta/v0/decision-commitment` (29 bytes, prefix `0x1d`), `TagSig` = `edicta/v0/sig` (13, `0x0d`; agent `signed_message` 46 bytes), `TagReceipt` = `edicta/v0/receipt` (17, `0x11`), `TagReceiptSig` = `edicta/v0/receipt-sig` (21, `0x15`; receipt `signed_message` 54 bytes). (2) The placeholder-prefix note in the status block is removed; the tag names are final for v0. (3) Module path `github.com/vgonkivs/edicta`; vector `format` is `edicta-vectors/v0`; the Python rules module is `spec/vectors/check/edicta_v0.py`. (4) Test-fixture labels were renamed too: namespace sub-ids `edicta/d01` and `edicta/d02` (10 bytes each, as before), and the seeds of the test signer, salt, 32-byte account and torsion nonce. | Changed by design: every commitment hash, agent signature, receipt hash and receipt signature; signed messages grow by 1 byte. CBOR layout, limits and check outcomes unchanged | Every file regenerated. Changed: `format`; tags in signed messages; hashes and signatures; fixture namespace, signer, salt, `plaintext_hash` and the dependent payload hashes; `da_blob.json` namespaces and share commitments; the nonce of 6 small-order-key rejects (the forgery search runs over the nonce); `client_order_id` values (they are commitment hashes). Case ids, case counts, sentinels and receipt sizes unchanged. |
| `v0-draft.8` | 2026-10-03 | Payload blob details, additive. (1) Section 9.1: payload AEAD aad `tag("edicta/v0/payload")`, HPKE base mode with `info = tag("edicta/v0/payload-dek")` and `aad = uint8(len(kid)) \|\| kid`, 1..16 recipients with unique kids. (2) Section 9.2: strict blob decoding, rules B0..B7. (3) Section 9.3: payload plaintext schema; `media_type` REQUIRED in `context` and `metadata`, lower-case RFC 6838 `type/subtype` without parameters. (4) Section 9.4: opening procedure O1..O8; `plaintext_hash` is compared before parsing. (5) Section 9.5: producer checks before signing, including the local DA commitment recompute (default on). (6) Appendix A: media type `application/vnd.edicta.dca.v0+cbor`. (7) Section 12: SDK sentinels. (8) Threat model rows for kids, key commitment and the producer-side recompute. | Commitment, signed envelope and receipt bytes unchanged; existing tags unchanged; two new tags for the blob only | Existing files byte-identical (SHA-256 unchanged). New: `payload_blob.json`; checker files `hpke_base.py`, `hpke_rfc9180_a2_1.json`, `edicta_payload_v0.py`, `gen_payload_blob.py`, `check_payload_blob.py`. |
| `v0-draft.9` | 2026-10-04 | Platform-agnostic core, made before the v0 freeze. (1) Commitment key 8 `action` becomes opaque: `{3: type, 4: hash}` (action keys 1 `kind` and 2 `params` retired), `hash = H(tag("edicta/v0/action") \|\| uint8(len(type)) \|\| type \|\| action_bytes)` (sections 4.3, 5.1); `type` is a lower-case media type of 3..128 bytes. The `ibkr.order.v0` kind and its params, rule D20 and `ErrUnsupportedActionKind` are removed; the IBKR order moves to the dca-agent profile. (2) Commitment key 9 `constraints` (`max_notional`, `price_bound`, `deadline`) is retired; `valid_until` is the only expiry. (3) Scope keeps only key 1 `gate_id`; keys 2 `rail`, 3 `account`, 4 `chain_id` are retired. Retired keys are never reused, without exception. (4) Stage S keeps S1, S2, S3 (`da` only), S6, S7, S8, S12, S14; S4, S5, S9, S10, S11, S13, S15, S16 are retired. (5) New rule C2 (`ErrActionTypeNotAllowed`): the action type is one the gate is configured for. Rule A1 is redefined as hash equality over the supplied action bytes; new rule A0 (`ErrActionSize`, 1..65536 bytes). (6) New: the gate-signed Authorization (section 15), tags `edicta/v0/authorization` and `edicta/v0/authorization-sig`, 60-byte signed message, at most 256 bytes. The gate authorizes and never executes; stages 11..13 of section 8.7 are rewritten (sign, then consume the nonce with the signed Authorization, then return), with the retry rule. (7) Receipt (section 14): keys 5 `rail` and 7 `path` retired; key 8 keeps its number, field renamed `recorded_at`; new keys 9 `executor_pubkey` and 10 `executor_signature`; `rail_ref` is opaque. `Record` requires a request signed by an allowlisted executor key (tag `edicta/v0/record-request`, `record_message = tag || commitment_hash || uint8(len(gate_id)) || gate_id || uint8(len(rail_ref)) || rail_ref`, 61..251 bytes, rules RQ1..RQ6, R6); executor keys never equal gate or agent keys (`ErrKeyRole`, gate `ErrExecutorNotAllowed`). The receipt attests that a known executor claimed `rail_ref`, not execution. (8) New section 16, the integrator contract (executor MUSTs; non-normative: `commitment_hash` as the idempotency key). (9) Payload plaintext (section 9.3): key 5 `action` is `{3: type, 4: data}` (its keys 1 and 2 retired), key 6 retired; O8 and W1 compare type and hash. (10) Removed to the dca-agent profile: the client order id (old section 15), the DCA media type (old Appendix A), scales and notional arithmetic (old section 4.7). (11) Threat model rows for the action hash, the Authorization, executor dedupe and the integrator enforcement gap. | Changed by design: every commitment, envelope, commitment hash and agent signature; receipt bytes, hashes and signatures; payload plaintext, blob and hashes in `payload_blob.json`. Unchanged: tags of draft.7 and draft.8, signed-envelope layout, limits `MaxSignedSize`/`MaxCommitmentSize`/depth/entries, payload blob format, anchor rules | Regenerated: `valid.json`, `reject.json`, `receipt.json`, `payload_blob.json`. New: `authorization.json`, `record_request.json`. Removed: `client_order_id.json` (now profile data). Byte-identical: `keys.json`, `payload.json`, `anchor.json`, `da_blob.json`. Profile vectors in `spec/vectors/profiles/dca-agent/`. |
| `v0-draft.10` | 2026-10-04 | Publication through an untrusted submitter, additive. (1) Section 1: threat-model rows for the blob submitter, the inclusion check and its trust levels, the publish request, the DA allowlist and byte-identical resends. (2) Section 9.5: producer rules W5 (independent inclusion check; mandatory when the submitter is a different party) and W6 (bounded publication wait; a retry is a new payload with a new nonce). (3) Section 8.3: gate rule C3 (`payload_ref.da` is in the gate's configured DA set, `ErrDANotAllowed`), evaluated right after stage C; with the set unset (`{1, 2}`) every existing outcome is unchanged. (4) Section 10.5: `signer` names the submitter's account, not who decided. (5) Section 16.1: rule I5 amended for byte-identical resends of one signed rail request inside a profile-bounded window, then hand-off to the operator. (6) New section 17: the agent-signed publish request, tag `edicta/v0/publish-request` (25 bytes, `0x19`), its wrapper, response and checks PR1..PR6. (7) Section 12: new sentinels. (8) New profile `spec/profiles/bank-send-v0.md`. | Unchanged: commitment, envelope, Authorization, receipt and record-request bytes; every existing tag; every existing check outcome. New: the publish-request message and wrapper | Every existing file byte-identical (SHA-256 unchanged), including the `"revision": "v0-draft.9"` field of the files that carry one: their bytes and meaning did not change. New: `spec/vectors/api/publish_request.json` (`v0-draft.10`); profile set `spec/vectors/profiles/bank-send/`; generator module `spec/vectors/tools/banksend-gen`; checker files `edicta_publish_v0.py`, `gen_api_vectors.py`, `check_api_vectors.py`, `profile_bank_send.py`, `gen_profile_bank_send.py`, `check_profile_bank_send.py`. |
| `v0-draft.11` | 2026-10-04 | Publish request review. (1) `publish_message` gains the Recorder's `gate_id` with a one-byte length, right after the tag: a request is valid at one server only. The wire request is unchanged; the server fills in its own `gate_id`, as for record requests. (2) New rule PR6: dedupe by `SHA-256(blob)`; the same blob inside its window is published once and every accepted retry gets the same response. Quotas move to PR7 and are not charged for a deduplicated request. (3) Threat rows and section 17 notes updated: cross-Recorder replay is closed. Bank-send profile `bank-send-v0-draft.2` (timeout budget, resend stop) at the same time. | Changed: `publish_message` (70..196 bytes) and so every publish signature. Unchanged: everything else | Regenerated: `spec/vectors/api/publish_request.json` (`v0-draft.11`; 2 new rejects). Every other core and dca-agent file byte-identical. |
| `v0-draft.12` | 2026-10-04 | HTTP API, additive. (1) New section 18: endpoints `POST /v0/publish`, `POST /v0/authorize`, `POST /v0/record`, `GET /v0/health`; `application/cbor` bodies; request, response and error body shapes reusing the canonical encodings; status and retry semantics; the error table (first match wins), with 409 carrying the stored Authorization only under the retry rule of section 8.7 and the stored receipt for `ErrReceiptExists`. (2) Section 12: the operational and HTTP-layer sentinels that cross the API get stable names (`gate.ErrChainUnavailable` and others, `recorder.*`, `edictaapi.*`). | Unchanged: every existing message, tag and check outcome. New: HTTP wrapper shapes and the error body | New: `spec/vectors/api/errors.json` (`v0-draft.12`), generator `gen_api_errors.py`, checker `check_api_errors.py`. Every existing file byte-identical. |
| `v0-draft.13` | 2026-10-04 | Single DA per instance. Section 7: the 256 KiB Recorder split between `celestia_blob` and `fibre` is replaced by a normative deployment rule: one DA per gate/Recorder instance, chosen by configuration; a payload that does not fit it is refused; switching DA is a restart with another configuration, after which commitments for the other DA fail C3. "Routing" wording for the gate's K2 choice between the DA and archive paths is renamed "path selection" (no change in meaning). | Unchanged | Every file byte-identical. |
| `v0-draft.14` | 2026-10-05 | HTTP error mapping (section 18.3): `recorder.ErrNodeUnavailable` and `recorder.ErrTooManyPending` added to section 12 and mapped to 503, retryable, matched after `recorder.ErrNotVisible`. Before this they fell through to 500 `edictaapi.ErrInternal`, so the status and retry advice for these failures change. | Unchanged | `spec/vectors/api/errors.json` regenerated: the two entries (74 codes) and `"revision": "v0-draft.14"`. Every other file byte-identical. |
| `v0-draft.15` | 2026-10-05 | Section 18.3 match order corrected to the reference server: `recorder.ErrNodeUnavailable` and `recorder.ErrTooManyPending` are matched **before** `recorder.ErrNotVisible`, not after it as draft.14 said. No Recorder error wraps more than one of these sentinels, so no status or code changes; the order is normative because `errors.json` is defined as match order. Section 12: `recorder.ErrNodeUnavailable` is also returned after a submit (search and read-back), not only before one. Bank-send profile `bank-send-v0-draft.3` (hand-off bounds and reconcile) at the same time. | Unchanged | `spec/vectors/api/errors.json` regenerated: the two entries move ahead of `recorder.ErrNotVisible`, `"revision": "v0-draft.15"`. Every other file byte-identical. |
| `v0-draft.16` | 2026-10-05 | Recorder and inclusion review. (1) Section 17.3: PR6 is the completed-blob cache only (a completed answer, or a concurrent request for the same blob that completes, is free); PR7 states that the quota counts requests that reach it, not spend, so a retry of a blob with an unresolved submission is charged; new rule PR8: an unresolved submission is never submitted again, the retry resumes its search (moved out of PR6). Before this the text said every deduplicated retry was free. (2) Section 18.3: `edictaapi.ErrDeadline` only for the handler's own deadline; a Recorder submit timeout is `recorder.ErrOutcomeUnknown`, a Recorder read timeout `recorder.ErrNodeUnavailable` (both 503), whatever context error they wrap. The match order and the `errors.json` table are unchanged; the statement is new. (3) Section 9.5: `CrossCheck` source identity, rules X1 to X4 (URL normalization) and a refusal to start when two sources share a normalized host. Bank-send profile `bank-send-v0-draft.4` (watch loop, `indexer_lag_blocks`, startup indexer check, rejection keeps watching) at the same time. | Unchanged | Every file byte-identical, including `spec/vectors/api/errors.json` (`"revision": "v0-draft.15"`: its bytes and meaning did not change) and `publish_request.json` (PR6 to PR8 are stateful, no vectors). |
| `v0-draft.17` | 2026-10-05 | Fibre (`da = 1`) as a first-class v0 mode; no wire change. (1) Section 8.5, 10.4: the Fibre commitment recompute exists (`fibre.NewBlob` at the pin, in a module separate from the core); a gate with a `da = 1` committer runs P3 itself on both paths, so the `da = 1` archive path is no longer refused. `ErrArchiveRecomputeUnsupported` keeps its name and now means only "no committer is configured for this `da`"; a gate whose configured DA is `fibre` MUST have one and refuses to start otherwise. (2) Section 10.4: the anchor is found by scanning block `height` (no tx index), and the PFF tx MUST have result code 0. (3) Section 10.6.1: the certificate rule for verifiers, byte-exact sign bytes, positional signatures over the keeper's validator order, and the chain's quorum test. (4) Section 10.7: archive MUST contents for `da = 1` (payload, PFF tx and inclusion proof, validator set and header at the promise height, header at `height`). (5) Section 10.8: startup compatibility check against pinned versions, MUST. (6) Section 11.2: where `fibre_retention_s` at `height` comes from (rules RS1 to RS6): echoed-height reads, a canary for height-ignoring endpoints at start and periodically, persisted observations; never the current value. (7) Section 9.5 W4: `da = 1` producers recompute with the same committer. Amended in place before merge (human decisions of 2026-10-05): (8) new section 10.9, at-height reads AH1 to AH5 for every module and both `da` (echoed height, binding to the header, canary per endpoint; observations-only retention mode, otherwise `ErrChainUnavailable` or a height-independent source; never a verdict from latest state). (9) Section 8.7 stage 4a, rules AR1 to AR4: the gate archives the envelope and action bytes, idempotently, after G, L and A and before signing; archive down gives `ErrArchiveUnavailable` (503, `Retry-After`), nonce not consumed. (10) Section 10.6.2: verifier header trust HT1 to HT7 (trusted header at `T >= H`, backward `last_block_id` hash chain, no signatures, optional cross-check; forward verification out of scope). (11) Section 10.6.1: settlement reported as `node-attested` (certificate, system blob, code 0); CV8 and section 10.7 updated (system blob MUST). (12) Section 10.4 and rule C4: Fibre payload limit, default 16 MiB, `ErrPayloadAboveCap`. (13) SC3: `da = 1` chain allowlist is configuration, default `mocha-5`. (14) Section 10.6.1: one certificate threshold rule for the gate, the Recorder and the verifier: the network threshold, the signed share reported, a warning when `3 * signed <= 2 * total`; all three MUST give the same verdict and warning. (15) Section 10.4: `da = 1` submission only through the operator's own node, which section 2 defines as a node the operator chose and controls, not necessarily self-hosted. (16) Sections 12 and 18.3: new codes `ErrPayloadAboveCap` (413), `recorder.ErrSubmitMismatch` (502), `ErrArchiveUnavailable`, `recorder.ErrArchiveUnavailable`, `recorder.ErrEscrowInsufficient` (503). (17) Section 8.7, rules AR5 to AR8: decisions archived at stage 4a and then refused stay in the archive, marked rejected with the section 12 error name; the marker is idempotent, conditional on no Authorization, and its write failure is fail-safe (verdict unchanged, nonce not consumed); verifiers report such records as rejected, never as authorized or executed. Archive-local metadata, no wire change and no new sentinel. | Unchanged | `spec/vectors/api/errors.json` regenerated additively: five new codes (79), `"revision": "v0-draft.17"`; every existing entry unchanged. Every other existing file byte-identical, including `anchor.json`: its `da = 1` cases that expect `ErrArchiveRecomputeUnsupported` describe a gate without a `da = 1` committer and keep that outcome there. New: `spec/vectors/da/fibre_commit.json` (`v0-draft.17`), generator module `spec/vectors/tools/fibrecommit-gen`, checker `check_fibre_commit.py`. |
| `v0-draft.18` | 2026-10-06 | Erratum to section 11.2, no wire change. (1) RS4: a sample records the bracket `[a - lag, b + lag]` (both ends saturating) instead of `[a - lag, b]`. Behind a load-balanced endpoint the params read can come from a backend ahead of the one that answered head `b`; without the upper widening a retention increase could be dated too early and K2 could take a too high value at `height` (invariant 4). With `lag = 0` the outcome is unchanged; with `lag > 0` coverage starts up to `lag` blocks later and the value is never higher than under draft.17. The backend-spread assumption is now stated. (2) RS threat note and section 1: the missed case is any non-monotone pair of changes between two samples, not only a change and its revert (wording; the rule was already so). A separate revision rather than an in-place amendment because draft.17 is already merged. | Unchanged | Every file byte-identical (RS rules are stateful, no vectors); `spec/vectors/api/errors.json` keeps `"revision": "v0-draft.17"`. |
| `v0-draft.19` | 2026-10-06 | At-height read review, no wire change. (1) Section 11.2, RS2: the canary is decided from success or failure and the echoed `x-cosmos-block-height` only, never from error codes or messages (an honest pruned node answers `codes.Unknown`, and grpc-go makes `codes.Internal` from transport faults, so the draft.17 rule kept honest pruned endpoints in observations-only mode and could pass a proxy). Configured heights per chain: a recent `h_r = head - canary_offset` (default offset 10, greater than `lag`) that must succeed and echo `h_r`, and an optional pre-activation `h_pre` (Mocha 1,082,619) that must fail; height 1 is dropped. Outcomes Honoured, Ignoring, Inconclusive. (2) Section 10.9, AH3: a missing or different height on a block or header read on a consensus endpoint marks it height-ignoring for state reads until a later canary passes; bridge endpoints get their own canary (header at `head - canary_offset`, returned height must equal the requested one), logged only, never driving the retention mode. (3) Section 10.9, AH5: a header or block "not found" at a height at or below an observed head, or above every observed head, is `ErrChainUnavailable` on both `da` paths; `ErrAnchorNotFound` only for a block read that passed AH1 and AH2 and holds no anchor. | Unchanged | Every file byte-identical (stateful rules, no vectors); `spec/vectors/api/errors.json` keeps `"revision": "v0-draft.17"`. |

## 1. Threat model in one table

Each mechanism below names what it defends against and what it assumes.

| Mechanism | Defends against | Assumes |
|---|---|---|
| Ed25519 over a tagged hash (section 5) | Forged or altered commitments; cross-protocol reuse of signatures | Agent private key is secret; gate allowlist maps `agent_id` to the right key (section 8.7) |
| Public key validity, rule G0 (section 5) | Universal forgery under a small-order `agent_pubkey` (for the identity key, `R = identity, S = 0` verifies for every message); key aliasing through non-canonical encodings | Ed25519 discrete log is hard in the prime-order subgroup |
| Canonical CBOR, strict decoder (section 6) | Two byte strings for one commitment (malleability); parser differentials between Go and Python; decoder DoS | Both implementations follow this document, checked by shared vectors |
| Scope `gate_id` (section 4.2) and the gate's action-type set (rule C2) | Replay at another gate; a commitment for an action type this gate was not set up for | Each gate has a unique `gate_id`. Scope does **not** bind an account, rail or chain: cross-domain binding is the profile's job (section 16) |
| Action hash (section 5.1) | Executing other bytes than the committed ones, or the same bytes under another type (type confusion between formats); an ambiguous `type \|\| bytes` split | SHA-256 collision resistance. Exact match only: the core never interprets the bytes, so a re-encoding of "the same" action is simply not authorized. **Not hiding**: the hash is public and low-entropy action bytes can be guessed from it; a profile that needs hiding adds a random field to its own format |
| Nonce (section 4.1) | Replay at the same gate | The gate consumes the nonce atomically with issuing the Authorization and returns the Authorization only after the mark is durable (invariant 5, section 8.7); at most one Authorization per `(agent_pubkey, nonce)` |
| `valid_until`, MaxTTL (section 11), Authorization `expires <= valid_until` (section 15) | Stale decisions authorized or executed late; executing after the payload may have left Fibre | Gate clock within 30 s of true time; the executor's clock within `skew_s` of the gate's |
| Authorization (section 15) | An executor acting on a decision the gate did not verify; reusing an Authorization for other bytes, another type or at another gate's executor; taking a gate signature for an agent or receipt signature | Gate key secret, and pinned by the executor as `gate_id -> gate_pubkey` out of band. It is a **bearer token**: whoever holds it and the action bytes can present it until `expires`, so it gives at-most-once execution only together with executor dedupe |
| Executor dedupe by `commitment_hash` (section 16) | One Authorization executed twice: replay at the executor, a retry after a timeout, a crash between send and record | The integrator implements it, atomically with execution or through rail-native idempotency; the record outlives `expires + skew_s` |
| Domain self-identification in the action format (section 16) | Bytes authorized for one domain executed in another (another broker account, chain or contract) | The profile's format names its domain inside the bytes (EVM: `chain_id` in the transaction; dca-agent profile: the IBKR account in the order) and the executor compares it with its own. The core provides only `gate_id` and the type allowlist |
| Integrator enforcement (section 16) | Nothing by itself: the core cannot make an executor check anything | **Open dependency.** Edicta protects a rail only where whatever holds the rail credentials (a signer, a contract, middleware in front of a broker API) runs `VerifyAuthorization` on the exact bytes it executes and refuses otherwise. An integrator that skips this has no Edicta protection, and the gate cannot detect it |
| `ciphertext_hash`, `payload_size` (section 9) | Archive or DA serving different bytes; oversized fetches | SHA-256 collision resistance |
| `plaintext_hash` with 32-byte salt (section 9) | Brute-forcing a low-entropy plaintext from the public commitment | Salt is uniformly random and stays inside the ciphertext |
| `payload_ref` + L1 anchor (section 10) | Claiming a payload was public when it was not | More than 2/3 of voting power is honest (Celestia assumption) |
| `payload_ref.signer` with share version 1 (section 10.5) | An L1 blob with the same bytes posted by another account being taken as the Edicta anchor; an unrecomputable share commitment | Same as the row above: the blob-signer rule is enforced in CheckTx and ProcessProposal |
| Archive fallback (section 11) | Fibre pruning before the commitment expires | Archive is honest for availability only; integrity comes from the hash (P2) and the recomputed DA commitment (P3) |
| DA commitment recompute, rule P3 (section 8.5) | "Anchor X, sign H(Y)": an agent or Recorder anchors blob X, archives blob Y and signs `ciphertext_hash = H(Y)`, so a hash-only check accepts bytes that were never public | SHA-256 collision resistance; the recompute is the upstream code at the pin (`fibre.NewBlob` for `da = 1`, go-square for `da = 2`), checked by vectors generated from that code alone |
| Anchor-relative time, rules K1 and K2 (section 11.2) | A commitment signed before its payload was public; a commitment whose validity outlives the DA retention window being executed as if the DA layer still served the payload | The gate reads true header time from a node it trusts (the operator's own node is recommended; a public endpoint is allowed). Every read at a past height, on every module and on both `da` paths, is used only if the response echoes the requested height and, where the content allows, is bound to the header at that height (AH1 to AH5, section 10.9). At-height retention comes from such a read on an endpoint that passed the canary, or from the gate's own persisted observations (observations-only mode when the endpoint ignores heights); a non-monotone pair of changes between two observations (for example a change and its revert) is missed (RS1 to RS6, section 11.2) |
| PFF certificate check, one rule for gate, Recorder and verifiers (section 10.6.1) | A forged or under-signed availability certificate presented after the chain pruned the state that could re-check it | More than 2/3 of voting power honest at `PaymentPromise.height`; the archived validator set is the one the chain used, tied to a header by `validators_hash` and that header to the chain by a light-client path; Ed25519 |
| Startup compatibility check (section 10.8) | Silent divergence after an upstream change: another Fibre encoding, another sign-bytes layout, another chain or a node that answers in another format | The pinned versions and the known-answer vectors describe the network; the check runs before the gate serves |
| Registry epoch, rule E1 (section 8.7) | Replay after the nonce registry was lost or recreated | The gate clock did not step back across the recreation |
| Signed receipt and record request (section 14) | A fabricated `commitment_hash -> rail_ref` mapping in an archive or report; two different mappings for one decision; a third party who holds the (non-secret) envelope recording a bogus `rail_ref` first and so owning the decision's only receipt | Gate and executor private keys are secret; the gate admits a claim only if it is signed by a key in its executor allowlist, over a message that names this gate, this decision and this `rail_ref`; the receipt carries the executor key and signature, so a verifier needs no trust in the gate for who claimed what; the gate stores at most one receipt per authorized decision. **Not proof of execution**: the receipt attests that a known executor claimed `rail_ref`, and that the gate recorded that claim; whether the rail executed anything is only in the rail's own records. A compromised or malicious allowlisted executor can still claim a false `rail_ref` first |
| HPKE-wrapped DEK per recipient, payload AEAD (section 9.1) | Reading the decision without a recipient key; using a payload ciphertext or a wrapped DEK under another Edicta or non-Edicta purpose (length-prefixed `edicta/v0/payload*` tags) | X25519 CDH is hard; recipient private keys are secret; the DEK is fresh per blob. Base mode authenticates no sender: authenticity comes only from the agent signature over `ciphertext_hash` and `plaintext_hash` |
| Public `kid` per recipient (section 9.1) | Nothing: it is a label that lets a recipient find its entry | **Leaks** the auditor and counterparty identities when kids are meaningful labels (`auditor-1`, a fund or broker name), the recipient count of every payload, and links all payloads that share a recipient. Accepted for v0. HPKE base mode does not reveal `pkR` from `enc`, so random per-blob kids (recipients try every entry) remove the leak without a format change |
| `plaintext_hash` checked before parsing, rule O7 (section 9.4) | A malicious agent showing two recipients two different decisions from one blob: ChaCha20-Poly1305 is not key-committing, so one ciphertext can open under two DEKs wrapped for different recipients (vector `pb_key_commitment_two_deks`) | SHA-256 collision resistance; every recipient runs O7 on the full AEAD plaintext before using it. A recipient that only runs the AEAD is not protected |
| Strict blob decoding, rules B0..B7 (section 9.2) | Two recipients or verifiers disagreeing on which entries or ciphertext a blob holds | Every reader implements B0..B7; shared vectors |
| Local DA commitment recompute before signing, rule W4 (section 9.5) | A buggy or malicious Recorder that anchors blob X while the agent signs `ciphertext_hash = H(Y)`: the agent's key would sign a false "Y was public at H". The gate would still reject at P2 or P3, so this protects the agent's reputation and liveness, not gate safety | The producer recomputes from its own bytes, for `da = 1` with the Fibre committer (section 10.4); a producer built without it refuses unless explicitly opted out |
| Nothing (open gap) | An agent that wraps a DEK no recipient can use, or that encrypts a payload unrelated to the action, still gets authorized: the gate never decrypts | Detected after the fact: any recipient holding the envelope and blob has signed evidence (O5, O6, O7 or O8 failure). Not prevented in v0 |
| Nothing (out of core scope) | Action bytes that are malformed, unsafe or semantically wrong for the rail (notional, price, instrument): the core authorizes exactly what the agent committed and checks no semantics | The profile's strict decoder and the executor's own limits (for example the dca-agent profile's account check and operator risk limit). A malicious caller can obtain an Authorization only for bytes the agent committed to |
| Blob submitter (Recorder, relay) trusted for liveness only; rules W4, W5, W6 (section 9.5) | A submitter that anchors other bytes, anchors under an unexpected account or namespace, or reports a false height or block time, getting the agent to sign a false "public at H" | The submitter is untrusted for integrity: it can refuse, delay, or anchor under its own account, and nothing else. The producer recomputes the DA commitment from its own bytes (W4), verifies inclusion of that commitment under a header it verified itself from sources the submitter does not control (W5), and only then signs; the gate re-checks K0, K1, P1 to P3. Worst case: censorship or delay, visible as a missing or late decision, bounded by W6 |
| Independent inclusion check, rule W5, three trust levels (section 9.5) | A lying submitter or a lying proof-serving node | `Light` (cryptographic): a trust anchor, more than 2/3 of voting power honest at H, and at least one honest header provider among primary and witnesses. `CrossCheck` (weaker interim substitute, MUST be identified as such): at least one of two or more independent header providers is honest and they do not collude; no signature is checked. `SelfCheck`: the operator's own node, allowed only when submitter and producer are one operator. A commitment proof can come from any node: it is checked against the verified header's data root |
| Agent-signed publish request (section 17) | A party without an allowlisted agent key spending the Recorder operator's fees; probing the allowlist; reusing an agent signature of another kind as a publish request; replaying a request at another Recorder | Agent keys are secret; each server's `gate_id` is unique (it is signed into the message). Domain separation (tag length 25, unique) keeps publish requests apart from commitment signatures. A replay at the same server inside the window is answered from the dedupe record (PR6) or finds the earlier submission (PR8), so it spends no second fee; it never creates a decision. Quotas are per `agent_id`, count requests rather than fees (PR7), and are checked before anything is submitted |
| DA allowlist, rule C3 (section 8.3) | A gate authorizing a `da` it cannot check on its chain (for example `da = 1` where `x/fibre` is absent) | The operator configures the set; a gate that allows `da = 1` refuses to start if it cannot read Fibre parameters |
| Byte-identical resend, amended rule I5 (section 16.1) | A transfer lost in a mempool never landing, and a "fix" that builds a second transaction and executes twice | The rail includes the same signed bytes at most once (an account sequence) and the profile bounds the window (a timeout height). The bound is in blocks, not seconds: a slower chain moves the last possible inclusion later in wall-clock time (bank-send profile, section 4) |

## 2. Notation

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
- `tag(t) = uint8(len(t)) || ASCII(t)`, with `1 <= len(t) <= 255`. One length
  byte means there is no width or endianness choice to get wrong.

| Tag name | ASCII | `tag(t)` hex prefix |
|---|---|---|
| `TagCommitment` | `edicta/v0/decision-commitment` (29 bytes) | `1d 656469637461...` |
| `TagSig` | `edicta/v0/sig` (13 bytes) | `0d 656469637461...` |
| `TagReceipt` | `edicta/v0/receipt` (17 bytes) | `11 656469637461...` (the receipt hash, section 14) |
| `TagReceiptSig` | `edicta/v0/receipt-sig` (21 bytes) | `15 656469637461...` (the gate's receipt signature, section 14) |
| `TagPayloadAEAD` | `edicta/v0/payload` (17 bytes) | `11 656469637461...` (aad of the payload AEAD, section 9.1) |
| `TagPayloadDEK` | `edicta/v0/payload-dek` (21 bytes) | `15 656469637461...` (HPKE `info` for wrapping the DEK, section 9.1) |
| `TagAction` | `edicta/v0/action` (16 bytes) | `10 656469637461...` (the action hash, section 5.1) |
| `TagAuthorization` | `edicta/v0/authorization` (23 bytes) | `17 656469637461...` (the Authorization hash, section 15) |
| `TagAuthorizationSig` | `edicta/v0/authorization-sig` (27 bytes) | `1b 656469637461...` (the gate's Authorization signature, section 15) |
| `TagRecordRequest` | `edicta/v0/record-request` (24 bytes) | `18 656469637461...` (an executor's record request, section 14.3) |
| `TagPublishRequest` | `edicta/v0/publish-request` (25 bytes) | `19 656469637461...` (an agent's publish request to a Recorder, section 17) |

`TagPayloadAEAD` has the same length as `TagReceipt`, and `TagPayloadDEK` the
same as `TagReceiptSig`. That is harmless: the prefix carries only the length,
the ASCII differs, and the payload tags are never hashed or signed, only used as
AEAD `aad` and HPKE `info` (vectors `pb_aead_aad_receipt_tag`,
`pb_hpke_info_payload_tag`).

Every hash that is signed or compared is under its own tag (`TagCommitment`,
`TagReceipt`, `TagAction`, `TagAuthorization`), and every signature is over its
own signature tag, with signed-message lengths 46 (agent), 54 (receipt) and 60
(Authorization) bytes. An executor's record request (section 14.3) is signed
directly, without a hash, and its tag has a length (24) that no other hashed
or signed tag has, so its first byte already differs from every other
preimage. An agent's publish request (section 17) is also signed directly,
under a tag of length 25, which likewise no other hashed or signed tag has.
No two hashing tags and no two signature tags are equal, so no
Edicta hash or signature can stand in for another (rule H3).

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
6. Required fields are always present, including when their value is zero
   (`version = 0`). Go structs MUST NOT tag required fields `omitempty`.
7. Text strings are UTF-8 and, in v0, restricted to ASCII charsets
   (section 4.6).

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

A schema-valid v0 commitment is at most 559 bytes (envelope 628), the largest
SignedAuthorization 221 bytes and the largest SignedReceipt 350 bytes, so
these limits only bite on hostile input. The commitment and envelope limits
are unchanged from draft.8 on purpose: the limit vectors keep their meaning.

`MaxActionSize` reasoning: an empty action is meaningless; 64 KiB fits any
order and typical EVM call data (the EVM initcode limit is 49152 bytes). An
action larger than that commits to a digest inside its own format.

## 4. Field tables

Columns: CBOR key, name, type, size limit, R (required) or O (optional),
scale, semantics, and the gate invariant the field serves. The gate
invariants, referred to by number throughout this document:

1. The agent signature over `commitment_hash` is valid.
2. The payload is available (DA layer or archive) and its hash matches.
3. The action bytes presented to the gate are exactly the committed ones
   (`ActionHash(type, bytes) == action.hash`, section 5.1), and the action
   type is one the gate is configured for. Exact match, no semantics.
4. `now < valid_until`, `valid_until` is well below the DA retention, and an
   Authorization's `expires <= valid_until`.
5. The nonce is unused, and it is marked used atomically with issuing the
   Authorization: at most one Authorization per `(agent_pubkey, nonce)`, and
   it leaves the gate only after the mark is durable.
6. `commitment_hash` is computed over the canonical encoding and is not a
   field of the struct it hashes. Neither the decision nor the Authorization
   contains a transaction hash or rail reference.
7. The gate signs an Authorization only after 1 to 6 hold, under its own
   tags; gate, agent and executor keys never overlap.

### 4.1 Commitment (envelope key 1)

| Key | Name | Type | Limit | R/O | Scale | Semantics | Inv. |
|---|---|---|---|---|---|---|---|
| 1 | `version` | uint | `= 0` | R | - | Wire format version. | 6 |
| 2 | `agent_id` | tstr | 1..64, ID charset | R | - | Allowlist key. The gate checks `allowlist[agent_id] == agent_pubkey` (section 8.7). | 1 |
| 3 | `agent_pubkey` | bstr | exactly 32 | R | - | Raw Ed25519 public key (RFC 8032 encoding). Verifies `signature`. MUST pass G0 (canonical, not small order). | 1 |
| 4 | `nonce` | bstr | exactly 16 | R | - | 128 uniformly random bits. Registry key is `(agent_pubkey, nonce)`. | 5 |
| 5 | `issued_at` | uint | `> 0` | R | seconds | When the agent signed. MUST be after the anchor tx at `payload_ref.height` was included; the gate enforces this up to `skew_s` (rule K1, section 11.2). | 4 |
| 6 | `valid_until` | uint | `> issued_at`, TTL `<= MaxTTL(da)` | R | seconds | Hard expiry, and the only one. Every Authorization for this commitment has `expires <= valid_until`. | 4 |
| 7 | `scope` | map | section 4.2 | R | - | Which gate may authorize this commitment. | scope |
| 8 | `action` | map | section 4.3 | R | - | The exact action, by type and hash. The bytes travel next to the envelope (gate input) and inside the encrypted payload (replay). | 3 |
| 9 | - | - | - | - | - | **Retired** in draft.9 (was `constraints`). Never reused; present means `ErrUnknownKey`. | - |
| 10 | `payload_ref` | map | section 4.5 | R | - | DA locator of the payload blob. | 2 |
| 11 | `ciphertext_hash` | bstr | exactly 32 | R | - | `H(blob)` over the exact published blob bytes (section 9). | 2 |
| 12 | `plaintext_hash` | bstr | exactly 32 | R | - | `H(salt || plaintext)`, salt 32 bytes (section 9). | 2 |
| 13 | `payload_size` | uint | `1..2^27` | R | bytes | `len(blob)`. Bounds every fetch. Never compared with `da`. | 2 |

There is no field for the commitment hash, the signature, any transaction
hash or any rail reference (invariant 6). Unknown keys are rejected, so none
can be smuggled in. `payload_ref.commitment` is a DA blob commitment, not a
transaction hash.

Key numbering rule: a field whose meaning is unchanged keeps its key; a
removed field's key is retired and never reused, in every map (commitment,
action, scope, receipt, payload), without exception.

### 4.2 Scope (commitment key 7)

| Key | Name | Type | Limit | R/O | Semantics |
|---|---|---|---|---|---|
| 1 | `gate_id` | tstr | 1..64, ID charset | R | MUST equal the gate's own id (rule C1). |
| 2 | - | - | - | - | **Retired** in draft.9 (was `rail`). |
| 3 | - | - | - | - | **Retired** in draft.9 (was `account`). |
| 4 | - | - | - | - | **Retired** in draft.9 (was `chain_id`). |

Threat note: scope binds only the gate. Account, chain and broker binding
moved into the action bytes, where the profile defines it and the executor
checks it (section 16). A gate in front of two accounts of one broker
therefore authorizes an order for either account; the executor of each
account refuses an order that names the other.

### 4.3 Action (commitment key 8)

| Key | Name | Type | Limit | R/O | Semantics |
|---|---|---|---|---|---|
| 1, 2 | - | - | - | - | **Retired** in draft.9 (were `kind` and `params`). Never reused; present means `ErrUnknownKey`. |
| 3 | `type` | tstr | 3..128 bytes, media-type grammar (section 4.6) | R | What the action bytes are, for example `application/vnd.edicta.ibkr.order.v0+cbor`. Not interpreted by the core: the gate only checks that it is in its configured set (rule C2). |
| 4 | `hash` | bstr | exactly 32 | R | `ActionHash(type, action_bytes)` (section 5.1). |

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

### 4.4 Constraints (retired)

Commitment key 9 is retired in draft.9. `max_notional` and `price_bound` were
static self-consistency checks on an exactly matched order; semantic bounds are
now profile or executor rules (the dca-agent profile has an operator risk
limit in its executor). `deadline` is gone: `valid_until` is the only expiry,
and an Authorization never outlives it.

### 4.5 PayloadRef (commitment key 10)

Keys 1 to 4 exist for both DA types; `da` selects the meaning of keys 3 and
4. Key 5 exists only for `da = 2`.

| Key | Name | Type | Limit | R/O | `da = 1` (fibre) | `da = 2` (celestia_blob) |
|---|---|---|---|---|---|---|
| 1 | `da` | uint enum | `{1, 2}` | R | Fibre blob anchored by `MsgPayForFibre` (PFF) | L1 blob paid by `MsgPayForBlobs` (PFB), share version 1 |
| 2 | `namespace` | bstr | exactly 29 | R | Namespace in the PaymentPromise | Namespace of the blob |
| 3 | `commitment` | bstr | exactly 32 | R | Fibre blob commitment (rsema1d) | Share commitment of the share-version-1 blob |
| 4 | `height` | uint | `> 0` | R | L1 height at which the PFF was included | L1 height at which the PFB was included |
| 5 | `signer` | bstr | exactly 20 | R if `da = 2`; not defined if `da = 1` | Not defined (`ErrUnknownKey`) | Raw 20-byte account address of the PFB signer, embedded in the blob's first share. Not bech32 text. |

Details, sources and the namespace rule are in section 10.

### 4.6 Charsets and grammars

| Name | Characters | Used by |
|---|---|---|
| ID | `A-Z a-z 0-9 . _ : / -` | `agent_id`, `gate_id` (commitment, Authorization, receipt), receipt `rail_ref` |
| media type | `name "/" name`, `name = [a-z0-9][a-z0-9!#$&^_.+-]*`: lower case, exactly one `/`, no parameters (`;`), no whitespace (RFC 6838 restricted-name characters, lower case only) | `action.type` (3..128 bytes), payload `action.type` (3..128) and `media_type` (1..64, section 9.3) |

Lengths are in bytes, which equals characters because every charset is ASCII.
Restricting identifiers to ASCII prevents look-alike scopes such as a
`gate_id` with a Greek omicron in place of `o` (vector `gate_id_unicode`).
`action.type` is checked first for its length (D18, `ErrFieldSize`), then for
the grammar (D19, `ErrInvalidString`). The shortest type is `a/b` (3 bytes).

The draft.8 section 4.7 (scales and notional arithmetic) moved to the
dca-agent profile; the core has no amounts.

## 5. Hashing and signing (byte-exact)

```
canon            = the canonical CBOR bytes of the Commitment map (envelope key 1 value)
commitment_hash  = H( 0x1d || "edicta/v0/decision-commitment" || canon )         ; 32 bytes
signed_message   = 0x0d || "edicta/v0/sig" || commitment_hash                    ; 46 bytes
signature        = Ed25519-Sign(agent_sk, signed_message)                          ; 64 bytes
envelope         = canonical CBOR of { 1: <canon spliced verbatim>, 2: signature }
```

| Rule | Statement | Inv. |
|---|---|---|
| H1 | `commitment_hash` is computed over `canon` only, never over the envelope. The signature is outside the hashed struct. | 6 |
| H2 | The decoder has already proven `canon` is canonical (rule D21), so hashing the received bytes and hashing a re-encoding give the same result. Implementations MAY do either. | 6 |
| H3 | The hash has a length-prefixed domain tag, so it cannot collide with a receipt, action or Authorization hash or any other Edicta hash over the same bytes. | 6 |
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
keys remain allowed by G0 in v0; the cofactorless rule pins their outcome too.
Vector: `sig_torsion_r`.

Threat note: a signature over the raw CBOR would tie verification to one
encoder and lets a lenient decoder accept a second encoding that verifies.
Signing a fixed 46-byte tagged message removes both problems. Ed25519
signatures are deterministic, so every vector signature is reproducible from
the RFC 8032 test seed.

Worked example (vector `minimal_lmt`, signer `agent1` = RFC 8032 TEST 1;
`canon` is 351 bytes, the envelope 420):

```
canon[0:8]       ac 01 00 02 6b 64 63 61     ; map(12), 1: 0, 2: tstr(11) "dca..."
canon key 8      08 a2 03 78 29 "application/vnd.edicta.ibkr.order.v0+cbor"
                    04 58 20 f6629c23488afdd088b035154e2e546c1ecced95d976443b1c8b9b9ad43361fb
commitment_hash  e2ea62234c504e4df72e172c8e0da5f02a1eeb784ccd39ac9e20f6dd4c7c8f1d
signed_message   0d6564696374612f76302f736967 || commitment_hash
signature        37a1f97bfc37eb4988a05b6ac66582939032f2d83c722eaab0d17bfe7e1f0c99
                 ed8bc1677d820ca8eafac46c488646ce5945f972745790c340c40ffcac1ce307
```

### 5.1 Action hash

```
TagAction    = "edicta/v0/action"                                   ; 16 bytes, tag(t) = 0x10 || ASCII
action_hash  = H( 0x10 || "edicta/v0/action"
                  || uint8(len(action_type)) || action_type
                  || action_bytes )                                 ; 32 bytes
ActionHash(action_type, action_bytes) -> action_hash, or ErrActionSize, ErrInvalidString
```

| Rule | Statement | Inv. |
|---|---|---|
| AH1 | `action_type` is inside the preimage, after a one-byte length (`len <= 128`). An executor recomputes the hash with the type it expects, so bytes committed under another type never match, and the Authorization need not carry the type. The length byte makes `type \|\| bytes` split one way only. | 3 |
| AH2 | `action_bytes` run to the end of the preimage; no length prefix is needed. They are hashed exactly as supplied: never parsed, normalized or re-encoded. | 3 |
| AH3 | `1 <= len(action_bytes) <= 65536` (`MaxActionSize`), checked before hashing (`ErrActionSize`); `action_type` passes the section 4.6 grammar (`ErrInvalidString`). | 3 |
| AH4 | Comparison of a recomputed hash with a committed one is constant-time. | 3 |

Threat notes:
- The hash is not hiding: it is public in the commitment, and low-entropy
  action bytes (an order with a few plausible quantities and prices) can be
  found by trying candidates. The payload's `plaintext_hash` is salted; the
  action hash is deliberately not, so any executor can recompute it from the
  bytes alone. A profile that needs hiding adds a random field to its own
  format.
- Type confusion: without AH1, an attacker could present the committed bytes
  to an executor of another format whose parser reads them differently. With
  the type in the preimage, that executor recomputes under its own type and
  gets another hash.

Worked example (`minimal_lmt`; the action is the minimal IBKR order of the
dca-agent profile, 44 bytes):

```
action_type      application/vnd.edicta.ibkr.order.v0+cbor            ; 41 bytes (0x29)
preimage prefix  10 6564696374612f76302f616374696f6e 29 6170706c...63626f72   ; 58 bytes
action_bytes     a80169445531323334353637021a00040d7e0401051a000186a00601071b000000046f77ee8008635553440901
action_hash      f6629c23488afdd088b035154e2e546c1ecced95d976443b1c8b9b9ad43361fb
```

Vectors: every `valid.json` case carries `action_type`, the bytes
(`action_hex`, or a pattern for large actions), `action_preimage_prefix_hex`
and `action_hash_hex`; stage A rejects of `reject.json`.

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
| D15 | Every key is defined for its map; retired keys are not defined. In `payload_ref`, key 5 (`signer`) is not defined when `da == 1` | `ErrUnknownKey` | `unknown_top_key`, `unknown_action_key`, `unknown_payload_ref_key`, `unknown_envelope_key`, `signer_on_fibre`, `retired_constraints_key`, `retired_action_kind_key`, `retired_action_params_key`, `retired_scope_rail_key`, `retired_scope_account_key`, `retired_scope_chain_id_key`, `draft8_minimal_lmt_envelope` |
| D16 | Every value has the major type in the schema. A negative integer where a uint is expected, a bstr for a tstr, or an array for a map are all type errors | `ErrWrongType` | `nint_payload_size`, `bstr_for_tstr`, `array_for_scope`, `action_hash_tstr`, `signer_bech32_tstr` |
| D17 | Every required key is present. In `payload_ref`, key 5 (`signer`) is required when `da == 2` | `ErrMissingField` | `missing_nonce`, `missing_action_hash`, `missing_height`, `missing_locator_commitment`, `missing_locator_signer`, `missing_signature` |
| D18 | Byte and text strings are within their length limits | `ErrFieldSize` | `nonce_15_bytes`, `sig_63_bytes`, `namespace_28_bytes`, `share_commitment_31_bytes`, `fibre_commitment_33_bytes`, `signer_19_bytes`, `signer_32_bytes`, `agent_id_empty`, `agent_id_65_chars`, `action_type_129_chars`, `action_type_empty`, `action_type_2_chars`, `action_hash_31_bytes` |
| D19 | Text strings use their charset or grammar (section 4.6) | `ErrInvalidString` | `gate_id_unicode`, `action_type_uppercase`, `action_type_space`, `action_type_no_slash`, `action_type_two_slashes`, `action_type_parameter`, `action_type_bad_first_char`, `action_type_unicode` |
| D20 | **Retired** in draft.9 (was: `action.kind` names a known params schema, `ErrUnsupportedActionKind`). The action type is opaque at decode time; an unknown type is a gate configuration matter (rule C2) | - | - |

Within one map, keys are visited in ascending order; for each key D15, D16,
D18, D19 apply, then nested maps recurse; D17 is checked after the map.

The `signer` conditions read `da` (key 1), which precedes key 5 in canonical
order, so they are decided in a single pass. If `da` is neither 1 nor 2,
`signer` is optional at stage D and S3 rejects the `da` value
(`ErrInvalidEnum`, vectors `da_0`, `da_3`, which carry a signer).

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
state at check time (section 11). Normative order:

| Rule | Check | Sentinel | Vectors | Inv. |
|---|---|---|---|---|
| S1 | `version == 0` | `ErrUnsupportedVersion` | `version_1` | 6 |
| S2 | Every uint field `<= 2^63-1` | `ErrIntRange` | `height_2pow63` | 2, 4 |
| S3 | `da in {1,2}` | `ErrInvalidEnum` | `da_0`, `da_3`, `da_256` | 2 |
| S4, S5 | **Retired** in draft.9 (rail, order type) | - | - | - |
| S6 | Nonzero: `issued_at`, `height`, `payload_size` | `ErrZeroValue` | `issued_at_0`, `height_0`, `payload_size_0` | 2, 4 |
| S7 | `payload_size <= 2^27` | `ErrPayloadTooLarge` | `payload_size_2pow27_plus1` | 2 |
| S8 | `namespace` is a valid user blob namespace (section 10.3) | `ErrInvalidNamespace` | `namespace_version_1`, `namespace_nonzero_prefix`, `namespace_reserved` | 2 |
| S9, S10, S11 | **Retired** in draft.9 (limit price, account, chain id) | - | - | - |
| S12 | `valid_until > issued_at` | `ErrTimeOrder` | `valid_until_eq_issued`, `valid_until_lt_issued` | 4 |
| S13 | **Retired** in draft.9 (deadline) | - | - | - |
| S14 | `valid_until - issued_at <= MaxTTL(da)` (section 11) | `ErrTTLTooLong` | `ttl_3601`, `ttl_ok_at_4h_rejected_at_10m`, `ttl_floor_division` | 4 |
| S15, S16 | **Retired** in draft.9 (price bound, notional) | - | - | - |

Retired rule ids are never reused, so a test or log line that names one is
unambiguous across drafts. The order and IBKR rules that S3, S5, S6, S9, S15
and S16 used to apply to the order now live in the dca-agent profile.

S2 keeps every value representable as a signed 64-bit integer, so SQL
stores, JSON consumers and languages without unsigned types handle them
without loss.

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
each entry passes the section 4.6 grammar):

| Rule | Check | Sentinel | Vectors |
|---|---|---|---|
| C1 | `scope.gate_id == gate.gate_id` | `ErrScopeMismatch` | `foreign_gate_id` |
| C2 | `action.type` is in `gate.action_types`, by bytewise equality | `ErrActionTypeNotAllowed` | `action_type_not_allowed`, `action_type_suffix_differs` |
| C3 | `payload_ref.da` is in the gate's configured DA set (`allowed_da`); an unset set means `{1, 2}` | `ErrDANotAllowed` (package `gate`) | none (gate configuration; gate tests) |
| C4 | `da = 1` only, and only on a gate with a `da = 1` committer: `payload_size <= fibre_max_data_bytes` (section 10.4, Fibre payload limit; default 16 MiB) | `ErrPayloadAboveCap` (package `gate`) | none (gate configuration; gate tests) |

C3 and C4 are gate rules, not part of `VerifyForGate`: the gate evaluates
them, C3 first, right after `VerifyForGate` succeeds and before stage 2 of
section 8.7, so they are never an oracle for unsigned input. C4 does not
apply to a gate without a `da = 1` committer (it delegates P3 and never
encodes), so every existing vector keeps its outcome. With `allowed_da` unset, C3 always
holds, so every existing vector keeps its outcome. A gate that does not
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

### 8.4 Stage A: action match

`CheckAction(c, action_bytes)`, on the bytes the caller supplied with the
envelope:

| Rule | Check | Sentinel | Vectors |
|---|---|---|---|
| A0 | `1 <= len(action_bytes) <= 65536`, before hashing | `ErrActionSize` | `action_empty`, `action_too_large` |
| A1 | `ActionHash(c.action.type, action_bytes) == c.action.hash` (section 5.1), constant-time | `ErrActionMismatch` | `action_byte_flipped`, `action_truncated`, `action_extra_byte`, `action_qty_differs`, `action_reencoded_noncanonical`, `action_hash_of_other_type`, `action_hash_untagged`, `action_hash_type_unprefixed`, `action_hash_bare_sha256` |

Exact match, no semantics (invariant 3). `action_qty_differs` and
`action_reencoded_noncanonical` show the consequence: an order that differs in
one field, or the same order in a non-canonical encoding, is simply other
bytes. Each stage A vector carries `committed_preimage_hex`, so a checker can
see that exactly one thing is wrong: either the supplied bytes, or the way the
committed hash was built.

### 8.5 Stage P: payload bytes

`CheckPayload(c, blob)`, given the bytes from DA or the archive, then the DA
commitment check:

| Rule | Check | Sentinel | Vectors |
|---|---|---|---|
| P1 | `len(blob) == payload_size`, checked first and cheaply. A source that returns more bytes is rejected before hashing | `ErrPayloadSizeMismatch` | `blob_truncated` |
| P2 | `H(blob) == ciphertext_hash` | `ErrPayloadHashMismatch` | `blob_flipped_byte`, `blob_with_share_padding` |
| P3 | The DA commitment recomputed from `blob` equals `payload_ref.commitment` (`da = 2`: section 10.5; `da = 1`: section 10.4). MUST hold on every path the gate accepts bytes from; how it is established depends on the path and `da` (table below) | `ErrDACommitmentMismatch` (gate) | `da_blob.json`, `da/fibre_commit.json` (Go only) |

P1, P2 and P3 run in this order on each path, cheapest first. P1 and P2 live in
package `commitment`; P3 lives in the gate (`DACommitter`, keyed by `da`).

| Path (Authorization `path`) | `da` | When the gate may use it | P3 is established by |
|---|---|---|---|
| DA, `path = 1` | 2 `celestia_blob` | K2 holds (section 11.2) | The gate itself: `CreateCommitment(NewV1Blob(namespace, blob, signer), RFC6962, 64)` (section 10.5). The node is trusted for nothing about the bytes. |
| DA, `path = 1` | 1 `fibre` | K2 holds | With a `da = 1` committer (required for a gate whose configured DA is `fibre`, below): the gate itself, `fibre.NewBlob(blob, DefaultBlobConfigV0()).ID().Commitment() == payload_ref.commitment` (section 10.4), whichever client or bridge returned the bytes. Without one (a library gate with `allowed_da` unset): delegated to the operator's own node, which downloads `BlobID = 0x00 \|\| payload_ref.commitment` and verifies every row against it; that `Download` never returns partial or unverified data and returns exactly the submitted bytes (header and row padding stripped) was VERIFIED on Mocha on 2026-10-05 with the client at the pin. The delegated form is a self-check and proves nothing to a party that distrusts that node. |
| Archive, `path = 2` | 2 | K2 fails, or the DA path failed for any reason (not found, error, timeout, P1/P2/P3 failure) | The gate itself, on the full archived blob, as for the DA path. Mandatory: an archive copy is accepted only if P1, P2 and P3 all pass. |
| Archive, `path = 2` | 1 | As for `da = 2` | The gate itself, with its `da = 1` committer, as on the DA path. Mandatory, as for `da = 2`. A gate without a `da = 1` committer MUST refuse with `ErrArchiveRecomputeUnsupported` **before fetching**. |

Committers (normative, `v0-draft.17`). The gate holds at most one DA committer per `da`. `ErrArchiveRecomputeUnsupported` means exactly: the archive path is needed and the gate has no committer for this `da`. A gate whose configured DA (section 7, single DA per instance) is `fibre` MUST have a `da = 1` committer, MUST use it on both paths, and MUST refuse to start without one. A library gate with `allowed_da` unset and no `da = 1` committer keeps the draft.16 behaviour, which is what the `da = 1` cases of `anchor.json` describe; `spec/vectors/da/fibre_commit.json` restates those cases for a gate with the committer (route `archive`). The `da = 1` committer lives in a Go module separate from the core, so that the core and `celestia_blob` users never import celestia-app. It is pure computation, copies its input (`NewBlob` takes ownership of the slice and may reuse it as row storage) and refuses a blob above a configured size cap before encoding, because encoding needs about 12 times the data size in memory; the cap MUST be at least the Fibre payload limit of the Recorder in the same deployment. A blob that is empty, above the cap or above the Fibre maximum (`2^27 - 5` bytes, while S7 allows `2^27`) gives `ErrDACommitmentMismatch`: no commitment can be computed for it, and no such blob can have been anchored (vectors `fibre_empty`, `fibre_size_134217724`).

Threat note (P3, "anchor X, sign H(Y)"). An agent or a Recorder (1) anchors
blob X at height H, (2) writes blob Y to the archive, (3) signs a commitment
with `payload_ref.commitment = C(X)` and `ciphertext_hash = H(Y)`. On the DA
path the DA layer serves X, so P2 fails. On the archive path P2 alone accepts
Y, and the gate would authorize on a payload that was never public. P3 computes
`C(Y) != C(X)` and rejects (vector `anchor_x_sign_hash_y` in `da_blob.json`; for `da = 1`, `fibre_anchor_x_sign_hash_y` in `da/fibre_commit.json`).
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

### 8.6 Normative pipeline (stateless part)

`VerifyForGate(envelope, now, gate, params)` = `params.Validate()`, then
D, S, G, T, C. Then the gate calls `CheckAction(c, action_bytes)` for the
bytes it was given and `CheckPayload` for the fetched blob. `Params.Validate` requires
`fibre_retention_s` and `blob_retention_s` in `1..2^63-1` and `skew_s` in
`0..300`; otherwise `ErrInvalidParams` (Go unit tests only).

### 8.7 Gate authorization order (stateful stages)

The gate verifies and authorizes; it never executes and holds no rail
credentials. Its input is the envelope bytes and the action bytes; it never
accepts a decoded struct from its caller. Its output is a signed
Authorization (section 15). A gate in strict mode issues an Authorization only
if every stage below passes, in this order. An implementation MUST NOT report
a later stage's sentinel when an earlier stage fails.

| # | Stage | Rule | Check | Sentinel | Inv. |
|---|---|---|---|---|---|
| 1 | D, S, G, T, C | section 8.6, C3 | `VerifyForGate` with `now` read once from the gate clock and params read from chain state; C includes C2 (action type allowed); then C3 (DA allowed) and C4 (`da = 1` payload cap), section 8.3 | stage D to C sentinels, `ErrDANotAllowed`, `ErrPayloadAboveCap` | 1, 4, 6 |
| 2 | E | E1 | `issued_at > epoch + skew_s`, where `epoch` is the gate clock when the nonce registry was created, persisted inside the registry in its creation transaction and never rewritten | `ErrBeforeRegistryEpoch` | 5 |
| 3 | L | L0, L1, L2 | `agent_pubkey` is not a gate key: not the gate's own key (which signs Authorizations and receipts) and not any gate key in its configuration (L0). The allowlist has `agent_id` (L1), and maps it to exactly `agent_pubkey` (L2). Checked in the order L0, L1, L2, after G, so it is never an oracle for unsigned input | `ErrAgentKeyIsGateKey`, `ErrAgentNotAllowed`, `ErrAgentKeyMismatch` | 1, 7 |
| 4 | A | A0, A1 | `CheckAction(c, action_bytes)` on the supplied bytes (section 8.4) | `ErrActionSize`, `ErrActionMismatch` | 3 |
| 4a | AR | AR1 to AR4 | Archive the decision before any Authorization exists (below): write `envelope` and `action_bytes` under `commitment_hash`, idempotently, and wait until the write is durable. Required for a gate with an archive configured (every `edictad` gate); a library gate without one skips this stage. Writes nothing to the nonce registry | `ErrArchiveUnavailable` (503, `Retry-After`) | 2, 5 |
| 5 | N0 | N1 | No registry entry exists for `(agent_pubkey, nonce)`. Advisory; stage 12 is authoritative. If one exists, the retry rule below applies | `ErrNonceUsed` | 5 |
| 6 | K | K0 | The anchor tx exists at `payload_ref.height` (section 10.4 for `da = 1`: found by scanning that block, result code 0; 10.5 for `da = 2`), and the header time `T_H` is readable | `ErrAnchorNotFound` | 2 |
| 7 | K1 | K1 | Section 11.2 | `ErrIssuedBeforeAnchor` | 4 |
| 8 | K2 | K2 | Section 11.2. Selects the DA or archive path only, never a rejection by itself | none | 2, 4 |
| 9 | P | P1, P2, P3 | Section 8.5, per path | P sentinels, precedence in 8.5 | 2 |
| 10 | T' | T1, T2 | `CheckTime` again with a fresh clock reading `authorized_at`, because fetches take time | `ErrNotYetValid`, `ErrExpired` | 4 |
| 11 | Z | Z1 | Build the Authorization (section 15.1): `commitment_hash`, `action_hash = c.action.hash`, the gate's `gate_id`, `expires = min(valid_until, authorized_at + MaxAuthorizationTTL)`, `path` of stage 9. Sign it with the gate key under `TagAuthorizationSig` and verify the signature before use. Nothing is stored yet | (operational: signer error, timeout) | 7 |
| 12 | N | N1 | Atomically create the registry entry for `(agent_pubkey, nonce)` holding `commitment_hash` and the canonical SignedAuthorization; fails if the key exists. Committed durably before stage 13 | `ErrNonceUsed` | 5 |
| 13 | R | | Return the SignedAuthorization bytes | - | - |

`MaxAuthorizationTTL` is gate configuration (default 300 s) and MUST exceed
`skew_s`. Stage 10 enforces `authorized_at + skew_s < valid_until`, so a fresh
Authorization passes an executor whose clock agrees with the gate's.

Retry rule (normative). When stage 5 or stage 12 finds an existing entry for
`(agent_pubkey, nonce)`, the gate returns `ErrNonceUsed`, and returns the
stored SignedAuthorization with it **only if** both hold:
1. the stored `commitment_hash` equals the hash of the presented envelope; and
2. `ActionHash(c.action.type, presented action bytes)` equals the stored
   Authorization's `action_hash`.

Otherwise nothing from the stored entry is returned. If (2) fails, the result
is the normal mismatch error `ErrActionMismatch`; if (1) fails, `ErrNonceUsed`
alone. A same-commitment retry receives the same bytes as the first answer,
so there is still exactly one Authorization per `(agent_pubkey, nonce)`
(invariant 5).

Precedence (normative): the stage order decides. Stage A runs before any
registry read, so bytes that do not hash to the presented commitment's
`action.hash` give `ErrActionMismatch` whether or not the nonce is used, and
no registry read happens. Bytes that pass A1 on a used nonce give
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

Archive before authorize (normative since `v0-draft.17`):

| Rule | Requirement |
|---|---|
| AR1 | The record is keyed by `commitment_hash` and holds the envelope bytes and the action bytes exactly as presented. Nothing else is required before stage 11; the Authorization, its path and the K2 inputs are written after stage 12 (section 10.7). |
| AR2 | Idempotent. The same bytes under an existing key succeed without a change. The archive never overwrites: different bytes under an existing key are a conflict. Because G and A1 run first, a conflict on the action bytes is impossible (equal `commitment_hash` fixes `action.hash`); envelopes can differ only by a second valid signature of the agent key over the same hash (G2 rules out malleated `S`), and the gate treats that conflict as success, keeping the stored record, which verifies equally. Any other conflict is an archive fault: `ErrArchiveUnavailable`, nothing signed. |
| AR3 | Failure, timeout or an archive the gate cannot reach: answer `ErrArchiveUnavailable` (HTTP 503 with a `Retry-After` header, section 18.3). The nonce is not consumed and nothing is signed, so the same request can be retried unchanged. |
| AR4 | No fallback: a gate with an archive configured MUST NOT issue an Authorization whose decision record is not durable, whatever its mode. |
| AR5 | Rejection marker. When a request whose decision record exists (stage 4a passed) is then refused with a verdict, the gate marks that record rejected with the error name exactly as listed in section 12 (for example `ErrExpired`, `ErrIssuedBeforeAnchor`, `ErrNonceUsed`), its `gate_id` and the gate clock at refusal. Verdicts are the sentinels of stages 5 to 12. Operational failures (`ErrChainUnavailable`, `ErrArchiveUnavailable`, a signer error or timeout) say nothing about the decision and are not marked. The marker is archive metadata of the gate: not signed, not in any wire format, no vector changes. |
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
published envelope but not the committed action bytes cannot store wrong
bytes under its key first and lock the real request out. A request that
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
records are not specified in v0.

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
is covered by the retry rule. The draft.8 order
(consume, then execute) could burn a nonce with no outcome; this order cannot.

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
as a gate key, never both. Domain separation already makes a gate signature
useless as a commitment signature and vice versa (`edicta/v0/sig` versus
`edicta/v0/authorization-sig` and `edicta/v0/receipt-sig`, over hashes under
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

## 9. Payload blob and its hashes

The blob is the canonical CBOR encoding (same profile, arrays allowed) of:

```
{ 1: version      uint = 0,
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

Vectors: `ciphertext_hash_small_blob` (the blob of `minimal_lmt`),
`plaintext_hash_basic`, and the three payload rejects.
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
                                     aad = tag("edicta/v0/payload"),         ; 18 bytes, 0x11 || ASCII
                                     pt  = salt || plaintext)                 ; RFC 8439, 16-byte tag appended
for each recipient i, in producer order, with X25519 public key pkR_i and label kid_i:
  enc_i, ctx_i  = SetupBaseS(pkR_i, info = tag("edicta/v0/payload-dek"))   ; 22 bytes, 0x15 || ASCII
  wrapped_dek_i = ctx_i.Seal(aad = uint8(len(kid_i)) || kid_i, pt = DEK)   ; sequence 0, 48 bytes
blob        = canonical CBOR { 1: 0, 2: [ {1: kid_i, 2: enc_i, 3: wrapped_dek_i} ... ], 3: aead_nonce, 4: ciphertext }
```

| Item | Value |
|---|---|
| HPKE suite | RFC 9180 mode_base (`0x00`); KEM DHKEM(X25519, HKDF-SHA256) `0x0020`; KDF HKDF-SHA256 `0x0001`; AEAD ChaCha20Poly1305 `0x0003` (the suite of RFC 9180 Appendix A.2). No PSK, no auth mode. |
| `enc` | The 32-byte serialized ephemeral X25519 public key (`SerializePublicKey`). |
| Recipients | 1..16 entries. `kid` is an opaque byte string of 1..32 bytes chosen by the producer; kids are pairwise distinct within one blob. Order is the producer's and carries no meaning; it is not sorted. |
| Size | A producer MUST NOT emit a blob longer than `2^27 - 5` bytes (the Fibre data maximum, section 10.2); `payload.ErrTooLarge`. Readers accept up to `2^27` (B0). |
| Randomness | `DEK`, `aead_nonce`, `salt` and every HPKE ephemeral key come from a CSPRNG. Test vectors fix them from labels (section 13); no production API may accept them from the caller. |

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
  read each decision (auditor, counterparty) and link payloads. v0 guidance:
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
| B2 | `version` is a uint; a uint other than `0` is `blob.ErrVersion` | `blob.ErrVersion` (`blob.ErrMalformed` if not a uint) | `pb_blob_version_1` |
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
kids with the same sentinels. The pre-existing `payload.json` blob
`ciphertext_hash_small_blob` conforms to B0..B7 (checked by the Python
checker).

Threat note: two readers that disagree on what a blob contains could be shown
different recipient lists or ciphertexts from the same `ciphertext_hash`.
A fixed layout with one encoding per blob removes that room.

### 9.3 Payload plaintext

`plaintext` is the canonical CBOR (section 3 profile) of:

```
Payload = { 1: version     uint = 0,
            2: model       Model,
            3: policy      Policy,
            4: context     Data,                 ; REQUIRED
            5: action      PayloadAction,        ; the cleartext action; O8 ties it to commitment key 8
            ; 6 retired in draft.9 (was constraints)
            7: metadata    Data (O) }
PayloadAction = { 3: type tstr 3..128 (media-type grammar, section 4.6), 4: data bstr 1..65536 }   ; 1, 2 retired
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
| Depth, entries | Payload 1; model, policy, context, action, metadata 2. At most 16 entries per map. |
| Size | No limit of its own; the blob bound (section 9.1) applies. |

Decoding: any profile, schema, limit, charset or media type failure, or a
re-encoding that differs from the input, is `payload.ErrMalformed`. If the
bytes are a well-formed canonical payload except that `version != 0`, the
result is `payload.ErrVersion`. Input with several defects may yield either.

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
- The salt is not a CBOR field. It is the fixed 32-byte prefix of the AEAD
  plaintext (section 9), so `salt || plaintext` splits one way only.

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
| O6 | ChaCha20-Poly1305 open of `ciphertext` with the DEK, `aead_nonce` and `aad = tag("edicta/v0/payload")` | `blob.ErrDecrypt` | `pb_flipped_ciphertext`, `pb_flipped_aead_tag`, `pb_flipped_aead_nonce`, `pb_aead_aad_*` |
| O7 | `H(aead_plaintext) == plaintext_hash`, over the full decrypted bytes as they are, **before any parsing** | `sdk.ErrPlaintextHashMismatch` | `pb_plaintext_hash_unsalted`, `pb_plaintext_hash_of_other_salt`, `pb_key_commitment_two_deks` |
| O8 | `aead_plaintext[32:]` decodes as a Payload (section 9.3); then `payload.action.type == c.action.type` (bytewise) and `ActionHash(payload.action.type, payload.action.data) == c.action.hash` (section 5.1) | `payload.ErrMalformed`, `payload.ErrVersion`, then `sdk.ErrPayloadMismatch` | `pb_payload_*` |

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
| W1 | The payload plaintext re-decodes under section 9.3, and its `action` matches the commitment's key 8 as in O8 | refuse (`payload.ErrMalformed`, `sdk.ErrPayloadMismatch`) |
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

`da = 1` (`v0-draft.17`): there is no `signer` and no blob commitment proof
for a Fibre payload. The evidence equivalent to step 3 is the PFF tx at
`height` (section 10.4), proven against that header's data root by a tx
inclusion proof; a serving API and an offline verifier for that proof are
`UNVERIFIED` (section 10.7). Until they are settled, a `da = 1` producer
MUST have its submitter under the same operator and runs W5 at `SelfCheck`
level or omits it; a hosted `da = 1` submitter is not supported in v0.

Trust levels, in decreasing strength:

| Level | Header source | Assumption | Allowed |
|---|---|---|---|
| `Light` | Light-client verification as in step 2 | A trust anchor (height and hash) inside its trust period, which is below the chain's unbonding time; more than 2/3 of voting power honest at H; one honest provider among primary and witnesses (equivocation is detected only with an honest witness) | Always |
| `CrossCheck` | The header of H (hash, data root, time) from two or more independent providers that agree bytewise | Non-collusion of the providers; no signature is checked. Weaker: it MUST be identified as such in configuration and logs | As an interim substitute for `Light`, at either trust relation |
| `SelfCheck` | The operator's own node | The operator's own node is honest | Only when submitter and producer are under one operator |

When submitter and producer are under one operator, W5 MAY use the operator's
own node, or MAY be omitted; then the producer relies on its Recorder for
`height` and `T_H`, as before `v0-draft.10`. When the submitter is a
different party (a hosted relay, another operator), W5 MUST be performed at
level `Light` or `CrossCheck`, and a producer MUST refuse to start with
`SelfCheck` or without W5.

`CrossCheck` source identity (v0 minimum). Independence is counted per
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

## 10. payload_ref, Fibre and L1

### 10.1 Pins

| Repo | Tag | Commit | Why |
|---|---|---|---|
| celestiaorg/celestia-app | `v10.4.0-mocha` | `5187d2fb5eb8bc4b534c74724882943c54253ae9` | Latest v10 tag on 2026-10-03; contains `x/fibre`, `fibre/`, `x/blob`. Same commit as `v10.4.0-corto`. |
| celestiaorg/go-square | `v4.0.1` | `948e81207e45d7daa9b4c68a8a4931b9118eae9f` | Version required by the app pin's `go.mod`. Namespace and share commitment code. |
| celestiaorg/celestia-node | `v0.34.2-mocha` | `cd6cd46f00a572a7010fecc7e0dacf8a456982d2` | Latest node tag; pruning windows; Fibre and blob client APIs. |

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

Recompute (normative since `v0-draft.17`; celestia-app at the pin,
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
produced by upstream code only (section 13), including the live Mocha blob
`fibre_live_mocha_popsmin1` whose commitment was read from the chain. A
second-language gate links the same upstream code or reproduces every vector
bit for bit; the Python checker checks the file structure and the size
arithmetic, not the commitments.

Fibre payload limit (normative since `v0-draft.17`). Every component that
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

Submission (normative for v0). A Recorder submits `da = 1` blobs only
through the operator's own node (section 2: chosen and controlled by the
operator, not necessarily self-hosted), holding the escrow account key in
that node's keyring. A node or relay controlled by someone else is not
supported for `da = 1` submission in v0. Reason: the node signs the
`PaymentPromise` with the escrow key and runs the upload; a third party would
hold the key that pays and could spend the escrow on blobs of its own.
`recorder.ErrSubmitMismatch` (section 12) and W4 catch a substituted commitment, not
that spending. The
gate's reads (anchor, retention, download) may still use other endpoints
under the rules of section 10.9.

Anchor lookup (rule K0 for `da = 1`, normative since `v0-draft.17`). The gate
does not use the tx index (it may be disabled on a node, and the event query
needs a JSON-quoted base64 value):

1. Read block `height` (header and txs) and the results of its txs from the
   gate's node, under the at-height rules of section 10.9 (the block and the
   results echo `height`, the txs hash to the header's `data_hash`).
2. A tx is a candidate iff upstream `fibretypes.TryParseFibreTx` (`APP/x/fibre/types/classified_tx.go`)
   classifies it as a Fibre tx, its single `MsgPayForFibre` carries a
   `PaymentPromise` with `namespace == payload_ref.namespace`,
   `commitment == payload_ref.commitment`, `blob_version == 0` and
   `chain_id` equal to the gate's configured chain id.
3. A candidate counts only if its result code at `height` is 0. A PFF that
   failed in execution (for example an escrow too small to pay) settled no
   payment and is not an anchor. `UNVERIFIED`: whether such a tx can be
   included at all, given that the promise is checked in CheckTx and
   ProcessProposal, and whether its system blob still appears in the square.
4. If several candidates have code 0 (one blob paid twice in one block),
   the anchor is the one with the earliest `creation_timestamp`, ties broken
   by block order. They attest the same blob; the earliest timestamp gives
   the earliest `start` in K2, which is the conservative side.
5. No candidate: `ErrAnchorNotFound`. A transport or node failure, or a
   response that fails the at-height rules (section 10.9), is operational
   (`ErrChainUnavailable`), never `ErrAnchorNotFound`.

From the anchor the gate takes `PaymentPromise.creation_timestamp` for K2
(section 11.2) and `T_H` from the header of `height`. It MAY also check that
`PaymentPromise.blob_size` equals the upload size of `payload_size` and run
the certificate rule of section 10.6.1; P3 already implies the first, and
inclusion with code 0 implies that the chain accepted the second.

Threat note (lookup). Scanning one block costs at most one block of txs and
needs no index the operator may not run. Requiring code 0 keeps a PFF that
the chain rejected in execution from serving as evidence; matching
`chain_id` keeps a promise signed for another chain from matching, although
inclusion on this chain already implies it.

### 10.5 celestia_blob locator (`da = 2`)

Rule (normative, `v0-draft.3`): a `celestia_blob` payload MUST be published
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
  agent like any other field. Nothing in v0 ties `signer` to `agent_pubkey`
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

#### 10.6.1 Certificate rule for verifiers (`da = 1`, normative since `v0-draft.17`)

A verifier (the `verify` and `replay` tools, an auditor) that re-checks the
availability certificate without the chain, for example after the chain
pruned the validator history (about 8 h, below), applies these rules to the
archived PFF tx. They mirror the keeper at the pin
(`APP/x/fibre/keeper/msg_server.go` `validateValidatorSignatures`,
`APP/fibre/payment_promise.go`, `APP/fibre/validator/signature_set.go`;
VERIFIED, code), so that a verifier never rejects what the chain accepted for
a reason the chain does not have, and never accepts less. Any failure is a
verification failure; the verifier reports the first rule that failed.

| Rule | Check |
|---|---|
| CV1 | The archived tx parses as a Fibre tx (`TryParseFibreTx`) with exactly one `MsgPayForFibre`. |
| CV2 | Binding: `promise.namespace == payload_ref.namespace`, `promise.commitment == payload_ref.commitment`, `promise.blob_version == 0`, `promise.chain_id` equals the expected chain id, and `promise.blob_size == 4096 * row_size(payload_size)` (section 10.4). |
| CV3 | Promise well-formed and owner-signed, as `PaymentPromise.Validate`: `signer_public_key` is a 33-byte compressed secp256k1 key, `chain_id` is 1..20 bytes, `blob_size > 0`, `creation_timestamp` is not zero, `height > 0`, the owner signature is 64 bytes (`r \|\| s`) and verifies over `sign_bytes` below. |
| CV4 | Validator list `V`: the bonded validators of x/staking `HistoricalInfo` at `promise.height`, each with its Ed25519 consensus key and power `tokens` (the integer token amount, not the consensus power), sorted as CometBFT `NewValidatorSet` sorts: power descending, then address (the first 20 bytes of `SHA-256(pubkey)`) ascending. The order is positional: signature `i` belongs to `V[i]`. |
| CV5 | `len(validator_signatures) <= len(V)`. |
| CV6 | Quorum, exactly as the chain: `required = floor(2 * total / 3)` with `total` the sum of `V`'s powers. Walk `i = 0, 1, ...`; skip empty entries; a non-empty entry MUST verify as an Ed25519 signature by `V[i]` over `sign_bytes` (the Go `crypto/ed25519.Verify` equation, as rule G1) or the certificate is rejected; add `V[i]`'s power once; as soon as the sum is `>= required`, accept and stop (entries after that point are not checked, as on chain). If the walk ends below `required`, reject. |
| CV7 | `V` is the chain's: the CometBFT validator set committed by a header at `promise.height` (see below) holds exactly `V`'s keys, with consensus power `floor(tokens / 10^6)` for each. The header is tied to the chain by the header trust rules of section 10.6.2. |
| CV8 | Anchor (settlement), v0 level `node-attested` (below): the share-version-2 system blob for `(payload_ref.namespace, payload_ref.commitment)` is included in block `payload_ref.height` (proof against the data root of that header, trusted by section 10.6.2); the archived result of the PFF tx at that height has code 0; if the archive holds an inclusion proof of the PFF tx against `data_hash`, it MUST verify. |

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
  commits. VERIFIED (code). Decided for v0: every component applies the
  network rule (CV6) and never rejects what the network accepted; none
  adds `3 * signed > 2 * total` as a condition (one rule, below). Whether the network rule
  should be strict is an open question with the Fibre team.
- Token amounts versus consensus power: CometBFT and the light client use
  `floor(tokens / 10^6)`; the keeper sorts and counts by tokens. Two
  validators with equal consensus power but different tokens can be in a
  different order in the two lists, so a verifier that uses the CometBFT
  set alone can mis-assign signatures. That is why the archive keeps the
  `HistoricalInfo` set (section 10.7) and CV7 only cross-checks it.
  `UNVERIFIED`: the power reduction `10^6` on Celestia, and whether rounding
  at exactly two thirds can change a verdict between the two powers.
- Which header commits to `V`: `HistoricalInfo(h)` is written in BeginBlock
  of `h` from the validators of the previous EndBlock, which CometBFT
  applies one height later, so `V` is expected to equal the set behind
  `next_validators_hash` of the header at `promise.height` (the same as
  `validators_hash` of `promise.height + 1`). `UNVERIFIED`; in the 009 probe
  the set did not change around that height, so both matched. A verifier
  MUST accept either and MUST record which one matched.
- The chain itself can re-check the certificate only while x/staking keeps
  `HistoricalInfo` (`historical_entries` = 10000 blocks, about 7 h 56 min at
  2.855 s per block; VERIFIED, probe). After that only the archive can.

One threshold rule (normative since `v0-draft.17`). The gate (whenever it
checks a certificate: the optional check after K0 in section 10.4, and
fast mode once it is defined, `ErrCertInvalid` being reserved), the
Recorder (when it checks the certificate of a PFF it submits) and the
verifier MUST apply the same rule: accept iff CV6 accepts, and warn iff
`3 * signed <= 2 * total` (`cert_quorum_warning`, below). Given the same
PFF tx and validator set, all three MUST produce the same verdict and the
same warning. The warning never changes a verdict. In the Go code the rule
is one shared function that all three call, never a copy, so a change of
the network threshold is made in one place; a change of the rule itself is
a spec change. The gate and the Recorder surface the warning in logs and
metrics; no v0 wire field carries it.

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

Verifier report for `da = 1` (normative since `v0-draft.17`). Besides the
verdict, `verify` and `replay` report:

| Field | Value |
|---|---|
| `cert_signed_power` | Sum of the token powers of every non-empty entry that verifies, walking the whole list (not only up to the CV6 stop point). An entry after the stop point that fails is reported as a warning and does not change the verdict, because the chain never checked it. |
| `cert_total_power` | `total` of CV6. |
| `cert_signed_share` | `cert_signed_power / cert_total_power`, informational, printed with at least four decimals; comparisons use the integers. |
| `cert_quorum_warning` | `WARN` iff `3 * cert_signed_power <= 2 * cert_total_power`: the certificate passed the network rule but not the classic BFT "more than 2/3". The verdict stays valid. |
| `cert_valset_header` | Which header committed to `V` in CV7 (`next_validators_hash` at `promise.height`, or `validators_hash` at `promise.height + 1`). |
| `settlement` | `node-attested` in v0 (below); `failed` if CV8 fails. |
| `header_trust` | Section 10.6.2: the trusted header's height and hash, and the cross-check result. |

Settlement level `node-attested` (v0). Settlement means the PFF executed
with code 0 at `height`, so the escrow paid and the promise is on chain. In
v0 the verifier establishes it from three parts: the certificate (CV1 to
CV7, cryptographic given the validator set), the system blob at `height`
(cryptographic given the header), and code 0, which is only what the
Recorder's node reported when the archive was written. A verifier MUST
report it as `node-attested` and MUST NOT call it proven. Planned right after
v0 Fibre: a proof of code 0 against `last_results_hash` of the header at
`height + 1`, by recomputing the results Merkle root from the archived
results of block `height`; that level will be reported as `proven`.
Threat note: a node that lies about code 0 can make a PFF that failed in
execution look settled. The certificate and the system blob still show that
validators attested the blob and that the blob was in block `height`; what
is not proven is the payment. `UNVERIFIED`: whether a PFF with a nonzero
code can be included with its system blob at all (section 10.4, step 3).

Threat note (CV). The certificate is what turns "a tx was included" into
"validators holding the required stake attested custody of shards of this
blob". Inclusion already implies it under the honest-majority assumption,
because the chain checks it in CheckTx and ProcessProposal, not in
FinalizeBlock. CV lets a verifier check it without trusting the proposer and
the 2/3 that accepted the block, given a validator set it trusts through CV7.
It does not prove that validators still hold the shards (retention ends at
`pruneAt`), nor that the blob is the agent's payload (that is P2 and P3).

### 10.6.2 Header trust for verifiers (both `da`, normative since `v0-draft.17`)

The verifier works from the archive and needs headers it can trust: at
`payload_ref.height` (`T_H`, `data_hash`, the inclusion proofs) and, for
`da = 1`, at `promise.height` (and `promise.height + 1` when CV7 uses its
`validators_hash`). Archived headers are untrusted (the archive is trusted
for availability only). v0 ties them to the chain with a trusted header and
the hash chain, without signatures:

| Rule | Requirement |
|---|---|
| HT1 Trusted header | The auditor supplies a trusted header file: one header at height `T` with its hash, obtained out of band. `T` MUST be at least the highest height the verifier needs (`payload_ref.height`, or `promise.height + 1` if that is higher). A file with `T` below that is refused: forward verification from an older header is out of scope for v0. |
| HT2 Hash of the trusted header | The verifier recomputes the header hash (CometBFT `Header.Hash()`, the Merkle root of the header fields) and it MUST equal the hash in the file. |
| HT3 Backward chain | For each `k` from `T` down to the lowest needed height, the header at `k - 1` is accepted iff its recomputed hash equals `last_block_id.hash` of the accepted header at `k`. Headers between come from the archive, a file or any online source; they need no trust, because the chain checks them. Any break: the header trust fails. |
| HT4 No signatures | Commit signatures are not checked in v0: the trust comes from the trusted header and SHA-256 collision resistance, not from a validator set. |
| HT5 Archived headers | An archived header at a needed height is used only if its hash equals the one reached by HT3. |
| HT6 Cross-check (optional) | The verifier MAY additionally read the header at `T` (or at `payload_ref.height`) from one or more configured endpoints, under the at-height rules (section 10.9: the response echoes the height), and compare hashes. A mismatch fails the header trust. An unreachable endpoint is reported as `cross-check: not done`, never as a pass. |
| HT7 Verdict | Without a trusted header file, or if HT1 to HT3 fail, the verifier MUST NOT report the anchor as valid: it reports `header_trust: none` or the failed rule, and the overall verdict is not valid. The report always carries `T`, the trusted hash and the cross-check result. |

`UNVERIFIED`: that celestia-core at the pin computes `Header.Hash()` and
`last_block_id.hash` exactly as upstream CometBFT (the fields and their
order), so that a generic CometBFT implementation reproduces them.

Threat note (HT). The whole anchor proof rests on the trusted header: an
auditor who takes it from the party being audited proves nothing. With a
correct header the backward chain is as strong as SHA-256; no assumption
about validator honesty enters, except the one already in the certificate
(CV) and in inclusion. Cost: `T - H` headers (about 1,260 per hour of
blocks). A light client that verifies forward from an older trusted header
(signature bisection) would remove the need for `T >= H` and is planned
after v0.

### 10.7 What must be archived for later verification

Archive formats (the byte layout of an archive record) are out of scope for
this document; a later revision that fixes one adds a new vector file.
Contents and reasons:

| Item | `da` | Level | Why |
|---|---|---|---|
| The blob bytes, written before the anchor tx is submitted | both | MUST | Fibre prunes after `pruneAt` (about 4 h); L1 pruned nodes after 7d + 1h. P2 and P3 tie the bytes to the commitment. |
| The signed envelope and the action bytes, written by the gate before it signs (stage 4a, rules AR1 to AR4); the SignedAuthorization, written after stage 12 (a crash between the two is repaired from the registry at the next start); for a refused decision, the rejection marker with the error name (AR5 to AR8) | both | MUST | The object being verified, and which path the gate used (section 15). Writing the decision first means no Authorization exists for a decision the archive lacks. |
| The anchor tx bytes exactly as included (PFF or PFB), its index in block `height`, and its inclusion proof against `data_hash` of that header (for `da = 1` the proof is SHOULD: the system blob below is the v0 inclusion evidence, CV8) | both | MUST | Proves namespace and commitment were committed on L1 at `height`; for `da = 1` it also carries the `PaymentPromise` and the positional certificate (section 10.6.1). About 5.3 KB at 83 validators. |
| The signed header (header and commit) of block `height` | both | MUST | Root of the inclusion proof, `T_H` for K1 and K2. |
| For PFF: the x/staking `HistoricalInfo` validator set at `PaymentPromise.height` (consensus keys and token amounts) | 1 | MUST | CV4 and CV6 need the keeper's order and powers. The chain keeps it only for `historical_entries` blocks (about 8 h), after which nobody can re-check the certificate without the archive. |
| For PFF: the signed header at `PaymentPromise.height` and the CometBFT validator set its `next_validators_hash` (or the `validators_hash` of `promise.height + 1`) commits to | 1 | MUST | CV7: ties the `HistoricalInfo` set to the chain. |
| The retention inputs the gate used: `shard_retention` latest and at `height`, and which source gave the at-height value (section 11.2, RS rules) | 1 | MUST | K2 replay; the at-height value cannot be read back reliably later. |
| The result of the anchor tx (code 0) as the node reported it | 1 | MUST | CV8, settlement `node-attested` (section 10.6.1). |
| The results of all txs of block `height` and the header at `height + 1`, for a proof of code 0 against `last_results_hash` | 1 | SHOULD | Lets the planned `proven` settlement level be checked later for decisions archived now. |
| The share-version-2 system blob and its inclusion proof against the data root of the header at `height` | 1 | MUST | CV8: the v0 evidence that `(namespace, commitment)` was in block `height`; it has no timestamp and no signatures, which the PFF tx and the certificate supply. |

Headers the verifier needs between the trusted header and `height` (section
10.6.2) need not be archived: the hash chain checks them from any source.

The Recorder MUST write the blob before submitting and the remaining MUST
items, other than the gate's decision record and Authorization, before
returning `payload_ref` to the producer, so a signed
commitment never exists without them. For `da = 1` this is also before the
`historical_entries` horizon, which is hours away at that point.

`UNVERIFIED`: an API that serves a PFF tx inclusion proof at the pin. The
upstream `pkg/proof.NewTxInclusionProof` handles Fibre txs (code), so an
archiver can build the proof from the block's txs with upstream code when no
node serves it. The archive task settles which.

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

### 10.8 Startup compatibility check (normative since `v0-draft.17`)

Fibre is on a pre-release line and changes between tags. Any component that
handles `da = 1` (gate, Recorder, verifier, SDK with the Fibre committer)
MUST, before it serves or signs, run the checks below, and MUST refuse to
start if one fails. There is no override; a failure is a configuration
error, not a sentinel.

| Check | Requirement |
|---|---|
| SC1 Build pin | The linked celestia-app module is exactly the pinned version (section 10.1, read from the build information). |
| SC2 Known answers | The `da = 1` committer reproduces the commitments of `fibre_commit.json` it embeds: at least `fibre_live_mocha_popsmin1`, `fibre_size_262139`, `fibre_size_262140` and one row size above 128. |
| SC3 Chain | The node's chain id is in the configured `da = 1` chain allowlist, and the app version in the latest header is 10. The allowlist is configuration; its default, and the only value validated for v0, is `["mocha-5"]`. Adding a chain (for example Arabica or Corto) is an operator decision after checking that the pins and `fibre_commit.json` hold there. |
| SC4 Parameters | x/fibre `Params` is readable and `shard_retention` is within the governance bounds (10 min to 168 h). |
| SC5 Retention source and at-height reads | The retention store is bound to this chain id and gets its first sample; the canary runs (section 11.2, RS2; section 10.9). A failing canary disables only the direct at-height read, never the start: the gate then runs in observations-only mode for retention and MUST log the mode and the reason at startup at warning level (and again whenever a later canary changes it). |
| SC6 Fallback node | A bridge used as a download fallback reports the pinned celestia-node version, otherwise the fallback is disabled (logged); it is never trusted for P3, which the gate computes itself. |

An app version change seen at runtime (an upgrade) stops `da = 1` service
(`ErrChainUnavailable`) until a restart has re-run the checks.

Threat note (SC). The commitment, the sign bytes and the parameters are
upstream definitions that a new tag may change; the vectors are the only
independent memory of what the network did at the pin. Refusing to start on
any difference turns a silent divergence (accepting bytes the network never
committed, rejecting every anchor) into a visible configuration error.

### 10.9 At-height reads (all modules, both `da`; normative since `v0-draft.17`)

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
  proof. This covers the `celestia_blob` path (K0 and `T_H` for `da = 2`)
  as much as `da = 1`.

| Rule | Requirement |
|---|---|
| AH1 Echo | A response is used only if it carries the requested height and that height equals `h`: for a state read the response header `x-cosmos-block-height`; for a block read the height inside the returned object (`header.height`, `block.header.height`, the results' height, `HistoricalInfo.header.height`). A response without a height (for example `blob.Get`) is used only through AH2. Missing or different: the response is discarded as a failure of that endpoint. |
| AH2 Binding | Where the content can be tied to the header at `h`, it MUST be, and the header itself MUST pass AH1: txs to its `data_hash`; a blob or its share commitment to its data root through the inclusion proof; a validator set to `validators_hash` or `next_validators_hash`. A block read that passes AH1 and AH2 does not depend on whether the endpoint honours heights. |
| AH3 Canary per endpoint | The RS2 canary (section 11.2) is a property of the endpoint, not of a module: a canary that does not pass marks the consensus endpoint height-ignoring for every state read, whatever the module. Block reads are checked by AH1 and AH2 on every response. A block or header read on a consensus endpoint whose returned height is missing or differs from the requested one also marks that endpoint height-ignoring for state reads (retention goes to observations-only mode, AH4) until a later canary on it passes (Honoured). Bridge (celestia-node) endpoints do no state reads, so they have their own canary: read the header at `head - canary_offset` (RS2) and compare its height with the requested one: equal is Honoured, a header at another height is Ignoring, anything else (error, not found, timeout) is Inconclusive. The bridge result is logged (warning level unless Honoured, again on every change) and MUST NOT drive the retention mode; a bridge AH1 mismatch discards that response only. |
| AH4 On failure, retention | The x/fibre retention at `height` comes only from the gate's own observations (RS4 to RS6): observations-only mode, logged at startup and on every change (SC5). A height the observations do not cover gives `ErrRetentionUnavailable`. |
| AH5 On failure, other reads | Any other read at a height that fails AH1 or AH2 on every configured source gives nothing: the check that needed it is not evaluated from latest state or from another height. The gate answers `ErrChainUnavailable` (503, nonce untouched), never `ErrAnchorNotFound`, never a K1 or K2 verdict from the wrong block. It MAY instead use a source that does not depend on the endpoint honouring heights: a header verified by the W5 light verifier (section 9.5), or a block read from another endpoint that passes AH1 and AH2. A state read other than x/fibre `Params` from a height-ignoring endpoint MUST NOT be used; v0 defines no other. A header or block read that answers "not found" for a height the chain must have (at or below a head the gate has observed on any configured source) is a failed at-height read under this rule, on both `da` paths (K0 and `T_H`): `ErrChainUnavailable`, never `ErrAnchorNotFound`. A pruned or trailing backend answers "not found" for blocks that exist, so the answer says nothing about the chain. A height above every observed head gives `ErrChainUnavailable` too (retryable, nonce untouched; `valid_until` bounds the retries). `ErrAnchorNotFound` is given only after the block at `height` was read and passed AH1 and AH2 and holds no anchor. |

The Recorder applies AH1, AH2 and AH5 to its read-back (an AH failure is
`recorder.ErrNodeUnavailable`); the verifier applies them to HT6
(section 10.6.2).

Threat note (AH). A height-ignoring endpoint answers "latest" for "at `h`".
For retention that silently replaces the at-height half of `r` (RS1); for a
block read it would make a gate find no anchor, or the wrong block time.
AH1 detects it whenever the object names its height, AH2 makes the content
self-checking against the header, and AH5 turns any remaining doubt into a
retryable refusal instead of a verdict. What AH does not cover: an endpoint
that echoes the requested height and serves a consistent but false header.
The header is trusted from the node (own node recommended), or from the W5
light verifier; that is the same assumption as K1 and K2 (section 11.2).

## 11. MaxTTL, retention, anchor time and the archive

### 11.1 MaxTTL (stage S)

```
MaxTTL(da) = min(3600, floor(retention(da) / 4))
retention(1 fibre)         = params.fibre_retention_s   ; x/fibre shard_retention, read at check time
retention(2 celestia_blob) = params.blob_retention_s    ; default 14400 in v0
```

| Point | Rule and reasoning |
|---|---|
| Hard cap | TTL never exceeds 1 h, default TTL 15 min (SDK default). |
| Factor 4 | Leaves room for the time between the Fibre `creation_timestamp` (start of retention) and `issued_at`: upload, PFF inclusion, archive write, signing. With 4h retention and 1h TTL, any `issued_at` within 3h of the promise creation keeps the shards alive until `valid_until`. Rule K2 (section 11.2) checks this per commitment instead of assuming it. |
| Read at check time | The gate passes the current `shard_retention` as `params`. If governance lowers it, commitments with a TTL above the new MaxTTL fail with `ErrTTLTooLong` (vector `ttl_ok_at_4h_rejected_at_10m`). Fail-closed: only liveness is lost. Governance changes are visible days ahead and the default TTL is 15 min. |
| Floor division | `floor(601 / 4) = 150` (vectors `ttl_max_at_601s_retention`, `ttl_floor_division`). |
| Retention lowered after upload | At the pin, `pruneAt` is fixed when the shard is stored, so lowering retention does not shorten the life of shards already stored. The check-time rule is therefore stricter than needed today; it stays because server behaviour may change and a server may prune early or lose data. |
| `celestia_blob` | Real retention is 7d + 1h on pruned nodes (section 10.2), so MaxTTL is 1h with any realistic value. v0 keeps the conservative default `blob_retention_s = 14400`; this is a local constant, not a chain parameter. |

### 11.2 Anchor-relative rules K1 and K2 (gate, strict mode)

MaxTTL bounds `valid_until - issued_at`, but `issued_at` is chosen by the
agent: nothing in the commitment alone stops an agent from anchoring a
payload, waiting hours, and then signing, at which point the DA layer may
prune the payload before `valid_until`; nor from signing before the payload
was public at all. A strict-mode gate MUST therefore relate the commitment's
times to the anchor block.

Definitions. All values are Unix seconds. Arithmetic is exact; an
implementation in unsigned 64-bit integers MUST saturate on addition, which
yields the same verdicts because every left-hand side below is under
`2^63 + 600` (rule S2 bounds `issued_at` and `valid_until`).

```
T_H    = header time of block payload_ref.height, truncated to whole seconds (floor)
r      = da = 1: min(fibre_retention_s(latest), fibre_retention_s(at height))
         da = 2: blob_retention_s
start  = da = 1: min(T_H, floor(PaymentPromise.creation_timestamp))
         da = 2: T_H
margin = min(600, floor(r / 8))          ; 600 at 4h; 75 at the 10 min governance minimum
```

| Rule | Exact inequality | On failure |
|---|---|---|
| K1 | `issued_at + skew_s >= T_H` | Reject with `ErrIssuedBeforeAnchor` (package `commitment`). |
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

Retention at `height` (normative since `v0-draft.17`). Facts: on 2026-10-05
the public QuickNode Mocha endpoint answered x/fibre queries with the latest
value for any requested height, including heights whose state does not
exist, and sent no response height header; P-OPS and nodes.guru, one of
them on the same binary, honoured the height and echoed it (VERIFIED,
probe; the cause is in front of the QuickNode node). The client cannot tell
from a normal answer which kind of endpoint it talks to, so the gate uses:

| Rule | Requirement |
|---|---|
| RS1 | The latest value is never used as the value at `height`, unless one of the sources below establishes it for `height`. |
| RS2 Canary | At start and at least every `canary_interval` (default 600 s, at most 3600 s), the gate runs the canary on each consensus endpoint it uses for state reads. Canary heights are configuration, per chain id, and logged at startup: (a) the recent height `h_r = head - canary_offset`, where `head` is the latest height the same endpoint reports just before, and `canary_offset` (default 10) MUST be at least 1 and greater than `lag` (RS4) and MUST stay inside the state the node retains; (b) `h_pre`, the last height before x/fibre was activated (Mocha: 1,082,619), optional (absent on a chain that has x/fibre from genesis). The gate queries x/fibre `Params` pinned to `h_r` and, if configured, to `h_pre`. Outcomes, decided only from success or failure and the response header `x-cosmos-block-height`, never from error codes or messages: **Ignoring** if the `h_r` query succeeds without the header or with a value other than `h_r`, or if the `h_pre` query succeeds (any response message, empty included, whatever its header). **Honoured** if the `h_r` query succeeds with the header equal to `h_r` and the `h_pre` query, if configured, fails (any error). **Inconclusive** in every other case (the `h_r` query fails, the head cannot be read, timeout, cancellation). Ignoring takes precedence over Inconclusive. Only Honoured passes; Inconclusive counts as not passed. |
| RS3 Direct read | A read of x/fibre `Params` pinned to `height` establishes the value only if: the canary passed at start; the response carries the response header `x-cosmos-block-height` equal to `height`; and a canary on the same connection right after the read passes. Otherwise the direct source gives nothing for this check (it is not a rejection by itself). While the canary fails, the gate is in observations-only mode (section 10.9, AH4). |
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
  x/fibre store at that version and the query fails). `UNVERIFIED`: the
  archival behaviour at `h_pre` is from reading the pinned celestia-app and
  cosmos-sdk code (store not registered, panic recovered into a gRPC error),
  not from a live probe. Error codes and messages are not used because
  they do not separate node from transport: an honest pruned node answers
  `codes.Unknown`, and grpc-go itself produces `codes.Internal` for a proxy's
  HTTP 400 or a reset stream. An endpoint that echoes but ignores heights
  and has no `h_pre` configured passes the canary; the next note bounds
  that case. `canary_offset > lag` keeps `h_r` at or below the head of every
  backend behind a load balancer, so an honest one does not answer "height
  in the future"; an offset beyond the node's retained state makes every
  canary Inconclusive (fail-closed, observations-only mode). `UNVERIFIED`:
  that the default pruning of the pinned celestia-app keeps more than 10
  recent heights of state.
- Any non-monotone pair of changes between two samples is missed, not only
  a change and its revert (for example 4 h to 2 h to 3 h: both neighbouring
  runs are above 2 h): the gate may then take a too high value at `height`.
  One change between samples is covered, because both neighbouring runs
  count. Sampling every 30 s against
  governance voting periods makes this unlikely; the residual risk is
  accepted for v0, and the post-v0 source is the history of executed
  parameter changes (governance events), which needs no state at height.
- A source that echoes the height but still answers from other state passes
  RS3. The canary and the minimum with the samples limit the damage to a
  too low value at most when the samples cover `height`; when they do not,
  the gate trusts that node (v0: the operator's own node or a provider the
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
- `T_H` uses the block header time, which is CometBFT BFT time, fixed when
  the block is committed (`UNVERIFIED` for the pinned celestia-core). Floor
  makes K1 at most one second more lenient, which `skew_s` already covers,
  and makes `start` for `da = 2` earlier, which is the conservative side.
- `start` for `da = 1` uses `min(T_H, creation_timestamp)` because Fibre
  computes `pruneAt = max(promise expiry, creation_timestamp + retention)`
  from the promise, which is created before inclusion (section 10.2).
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
  was included"): a decision signed before its payload was public is not a
  pre-committed decision. `skew_s` tolerates a fast agent clock only.
- K2 makes `path = 1` mean "the DA layer was expected to serve the payload for
  the whole validity window". Without K2 a gate could report DA availability
  for a commitment whose payload the DA layer prunes before `valid_until`.
- Both rules trust the node for `T_H`, `creation_timestamp` and the retention
  parameters, read under section 10.9. The operator's own node is
  recommended (self-check); a public endpoint is allowed, and the operator
  docs list the providers that passed the canary (P-OPS, nodes.guru). A gate MAY
  instead take K0 and `T_H` for `da = 2` from the W5 verifier (section 9.5),
  which removes the trust in its node for those two inputs.
- Vectors: `anchor.json`: `k1` (equality accepted, one second earlier
  rejected, `skew_s = 0`, a `2^64-1` block time), `k2` (at the limit and one
  second over for both `da`, unknown `creation_timestamp`, unreadable
  at-height retention, retention lowered and raised since `height`, the
  governance minimum, the margin floor and cap, saturation), `epoch` (rule
  E1, section 8.7). Each K2 case carries the expected `r`, `start`, `margin`,
  verdict and route.

Settled in `v0-draft.17`: the PFF is found by scanning block `height`
(section 10.4); x/fibre params at a past height are served by honest nodes
and are not by the QuickNode public endpoint (RS rules above). Still
`UNVERIFIED`: header time final at commit for the pinned celestia-core.

### 11.3 The archive

| Point | Rule and reasoning |
|---|---|
| When it is used | When K2 fails, or when the DA path fails for any reason, for both `da` values when the gate has the committer for that `da` (section 8.5). |
| What is checked | P1, P2 and P3 on the full archived blob. The archive is trusted for availability only. |
| Recorder duty | The Recorder writes the archive synchronously before submitting the anchor tx, so the archive copy exists whenever a valid commitment exists. Archive unavailable: `recorder.ErrArchiveUnavailable` (503), nothing submitted; after a submit the write is retried by resubmitting the same bytes, which pays nothing again (PR8). |
| Gate duty | The gate writes the decision record (envelope, action bytes) before it signs and the Authorization after it commits the nonce (section 8.7, stage 4a, AR1 to AR4), and marks a record it then refuses as rejected with the error name (AR5 to AR8). Archive unavailable: `ErrArchiveUnavailable` (503, `Retry-After`), nonce not consumed. |
| Residual risk | If the archive loses or withholds the blob after the DA layer pruned it, the gate rejects (`ErrAnchorTooOld` when K2 failed, otherwise `ErrPayloadUnavailable`), and later `verify` or `replay` cannot recover the payload. Mitigations post-v0: archive replication, archive health check before signing. |
| `da = 1` and the archive | Accepted since `v0-draft.17` by a gate with the `da = 1` committer, which every gate configured for `fibre` has (section 8.5). With 4 h retention the archive is the only source a few hours after the anchor, so for `da = 1` it is part of normal operation, not a rare fallback. |

## 12. Sentinel errors

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
| S | `ErrUnsupportedVersion` | S1 |
| S | `ErrIntRange` | S2 |
| S | `ErrInvalidEnum` | S3 |
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
| A | `ErrActionMismatch` | A1 |
| P | `ErrPayloadSizeMismatch` | P1 |
| P | `ErrPayloadHashMismatch` | P2 |

Removed in draft.9, and never reused for another meaning:
`ErrUnsupportedActionKind` (D20), `ErrUnsupportedRail` (S4, R4),
`ErrUnsupportedOrderType` (S5), `ErrLimitPrice` (S9), `ErrAccountMismatch`
(S10), `ErrChainIDRule` (S11), `ErrDeadlineRange` (S13), `ErrPriceBound`
(S15), `ErrNotionalExceeded` (S16), and the SDK's `dca.ErrMalformed` (now a
dca-agent profile sentinel). The order and account rules have profile
sentinels instead (`ibkrorder.ErrMalformed`, `ibkrorder.ErrInvalid`,
`ibkr.ErrAccountMismatch`, `ibkr.ErrRiskLimit`).

The Authorization and receipt decoders and verifiers (sections 14 and 15)
reuse the stage D, S, G, C, A and T sentinels above; they define no new ones.

Gate sentinels (stateful, section 8.7). A second gate implementation MUST use
the same names so that operators, tests and the verifier agree on the reason.
Package is where the Go sentinel lives.

| Stage | Sentinel | Package | Rules | Vectors |
|---|---|---|---|---|
| E | `ErrBeforeRegistryEpoch` | `gate` | E1 | `anchor.json` `epoch` |
| L | `ErrAgentKeyIsGateKey` | `gate` | L0 | none (gate configuration) |
| L | `ErrAgentNotAllowed` | `gate` | L1 | none (stateful) |
| L | `ErrAgentKeyMismatch` | `gate` | L2 | none (stateful) |
| N0, N | `ErrNonceUsed` | `gate` | N1 | none (stateful) |
| K | `ErrAnchorNotFound` | `gate` | K0 (for `da = 1`: no PFF with result code 0 in block `height`, section 10.4) | none (stateful) |
| K1 | `ErrIssuedBeforeAnchor` | `commitment` | K1 | `anchor.json` `k1` |
| K2 | `ErrRetentionUnavailable` | `gate` | K2: `fibre_retention_s` at `height` not established by RS3 or RS6 (`da = 1`, section 11.2) | `anchor.json` `k2_fibre_at_height_unreadable` |
| P | `ErrDACommitmentMismatch` | `gate` | P3 | `da_blob.json` `reject`, `da/fibre_commit.json` `reject` (Go only) |
| P | `ErrArchiveRecomputeUnsupported` | `gate` | P3, K2 path selection: the archive path is needed and the gate has no DA committer for this `da` (since `v0-draft.17` only a library gate without the `da = 1` committer) | `anchor.json` `k2` (`da = 1`, K2 false, gate without the committer) |
| P | `ErrAnchorTooOld` | `gate` | K2 failed and the archive did not return the blob; also matches `ErrPayloadUnavailable` | none (stateful) |
| P | `ErrPayloadUnavailable` | `gate` | No path returned the blob | none (stateful) |
| Record | `ErrExecutorNotAllowed` | `gate` | Section 14.3 RQ3: the request's executor key is not in the executor allowlist | `record_request.json` |
| Record | `ErrNotAuthorized` | `gate` | Section 14.3: no Authorization is stored for this commitment (never authorized, another commitment holds the nonce, or the entry was pruned) | none (stateful) |
| Record | `ErrReceiptExists` | `gate` | Section 14.3: a receipt is already stored; returned with the stored receipt | none (stateful) |

Still reserved: `ErrCertInvalid` (fast mode, not defined in v0 code).

SDK sentinels (payload blob and opening, sections 9.1 to 9.5). The
prefix is the Go package; vectors write them as `pkg.ErrName`.

| Sentinel | Rules | Vectors |
|---|---|---|
| `blob.ErrTooLarge` | B0 | none (size only) |
| `blob.ErrMalformed` | B1, B2 (not a uint), B4, B6, B7 | `payload_blob.json` decode rejects |
| `blob.ErrVersion` | B2 | `pb_blob_version_1` |
| `blob.ErrRecipients` | B3; producer with 0 or more than 16 recipients | `pb_recipients_0`, `pb_recipients_17` |
| `blob.ErrDuplicateKID` | B5; producer with a repeated kid | `pb_duplicate_kid` |
| `blob.ErrNoRecipient` | O4 | `pb_kid_absent` |
| `blob.ErrUnwrap` | O5 | `payload_blob.json` open rejects |
| `blob.ErrDecrypt` | O6 | `payload_blob.json` open rejects |
| `payload.ErrMalformed` | Section 9.3, O8, W1 | `pb_payload_*` |
| `payload.ErrVersion` | Section 9.3, O8 | `pb_payload_version_1` |
| `payload.ErrTooLarge` | Section 9.1 size (producer) | none (size only) |
| `sdk.ErrPlaintextHashMismatch` | O7 | `pb_plaintext_hash_*`, `pb_key_commitment_two_deks` |
| `sdk.ErrPayloadMismatch` | O8 | `pb_payload_action_differs`, `pb_payload_action_type_differs` |
| `sdk.ErrDACommitmentMismatch` | W4 | none (needs a Recorder fake; SDK e2e test) |
| `sdk.ErrDACheckUnavailable` | W4 | none (configuration) |
| `sdk.ErrInclusionUnverified` | W5 | none (needs a chain fake; SDK tests) |
| `sdk.ErrBlockTimeMismatch` | W5 step 4 | none (SDK tests) |
| `sdk.ErrUnexpectedRef` | W5 step 1 | none (SDK tests) |
| `sdk.ErrPublishTimeout` | W6 | none (SDK tests) |

Gate sentinel added in `v0-draft.10`: `ErrDANotAllowed` (package `gate`,
stage C, rule C3; no vector, gate configuration).

Gate sentinel added in `v0-draft.17`: `ErrPayloadAboveCap` (package `gate`,
stage C, rule C4: `da = 1` `payload_size` above the gate's Fibre payload
limit, section 10.4; no vector, gate configuration). It is not
`ErrPayloadTooLarge`: that name is S7 and both are reported as bare codes.

Publish-request sentinels (section 17; package `edictaapi`). The stage D and
S sentinels of the request wrapper are the core ones above.

| Sentinel | Rules | Vectors |
|---|---|---|
| `edictaapi.ErrPublishSignature` | PR3: unknown `agent_id`, key check, `S < L` or signature equation (including a message signed for another `gate_id`) | `publish_request.json` stage G |
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
| `ErrArchiveUnavailable` (package `gate`) | The decision record could not be written durably before signing (section 8.7, stage 4a, AR3); nothing signed, nonce not consumed | 503 |
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

The draft.8 execution errors (execution rejected or unknown, receipt
pending) no longer exist: the gate does not execute.

## 13. Test vectors

Location `spec/vectors/v0/` (draft.9). The dca-agent profile vectors are in
`spec/vectors/profiles/dca-agent/` (profile document, section "Vectors").

Generators and checkers (Python 3.11+, stdlib plus `cryptography` for
Ed25519; hand-written strict CBOR in `cbor_strict.py`):

| Script | Does |
|---|---|
| `spec/vectors/check/gen_vectors.py [--out DIR]` | Writes the core set (default `v0/`), including `payload_blob.json` via `gen_payload_blob.py`. Not `da_blob.json` (below). |
| `spec/vectors/check/gen_profile_dca_agent.py [--core DIR] [--out DIR]` | Writes the profile set from a draft.9 core set. |
| `spec/vectors/check/check_vectors.py [--dir DIR]` | Checks one core set (default `v0/`). Without `--dir` it also runs the profile checker. |
| `spec/vectors/check/check_profile_dca_agent.py [--core DIR] [--dir DIR]` | Checks the profile set and its cross-references into the core set (default `v0/`). |

```
python3 -m venv .venv && .venv/bin/pip install -r spec/vectors/check/requirements.txt
.venv/bin/python spec/vectors/check/check_vectors.py     # exit 0 when every set passes
```

`ed25519_point.py` is the checker's own RFC 8032 point decoding and
small-order test for G0, because OpenSSL does not enforce G0, and its own
cofactorless equation for G1, which the checker cross-checks against OpenSSL
on every signature. The checker rebuilds the action-hash and Authorization
preimages from literal tag bytes rather than through the functions it tests.

JSON conventions: every uint (including enums, `now` and params) is a decimal
string; byte strings are lowercase hex; text strings are JSON strings
(ASCII-escaped); optional fields are absent when unset; input field names are
the names in sections 4, 14 and 15. Every draft.9 file except the four
byte-identical ones carries `"revision": "v0-draft.9"`. Actions longer than
1024 bytes are given as `action_pattern` (defined in the file's `patterns`:
`affine-7-3`, byte `i` is `(7*i + 3) mod 256`), `action_size` and
`action_sha256_hex` instead of `action_hex`.

| File | Contents |
|---|---|
| `keys.json` | `agent1` = RFC 8032 section 7.1 TEST 1, `agent2` = TEST 2, `gate1` = TEST 3 (the gate's key: it signs Authorizations and receipts): seed, public key, RFC known-answer signature. Byte-identical to draft.8. |
| `valid.json` | Top-level `params`, `gate` (`gate_id`, `action_types`) and `patterns`. Each case: `input`, `commitment_cbor_hex`, `commitment_hash_hex`, `signer`, `signed_message_hex`, `signature_hex`, `envelope_hex`, `now`, optional `params`, `action_type`, the action bytes, `action_preimage_prefix_hex` (`tag \|\| uint8(len(type)) \|\| type`), `action_hash_hex`, and `placeholders` (field path to a note: values that are not real chain data; today `payload_ref.commitment` in every case, which is a SHA-256 of a label; for `minimal_lmt` the note points to the real share commitment in `da_blob.json`). All signed by `agent1`. 14 cases. |
| `reject.json` | Same top-level fields. Each case: `id`, `stage`, `rule`, `description`, `envelope_hex`, `now`, optional `params`, `gate`, and exactly one `expect_error`. Stage S, G, T, C and A cases also carry `input`, `commitment_cbor_hex` and `commitment_hash_hex`. Stage A cases carry the supplied `action_type` and action bytes and `committed_preimage_hex` (the exact preimage of the committed `action.hash`). 126 cases. |
| `payload.json` | `cases` (blob and `ciphertext_hash`; salt, plaintext and `plaintext_hash`) and `reject` (claimed `payload_size` and `ciphertext_hash_hex`, `blob_hex`, `expect_error`). Byte-identical to draft.8. |
| `authorization.json` | Top-level `max_authorization_ttl_s` (`300`), `gate`, `patterns`. `cases`: `commitment_ref` (a `valid.json` id), `authorized_at`, `signer` (`gate1`), `input` (section 15 names), `authorization_cbor_hex`, `authorization_hash_hex`, `signed_message_hex`, `signature_hex`, `signed_authorization_hex`, and `check` (what the executor knows: `gate_pubkey_hex`, `gate_id`, `action_type`, the action bytes, `now`, `skew_s`). `reject`: `id`, `stage` (`D`, `S`, `G` or `X`), `rule`, `description`, `signed_authorization_hex`, `check`, one `expect_error`; stage S, G and X cases also carry `input`, `authorization_cbor_hex`, `authorization_hash_hex`. 7 cases, 42 rejects. |
| `record_request.json` | Top-level `gate` (`gate_id`, `gate_pubkey_hex`, `executor_keys`) and `keys` (`executor1` = RFC 8032 section 7.1 TEST SHA(abc), with its known-answer signature; `executor2` from a fixed label). `cases`: `commitment_ref`, `commitment_hash_hex`, `agent_pubkey_hex`, `rail_ref`, `signer`, `executor_pubkey_hex`, `record_message_hex`, `signature_hex`. `reject`: `id`, `stage` (`D`, `G` or `R`), `rule`, `description`, `commitment_hash_hex`, `agent_pubkey_hex`, `rail_ref`, `executor_pubkey_hex`, `signature_hex`, optional `executor_keys` (overrides the allowlist), one `expect_error`. 5 cases, 19 rejects. |
| `receipt.json` | Top-level `gate`. `cases`: `input` (section 14 names), `commitment_ref` (a `valid.json` id that also has an Authorization vector), `signer` (`gate1`; the executor is named by `input.executor_pubkey`), `receipt_cbor_hex`, `receipt_hash_hex`, `signed_message_hex`, `signature_hex`, `signed_receipt_hex`. `reject`: `id`, `stage`, `rule`, `description`, `signed_receipt_hex`, one `expect_error`; stage S and G cases also carry `input`, `receipt_cbor_hex`, `receipt_hash_hex`. 6 cases, 47 rejects. |
| `anchor.json` | `margin_cap`; `k1`: `issued_at`, `block_time`, `skew_s`, optional `expect_error`; `k2`: `da`, `valid_until`, `block_time`, then `blob_retention_s` (`da = 2`) or `fibre_retention_latest_s`, optional `fibre_retention_at_height_s` (absent = unreadable) and `creation_timestamp` (`0` = unknown) (`da = 1`), and `expect` (`within`; `r`, `start`, `margin` when a window exists; `route` `da` or `archive`, or `expect_error`; or only `expect_error` when the window itself cannot be established); `epoch`: `issued_at`, `epoch`, `skew_s`, optional `expect_error`. Byte-identical to draft.8. |
| `payload_blob.json` | Section 9. `suite` (ids, HPKE `info`, payload `aad`); `derivation` (how every value that is random in production is fixed, below); `params`, `gate`; `hpke_kat` (RFC 9180 Appendix A.2.1 as printed in the RFC: setup values, encryptions with sequence numbers 0, 1, 2, 4, 255, 256, and 3 exports); `recipient_keys` (name -> `kid_hex`, `ikm_hex`, `sk_hex`, `pk_hex`). `cases`: `payload` (section 9.3 names; `context.data` and `action.data` hex), `plaintext_cbor_hex`, `salt_hex`, `plaintext_hash_hex`, `dek_hex`, `aead_nonce_hex`, `recipients` (`key`, `kid_hex`, `ikme_hex`, `ske_hex`, `enc_hex`, `shared_secret_hex`, `hpke_key_hex`, `hpke_base_nonce_hex`, `wrapped_dek_hex`), `ciphertext_hex`, `blob_hex`, `payload_size`, `ciphertext_hash_hex`, `action_type`, `action_hex`, `action_hash_hex`, and `commitment` (a signed envelope over this blob, same fields as `valid.json`). `reject`: `id`, `stage` (`decode`, `open` or `plaintext`), `rule`, `description`, `blob_hex`, for `open` and `plaintext` the recipient `key` and optional `kid_hex` (absent: try every entry), for `plaintext` `plaintext_hash_hex`, `action_type`, `action_hash_hex` (the commitment's), and one `expect_error`. The DCA body vectors of draft.8 (`dca`) moved unchanged to the profile set. |
| `da_blob.json` | `da = 2` share commitments computed by upstream code only (go-square `v4.0.1` and the celestia-core RFC 6962 root the app uses), by the separate module `spec/vectors/tools/dacommit-gen` (`go run .`). `cases`: `namespace_hex`, `signer_hex`, `size`, the blob as `blob_hex` or `blob_pattern` (defined in `patterns`), `blob_sha256_hex`, `share_count`, `commitment_hex`. `reject`: same fields with a commitment that must not match, and `expect_error` = `ErrDACommitmentMismatch`. Checked by Go only (Python has no NMT); the Python checker checks the blob descriptions and that `blob_v1_minimal_lmt_payload` still describes the `minimal_lmt` payload. Byte-identical to draft.8. |

Added in `v0-draft.10` (the API file regenerated in `v0-draft.11`), without changing any existing file (every core file
keeps its bytes and its `"revision": "v0-draft.9"` field):

| File | Contents |
|---|---|
| `spec/vectors/api/publish_request.json` | Section 17 (`"revision": "v0-draft.11"`). `tag`, `publish_window_s`, `request_overhead`, `patterns`, `server` (`gate_id`, `now`, `skew_s`, `max_blob_bytes`, `allowlist` of `agent_id` -> public key, `gate_keys`). `cases`: `signer`, `agent_id`, `requested_at`, the blob as `blob_hex` or `blob_pattern` + `blob_size`, `blob_sha256_hex`, `publish_message_hex`, `signature_hex`, and `request_cbor_hex` (or `request_size` + `request_sha256_hex` for a pattern blob). `reject`: `id`, `stage`, `rule`, `description`, `request_cbor_hex`, optional `server` overrides, one `expect_error`. `response`: `commitment_ref` (a `valid.json` id), `payload_ref_cbor_hex`, `block_time`, `retention_start`, `response_cbor_hex`. 7 cases, 30 rejects, 1 response. PR6 to PR8 are stateful and have no vectors. Generated by `gen_api_vectors.py`, checked by `check_api_vectors.py`. |

| File (`v0-draft.12`, regenerated in `v0-draft.14` and `v0-draft.15`) | Contents |
|---|---|
| `spec/vectors/api/errors.json` | Section 18. `statuses` (status -> `retryable`); `errors` in match order: `code`, `status`, `retryable`, `stored` (`none`, `authorization` or `receipt`), `endpoints`, `rules`; `not_api_visible`: every other name in section 12 with the reason it never crosses the API; `examples`: per endpoint, `request_cbor_hex` (or none for `GET /v0/health`), `status`, `response_cbor_hex`, with refs into the core vectors. Generated by `gen_api_errors.py`, checked by `check_api_errors.py`, which also parses section 12 of this document and fails if a sentinel there is neither mapped nor listed as not API-visible. |

| File (`v0-draft.17`) | Contents |
|---|---|
| `spec/vectors/da/fibre_commit.json` | Section 10.4. `revision`, `generator`, `upstream` (celestia-app `v10.4.0-mocha` functions; the replace set), `params` (`blob_version`, `original_rows`, `parity_rows`, `min_row_size`, `header_size`, `max_data_size`), `patterns`. `cases`: `id`, `description`, `size`, the blob as `blob_hex` or `blob_pattern`, `blob_sha256_hex`, `row_size`, `upload_size`, `blob_id_hex`, `commitment_hex`, and for the live Mocha blob `live` (`chain_id`, `height`, `tx_hash`, `namespace_hex`, `upload_size`, `observed_on`). `reject`: same blob fields, a `commitment_hex` that must not match, `expect_error` = `ErrDACommitmentMismatch` (includes empty and over-maximum blobs, for which no commitment exists). `anchor_k2_with_fibre_committer`: `anchor_ref` (an `anchor.json` `k2` id), `without_committer` (its expected sentinel there), `route` (`archive` for a gate with the committer). 11 cases, 7 rejects, 4 anchor routes. Generated only by upstream code in the separate module `spec/vectors/tools/fibrecommit-gen` (`go run .`, `go run . -check`); commitments are checked by Go only, `check_fibre_commit.py` checks structure, sizes, blob descriptions and cross-references. |

Bank-send profile vectors are in `spec/vectors/profiles/bank-send/` (profile
document, section "Vectors"). `check_vectors.py` without `--dir` runs the
API and both profile checkers too.

`client_order_id.json` is no longer a core file: the IBKR client order id is
a dca-agent profile rule, and its vectors are in the profile set.

`payload_blob.json` derivation (test only): recipient keys are
`DeriveKeyPair(SHA-256("edicta/v0 test recipient|" + name))` (RFC 9180
section 7.1.3); the HPKE ephemeral key of recipient `i` (0-based) in case `id`
is `DeriveKeyPair(SHA-256("edicta/v0 test ephemeral|" + id + "|" + i)).sk`;
`DEK = SHA-256("edicta/v0 test dek|" + id)`, `aead_nonce = SHA-256("edicta/v0
test aead nonce|" + id)[0:12]`, `salt = SHA-256("edicta/v0 test payload salt|"
+ id)`. The Python generator passes `skE` into Encap explicitly. Go's
`crypto/hpke` cannot take an ephemeral key, so Go checks the open direction,
the byte-exact blob encoding from the listed components, and the RFC 9180
`hpke_kat`; Python checks the seal direction as well. The Python HPKE
(`hpke_base.py`) is hand-written over `cryptography` primitives and runs the
full RFC 9180 A.2.1 set (`hpke_rfc9180_a2_1.json`, from the CFRG test vector
file) before any `payload_blob.json` check.

How an implementation uses them:
- valid: `encode(input) == commitment_cbor_hex`; hash, signed message,
  signature and envelope match; `DecodeSigned(envelope)` round-trips to
  `input`; `ActionHash(action_type, action bytes) == action_hash_hex` and
  equals `input.action.hash`; `VerifyForGate(envelope, now, gate, params)`
  succeeds; `CheckAction(c, action bytes)` succeeds.
- reject, stages D to C: `VerifyForGate` fails with `expect_error`.
- reject, stage A: `VerifyForGate` succeeds, `CheckAction(c, action bytes)`
  fails with `expect_error`.
- payload rejects: `CheckPayload` with the claimed size and hash fails with
  `expect_error`.
- Authorizations: `EncodeAuthorization(input) == authorization_cbor_hex`;
  hash, signed message, signature and signed Authorization match;
  `VerifyAuthorization(signed_authorization, check)` succeeds and round-trips
  to `input`; `input` agrees with the referenced commitment (its hash, its
  `action.hash`, its `gate_id`, and `expires = min(valid_until, authorized_at
  + max_authorization_ttl_s)`). Rejects: `VerifyAuthorization(bytes, check)`
  fails with `expect_error`.
- record requests: `RecordMessage(commitment_hash, gate.gate_id, rail_ref) == record_message_hex`;
  the signature verifies; the stateless `Record` checks (RQ1 to RQ4, with the
  file's `gate_id`, allowlist and gate key) accept every case and reject every `reject`
  case with `expect_error`.
- receipts: `EncodeReceipt(input) == receipt_cbor_hex`; hash, signed message,
  signature and signed receipt match; `VerifyReceipt(signed_receipt)`
  succeeds and round-trips to `input`. Rejects: `VerifyReceipt` fails with
  `expect_error`.
- anchor: `CheckAnchorTime` (K1), `RetentionMargin` and `WithinRetention`
  (K2, with `r` and `start` from section 11.2) and the epoch rule give the
  stated verdicts; for K2 the gate's path selection gives `route` or `expect_error`.
- `payload_blob.json`: `payload.Encode(payload) == plaintext_cbor_hex`;
  blob encoding of the listed components equals `blob_hex`; every recipient
  key opens the blob (with and without its kid) to `salt || plaintext`;
  `plaintext_hash`, `ciphertext_hash`, `payload_size` match;
  `OpenPayload(commitment.envelope_hex, blob_hex, key)` returns `payload`.
  Rejects: `decode` fails blob decoding, `open` fails O4 to O6 with the given
  key and kid, `plaintext` fails O7 or O8, each with `expect_error`. For
  `pb_key_commitment_two_deks` the `honest_key` also opens successfully.
- `da_blob.json`: the gate's `DACommitter` for `da = 2` accepts every case
  (commitment equal to `commitment_hex`) and rejects every `reject` case with
  `ErrDACommitmentMismatch`. Regenerate or check with
  `cd spec/vectors/tools/dacommit-gen && go run . -check`;
  it needs network access the first time to download modules, and is never
  run by `go test` of the main module.
- `da/fibre_commit.json`: the gate's `da = 1` committer accepts every case
  (and its commitment equals `commitment_hex`, its BlobID `blob_id_hex`) and
  rejects every `reject` case with `ErrDACommitmentMismatch`; a gate with the
  committer routes each `anchor_k2_with_fibre_committer` entry to the
  archive, a gate without it keeps the `anchor.json` sentinel. Regenerate or
  check with `cd spec/vectors/tools/fibrecommit-gen && go run . -check`.

Stage D vectors whose defect is inside the commitment are signed over
`tag || <malformed commitment bytes>`, so the encoding defect is the only
defect. Stage S, T, C and A vectors are correctly signed.

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
Receipt       = { 1: version         uint = 0,
                  2: commitment_hash bstr 32,
                  3: gate_id         tstr 1..64, ID charset,
                  4: gate_pubkey     bstr 32,
                  ; 5 retired in draft.9 (was rail)
                  6: rail_ref        tstr 1..128, ID charset,
                  ; 7 retired in draft.9 (was path; now in the Authorization)
                  8: recorded_at        uint 1..2^63-1,
                  9: executor_pubkey    bstr 32,
                  10: executor_signature bstr 64 }
SignedReceipt = { 1: Receipt, 2: signature bstr 64 }
```

| Key | Name | Type | Limit | Semantics |
|---|---|---|---|---|
| 1 | `version` | uint | `= 0` | Receipt format version; same versioning rules as the commitment (section 0). |
| 2 | `commitment_hash` | bstr | exactly 32 | `commitment_hash` of the authorized commitment (section 5). Binds agent, nonce, scope, action and payload. |
| 3 | `gate_id` | tstr | 1..64, ID charset | The gate's own id; equals `scope.gate_id` of that commitment. |
| 4 | `gate_pubkey` | bstr | exactly 32 | The gate's Ed25519 key (the same key that signs its Authorizations). MUST pass G0. |
| 5 | - | - | - | **Retired** (was `rail`). Present means `ErrUnknownKey`. |
| 6 | `rail_ref` | tstr | 1..128, ID charset | Opaque, supplied by the integrator. Decoding enforces only the type, length and ID charset; its shape is a profile matter (the dca-agent profile: the IBKR `order_id`; an EVM integrator: the transaction hash in lowercase hex). A verifier MUST NOT reject a receipt because `rail_ref` lacks some rail's usual shape. |
| 7 | - | - | - | **Retired** (was `path`, which moved to the Authorization, section 15). |
| 8 | `recorded_at` | uint | `1..2^63-1` | Gate clock (Unix seconds) when the gate recorded the executor's claim. Same CBOR key 8 as draft.8 `executed_at`; only the field name changed, because the gate no longer observes execution. |
| 9 | `executor_pubkey` | bstr | exactly 32 | The Ed25519 key of the executor that made the claim; in the gate's executor allowlist when recorded. MUST pass G0 and MUST differ from `gate_pubkey`. New key number; retired numbers are not reused. |
| 10 | `executor_signature` | bstr | exactly 64 | The executor's signature over `record_message(commitment_hash, gate_id, rail_ref)` (section 14.3), as presented to `Record`. |

All keys are required; there are no optional fields. The CBOR profile is
section 3 (keys one byte each, strictly ascending; shortest heads; definite
lengths; no floats, tags or simple values). Limits: SignedReceipt bytes
`<= 512` (`MaxReceiptSize`), checked before parsing (`ErrTooLarge`); the
largest SignedReceipt that passes every rule below is 452 bytes.

```
receipt_canon  = canonical CBOR of Receipt (SignedReceipt key 1 value)
receipt_hash   = H( 0x11 || "edicta/v0/receipt" || receipt_canon )     ; 32 bytes
signed_message = 0x15 || "edicta/v0/receipt-sig" || receipt_hash       ; 54 bytes
signature      = Ed25519-Sign(gate_sk, signed_message)                 ; 64 bytes
SignedReceipt  = canonical CBOR of { 1: <receipt_canon spliced verbatim>, 2: signature }
```

The tags are unchanged from draft.7.

### 14.2 Verification

`VerifyReceipt(bytes)` runs, in this order:

| Stage | Rules | Check | Sentinels |
|---|---|---|---|
| D | D0 to D21 | As for the envelope (section 6), with the receipt schema above and the 512-byte limit in place of D0 and D14 | stage D sentinels |
| S | R1 | `version == 0` | `ErrUnsupportedVersion` |
| S | R2 | `version`, `recorded_at` `<= 2^63-1` | `ErrIntRange` |
| S | R3, R4 | **Retired** in draft.9 (rail and path enums) | - |
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
TagRecordRequest = "edicta/v0/record-request"              ; 24 bytes, tag(t) = 0x18 || ASCII
record_message   = 0x18 || "edicta/v0/record-request"      ; 25 bytes
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

Vectors: `record_request.json`: 5 valid (both executors, `rail_ref` of 1 and
128 characters, a hex transaction hash) and 19 rejects for RQ1 to RQ4,
including a request signed for another gate
(registry steps RQ5, RQ6 are stateful; gate tests cover them).

### 14.4 Worked example (vector `receipt_minimal_lmt`, gate `gate1`, executor `executor1`)

```
record_message   18 6564696374612f76302f7265636f72642d72657175657374
                 e2ea62234c504e4df72e172c8e0da5f02a1eeb784ccd39ac9e20f6dd4c7c8f1d
                 0c 676174652d70617065722d31                                 ; "gate-paper-1"
                 0a 31333730303933323339                                     ; "1370093239", 81 bytes
executor_sig     c209bec78ec15ce9783f54b680fa3cdd83f2886761292e1dc3383f316ff20e39
                 60b89295a2d3e0941b2f204f5f4028d3028b0e4b700ba073b594da463bed2003
receipt_canon    a8 01 00 02 58 20 e2ea...8f1d 03 6c "gate-paper-1" 04 58 20 fc51...8025
                 06 6a "1370093239" 08 1a 6ac07dfe 09 58 20 ec17...e2bf 0a 58 40 c209...2003   ; 207 bytes
receipt_hash     407392b772c848dc09008009d20f6cb57b2afc4fd2bdd154d6463a6d9601f78f
signed_message   15 6564696374612f76302f726563656970742d736967 || receipt_hash
signature        0cc6a1f5e7e858c163ebc74a5271e49712550a2c3e3f054fdc399bc2c73b2355
                 b34d915fd4e4ee07745a1ac8d05a1278988de523ab3d6a1c3c3c3bd40ea07600
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

Vectors: `receipt.json`: 6 valid (`minimal_lmt`, a `da = 1` commitment, a
128-character `rail_ref`, a 64-character hex `rail_ref` for a JSON action,
`recorded_at = 2^63-1`, a claim by `executor2`) and 47 rejects covering every
rule above, including the retired keys 5 and 7, an Authorization fed to the
receipt decoder, and the executor key and signature.

## 15. Authorization (gate output)

The Authorization is the gate's signed statement that one commitment passed
every check of section 8.7 at this gate, for exactly one action (type and
bytes), until `expires`. The integrator's executor verifies it before acting
(section 16).

### 15.1 Wire format

```
Authorization       = { 1: version         uint = 0,
                        2: commitment_hash bstr 32,
                        3: action_hash     bstr 32,
                        4: gate_id         tstr 1..64, ID charset,
                        5: expires         uint 1..2^63-1, Unix seconds,
                        6: path            uint enum (1 = da, 2 = archive) }
SignedAuthorization = { 1: Authorization, 2: signature bstr 64 }
```

| Key | Name | Type | Limit | Semantics | Inv. |
|---|---|---|---|---|---|
| 1 | `version` | uint | `= 0` | Format version; section 0 rules. | 6 |
| 2 | `commitment_hash` | bstr | exactly 32 | The authorized commitment (section 5). The executor's idempotency key. | 1, 5 |
| 3 | `action_hash` | bstr | exactly 32 | Equals the commitment's `action.hash`: `ActionHash(type, bytes)` (section 5.1). The type is inside it, so the Authorization does not carry the type. | 3 |
| 4 | `gate_id` | tstr | 1..64, ID charset | The issuing gate; equals the commitment's `scope.gate_id`. | scope |
| 5 | `expires` | uint | `1..2^63-1` | Last moment of use, exclusive with skew: `expires = min(valid_until, authorized_at + MaxAuthorizationTTL)`. Never later than `valid_until`. | 4 |
| 6 | `path` | uint enum | `1 = da`, `2 = archive` | Where the gate accepted the payload from (section 8.5), the gate's availability statement made at authorization time. `2` means DA retrievability during the validity window was not shown; publication is still proven by the anchor. Executors may ignore it. | 2 |

All keys are required. There is no agent key, no signature of the agent, no
action type, no `authorized_at` and no rail reference: the executor needs only
the bound, and the registry keeps `authorized_at`. The gate key is not a
field: the executor pins `gate_id -> gate_pubkey` out of band, exactly like a
receipt verifier.

### 15.2 Tags and exact bytes

```
TagAuthorization    = "edicta/v0/authorization"        ; 23 bytes, tag(t) = 0x17 || ASCII
TagAuthorizationSig = "edicta/v0/authorization-sig"    ; 27 bytes, tag(t) = 0x1b || ASCII

auth_canon          = canonical CBOR of Authorization (SignedAuthorization key 1 value)
authorization_hash  = H( 0x17 || "edicta/v0/authorization" || auth_canon )        ; 32 bytes
signed_message      = 0x1b || "edicta/v0/authorization-sig" || authorization_hash  ; 60 bytes
signature           = Ed25519-Sign(gate_sk, signed_message)                       ; 64 bytes
SignedAuthorization = canonical CBOR of { 1: <auth_canon spliced verbatim>, 2: signature }
```

The CBOR profile is section 3 (keys `1..6`, one byte each, strictly
ascending; shortest heads; definite lengths; no floats, tags or simple
values). SignedAuthorization bytes `<= 256` (`MaxAuthorizationSize`), checked
before parsing (`ErrTooLarge`); the largest one that passes every rule below
is 221 bytes. Signed-message lengths are 46 (agent), 54 (receipt) and 60
(Authorization) bytes: all different, and every hash is under a distinct tag
(H3).

### 15.3 Verification (executor side)

`VerifyAuthorization(bytes, check)`, where `check` is what the executor knows
on its own: the pinned `gate_pubkey`, the expected `gate_id`, the
`action_type` it executes, the exact `action_bytes` it is about to execute,
its clock `now` and its `skew_s` (0..300). Pure: no I/O. In this order:

| Stage | Rule | Check | Sentinel |
|---|---|---|---|
| D | D0 to D21 | As for the envelope (section 6), with the Authorization schema and the 256-byte limit in place of D0 and D14 | stage D sentinels |
| S | Q1 | `version == 0` | `ErrUnsupportedVersion` |
| S | Q2 | `version`, `expires`, `path` `<= 2^63-1` | `ErrIntRange` |
| S | Q3 | `path in {1, 2}` | `ErrInvalidEnum` |
| S | Q4 | `expires != 0` | `ErrZeroValue` |
| G | G0, G2, G1 | Section 5, with the **pinned** `gate_pubkey` for `agent_pubkey`, `authorization_hash` for `commitment_hash` and `TagAuthorizationSig` for `TagSig` | `ErrInvalidPublicKey`, `ErrSignatureInvalid` |
| X | X1 | `gate_id == check.gate_id` | `ErrScopeMismatch` |
| X | X2 | `1 <= len(action_bytes) <= 65536` | `ErrActionSize` |
| X | X3 | `ActionHash(check.action_type, action_bytes) == action_hash`, constant-time | `ErrActionMismatch` |
| X | X4 | `now + skew_s < expires` | `ErrExpired` |

The stage order is normative, as in section 6.5. X3 is where "exact bytes"
is enforced at the executor: it hashes the bytes it holds under the type it
executes, so other bytes, the same bytes under another type, or bytes of
another decision all fail.

### 15.4 Worked example (vector `auth_minimal_lmt_da`, signer `gate1`)

`minimal_lmt`, authorized at `now = 1791000060` with `MaxAuthorizationTTL =
300`, so `expires = min(1791000900, 1791000360) = 1791000360`; DA path.

```
auth_canon          a6 01 00 02 58 20 e2ea...8f1d 03 58 20 f662...61fb
                    04 6c "gate-paper-1" 05 1a 6ac07f28 06 01                  ; 95 bytes
authorization_hash  9925e8e1cef21cd8b6899ceffd065a5210733a13d1efce1101c69bcefbf2282f
signed_message      1b 6564696374612f76302f617574686f72697a6174696f6e2d736967 || authorization_hash
signature           c23160f31ce528b2b1883b3be5835eec64ecbe87642a05c5d889fdb1b40b54b0
                    825852491e8f46d54d0c1137f8966352e20bf33d88a27999c92ecd1e7cc87f00
SignedAuthorization a2 01 <auth_canon> 02 58 40 <signature>                     ; 164 bytes
```

### 15.5 Threat notes

- Bearer token. Anyone who holds the SignedAuthorization and the action bytes
  can present them to an executor until `expires`; the gate issues one
  Authorization per nonce but cannot stop it being presented twice. At most
  once execution therefore needs the executor's dedupe (section 16, I5).
  `MaxAuthorizationTTL` bounds how long a leaked Authorization is usable and
  how long the executor must keep its dedupe record.
- Never longer than the decision: `expires <= valid_until` (invariant 4), and
  K2 covers `valid_until`, so the payload stays retrievable for as long as an
  Authorization can be used.
- Replay across gates and actions: `gate_id` is in both the commitment and the
  Authorization, and the executor pins its gate; `action_hash` binds type and
  bytes (vectors `authorization_foreign_gate_id`,
  `authorization_action_other_type`, `authorization_action_other_order`).
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
  Key rotation and revocation are out of scope for v0.
- Clock: X4 subtracts the skew on the executor's side (`now + skew_s <
  expires`), so an executor clock up to `skew_s` slow still stops at the true
  `expires`; a clock slower than that extends use. Assumption: executor clock
  within `skew_s` of true time.

Vectors: `authorization.json`: 7 valid (both paths, `expires` capped by
`valid_until`, a `da = 1` commitment, a JSON action, a 65536-byte action, a
128-byte type) and 42 rejects covering every rule above.

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
- confidentiality of the action bytes against a guesser (section 5.1).

### 16.1 Executor rules (normative)

An executor is whatever holds the rail credentials and acts on an action: a
signer that signs only authorized transactions, a contract that verifies the
Authorization, or middleware in front of a broker API. A conforming executor:

| Rule | Requirement |
|---|---|
| I1 | Pins `gate_id -> gate_pubkey` out of band, and the action type(s) it executes. It never takes the key, the gate id or the type from the Authorization, the caller or the agent. |
| I2 | Calls `VerifyAuthorization` (section 15.3) with its pinned key and gate id, its type, **the exact bytes it is about to execute**, its clock and skew, and refuses on any error. |
| I3 | Executes exactly the authorized bytes: it parses those bytes as they are with the profile's strict decoder and acts on the result of that parse. It never builds the rail request from a struct supplied by the caller or the agent, and never re-encodes its own struct to compare it with the bytes. Where the rail needs another encoding (for example a broker's JSON API), the mapping from the parsed bytes is fixed by the profile, field for field. |
| I4 | Checks the domain the bytes name (account, chain id, contract, as the profile defines) against its own, and refuses a mismatch. |
| I5 | Dedupes by `commitment_hash`: records it as in flight atomically before or with the send, refuses a second execution of the same `commitment_hash`, and keeps the record at least until `expires + skew_s`. After a crash it resolves an in-flight record by looking the action up at the rail (by the idempotency key), never by sending again. |
| I6 | Does not start a send once `now + skew_s >= expires`; a send started before may complete. |
| I7 | Optionally reports the rail reference to the gate after the rail acknowledged the action: a record request signed with its own executor key, which the gate operator has put in the executor allowlist (section 14.3). The executor key is used for nothing else. |

Amendment to I5 (`v0-draft.10`). A profile MAY allow re-sending
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

### 16.4 Moved out of the core in draft.9

- The client order id and the IBKR facts (draft.8 section 15) and the DCA
  media type (draft.8 Appendix A) are in the dca-agent profile
  (`spec/profiles/dca-agent-v0.md`), with their vectors in
  `spec/vectors/profiles/dca-agent/`.
- The draft.8 rail adapter rules, execution outcomes (Unknown, Rejected),
  reconciliation and manual resolution are gone from the core: the gate does
  not execute. Their executor-side analogue (in-flight records resolved by
  lookup) is I5 and, for IBKR, the profile.

## 17. Publish request (agent to Recorder)

A Recorder spends its operator's fees on every blob it submits, so it accepts
a blob only in a request signed by an allowlisted agent key, and applies
per-agent quotas before any fee is spent. The request authenticates the
agent to the Recorder; it is not part of the decision, and nothing in a
commitment, Authorization or receipt refers to it.

### 17.1 Message

```
TagPublishRequest = "edicta/v0/publish-request"            ; 25 bytes, tag(t) = 0x19 || ASCII
publish_message   = 0x19 || "edicta/v0/publish-request"    ; 26 bytes
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

Transport is HTTP with `application/cbor` bodies, `POST /v0/publish`. Both
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
| PR8 | Unresolved submissions, by `SHA-256(blob)`. If an earlier submission of the same blob has an unresolved outcome and is still held (section 12, `recorder.ErrNodeUnavailable`), the Recorder does not submit again: it resumes the search for that submission and answers the PublishResponse if found, otherwise retryable `recorder.ErrOutcomeUnknown`. Unresolved submissions are held at least `2 * (skew_s + 300)` seconds, like completed ones. Otherwise it submits | `recorder.ErrOutcomeUnknown` |

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
- The Recorder is untrusted for integrity (section 1): the request protects
  the operator's fees, not the agent. The agent's protection is W4 to W6.
- Quotas held in memory reset on restart; a restart therefore restores a
  quota early. Accepted for v0.
- What the quota counts. v0 has one quota and it counts requests that reach
  PR7, not fees spent. Only completed answers (PR6) are free. A retry
  of an unresolved blob spends no fee (PR8 never submits it twice) but is
  charged, because it costs the Recorder node reads (the search resumes from
  where the last one stopped) and because an agent that keeps retrying must
  not hold Recorder capacity for free: unresolved entries count toward the
  Recorder's limit on unresolved submissions (`recorder.ErrTooManyPending`).
  Consequence for clients: retrying `recorder.ErrOutcomeUnknown` with the
  same blob uses quota; after a few such answers a client SHOULD discard the
  blob and seal a new payload (W6) instead. A separate request-rate limit and
  spend quota are possible later and are not part of v0.

Vectors: `spec/vectors/api/publish_request.json` (section 13).

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
| Versioning | Paths start with `/v0/`. An incompatible change gets `/v1/`. |
| Size | Each endpoint's request limit (18.2) is checked before parsing: `ErrTooLarge` (413). |
| Authentication | `/v0/publish` by the agent signature (section 17); `/v0/record` by the executor signature (section 14.3); optionally, per endpoint class, a bearer token in `Authorization: Bearer` (`edictaapi.ErrTokenInvalid`, 401). `/v0/health` is unauthenticated and carries no secrets. Tokens over plain HTTP to a non-loopback address are refused by configuration. |
| Order of checks | Route (404), method (405), media type (415), token (401), size (413), wrapper decoding (400), then the operation's own stage order (sections 8.7, 14.3, 17). |

### 18.2 Endpoints

| Method, path | Request | 200 response | Request limit |
|---|---|---|---|
| `POST /v0/publish` | `PublishRequest` (section 17.2) | `PublishResponse` (section 17.2) | `max_blob_bytes + 256` |
| `POST /v0/authorize` | `{1: envelope bstr, 2: action bstr}` | `{1: signed_authorization bstr}` | `2176 + 65536 + 24 = 67736` bytes |
| `POST /v0/record` | `{1: envelope bstr, 2: rail_ref tstr, 3: executor_pubkey bstr 32, 4: executor_signature bstr 64}` | `{1: signed_receipt bstr}` | `2560` bytes |
| `GET /v0/health` | no body | `Health` (below) | - |

`/v0/authorize` runs section 8.7 on the envelope and action bytes as given
and answers the SignedAuthorization of stage 13. `/v0/record` runs section
14.3 with the server's own `gate_id`. `/v0/publish` with the Recorder
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
signer or a namespace from it as trusted configuration (core I1 pins the
gate key out of band); it may compare them with its configuration.

### 18.3 Errors

Every non-200 response has the body

```
Error = { 1: code      tstr,                  ; the sentinel name, exactly as section 12 writes it
          2: message   tstr,                  ; human-readable, not normative, no secrets
          3: retryable uint (0 or 1),
          4: stored    bstr (O) }             ; 409 only, see below
```

`code` is stable: it is the sentinel's name as written in section 12 (bare
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
  presented action bytes hash to the stored `action_hash`); otherwise key 4
  is absent. A caller that receives `stored` verifies it with
  `VerifyAuthorization` like any Authorization; it is the same answer the
  first request got.
- `ErrReceiptExists` always carries `stored` = the stored SignedReceipt.
- No other code carries key 4.

Mapping (normative). The server maps the error returned by the operation to
the first row below whose sentinel it matches (Go: `errors.Is`, in table
order). Order matters where one sentinel also matches another:
`ErrAnchorTooOld` matches `ErrPayloadUnavailable` too (section 8.5), so it is
listed first. The sentinels added in `v0-draft.17` (`ErrPayloadAboveCap`,
`recorder.ErrSubmitMismatch`, `ErrArchiveUnavailable`,
`recorder.ErrArchiveUnavailable`, `recorder.ErrEscrowInsufficient`) wrap
no other section 12 sentinel and are matched after the existing codes of
their status.

| Status | Codes, in match order |
|---|---|
| 410 | `ErrAnchorTooOld`, `ErrExpired`, `edictaapi.ErrPublishStale` |
| 400 | `ErrMalformed`, `ErrTrailingData`, `ErrFloat`, `ErrSimpleValue`, `ErrTag`, `ErrIndefiniteLength`, `ErrNonMinimalInt`, `ErrNestingTooDeep`, `ErrUnsortedMap`, `ErrDuplicateKey`, `ErrKeyType`, `ErrInvalidString`, `ErrUnknownKey`, `ErrWrongType`, `ErrMissingField`, `ErrFieldSize`, `ErrNonCanonical`, `ErrUnsupportedVersion`, `ErrIntRange`, `ErrInvalidEnum`, `ErrZeroValue`, `ErrPayloadTooLarge`, `ErrInvalidNamespace`, `ErrTimeOrder`, `ErrActionSize` |
| 401 | `edictaapi.ErrTokenInvalid`, `edictaapi.ErrPublishSignature` |
| 403 | `ErrInvalidPublicKey`, `ErrSignatureInvalid`, `ErrScopeMismatch`, `ErrActionTypeNotAllowed`, `ErrDANotAllowed`, `ErrAgentKeyIsGateKey`, `ErrAgentNotAllowed`, `ErrAgentKeyMismatch`, `ErrExecutorNotAllowed`, `ErrKeyRole` |
| 404 | `edictaapi.ErrRouteNotFound`, `edictaapi.ErrPublishDisabled` |
| 405 | `edictaapi.ErrMethodNotAllowed` |
| 409 | `ErrNonceUsed`, `ErrReceiptExists`, `ErrBeforeRegistryEpoch` |
| 413 | `ErrTooLarge`, `recorder.ErrTooLarge`, `ErrPayloadAboveCap` |
| 415 | `edictaapi.ErrMediaType` |
| 422 | `ErrActionMismatch`, `ErrPayloadSizeMismatch`, `ErrPayloadHashMismatch`, `ErrDACommitmentMismatch`, `ErrArchiveRecomputeUnsupported`, `ErrIssuedBeforeAnchor`, `ErrTTLTooLong`, `ErrNotAuthorized` |
| 425 | `ErrNotYetValid`, `ErrAnchorNotFound` |
| 429 | `edictaapi.ErrQuotaExceeded` |
| 502 | `recorder.ErrSignerMismatch`, `recorder.ErrSubmitMismatch` |
| 503 | `ErrPayloadUnavailable`, `ErrRetentionUnavailable`, `ErrChainUnavailable`, `ErrAllowlistUnavailable`, `ErrRegistryUnavailable`, `ErrClockRegression`, `ErrClosed`, `recorder.ErrOutcomeUnknown`, `recorder.ErrNodeUnavailable`, `recorder.ErrTooManyPending`, `recorder.ErrNotVisible`, `ErrArchiveUnavailable`, `recorder.ErrArchiveUnavailable`, `recorder.ErrEscrowInsufficient` |
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
An error that wraps a context deadline but matches no section 12 sentinel is
504 `edictaapi.ErrDeadline` only if the handler's deadline has fired;
otherwise it is 500 `edictaapi.ErrInternal`. Threat note: a Recorder timeout
reported as 504 would hide that a fee may have been spent and that a retry
is held by PR8; 503 with the Recorder code says exactly that.

The mapping is the whole contract: two servers report the same code and
status for the same failure because the operations' stage orders (sections
6.5, 8.7, 14.3, 17.3) decide which sentinel occurs, and this table decides
how it is reported. The full table, and the section 12 names that never
cross the API (client-side SDK checks, payload opening, profile sentinels,
removed names), are in `spec/vectors/api/errors.json`.

Threat notes:
- No oracle: an unknown agent and a bad signature give the same code
  (`ErrAgentNotAllowed` comes only after a valid signature, section 8.7; at
  `/v0/publish` both are `edictaapi.ErrPublishSignature`). `stored` is
  returned only under the retry rule, so a caller without the committed
  bytes learns nothing about a used nonce.
- `retryable` is advice the server derives from the sentinel, never from
  the client. A 503 at `/v0/authorize` means no nonce was consumed and no
  Authorization left the gate (section 8.7, sign before consume); at most
  the idempotent decision record of stage 4a exists, so a retry cannot
  produce a second Authorization.
- `message` is for operators. It MUST NOT contain tokens, keys or request
  bodies; for 500 it is a fixed redacted text.
