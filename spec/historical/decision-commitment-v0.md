# DecisionCommitment v0

> Superseded and unsupported. Historical draft, frozen at tag
> `v0-format-freeze-2`; its vectors and checkers are at that tag. Edicta
> supports `spec/decision-commitment-v1.md` only.

Edicta — verifiable decision layer for autonomous agents.

Status: revision `v0-draft.30` (2026-10-08). Working draft, subject to change.
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
| `v0-draft.19` | 2026-10-06 | At-height read review, no wire change. (1) Section 11.2, RS2: the canary is decided from success or failure and the echoed `x-cosmos-block-height` only, never from error codes or messages (an honest pruned node answers `codes.Unknown`, and grpc-go makes `codes.Internal` from transport faults, so the draft.17 rule kept honest pruned endpoints in observations-only mode and could pass a proxy). Configured heights per chain id: a recent `h_r = head - canary_offset` (default offset 10, greater than `lag`) whose bank `Params` query must succeed and echo `h_r`, and an optional pre-activation `h_pre` whose x/fibre `Params` query must fail, set per chain id (by default only `mocha-5`, 1,082,619; none elsewhere unless configured) and queried even when the `h_r` query fails; height 1 is dropped. Outcomes Honoured, Ignoring, Inconclusive. (2) Section 10.9, AH3: a missing or different height on a block or header read on a consensus endpoint marks it height-ignoring for state reads until a later canary passes; bridge endpoints get their own canary (header at `head - canary_offset`, returned height must equal the requested one), logged only, never driving the retention mode. (3) Section 10.9, AH5: a header or block "not found" at a height at or below an observed head, or above every observed head, is `ErrChainUnavailable` on both `da` paths; `ErrAnchorNotFound` only for a block read that passed AH1 and AH2 and holds no anchor. | Unchanged | Every file byte-identical (stateful rules, no vectors); `spec/vectors/api/errors.json` keeps `"revision": "v0-draft.17"`. |
| `v0-draft.20` | 2026-10-06 | Archive record format 0, additive (`v0-draft.19` is a separate revision of sections 10.9 and 11.2). (1) New section 19: the byte layout of archive records, deterministic CBOR with integer keys: five kinds (payload, evidence, decision, Authorization, rejection marker), their fields per `da`, the encodings of the opaque Celestia objects, strict decoding and its precedence (`archive.ErrCorrupt` with the core sentinel as cause), logical keys `(kind, da, commitment)` and `(kind, commitment_hash[, error])` with a canonical path, write-once storage with a per-kind identity (same identity: success and the stored record stays; other identity: `archive.ErrConflict`), write preconditions (the DA recompute before a payload is stored; evidence needs the payload, Authorization and markers need the decision record: `archive.ErrNotFound`; an Authorization whose K2 inputs carry a `da` other than the decision's is refused with `archive.ErrCorrupt`, before the identity comparison), and the record state of AR6 derived from the records present. (2) Section 10.7: the format is no longer out of scope; for `da = 2` the PFB tx with its index and proof is SHOULD, not MUST, because the commitment proof of the share-version-1 blob against `data_hash` already binds namespace, commitment and signer to block `height` (pending the human's confirmation). (3) Section 8.7 AR5: the marker is still unsigned and in no message between parties; its archive layout is section 19. (4) Section 11.3: pointer to section 19. (5) Section 10.6.1, from the task 016 vectors: CV4 corrected: `V` is `HistoricalInfo.valset` in its stored order, which SDK `NewHistoricalInfo` sorts by consensus power `floor(tokens / 10^6)` descending, then consensus address, and the keeper does not re-sort (draft.17 said: sorted by tokens); a verifier checks that order (VERIFIED, code). The power reduction `10^6`, and `next_validators_hash` at `h` = `validators_hash` at `h + 1` = the `HistoricalInfo` set, are VERIFIED (live Mocha data, 2026-10-06); the header inside `HistoricalInfo` is partial and not a trust anchor. New threat note on token precision (no header commits to exact tokens; an archive writer can shift tokens inside a `10^6` bucket and flip a verdict at the edge) and new report field `cert_token_precision` (`robust` or `bucket-dependent`, a warning that never changes the verdict); an independent second copy of the evidence is SHOULD for operators who rely on the archived set. No new section 12 sentinel: `archive.ErrNotFound`, `archive.ErrConflict` and `archive.ErrCorrupt` are archive package errors, never a gate verdict, and never cross the API (an archive failure at the gate stays `ErrArchiveUnavailable`). | Unchanged: every message, tag and gate check outcome. Verifier: CV4 now checks the stored order, new report field `cert_token_precision`. New: archive record bytes | Every existing file byte-identical. New: `spec/vectors/archive/records.json` and `state.json` (`v0-draft.20`), generator `gen_archive.py`, checker `check_archive.py` (run by `check_vectors.py`), rules module `archive_v0.py`. |
| `v0-draft.21` | 2026-10-06 | Fibre certificate rule review (section 10.6.1 only), no wire change. (1) CV4: a validator list the keeper would reject is rejected as a whole before any signature is checked: a key that is not 32 bytes, or a list on which CometBFT `NewValidatorSet` fails (duplicate address, power `<= 0`, a power or the total above `MaxInt64 / 8`). Before this a verifier could count a repeated validator once per copy and accept a certificate the chain rejects. (2) CV7: `NewValidatorSet` over `V` with consensus powers must hash to `next_validators_hash` of the header at `promise.height`, whose height and chain id equal the promise's; the fallback to `validators_hash` of `promise.height + 1` and the key-by-key comparison with an archived CometBFT set are removed (the fallback is redundant on a valid chain and, unbound, accepted a header of any height); CV7 also compares `V` position by position with that set, which enforces the stored order of CV4 (draft.20), because the hash alone is order-free. (3) `cert_valset_header` has one form. (4) Merged with draft.20: one CV4 row (draft.20's stored order MUST, consensus power then address, plus the list conditions and the `HistoricalInfo` height), one CV7 row, one `cert_valset_header` row; the "accept either header" sentence is removed. Verdicts change only for inputs the chain would not accept or whose header evidence does not bind. | Unchanged | `spec/vectors/da/fibre_cert.json` regenerated as `"revision": "v0-draft.21"`: new `boundary` cases (`total_one_invalid_first`, `duplicate_signer`, `zero_power`, `total_above_max`, `total_at_max`, `bad_key_length`) and a `valset` section; `promise_chain_id` and `header_promise_next_validators_hash` now also fail CV7; `cometbft_valset_key` moves to `undetected_mutations`; `zero_signatures_total_one` reports `stop_index` none; `valset_out_of_order` (two validators of equal power swapped: the walk accepts, the keeper over the stored order rejects, CV7 fails). Expectations come from upstream code (keeper transcription over `validator.SignatureSet`, `NewValidatorSet`, header hashes) and the Python checker is an independent implementation. Every other file byte-identical. |
| `v0-draft.22` | 2026-10-06 | Cleanup after draft.21 dropped the CV7 fallback; no wire change. (1) Section 10.6.2: the verifier needs a trusted header at `promise.height` only, not at `promise.height + 1`; HT1 requires `T >= max(payload_ref.height, promise.height)` (before: `promise.height + 1` if higher). A header at `promise.height + 1` is still read where the HT3 backward chain passes through it, from any source, like every header between. (2) Section 10.7: the `da = 1` header row asks for the signed header at `PaymentPromise.height` only; the CometBFT validator set and the `validators_hash` of `promise.height + 1` are no longer needed by CV7. (3) Section 19.2, evidence field 18 `promise_valset`: still R1 for `da = 1` in archive format 0 (its decoder requires it, and its bytes do not change), but kept for audit only: no v0 check reads it. (4) Section 1, PFF certificate row: the archived list is tied to the chain by `next_validators_hash` of the header at `PaymentPromise.height`, not by `validators_hash`. Verdicts unchanged: no v0 check read the items dropped here since draft.21. | Unchanged. Verifier: HT1 accepts a trusted header at `promise.height` | Every file byte-identical. |
| `v0-draft.23` | 2026-10-06 | `da = 1` anchor proof from namespace data (human decision of 2026-10-06); no wire change. (1) Section 10.4, K0 for `da = 1`: rules NA1 to NA7 replace the block scan. The header at `height` comes from the consensus endpoint (AH1) and gives `data_hash` and `T_H`; the DAH comes from a bridge and must pass `ValidateBasic` and hash to `data_hash`; `share.GetNamespaceData(height, PayForFibreNamespace)` comes from a bridge and must pass `NamespaceData.Verify` (one complete NMT namespace proof per row the DAH says holds the namespace); txs are reassembled with `ParseTxs` and accepted only if splitting them again gives the same shares; candidates as before; code 0 from gRPC `GetTx` with the echoed height (node-attested; needs the node's tx index, which the draft.17 lookup avoided); the anchor is the earliest `creation_timestamp` with code 0, ties by position in the namespace (before: block order). A failure of the bridge's answer, an unreadable code or a missing bridge at request time is `ErrChainUnavailable`; `ErrAnchorNotFound` only for complete namespace data without an anchor. No whole-block read for `da = 1`. A `fibre` gate without a configured bridge refuses to start. Threat notes on the lookup and on `ShareProof.Validate` (no row index, total or original-row check, no completeness; not used on this path, extra checks for anyone who does). (2) Section 10.9: `share.GetNamespaceData` is a block read bound through AH2 (DAH, row roots); `GetTx` is not a read at a height, its echoed height is checked, and a mismatch fails the read without marking the endpoint height-ignoring; AH5 names NA1 to NA4. (3) Section 10.6.1 CV8 and section 10.7: for `da = 1` the archived anchor proof (DAH plus namespace data, form 1) is the inclusion evidence, MUST; the system blob stays (format 0 requires it) and is checked only for equality with `NewV2Blob` of the archived PFF; the PFF `ShareProof` goes from SHOULD to MAY and is not used; a form-1 proof above `2^22` bytes cannot be archived (`recorder.ErrArchiveUnavailable`). New report fields `anchor_proof_form` and `anchor_candidates_earlier` (a warning). (4) Section 19.2: `system_blob_proof` holds form 1 (deterministic CBOR `{1: 1, 2: DAH protobuf, 3: NamespaceData.WriteTo stream}`) or, in records written before, form 0 (the `CommitmentProof` JSON), told apart by the first byte; `anchor_tx_index` for `da = 1` is the node's report, informational. Archive format 0 bytes and strict decoding unchanged. (5) Section 10.8: SC1 also pins nmt `v0.24.5` (NA3 needs the completeness fix of `v0.24.3`); SC6 covers the anchor-proof bridge (verified answers, so no version gate; the version is logged). Section 10.1: nmt pin row. Section 1: a row for the anchor proof. Outcomes change only in the `da = 1` lookup: a gate whose node has no tx index now answers `ErrChainUnavailable` where draft.22 scanned the block, a gate without a bridge does not start, and the tie order between equal timestamps is the namespace order. | Unchanged. Archive format 0 unchanged; the opaque `system_blob_proof` for `da = 1` gains form 1. Verifier: CV8 on form 1, two new report fields | New: `spec/vectors/da/fibre_anchor.json` (`"revision": "v0-draft.23"`: live Mocha namespace data and DAH at heights 1,402,819 and 1,439,696, 12 mutations, 14 reassembly cases, the form-1 archive proof), generated by `spec/vectors/tools/fibreanchor-gen` from upstream code and checked by the new `check_fibre_anchor.py` (independent NMT, RFC 6962, protobuf, compact-share parser and splitter), run by `check_vectors.py`. Every existing file byte-identical. |
| `v0-draft.24` | 2026-10-06 | Verifier fixes from the task 023 re-audit; no wire change. (1) Sections 10.4 (NA5) and 10.6.1 (CV2): a `da = 1` promise height MUST be at most the anchor height: `PaymentPromise.height <= payload_ref.height`, equality allowed. On chain this always holds (the keeper reads `HistoricalInfo` at the promise height, which does not exist yet above the current block), so the gate's candidates do not change; a verifier now rejects an archived promise above `height` instead of trusting a header above it. (2) Section 10.6.2: the header at `payload_ref.height` and the header at `promise.height` are checked through header trust separately; at equal heights both archived headers MUST have the same hash, and one never stands in for the other (before, an implementation keyed by height could let the genuine promise header vouch for a forged anchor header). (3) Section 19.2, K2 replay: `promise_created` is consistent iff it equals the creation time of a candidate created at or before the archived anchor (NA7 picks the earliest code-0 candidate, which need not be the archived one); with `anchor_candidates_earlier = 0` that is equality. Form 0 shows no other candidate: a smaller value is not checked. An absent `promise_created` is consistent iff the authorized path is the archive (`path = 2`). Before, the rule was unstated and an implementation that required equality reported a legitimate earlier candidate as a gate inconsistency. (4) CV2: the `blob_size` arithmetic is written out, from the committed `payload_size`. Verdicts change only in `verify` and `replay`: a promise above `height` fails CV2, a forged anchor header at the promise height fails header trust, and K2 replay accepts an earlier candidate and an absent `promise_created` on the archive path. | Unchanged | Every file byte-identical. |
| `v0-draft.25` | 2026-10-06 | Bridge fallback, Fibre cost and archive read faults; no wire change (`v0-draft.24` is a separate verifier revision whose status line was not bumped). (1) Section 10.8, SC6 (human decision of 2026-10-06): at the pin the only version method, `node.Info`, needs an admin token, so the download fallback is now enabled after compatibility is verified by version (BV, permitted, not recommended) or by a capability probe (BP1 to BP5: download one retained, anchored blob found through NA1 to NA6, check the raw `fibre.Download` answer's shape strictly, recompute P3). A version or capability declared in configuration is never a substitute. A failed or inconclusive probe disables the fallback with a warning, never the start. The anchor-proof bridge's version log is best effort (a read token gets a permission error). Rationale note: integrity comes from the P3 recompute of every answer; the check is about compatibility only. (2) Section 10.2 and the section 17.3 threat notes: a `PaymentPromise` handed to validators but never settled is charged once through `MsgPaymentPromiseTimeout` after the promise timeout (verified in x/fibre at the pin), so a failed `da = 1` upload may cost one fee without creating an anchor; earlier design notes said partial signatures cost nothing. (3) Sections 8.7 (stage 9), 8.5, 12 and 19.6: an unreadable or corrupt archive payload record on the archive path is `ErrArchiveUnavailable` (operational, 503, no rejection marker, nonce not consumed), never a P verdict or `gate.ErrBlobNotFound`. Verdicts change only for a corrupt archive payload record (before: an unnamed operational error that implementations could map to `ErrPayloadUnavailable`). | Unchanged. Gate: a probe hook for the bridge fallback; the archive source's read fault maps to `ErrArchiveUnavailable` | Every file byte-identical. |
| `v0-draft.26` | 2026-10-07 | Verifier online mode and execution check; no wire change. (1) New section 20.1: the report's named checks and the verdict rule of the reference verifier (first match: `invalid`, `not_authorized`, `unchecked`, `valid`; a required check that never ran is not a pass), and CLI exit codes 0 to 4, now normative; no outcome changes. (2) New section 20.2, rules EX1 to EX8: an optional, rail-agnostic `execution` check. A checker registered per action type takes the authorized action bytes and the receipt's `rail_ref` and returns the height, header hash, inclusion level (`proven` or `node-attested`), result level (`node-attested` in v0) and cross-check result. The core requires a passed receipt and the `authorized` state, `height > payload_ref.height` strictly, the header at `height` trusted from the same checkpoint, and no cross-check mismatch. When requested, the check is required for `valid`. A missing receipt or checker is `unchecked`. `proven_execution` means inclusion proven against a trusted header only. Warning `execution_after_expires`. The bank-send checker is in the profile (`bank-send-v0-draft.5`, section 3.4). (3) New section 20.3, rules HA1 to HA6: read-only HTTP archive reads at `<base>/<canonical path of 19.3>`. `404` and `410` mean absent; every other answer is a fault that stops `verify` without a verdict; per-kind body caps; the 19.1 and 19.3 reader checks; the record state from reads, with one probe per marker verdict; the server serves only canonical keys, never lists, and never caches a `404`. (4) New section 20.4, rules OH1 to OH8, with amendments to HT1, HT3 and HT7: the trusted header can also be an explicit checkpoint `T:HASH` or a checkpoint agreed by online CometBFT RPC sources. `T` is the minimum of their latest heights. Hashes are always recomputed. Sources are distinct by normalized host and by `/status` `node_info.id`, and the gate's own endpoints are excluded. Two answering sources with different hashes are `fail`. Fewer than `quorum` agreeing sources are `unchecked`; `quorum` defaults to 1 (human decision of 2026-10-07). The archived header at a needed height is preferred, and if it does not link, that is `fail`. An online header that does not link is that source's fault (`unchecked` if no source links), where HT3 alone said fail. A cross-check mismatch is `fail` for any quorum. (5) Section 10.6.2: the `UNVERIFIED` item on `Header.Hash()` is now verified on live Mocha data. Outcomes change only in modes that did not exist before (online sources, the execution check). Offline verdicts are unchanged. | Unchanged | Every file byte-identical. |
| `v0-draft.27` | 2026-10-07 | Execution check outcomes and the general INCONCLUSIVE rule (human decisions of 2026-10-07: the check is tri-state; execution code confirmation; header cross-check disagreement, which supersedes the earlier "a mismatch fails" decisions; archive cases follow the general rule); no wire change. (1) 20.1: the general rule. `invalid` only about the decision or action and only from verified data; any source problem, disagreements included, gives at most `unchecked`; a hostile source never causes `valid` or `invalid`. Archive cases: an absent decision, payload or evidence record, corrupt bytes (decoding, key, hashes, P1 to P3, signatures outside the commitment hash, the `da = 2` proof, Fibre CV1 to CV8 and the anchor proof), and an archived header that does not link are `unchecked` (was `fail`). The verdict for an absent decision is `unchecked` (state `unknown`). K1 is judged only against a trusted header, and replay inconsistencies are `unchecked`. The `fail` boundary is a closed list: verified archived data that proves a violation. New 20.1.1: a closed reason enum, one machine-readable reason per `unchecked`; HT3, OH6, 10.6.1, 19.2 and the HA threat note are amended. Exit codes restated (2 = INCONCLUSIVE); the output names the source. (2) New 20.2.1. Verified facts F1 to F5 and F7 (F7 = result proof), and the confirmed fact F6 (cross agreement), which supports only the interim `pass`. Rules EO1 to EO4, and the invariant with no exceptions. (3) Facts: new `outcome`; `result` is `proven`, `cross-confirmed` or `node-attested`; `sources` per source. (4) EX3: the checker classifies by 20.2.1. EX4: `fail` only under F5. EX5: the header at `height` passes trust before anything is compared, outcomes (a) to (d); a header that does not link is `unchecked`, naming the source (was `fail`); a header cross-check mismatch is `unchecked` with the reason "header disagreement with trusted chain: possible bad trusted header, hostile source, or fork". EX6: a tx cross mismatch is `unchecked` (was `fail`); a source that contradicts verified facts is reported and ignored. EX9: a failed result is `fail` only under F7; `pass` needs F7, or interim F6; never a node-attested `pass`. New EX10: alternates tried automatically, cross sources never promoted. EX threat note rewritten (fabricated height, result proof at `height + 1`). (5) OH4: waiting is MAY (was MUST). OH5, OH7 and HT6: a disagreement between header sources is `unchecked` with that reason (was `fail`). OH threat note and section 1 row updated. Outcome changes, all toward `unchecked`, apart from new `pass` paths (F7, or interim F6). In `verify` with online header sources: a checkpoint or cross-check disagreement. With `--check-execution`: a source's wrong bytes, bad proof, unverified height or code, a tx cross mismatch, a header that does not link, and a success attested by one source. Offline: every archive-side `fail` named above becomes `unchecked`, an absent decision gives `unchecked` (was `invalid`), and K1 against an untrusted header gives `unchecked` (was `fail`). Gate outcomes are unchanged. Bank-send profile `bank-send-v0-draft.6` at the same time (result proof RP1 to RP6). | Unchanged | New: `spec/vectors/verifier/execution_outcomes.json` (`v0-draft.27`): 37 outcome cases (5 pass, 23 unchecked, 9 fail), 9 inclusion-proof forms of the live Mocha tx at 1,442,606, a live result proof of that block (results, headers at H and H + 1, leaves, root, index, 9 mutations), and 4 transactions. Raw captures in `spec/vectors/verifier/live/`. New: `spec/vectors/verifier/reasons.json` (32 reasons, one case each or more: 45 cases, and 5 `fail` boundary cases), generator `gen_verifier_reasons.py`, checker `check_verifier_reasons.py`. Generator `gen_execution_outcomes.py`, checker `check_execution_outcomes.py` (an independent classifier and result-proof recompute; run by `check_vectors.py`). Every existing file byte-identical. |
| `v0-draft.28` | 2026-10-07 | The interim cross-confirmed `pass` is removed (human decision of 2026-10-07, execution code confirmation: the interim held until the result proof landed, and it has landed in the reference verifier; audit 027a2 A1). No wire change. (1) 20.2.1: F6 (cross agreement) is reported only. It supports neither `pass` nor `fail`. EO3 has no exception: `pass` needs proven inclusion (F5) and a proven result (F7). The invariant's limits drop the interim item, so two colluding sources can no longer cause `valid`. (2) EX9: `pass` needs `result = proven`; the interim rule is deleted. EX6: `cross_check = pass` never gives `pass`. The EX threat note and the section 1 row no longer name F6 as a basis for `pass`. (3) 20.2 facts: `result = cross-confirmed` is a reported level only. (4) 20.1.1: `result_unproven` now also covers a code that agreeing sources confirm, and its advice and that of `result_index_unbound` no longer suggest a cross tx source (the reason names are unchanged). (5) Bank-send profile `bank-send-v0-draft.7` at the same time: RP5 can bind the index by rebuilding the square from the block's txs (audit 027a2 m2), and BX9 drops the cross-confirmed `pass`. Outcome changes: with `--check-execution`, a success confirmed only by agreeing tx sources is `unchecked` (`result_unproven`, exit 2; was `valid`, exit 0); a tx that does not start at share 0, in a block with mixed codes, can now be `pass` or `fail` when a source serves the block's txs (was `unchecked`, `result_index_unbound`). Offline verdicts and gate outcomes are unchanged. | Unchanged | `spec/vectors/verifier/execution_outcomes.json` regenerated as `v0-draft.28` (profile `bank-send-v0-draft.7`): 41 cases (5 pass, 26 unchecked, 10 fail). `pass_cross_confirmed_interim` is replaced by `unchecked_result_cross_confirmed_only`. New: `unchecked_result_cross_confirmed_inclusion_proven`, `pass_proven_index_rebuilt`, `fail_tx_failed_index_rebuilt`, `unchecked_result_index_rebuild_mismatch`, and the result proof states `match_rebuilt` and `match_rebuild_mismatch`. Every other case, and the `txs`, `live`, `proofs` and `result_proof` sections, are byte-identical. The generator and the checker are updated: the checker's classifier no longer passes on cross agreement, and it requires every `pass` case to have proven inclusion and a proven result. `spec/vectors/verifier/reasons.json` regenerated as `v0-draft.28` (generator `gen_verifier_reasons.py` and checker updated): only the `meaning` and `advice` of `result_unproven` and `result_index_unbound` change, to the 20.1.1 text; the enum, cases and boundary are unchanged. The live vector of the square rebuild is planned with the live run. Every other file byte-identical. |
| `v0-draft.29` | 2026-10-07 | Policy v1 (task 028), additive: `spec/policy-v1.md` (`policy-v1-draft.1`). No v0 wire change. (1) Section 20.1: new named check `policy`, required for `valid` when it runs; new report field `gate_integrity` (`ok`, `violated`, `not_checked`, `unchecked`); the verdict is `unchecked` when `gate_integrity` is `violated` and no check fails; new exit code 5 (unchecked with the gate's integrity violated), precedence 4, 1, 5, 3, 2, 0, and the first-line banner; the `fail` list gains `policy` (verified data proving the allow broke the mandate). (2) Section 20.1.1: new reasons `policy_verdict_unavailable`, `policy_mandate_unavailable`, `policy_principal_untrusted`, `policy_no_extractor`, `state_history_unavailable`, `gate_equivocation` (integrity field only); `source_corrupt` and `blocked` also on `policy`, `source_corrupt` also on `gate_integrity`. (3) Sections 19.1, 19.2, 19.3 and 20.3: archive format 0 gains the policy kinds 7 to 12 (kind 6 stays undefined, as vector `rec_kind_6` pins), their caps and paths, and the policy deny names as marker verdicts (HA5 now probes 26 names). (4) Pointers only, no rule change: the tag namespace (section 2), the policy stages 4p and 10p (section 8.7) and the policy HTTP codes (section 18.3) are defined in `spec/policy-v1.md`. A gate without a mandate and a verifier without policy records behave exactly as in draft.28. | Unchanged | `spec/vectors/verifier/reasons.json` regenerated additively as `v0-draft.29` (38 reasons, 54 cases, 7 boundary; every existing case unchanged; the `checks` of `source_corrupt` and `blocked` extended). New: `spec/vectors/policy/*.json`, `spec/vectors/profiles/bank-send/tia_transfer_facts.json`, generator `gen_policy.py` with rules module `policy_v1.py`, independent checker `check_policy.py` (run by `check_vectors.py`). Every other file byte-identical. |
| `v0-draft.30` | 2026-10-08 | Policy walk truncation (human decision of 2026-10-08, approving an additive change to the closed reason enum). No wire change. (1) Section 20.1.1: new reason `policy_walk_truncated`, on `gate_integrity` only: the policy integrity walk took its step cap, default or explicit, before it reached genesis. (2) Section 20.1: after a policy walk `gate_integrity` is `ok` only when the walk reached genesis, the start of the counter's history; otherwise `violated` or `unchecked`. A truncated walk is never `ok`. The field carries `walk` (step cap, steps, walked seq range, chain length, why the walk ended) and the text output prints it, for example "last 10001 of 37000 verdicts checked". An `unchecked` `gate_integrity` does not change the verdict or the exit code; only `violated` does, as in draft.29. The verdict rule itself is unchanged. (3) Policy `policy-v1-draft.4` at the same time: the step cap is `--max-walk-steps` (default 10000; was `--policy-depth`), an explicit cap no longer reports `ok` when it cuts the walk (supersedes draft.3), and the retention horizon no longer ends the walk. Outcome changes, in `verify --policy-full` only, and only in `gate_integrity`: a walk cut by an explicit cap is `unchecked` (was `ok`); a walk that stopped at the horizon goes on toward genesis. Verdicts, exit codes and gate outcomes are unchanged. | Unchanged | `spec/vectors/verifier/reasons.json` regenerated additively as `v0-draft.30` (39 reasons, 55 cases, 7 boundary): the reason `policy_walk_truncated` and the case `policy_walk_truncated` (verdict `valid`, exit 0) are appended; every existing reason, case and boundary entry is byte-identical. `check_verifier_reasons.py` allows exactly one exception to "an unchecked check gives unchecked": a reason carried only by `gate_integrity` keeps the verdict `valid`, exit 0. `spec/vectors/policy/verify.json` moves to `policy-v1-draft.4` (see the policy document). Every other file byte-identical. |

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
| PFF certificate check, one rule for gate, Recorder and verifiers (section 10.6.1) | A forged or under-signed availability certificate presented after the chain pruned the state that could re-check it | More than 2/3 of voting power honest at `PaymentPromise.height`; the archived validator set is the one the chain used, tied by `next_validators_hash` to the header at `PaymentPromise.height` and that header to the chain by the hash chain of section 10.6.2; Ed25519 |
| Fibre anchor proof from namespace data, rules NA1 to NA7 (section 10.4) | A bridge or an archive presenting a PFF that was not in block `height`, hiding one that was (a false `ErrAnchorNotFound`, or an earlier promise that would move K2's `start`), or a cut or padded tx | The header at `height` is the chain's: the gate's trusted node or the W5 verifier (section 10.9), and for verifiers the header trust of section 10.6.2; SHA-256; NMT completeness as in nmt `v0.24.3` or later; more than 2/3 of voting power honest, so the square follows the protocol. Result code 0 stays `node-attested` |
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
| Verifier online mode: HTTP archive reads, agreed checkpoint, cross-check (section 20.3, 20.4) | An archive server or header source that withholds, alters or fabricates data in order to make `verify` print `valid` | The archive is trusted for availability only, because every record is re-checked. The checkpoint is as honest as the agreeing operators: with `quorum = 1` a single operator that colludes with the archive's writer can fake the chain (HT4 checks no signatures). The report names that operator, and one honest cross-check source turns the fake into `unchecked` (`header_disagreement`). A withheld or altered archive record gives `unchecked` with a reason (20.1.1), never `invalid` |
| Execution check (section 20.2 and the profile's checker) | A receipt whose `rail_ref` names no transaction, another transaction, one before the anchor, or one that failed | The trusted header and SHA-256: inclusion proof (F5) and result proof against `last_results_hash` (F7). Agreement of tx sources (F6) is reported only, and it never decides the outcome (since `v0-draft.28`). A hostile source can only make the check `unchecked` (20.2.1). Does not detect a second execution of the same decision |

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
- "Agent" is any decider that signs commitments: an LLM agent, a bot, a
  keeper or a script. The gate never asks the agent why an action is
  allowed. It verifies mathematically that an existing commitment (and the
  mandate, if one is configured, `spec/policy-v1.md`) allows exactly these
  action bytes.
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

Tag namespace (since `v0-draft.29`): every later tag family has the form
`edicta/<family>/v<N>/<name>`; this core keeps `edicta/v0/<name>`. Tags are
never reused, and no two tags of any family are equal. The policy family
`edicta/policy/v1/*` and its rules are in `spec/policy-v1.md` section 2.

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

Archive read faults (normative since `v0-draft.25`). When the archive path
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
| 6 | K | K0 | The anchor tx exists at `payload_ref.height` (section 10.4 for `da = 1`: proven from the PayForFibre namespace data of that block, result code 0, rules NA1 to NA7; 10.5 for `da = 2`), and the header time `T_H` is readable | `ErrAnchorNotFound` | 2 |
| 7 | K1 | K1 | Section 11.2 | `ErrIssuedBeforeAnchor` | 4 |
| 8 | K2 | K2 | Section 11.2. Selects the DA or archive path only, never a rejection by itself | none | 2, 4 |
| 9 | P | P1, P2, P3 | Section 8.5, per path. On the archive path, an archive payload record that is unreadable or corrupt (section 19.6) is an operational failure, not a verdict | P sentinels, precedence in 8.5; `ErrArchiveUnavailable` (operational, 503, `Retry-After`) for an unreadable or corrupt archive payload record: no rejection marker (AR5), nonce not consumed | 2 |
| 10 | T' | T1, T2 | `CheckTime` again with a fresh clock reading `authorized_at`, because fetches take time | `ErrNotYetValid`, `ErrExpired` | 4 |
| 11 | Z | Z1 | Build the Authorization (section 15.1): `commitment_hash`, `action_hash = c.action.hash`, the gate's `gate_id`, `expires = min(valid_until, authorized_at + MaxAuthorizationTTL)`, `path` of stage 9. Sign it with the gate key under `TagAuthorizationSig` and verify the signature before use. Nothing is stored yet | (operational: signer error, timeout) | 7 |
| 12 | N | N1 | Atomically create the registry entry for `(agent_pubkey, nonce)` holding `commitment_hash` and the canonical SignedAuthorization; fails if the key exists. Committed durably before stage 13 | `ErrNonceUsed` | 5 |
| 13 | R | | Return the SignedAuthorization bytes | - | - |

A gate with a mandate adds stage 4p (after A) and stage 10p (after T'), and
its stage 12 also commits the policy counter (invariant 8); `spec/policy-v1.md`
section 11 defines them. Without a mandate this table is complete.

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
| AR5 | Rejection marker. When a request whose decision record exists (stage 4a passed) is then refused with a verdict, the gate marks that record rejected with the error name exactly as listed in section 12 (for example `ErrExpired`, `ErrIssuedBeforeAnchor`, `ErrNonceUsed`), its `gate_id` and the gate clock at refusal. Verdicts are the sentinels of stages 5 to 12. Operational failures (`ErrChainUnavailable`, `ErrArchiveUnavailable`, a signer error or timeout) say nothing about the decision and are not marked. The marker is archive metadata of the gate: not signed and not part of any message between parties; its archive record layout is section 19 (since `v0-draft.20`). |
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
| celestiaorg/nmt | `v0.24.5` | `a2ba47691cbda955ca24fb9fa97b2a12ceb2ff91` | Added in `v0-draft.23`: the version the node pin resolves; NMT namespace proofs for the `da = 1` anchor lookup (section 10.4). SHA from the Go module proxy's origin record, 2026-10-06. |

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

Anchor lookup (rule K0 for `da = 1`; normative since `v0-draft.17`, procedure
since `v0-draft.23`). The gate proves the anchor from the PayForFibre
namespace of block `height` and never reads the whole block. Sources: the
gate's consensus endpoint for the header at `height` and for result codes; a
celestia-node bridge for the data availability header (DAH) and the namespace
data. `PFF_NS` is go-square `PayForFibreNamespace`, `0x00 || 0^27 || 0x05`
(VERIFIED, `SQ/share/consts.go` and the live vectors).

| Rule | Requirement | On failure |
|---|---|---|
| NA1 Header | The header at `height` is read from the consensus endpoint under AH1 (section 10.9): its height equals `height`. `data_hash` and `T_H` (K1, K2) come from this one header. A header returned by a bridge never stands in for it. | `ErrChainUnavailable` (AH3 and AH5 as for any header read) |
| NA2 DAH | The DAH (row roots and column roots) comes from a bridge (`header.GetByHeight(height)`, field `dah`; the returned header's height MUST equal `height`, AH1) or from any other source. It is accepted iff upstream `DataAvailabilityHeader.ValidateBasic` passes (as many row roots as column roots, each count from 2 to 1024) and `Hash()`, the RFC 6962 root over `row_roots \|\| column_roots`, equals `data_hash` of NA1. | `ErrChainUnavailable` |
| NA3 Namespace data | `share.GetNamespaceData(height, PFF_NS)` from a bridge. Accepted iff upstream `NamespaceData.Verify(dah, PFF_NS)` passes (celestia-node at the pin, nmt `v0.24.5`): with `R` the rows, ascending, whose row root's namespace range `[min, max]` contains `PFF_NS` (`RowsWithNamespace`; parity rows never qualify), the answer has exactly `len(R)` entries, and entry `j` is a complete NMT namespace proof against `row_roots[R[j]]`: an inclusion proof with the row's shares of the namespace, or an absence proof without shares. `VerifyNamespace` checks the leaf namespaces, the range and completeness (no leaf of the namespace left or right of the range). `R` empty with no entries is a valid proof that the block holds no PFF. The gate bounds the bytes it reads per answer (`fibre_anchor_read_max_bytes`, configuration, default 16 MiB); a larger answer fails. | `ErrChainUnavailable` |
| NA4 Reassembly | `S` = the shares of all entries, in order. If `S` is empty, `T` is empty. Otherwise `T = ParseTxs(S)` (go-square compact-share parsing), and splitting `T` again with `NewCompactShareSplitter(PFF_NS, 0)` MUST give exactly `S` (same count, every share byte-equal). | `ErrChainUnavailable` |
| NA5 Candidates | A tx of `T` is a candidate iff upstream `fibretypes.TryParseFibreTx` (`APP/x/fibre/types/classified_tx.go`) classifies it as a Fibre tx and its single `MsgPayForFibre` carries a `PaymentPromise` with `namespace == payload_ref.namespace`, `commitment == payload_ref.commitment`, `blob_version == 0`, `chain_id` equal to the gate's configured chain id, and `PaymentPromise.height <= height` (since `v0-draft.24`; equality allowed). Any other tx of `T` is not a candidate. | - |
| NA6 Code | The result code of a candidate `x` comes from the consensus endpoint's gRPC `cosmos.tx.v1beta1.Service/GetTx` with the hash `SHA-256(x)` (upper-case hex). It is used only if `tx_response.height == height` and `tx_response.txhash` is that hash (AH1). Settlement level `node-attested` (section 10.6.1). | Error, not found, or another height: `ErrChainUnavailable` |
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
depends on nothing else. The tx index of the node is needed for NA6 only
(draft.17 to draft.22 read codes from the block results and needed none).

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
| Whether a PFF can be included with a non-zero code, and whether its system blob is then in the square (the promise is checked in CheckTx and ProcessProposal) | `UNVERIFIED` (NA7 handles either answer) |

From the anchor the gate takes `PaymentPromise.creation_timestamp` for K2
(section 11.2) and `T_H` from the NA1 header. It MAY also check that
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
verification failure; the verifier reports the first rule that failed. For
`verify` and `replay`, since `v0-draft.27`, that failure makes `anchor`
`unchecked` with reason `source_corrupt`, and never `fail`. The archived
certificate and proofs are the archive's answer, and a failure shows that
this copy does not prove the anchor (20.1). The gate and the Recorder still
refuse on any failure.

| Rule | Check |
|---|---|
| CV1 | The archived tx parses as a Fibre tx (`TryParseFibreTx`) with exactly one `MsgPayForFibre`. |
| CV2 | Binding: `promise.namespace == payload_ref.namespace`, `promise.commitment == payload_ref.commitment`, `promise.blob_version == 0`, `promise.chain_id` equals the expected chain id, `promise.height <= payload_ref.height` (since `v0-draft.24`; equality allowed; see the fact under NA5, section 10.4), and `promise.blob_size == U`, the upload size of section 10.4 computed from the committed `payload_size` (the blob length P1 checks), never from the archived blob or from the promise itself: `rows = ceil((payload_size + 5) / 4096)`, `row_size = 64 * ceil(rows / 64)`, `U = 4096 * row_size`, in exact integer arithmetic (`ceil(a / b) = floor((a + b - 1) / b)`). So `U >= 262144`: `payload_size` 1 and 262139 give 262144, 262140 gives 524288, and `2^27 - 5` gives `2^27`. |
| CV3 | Promise well-formed and owner-signed, as `PaymentPromise.Validate`: `signer_public_key` is a 33-byte compressed secp256k1 key, `chain_id` is 1..20 bytes, `blob_size > 0`, `creation_timestamp` is not zero, `height > 0`, the owner signature is 64 bytes (`r \|\| s`) and verifies over `sign_bytes` below. |
| CV4 | Validator list `V`: `HistoricalInfo.valset` of x/staking at `promise.height` (the `HistoricalInfo` header's height MUST be `promise.height`), each entry with its Ed25519 consensus key and power `tokens` (the integer token amount, not the consensus power), in the stored order: the keeper walks the list as stored and does not re-sort it. The stored order is the one SDK `NewHistoricalInfo` writes: consensus power `floor(tokens / 10^6)` descending, then consensus address (the first 20 bytes of `SHA-256(pubkey)`) ascending, which is the order of the set CometBFT `NewValidatorSet` builds over consensus powers. `V` MUST be in that order; a list in any other order is rejected, and the check is made in CV7, where that set is built. The order is positional: signature `i` belongs to `V[i]`. Since `v0-draft.21`, `V` is rejected as a whole, before any signature is checked, if the keeper would reject it: a consensus key that is not 32 bytes, or a list on which `NewValidatorSet` over `(key, tokens)` fails (two entries with the same address, a power `<= 0`, a power or a total above `MaxTotalVotingPower = MaxInt64 / 8`). VERIFIED (code: keeper `validateValidatorSignatures`, SDK `NewHistoricalInfo` and `ValidatorsByVotingPower`). |
| CV5 | `len(validator_signatures) <= len(V)`. |
| CV6 | Quorum, exactly as the chain: `required = floor(2 * total / 3)` with `total` the sum of `V`'s powers. Walk `i = 0, 1, ...`; skip empty entries; a non-empty entry MUST verify as an Ed25519 signature by `V[i]` over `sign_bytes` (the Go `crypto/ed25519.Verify` equation, as rule G1) or the certificate is rejected; add `V[i]`'s power once; as soon as the sum is `>= required`, accept and stop (entries after that point are not checked, as on chain). If the walk ends below `required`, reject. |
| CV7 | `V` is the chain's list in the chain's order (since `v0-draft.21`): the header at `promise.height` has `height == promise.height` and `chain_id == promise.chain_id`; CometBFT `NewValidatorSet` over `V` with power `floor(tokens / 10^6)` for each key succeeds, its `ValidatorSet.Hash()` equals that header's `next_validators_hash`, and for every `i` the key of its `i`-th validator equals the key of `V[i]` (the stored order of CV4). Otherwise CV7 fails. No other header and no archived CometBFT set stands in for it. The header is tied to the chain by the header trust rules of section 10.6.2. |
| CV8 | Anchor (settlement), v0 level `node-attested` (below). Form 1 of the archived anchor proof (section 19.2, written since `v0-draft.23`): its DAH passes NA2 against `data_hash` of the archived header at `payload_ref.height` (trusted by section 10.6.2), its namespace data passes NA3 and NA4 (section 10.4), the archived PFF tx is byte-equal to a tx of `T` and is a candidate for `payload_ref` (NA5), and the archived system blob equals `NewV2Blob(namespace, 0, commitment, pff_signer)` of that tx. Form 0 (records written before `v0-draft.23`): the share-version-2 system blob for `(payload_ref.namespace, payload_ref.commitment)` is included in block `payload_ref.height` (proof against the data root of that header, trusted by section 10.6.2). Both forms: the archived result of the PFF tx at that height has code 0. The optional `anchor_tx_proof` is not part of CV8 (section 10.4, threat note on `ShareProof`). |

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
  Up to `v0-draft.19` a verifier also accepted `validators_hash` of
  `promise.height + 1`. That fallback is dropped (CV7): CometBFT makes it
  equal to `next_validators_hash` of `promise.height` (celestia-core
  v0.42.0, `state/validation.go` and the light client's `VerifyAdjacent`;
  VERIFIED, code), so once the next header must chain to the promise header
  it can never match where the promise header failed, and without that
  binding it let a header of any height vouch for `V`.
- The header inside `HistoricalInfo` is partial: it has no `version`,
  `last_block_id` or `validators_hash` (VERIFIED, live Mocha data,
  2026-10-06), so its hash is not the block hash and it is never a trust
  anchor. CV7 uses the archived signed header at `promise.height`, tied to
  the chain by section 10.6.2.
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
| `cert_token_precision` | `robust` iff CV6 gives the same verdict for every assignment of tokens that keeps each validator's consensus power (each `tokens` anywhere in `[10^6 * p, 10^6 * p + 10^6 - 1]`): the walk accepts with the lowest tokens for signers and the highest for the rest, or rejects with the opposite. Otherwise `bucket-dependent` (a warning; the verdict stays the one computed from the archived tokens). |
| `cert_valset_header` | The header that committed to `V` in CV7: `next_validators_hash` at `promise.height` (the only form since `v0-draft.21`). |
| `settlement` | `node-attested` in v0 (below); `failed` if CV8 fails. |
| `anchor_proof_form` | `1` (namespace data and DAH) or `0` (system blob commitment proof), section 19.2. |
| `anchor_candidates_earlier` | Form 1 only: the number of other candidates in `T` (NA5) whose `creation_timestamp` is earlier than the archived anchor's. Their result codes are not archived, so the verifier cannot tell whether the gate's NA7 picked one of them; a non-zero value is a warning that K2 replay rests on the `promise_created` the gate recorded, which replay checks against the creation times of these candidates (section 19.2, since `v0-draft.24`). It never changes the verdict. |
| `header_trust` | Section 10.6.2: the trusted header's height and hash, and the cross-check result. |

Settlement level `node-attested` (v0). Settlement means the PFF executed
with code 0 at `height`, so the escrow paid and the promise is on chain. In
v0 the verifier establishes it from three parts: the certificate (CV1 to
CV7, cryptographic given the validator set), the PFF tx in block `height`
(form 1; for form 0 the system blob; cryptographic given the header), and
code 0, which is only what the
Recorder's node reported when the archive was written. A verifier MUST
report it as `node-attested` and MUST NOT call it proven. Planned right after
v0 Fibre: a proof of code 0 against `last_results_hash` of the header at
`height + 1`, by recomputing the results Merkle root from the archived
results of block `height`; that level will be reported as `proven`.
Threat note: a node that lies about code 0 can make a PFF that failed in
execution look settled. The certificate and the anchor proof still show that
validators attested the blob and that the PFF was in block `height`; what
is not proven is the payment. `UNVERIFIED`: whether a PFF with a nonzero
code can be included with its system blob at all (section 10.4, facts).

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
Threat note (CV4 list conditions, CV7 binding and order; `v0-draft.21`). The archive
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

### 10.6.2 Header trust for verifiers (both `da`, normative since `v0-draft.17`)

The verifier works from the archive and needs headers it can trust: at
`payload_ref.height` (`T_H`, `data_hash`, the inclusion proofs) and, for
`da = 1`, at `promise.height`. Archived headers are untrusted (the archive is trusted
for availability only). v0 ties them to the chain with a trusted header and
the hash chain, without signatures:

| Rule | Requirement |
|---|---|
| HT1 Trusted header | The auditor supplies a trusted header file: one header at height `T` with its hash, obtained out of band. `T` MUST be at least the highest height the verifier needs (`payload_ref.height`, or `promise.height` if that is higher; since `v0-draft.22` no header at `promise.height + 1` is needed, other than as a link of the HT3 chain). A file with `T` below that is refused: forward verification from an older header is out of scope for v0. Since `v0-draft.24` CV2 rejects `promise.height > payload_ref.height`, so for any record that can verify this is `payload_ref.height`. Since `v0-draft.26` the trusted header may instead be an explicit or an agreed checkpoint (section 20.4), and with the execution check `T` MUST also be at least the execution height (EX5). |
| HT2 Hash of the trusted header | The verifier recomputes the header hash (CometBFT `Header.Hash()`, the Merkle root of the header fields) and it MUST equal the hash in the file. |
| HT3 Backward chain | For each `k` from `T` down to the lowest needed height, the header at `k - 1` is accepted iff its recomputed hash equals `last_block_id.hash` of the accepted header at `k`. Headers between come from the archive, a file or any online source; they need no trust, because the chain checks them. Any break: the header trust fails. Since `v0-draft.26`, OH6 (section 20.4) refines this for online sources: an online header that does not link is a fault of its source (`unchecked` if no source links). Since `v0-draft.27`, an archived header that does not link is `unchecked` too, with reason `chain_mismatch` (20.1). |
| HT4 No signatures | Commit signatures are not checked in v0: the trust comes from the trusted header and SHA-256 collision resistance, not from a validator set. |
| HT5 Archived headers | An archived header at a needed height is used only if its hash equals the one reached by HT3. |
| HT6 Cross-check (optional) | The verifier MAY additionally read the header at `T` (or at `payload_ref.height`) from one or more configured endpoints, under the at-height rules (section 10.9: the response echoes the height), and compare hashes. A mismatch fails the header trust (since `v0-draft.27`: `header_trust` is `unchecked` with the reason of OH7, never `fail`). An unreachable endpoint is reported as `cross-check: not done`, never as a pass. |
| HT7 Verdict | Without a trusted header (a file, or since `v0-draft.26` a checkpoint of section 20.4), or if HT1 to HT3 fail, the verifier MUST NOT report the anchor as valid: it reports `header_trust: none` or the failed rule, and the overall verdict is not valid. The report always carries `T`, the trusted hash and the cross-check result. |

Two needed heights (`da = 1`, normative since `v0-draft.24`). Let `H = payload_ref.height` and `P = promise.height`; `P <= H` (CV2), and a verifier rejects `P > H` before it walks HT3. The verifier checks the header at `H` and the header at `P` through HT3 and HT5 separately: the archived `header` is used only if its hash equals the one HT3 reached at `H`, and the archived `promise_header` only if its hash equals the one reached at `P`. If `P == H`, both archived headers MUST have that same hash. One never stands in for the other: `T_H` and `data_hash` (K1, K2, NA2, CV8) come only from the header at `H`, `next_validators_hash` (CV7) only from the header at `P`, and an implementation that keeps the needed hashes in one map keyed by height MUST NOT let one entry replace the other (keep them in two fields, each checked).

Threat note (two headers). The archive is trusted for availability only, so either header may be forged. If at `P == H` the promise header's hash replaced the anchor header's, the genuine promise header would pass header trust while a forged anchor header (any `data_hash` with a matching forged anchor proof, any `T_H`) fed CV8, K1 and K2 unchecked, and the verifier would report a valid anchor that the chain never had. `P > H` cannot occur on chain; rejecting it also keeps a verifier from accepting a trusted header above `H` only to vouch for a promise header.

Header hash on Mocha: VERIFIED on live data (2026-10-07, since
`v0-draft.26`). An independent implementation of upstream CometBFT
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
after v0.

### 10.7 What must be archived for later verification

The byte layout of these items is archive record format 0 (section 19,
since `v0-draft.20`); where each item lives is listed there. Contents and
reasons:

| Item | `da` | Level | Why |
|---|---|---|---|
| The blob bytes, written before the anchor tx is submitted | both | MUST | Fibre prunes after `pruneAt` (about 4 h); L1 pruned nodes after 7d + 1h. P2 and P3 tie the bytes to the commitment. |
| The signed envelope and the action bytes, written by the gate before it signs (stage 4a, rules AR1 to AR4); the SignedAuthorization, written after stage 12 (a crash between the two is repaired from the registry at the next start); for a refused decision, the rejection marker with the error name (AR5 to AR8) | both | MUST | The object being verified, and which path the gate used (section 15). Writing the decision first means no Authorization exists for a decision the archive lacks. |
| The PFF tx bytes exactly as included, and its index in block `height` as the node reports it (CometBFT `/tx` `index`; informational, no v0 check reads it) | 1 | MUST | Carries the `PaymentPromise` and the positional certificate (section 10.6.1). About 5.3 KB at 83 validators. |
| The anchor proof (since `v0-draft.23`): the DAH of the header at `height` and the namespace data of `PFF_NS` at `height`, exactly as NA2 to NA4 verified them (section 10.4), in form 1 (section 19.2) | 1 | MUST | CV8: proves that the PFF tx, and with it namespace and commitment, was in block `height`, and shows every other candidate of that block. Self-contained: it is checked against the archived header alone. |
| A `ShareProof` of the PFF tx against `data_hash` | 1 | MAY (SHOULD before `v0-draft.23`) | Not used by CV8; see the threat note on `ShareProof` (section 10.4) before relying on one. |
| The commitment proof of the share-version-1 blob against the data root of the header at `height` | 2 | MUST | Proves that namespace, commitment and, through the commitment, `signer` were in block `height`: the v0 inclusion evidence for `da = 2`. |
| The PFB tx bytes exactly as included, its index in block `height` and its inclusion proof against `data_hash` | 2 | SHOULD (MUST before `v0-draft.20`) | Adds the fee payer's tx, which no v0 check uses: the commitment proof above already binds the blob to `height`, and the chain rejects a share-version-1 blob whose signer is not the PFB signer (section 10.5). |
| The signed header (header and commit) of block `height` | both | MUST | Root of the inclusion proof, `T_H` for K1 and K2. |
| For PFF: the x/staking `HistoricalInfo` validator set at `PaymentPromise.height` (consensus keys and token amounts) | 1 | MUST | CV4 and CV6 need the keeper's order and powers. The chain keeps it only for `historical_entries` blocks (about 8 h), after which nobody can re-check the certificate without the archive. |
| For PFF: the signed header at `PaymentPromise.height` | 1 | MUST | CV7: its `next_validators_hash` ties the `HistoricalInfo` set to the chain. Since `v0-draft.21` CV7 reads no CometBFT validator set and no header at `promise.height + 1`; archive format 0 still stores the set (section 19.2, `promise_valset`), for audit only. |
| The retention inputs the gate used: `shard_retention` latest and at `height`, and which source gave the at-height value (section 11.2, RS rules), next to the Authorization (section 19.2, K2 inputs) | 1 | MUST | K2 replay; the at-height value cannot be read back reliably later. |
| The result of the anchor tx (code 0) as the node reported it | 1 | MUST | CV8, settlement `node-attested` (section 10.6.1). |
| The results of all txs of block `height` and the header at `height + 1`, for a proof of code 0 against `last_results_hash` | 1 | SHOULD | Lets the planned `proven` settlement level be checked later for decisions archived now. |
| The share-version-2 system blob | 1 | MUST (archive format 0 requires it) | Since `v0-draft.23` checked only for equality with `NewV2Blob` of the archived PFF (CV8). Up to `v0-draft.22` its inclusion proof against the data root was the CV8 evidence (form 0, still accepted for records written then). |

Headers the verifier needs between the trusted header and `height` (section
10.6.2) need not be archived: the hash chain checks them from any source.

The Recorder MUST write the blob before submitting and the remaining MUST
items, other than the gate's decision record and Authorization, before
returning `payload_ref` to the producer, so a signed
commitment never exists without them. For `da = 1` this is also before the
`historical_entries` horizon, which is hours away at that point.

Since `v0-draft.23` no tx inclusion proof is needed: the anchor proof is the
bridge's namespace data plus the DAH, both verified before they are
archived. If the encoded form-1 proof is larger than an opaque field of
format 0 allows (`2^22` bytes; a block with roughly 750 or more PFFs), the
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

### 10.8 Startup compatibility check (normative since `v0-draft.17`)

Fibre is on a pre-release line and changes between tags. Any component that
handles `da = 1` (gate, Recorder, verifier, SDK with the Fibre committer)
MUST, before it serves or signs, run the checks below, and MUST refuse to
start if one fails. There is no override; a failure is a configuration
error, not a sentinel.

| Check | Requirement |
|---|---|
| SC1 Build pin | The linked celestia-app module is exactly the pinned version (section 10.1, read from the build information). Since `v0-draft.23` also the linked nmt module: `v0.24.5`, the version celestia-node `v0.34.2-mocha` resolves (NA3 needs the completeness fix of `v0.24.3`). |
| SC2 Known answers | The `da = 1` committer reproduces the commitments of `fibre_commit.json` it embeds: at least `fibre_live_mocha_popsmin1`, `fibre_size_262139`, `fibre_size_262140` and one row size above 128. |
| SC3 Chain | The node's chain id is in the configured `da = 1` chain allowlist, and the app version in the latest header is 10. The allowlist is configuration; its default, and the only value validated for v0, is `["mocha-5"]`. Adding a chain (for example Arabica or Corto) is an operator decision after checking that the pins and `fibre_commit.json` hold there. |
| SC4 Parameters | x/fibre `Params` is readable and `shard_retention` is within the governance bounds (10 min to 168 h). |
| SC5 Retention source and at-height reads | The retention store is bound to this chain id and gets its first sample; the canary runs (section 11.2, RS2; section 10.9). A failing canary disables only the direct at-height read, never the start: the gate then runs in observations-only mode for retention and MUST log the mode and the reason at startup at warning level (and again whenever a later canary changes it). |
| SC6 Bridges | A bridge used as a download fallback is enabled only after its compatibility is verified, by version (BV) or by a capability probe (BP), below (since `v0-draft.25`; before, by version only). Otherwise the fallback is disabled and the gate logs the reason at warning level; this is never a refusal to start, because the fallback is optional. A version or capability declared in operator configuration is never accepted in place of BV or BP. The fallback is never trusted for P3, which the gate computes itself on every answer. A bridge used for the anchor proof (NA2, NA3; since `v0-draft.23`) is not gated on its version, because its answers are verified with the pinned code; the gate logs the version at startup if it can read it, at warning level if it differs from the pin. At the pin `node.Info` needs an admin token, so with a read token its permission error is the normal case: it is logged as "version unknown", never a refusal. A gate whose configured DA is `fibre` with no bridge configured for the anchor proof refuses to start. |

An app version change seen at runtime (an upgrade) stops `da = 1` service
(`ErrChainUnavailable`) until a restart has re-run the checks.

Threat note (SC). The commitment, the sign bytes and the parameters are
upstream definitions that a new tag may change; the vectors are the only
independent memory of what the network did at the pin. Refusing to start on
any difference turns a silent divergence (accepting bytes the network never
committed, rejecting every anchor) into a visible configuration error.

Bridge fallback compatibility (normative since `v0-draft.25`). Facts at the
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
  proof, `share.GetNamespaceData(h, namespace)`. This covers the
  `celestia_blob` path (K0 and `T_H` for `da = 2`) as much as `da = 1`.
- Not a read at a height: gRPC `GetTx(hash)` (NA6, section 10.4). It asks by
  hash; the answer names a height, which AH1 compares with the expected one.
  A mismatch fails that read only and does not mark the endpoint
  height-ignoring under AH3: the request carried no height, and the tx index
  keeps one result per hash, so if the same tx bytes were included twice an
  honest node reports the later inclusion (`UNVERIFIED` for the pin: that a
  tx that failed before its sequence was consumed can be included again).

| Rule | Requirement |
|---|---|
| AH1 Echo | A response is used only if it carries the requested height and that height equals `h`: for a state read the response header `x-cosmos-block-height`; for a block read the height inside the returned object (`header.height`, `block.header.height`, the results' height, `HistoricalInfo.header.height`). A response without a height (for example `blob.Get`) is used only through AH2. Missing or different: the response is discarded as a failure of that endpoint. |
| AH2 Binding | Where the content can be tied to the header at `h`, it MUST be, and the header itself MUST pass AH1: txs to its `data_hash`; a DAH to its `data_hash` (NA2); namespace data to the row roots of that DAH (NA3); a blob or its share commitment to its data root through the inclusion proof; a validator set to `validators_hash` or `next_validators_hash`. Result codes (NA6) have no binding in v0 (`node-attested`). A block read that passes AH1 and AH2 does not depend on whether the endpoint honours heights. |
| AH3 Canary per endpoint | The RS2 canary (section 11.2) is a property of the endpoint, not of a module: a canary that does not pass marks the consensus endpoint height-ignoring for every state read, whatever the module. Block reads are checked by AH1 and AH2 on every response. A block or header read on a consensus endpoint whose returned height is missing or differs from the requested one also marks that endpoint height-ignoring for state reads (retention goes to observations-only mode, AH4) until a later canary on it passes (Honoured). Bridge (celestia-node) endpoints do no state reads, so they have their own canary: read the header at `head - canary_offset` (RS2) and compare its height with the requested one: equal is Honoured, a header at another height is Ignoring, anything else (error, not found, timeout) is Inconclusive. The bridge result is logged (warning level unless Honoured, again on every change) and MUST NOT drive the retention mode; a bridge AH1 mismatch discards that response only. |
| AH4 On failure, retention | The x/fibre retention at `height` comes only from the gate's own observations (RS4 to RS6): observations-only mode, logged at startup and on every change (SC5). A height the observations do not cover gives `ErrRetentionUnavailable`. |
| AH5 On failure, other reads | Any other read at a height that fails AH1 or AH2 on every configured source gives nothing: the check that needed it is not evaluated from latest state or from another height. The gate answers `ErrChainUnavailable` (503, nonce untouched), never `ErrAnchorNotFound`, never a K1 or K2 verdict from the wrong block. It MAY instead use a source that does not depend on the endpoint honouring heights: a header verified by the W5 light verifier (section 9.5), or a block read from another endpoint that passes AH1 and AH2. A state read other than x/fibre `Params` from a height-ignoring endpoint MUST NOT be used; v0 defines no other. A header or block read that answers "not found" for a height the chain must have (at or below a head the gate has observed on any configured source) is a failed at-height read under this rule, on both `da` paths (K0 and `T_H`): `ErrChainUnavailable`, never `ErrAnchorNotFound`. A pruned or trailing backend answers "not found" for blocks that exist, so the answer says nothing about the chain. A height above every observed head gives `ErrChainUnavailable` too (retryable, nonce untouched; `valid_until` bounds the retries). `ErrAnchorNotFound` is given only after the block at `height` was read and passed AH1 and AH2 and holds no anchor (for `da = 1`: after NA1 to NA4 held and NA7 found no anchor, section 10.4). |

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
| RS2 Canary | At start and at least every `canary_interval` (default 600 s, at most 3600 s), the gate runs the canary on each consensus endpoint it uses for state reads. Canary heights are configuration, per chain id, and logged at startup: (a) the recent height `h_r = head - canary_offset`, where `head` is the latest height the same endpoint reports just before, and `canary_offset` (default 10) MUST be at least 1 and greater than `lag` (RS4) and MUST stay inside the state the node retains; (b) `h_pre`, the last height before x/fibre was activated, optional. Defaults are keyed by chain id, read from the same endpoint: `mocha-5` has `h_pre = 1,082,619`; every other chain has no `h_pre` unless configured (absent on a chain that has x/fibre from genesis). A configured `h_pre` MUST NOT be applied to another chain id. The `h_r` query is a state query whose module is present at every height of every chain (bank `Params`), pinned to `h_r`; if `h_pre` is configured, the gate also queries x/fibre `Params` pinned to `h_pre`, and runs that query even when the `h_r` query fails (Ignoring takes precedence, so its result still matters). If `h_pre` is configured but not below `h_r`, the `h_pre` query is not run and the outcome is Inconclusive, not Honoured. Outcomes, decided only from success or failure and the response header `x-cosmos-block-height`, never from error codes or messages: **Ignoring** if the `h_r` query succeeds without the header or with a value other than `h_r`, or if the `h_pre` query succeeds (any response message, empty included, whatever its header). **Honoured** if the `h_r` query succeeds with the header equal to `h_r` and the `h_pre` query, if configured, fails (any error). **Inconclusive** in every other case (the `h_r` query fails and the `h_pre` query, if run, fails too; the head cannot be read; `h_pre` not below `h_r`; timeout, cancellation). Ignoring takes precedence over Inconclusive. Only Honoured passes; Inconclusive counts as not passed. |
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

Settled in `v0-draft.17`, procedure replaced in `v0-draft.23`: the PFF is
proven from the PayForFibre namespace data of block `height` (section 10.4,
NA1 to NA7); x/fibre params at a past height are served by honest nodes
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
| Record format | Section 19: deterministic CBOR records, write-once, keyed by `(da, commitment)` for payloads and evidence and by `commitment_hash` for decisions, Authorizations and rejection markers. |
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
| K | `ErrAnchorNotFound` | `gate` | K0 (for `da = 1`: no PFF with result code 0 among the txs of the PayForFibre namespace of block `height`, proven complete by NA1 to NA4, section 10.4) | none (stateful) |
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

| File (`v0-draft.20`) | Contents |
|---|---|
| `spec/vectors/archive/records.json` | Section 19. `revision`, `generator`, `refs`, `params` (format, kinds, size limits, depth, entries, the verdict names a marker may carry), `patterns`, `placeholder` (how stand-in bytes are derived). `cases`: `id`, `description`, `kind`, `input` (section 19.2 names; uints as decimal strings, byte strings as hex or, above 1024 bytes, `{pattern, size, sha256_hex}`), `key` (canonical path, section 19.3), `record_cbor_hex` (or `record_size` + `record_sha256_hex` above 4096 bytes), `refs` into `valid.json`, `authorization.json`, `da_blob.json` or `da/fibre_commit.json`, and `placeholders` (fields whose bytes are stand-ins, not upstream encodings). `reject`: `id`, `description`, `record_cbor_hex`, `expect_error` = `archive.ErrCorrupt`, `cause` (the core sentinel of the first failing check, section 19.1). 26 cases, 58 rejects. |
| `spec/vectors/archive/state.json` | Sections 19.4 and 19.5. `da_check` (the `(da, commitment, blob)` pairs the DA committers accept, copied from the DA vector files). `scenarios`: `steps` (`put` a `records.json` case id on an empty store, `expect` = `written`, `unchanged`, `archive.ErrConflict`, `archive.ErrNotFound` or `gate.ErrDACommitmentMismatch`, optional `state_after`: `commitment_hash_hex`, `state`, `rejections`), and `final_records` (the case ids whose bytes the store holds at the end, nothing else). 7 scenarios. |

Archive vectors: `encode(input) == record bytes`; strict decoding returns `input`; the store files the record under `key`; every reject fails decoding with `archive.ErrCorrupt` (and SHOULD wrap `cause`); a store replaying each scenario from empty gives each `expect`, each `state_after` and exactly `final_records`, with the DA check of `da_check` (a Go store uses the real committers, which accept the same pairs). Generated by `gen_archive.py`, checked by `check_archive.py`, which also regenerates both files and compares bytes. Opaque Celestia fields are stand-ins: the files fix the record layout, not the upstream encodings, which the implementing tasks test against live data.

| File (`v0-draft.23`) | Contents |
|---|---|
| `spec/vectors/da/fibre_anchor.json` | Section 10.4 (NA2 to NA7) and anchor-proof form 1 (section 19.2). `revision`, `generator`, `upstream`, `rules` (including the mutation operations), `pff_namespace`. `live.source`: the read-only reads (bridge `header.GetByHeight` and `share.GetNamespaceData`, and the consensus node's `/header` whose `data_hash` must agree). `live.cases`: `h1402819` (the PFF of `fibre_cert.json`, one PFF in a 4 x 4 square, four rows) and `h1439696` (four PFFs of one namespace in a 64 x 64 square, one row), each with `raw` (`height`, `data_hash`, `row_roots`, `column_roots`, `namespace_data_hex` in the `WriteTo` stream form) and `expect` (`square_size`, `rows`, `share_count`, `txs` with `position`, `length`, `sha256`, `fibre`, the parsed `promise` and `system_blob_hex`; `queries` with `candidates` and `anchor` when every candidate has code 0, `none` meaning `ErrAnchorNotFound`; `archive_proof` with `hex`, `sha256`, `size`; `sizes`). `mutations`: `id`, `description`, `case`, `op`, `expect` (`verdict`; for a reject the first failing rule `fails` and an informational `upstream_error`; for an accept `same_txs`). `reassembly`: synthetic share sequences for NA4 alone, `expect` (`verdict`, `txs_sha256` or `fails`) and `upstream_parse_txs`, what `ParseTxs` alone returns (several rejects parse without an error). 2 live cases, 12 mutations, 14 reassembly cases. Generated by upstream code only in `spec/vectors/tools/fibreanchor-gen` (`go run . -fetch` reads Mocha, read-only; `go run .` regenerates offline from the stored raw inputs; `go run . -check`); checked by `check_fibre_anchor.py`, an independent implementation (its own RFC 6962 root, protobuf decoding, NMT hashing and namespace-proof verification, compact-share parser and splitter, strict CBOR), which also ties `h1402819` to the PFF of `fibre_cert.json`. |

| File (`v0-draft.29`) | Contents |
|---|---|
| `spec/vectors/policy/*.json` | Policy v1: facts, mandate, render, state, engine, verify, archive, api (`spec/policy-v1.md` section 15; each file carries the policy revision that last changed it). Generated by `gen_policy.py` (rules module `policy_v1.py`), checked by `check_policy.py`, an independent implementation, run by `check_vectors.py`. |

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
- `da/fibre_anchor.json`: the gate's `da = 1` anchor lookup, given each live
  case's `data_hash`, DAH and namespace data, returns `txs` and, with every
  NA6 code 0, each query's `anchor`; every mutation is rejected at `fails`
  (the lookup answers `ErrChainUnavailable`) or accepted with the same txs;
  the NA4 function accepts or rejects each `reassembly` case as stated; the
  Recorder's archive writer produces `archive_proof` byte for byte from the
  DAH and the namespace data, and the verifier's CV8 accepts it against
  `data_hash`. Regenerate or check with
  `cd spec/vectors/tools/fibreanchor-gen && go run . -check`.

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
- Fee of a failed `da = 1` upload. The upload hands the signed
  `PaymentPromise` to validators before any signature set exists. A promise
  that never settles through a PFF (fewer than 2/3 signatures, a crash, a
  timeout) can still be charged once by anyone holding it, through
  `MsgPaymentPromiseTimeout` after the promise timeout (section 10.2,
  "Unsettled promise is charged"). So a failed upload is not free: it may
  cost one fee and never creates an anchor, and every new upload attempt
  signs a new promise that may be charged once. Operators size the escrow
  and quotas with this in mind; "nothing was submitted" in section 12 means
  that no promise left the Recorder.
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
removed names), are in `spec/vectors/api/errors.json`. A gate with a mandate
also reports the policy codes and the error body key 5 of `spec/policy-v1.md`
section 11.3, each matched after every code above of its status.

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

## 19. Archive records (format 0, normative since `v0-draft.20`)

The archive store (a directory, an object store, a database) is
implementation-defined; the bytes of each record are not. A Recorder, a gate,
a verifier in another language and an auditor's tool read each other's
records, so the record layout is fixed here, in the CBOR style of the rest of
v0. Records are never signed and never hashed into a commitment, an
Authorization or a receipt: the archive is trusted for availability only
(section 11.3), and every reader re-checks what it uses.

### 19.1 Encoding and strict decoding

Profile: section 3 rules 2 to 7 (shortest heads, definite lengths, uint keys
in `1..23` strictly ascending, optional fields absent when unset, required
fields always present, text in the charsets below), restricted further:

| Point | Rule |
|---|---|
| Data items | Major 0, 2, 3 and 5 only. No arrays, negative integers, tags, floats or simple values. |
| Nesting | Depth at most 2 (the record is depth 1, the K2 inputs map depth 2). |
| Entries | At most 24 per map. |
| Record size | At most `MaxRecordSize = 2^27 + 4096` bytes before parsing; per kind at most: payload `2^27 + 4096`, evidence `2^25`, decision 69,632, Authorization 512, rejection 256; policy kinds as `spec/policy-v1.md` section 12.1. |
| Opaque Celestia objects | Each 1 to `2^22` bytes (4 MiB). |

Every record is a map with two common keys:

| Key | Name | Type | Rule |
|---|---|---|---|
| 1 | `format` | uint | `= 0`. Archive record format, independent of the wire `version`. |
| 2 | `kind` | uint enum | 1 payload, 2 evidence, 3 decision, 4 Authorization, 5 rejection; since `v0-draft.29` 7 to 12, the policy records of `spec/policy-v1.md` section 12. 6 is never assigned. |

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
   `format != 0` (`ErrUnsupportedVersion`); then `kind` outside 1..5 and 7..12
   (`ErrInvalidEnum`).
4. Size above the cap of the kind: `ErrTooLarge`.
5. Schema, per key in encoded order: a key the kind does not define, or does
   not define for the record's `da` (or, for `anchor_tx_index` and
   `anchor_tx_proof`, without `anchor_tx`): `ErrUnknownKey`; wrong major
   type: `ErrWrongType`; length outside the limit: `ErrFieldSize`;
   characters outside the charset: `ErrInvalidString`. The same, recursively,
   for the K2 inputs map.
6. A required field absent (in key order): `ErrMissingField`.
7. Values: any uint above `2^63 - 1`, or `tx_code != 0`: `ErrIntRange`; `da`
   outside `{1, 2}`, `retention_source` outside `{1, 2, 3}`, or a marker name
   that is not a verdict (19.2): `ErrInvalidEnum`; zero where the field is
   `> 0`: `ErrZeroValue`; a namespace failing rule S8: `ErrInvalidNamespace`.
8. Nested messages: `envelope` passes strict decoding of section 6 (stage D);
   `signed_authorization` passes the decoding of section 15 and its `version`,
   integer range, `path` and `expires` rules. Their own sentinels are the
   cause.
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
| 9 | `anchor_tx_index` | uint | | with `anchor_tx` | Its index in the block's txs. For `da = 1` as the node reports it; informational, no v0 check reads it. |
| 10 | `anchor_tx_proof` | bstr | opaque | O, only with `anchor_tx` | Its inclusion proof against `data_hash` (section 10.7: SHOULD for `da = 2`; MAY for `da = 1`, not used by CV8). |
| 11 | `blob_proof` | bstr | opaque | R2 | Commitment proof of the share-version-1 blob against the data root of `header`. |
| 12 | `tx_code` | uint | `= 0` | R1 | The PFF result code as the node reported it (CV8, `node-attested`). Only code 0 is archived: any other code means no anchor. |
| 13 | `system_blob` | bstr | opaque | R1 | The share-version-2 system blob. |
| 14 | `system_blob_proof` | bstr | opaque | R1 | The CV8 inclusion evidence, in one of two forms (below): form 1, the anchor proof (DAH and PayForFibre namespace data at `height`), which writers MUST use since `v0-draft.23`; form 0, the commitment proof of the system blob against the data root of `header`, in records written before. |
| 15 | `promise_height` | uint | `> 0` | R1 | `PaymentPromise.height`. |
| 16 | `promise_header` | bstr | opaque | R1 | Signed header at `promise_height` (CV7). |
| 17 | `historical_info` | bstr | opaque | R1 | x/staking `HistoricalInfo` at `promise_height` (CV4, CV6). |
| 18 | `promise_valset` | bstr | opaque | R1 | The CometBFT validator set that `next_validators_hash` of `promise_header` commits to. Kept for audit only: since `v0-draft.21` no v0 check reads it (CV7 builds the set from `historical_info`). Still required for `da = 1` in format 0, whose decoder rejects a record without it; a writer that has no use for it still stores the set as read from the node. |

Encodings of the opaque fields. A reader decodes them with upstream code at
the pins of section 10.1 and checks each against the header it hangs from
(section 10.6.2, HT5; AH2), so a wrong encoding fails verification, never
passes it.

| Field | Encoding | Status |
|---|---|---|
| `header`, `promise_header` | protobuf `tendermint.types.SignedHeader` (celestia-core at the pin) | `UNVERIFIED`: proto package name and field set at celestia-core `v0.42.x` |
| `promise_valset` | protobuf `tendermint.types.ValidatorSet` | `UNVERIFIED`, as above |
| `historical_info` | protobuf `cosmos.staking.v1beta1.HistoricalInfo` (the `hist` field of the x/staking `HistoricalInfo` query response at the pin's cosmos-sdk fork), `valset` in the stored order (CV4); its embedded header is partial and never a trust anchor (section 10.6.1) | Message VERIFIED (code, cosmos-sdk `v0.50` proto: `header`, `valset`); at the fork `UNVERIFIED` |
| `anchor_tx` | Raw bytes of the element of the block's `data.txs` | VERIFIED (definition) |
| `anchor_tx_proof` | protobuf `celestia.core.v1.proof.ShareProof`, as `pkg/proof.NewTxInclusionProof` returns it | VERIFIED (code, `APP/pkg/proof/proof.go`) |
| `system_blob_proof` form 1 | Anchor proof, deterministic CBOR (below) | VERIFIED (vectors `spec/vectors/da/fibre_anchor.json`, `archive_proof`, live Mocha data) |
| `blob_proof`, `system_blob_proof` form 0 | JSON of celestia-node `blob.CommitmentProof` (`MarshalJSON`, the CometBFT JSON encoder), the form the node API returns; verified with `CommitmentProof.Verify(data_root, commitment)` | VERIFIED (code: celestia-node `v0.34.2-mocha` `blob/commitment_proof.go` has no protobuf form). `UNVERIFIED`: that the node serves this proof for a share-version-2 system blob; if not, the Recorder builds it from the block shares with upstream code |
| `system_blob` | protobuf `BlobProto` of go-square `v4` `share.Blob.Marshal`; MUST equal `NewV2Blob(namespace, 0, commitment, pff_signer)`, where `pff_signer` is the 20-byte signer of the archived PFF; upstream `TryParseFibreTx` returns this blob with the tx (`FibreTx.SystemBlob`) | VERIFIED (code, go-square `v4.0.1` `share/blob.go`; vectors `fibre_anchor.json` `system_blob_hex`, from `FibreTx.SystemBlob`) |

Anchor-proof forms (`system_blob_proof`, `da = 1`; since `v0-draft.23`). A
reader tells the forms apart by the first byte: `0x7b` (`{`, the JSON object
of a `CommitmentProof`) is form 0; `0xa3` (a CBOR map of three entries) is
form 1; any other first byte fails CV8. The record itself still decodes:
the field is opaque to section 19.1, which is why form 1 fits archive format
0 without a byte change. Form 1 is a deterministic CBOR map under the
profile of section 19.1 (shortest heads, definite lengths, keys ascending,
no other key, no tag, float or simple value; re-encoding gives the same
bytes):

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

Threat note (forms). A writer that stores form 0 after `v0-draft.23` does
not break decoding, but its record carries the weaker evidence (the system
blob, not the PFF tx, and no completeness), and `verify` reports
`anchor_proof_form: 0`. Telling the forms apart by one byte is unambiguous
because a `CommitmentProof` from the CometBFT JSON encoder is a JSON object
and form 1 is a CBOR map with exactly three entries; a form that is neither
is never guessed at.

Decision (kind 3). Written by the gate at stage 4a (AR1 to AR4).

| Key | Name | Type | Limit | Presence | Semantics |
|---|---|---|---|---|---|
| 3 | `envelope` | bstr | `1..2176`, strict decoding | R | The signed envelope exactly as presented. |
| 4 | `action` | bstr | `1..65536` | R | The action bytes exactly as presented. |

No `commitment_hash` field: it is computed from `envelope` (invariant 6),
never stored next to it.

Authorization (kind 4). Written after stage 12, or later from the registry by
the gate's repair (section 8.7, threat note on rejected records).

| Key | Name | Type | Limit | Presence | Semantics |
|---|---|---|---|---|---|
| 3 | `signed_authorization` | bstr | `1..256`, section 15 decoding | R | The SignedAuthorization exactly as the registry holds it. |
| 4 | `authorized_at` | uint | `> 0` | R | The gate clock at stage 10 (`T'`), as the registry keeps it (section 15.1). |
| 5 | `k2` | map | K2 inputs, below | O | The inputs of rule K2 (section 11.2) as the gate used them. Absent when the record was repaired from the registry, which does not keep them; `replay` then reports K2 as not replayable. |

K2 inputs (Authorization key 5), conditions on its own `da`:

| Key | Name | Type | Presence | Semantics |
|---|---|---|---|---|
| 1 | `da` | uint enum `{1, 2}` | R | Equals the decision's `payload_ref.da` (a reader that finds otherwise reports the record corrupt). |
| 2 | `checked_at` | uint `> 0` | R | The gate clock read once at stage 1 (`now`). |
| 3 | `block_time` | uint `> 0` | R | `T_H`. |
| 4 | `blob_retention_s` | uint `> 0` | R2 | `r` for `da = 2`. |
| 5 | `retention_latest_s` | uint `> 0` | R1 | `fibre_retention_s(latest)`. |
| 6 | `retention_at_height_s` | uint `> 0` | R1 | `fibre_retention_s(at height)` (always known when an Authorization exists: otherwise the gate refused with `ErrRetentionUnavailable`). |
| 7 | `retention_source` | uint enum | R1 | Where the at-height value came from: 1 the direct read (RS3), 2 the observations (RS6), 3 both (the minimum was taken). |
| 8 | `promise_created` | uint `> 0` | O1 | `floor(PaymentPromise.creation_timestamp)`; absent when unknown (then K2 is false). |

Replay recomputes `r`, `start`, `margin` and K2 from these fields and the
decision; a K2 that fails with `path = 1` in the Authorization is reported as
an inconsistency of the gate. Since `v0-draft.27`, every inconsistency in this
section makes `retention_replay` `unchecked`, with reason
`replay_inconsistent`, and never `fail`. The K2 inputs are unsigned archive
data, so a gate error and an altered record look the same (20.1). Missing
inputs give `replay_inputs_missing`. A form-0 value that cannot be checked
gives `replay_unconfirmed`.

For `da = 1` replay first checks `promise_created` against the archived
evidence (normative since `v0-draft.24`). The gate's NA7 takes the earliest
candidate with code 0, which need not be the PFF the Recorder archived:
another promise for the same blob in the same block, paid by anyone, may be
earlier and also settled. Hence:

- Present: consistent iff it equals `floor(creation_timestamp)` of a
  candidate of `T` (NA5 on the form-1 anchor proof) whose
  `creation_timestamp` is at or before the archived anchor's. With
  `anchor_candidates_earlier = 0` this is equality with the archived
  anchor's value. Form 0 shows no other candidate: equality is consistent, a
  smaller value is reported as not checked and used as recorded. Any other
  value, in particular one later than the archived anchor's (NA7 would have
  reached the archived anchor first), is an inconsistency of the gate.
- Absent: the gate did not know the creation time, so K2 was false for it
  (section 11.2) and the archive path was the only one. Consistent iff the
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
| 4 | `error` | tstr | 4..64, `Err` followed by ASCII letters and digits, and one of the verdicts below | R | The refusal, by its section 12 name without package. |
| 5 | `gate_id` | tstr | 1..64, ID charset | R | The refusing gate (equals the decision's `scope.gate_id`, since stage 4a runs after C1). |
| 6 | `rejected_at` | uint | `> 0` | R | The gate clock at the refusal. |

Verdicts (the sentinels of stages 5 to 12 in section 8.7):
`ErrActionMismatch` (stage 5, retry rule condition 2), `ErrAnchorNotFound`,
`ErrAnchorTooOld`, `ErrArchiveRecomputeUnsupported`,
`ErrDACommitmentMismatch`, `ErrExpired`, `ErrIssuedBeforeAnchor`,
`ErrNonceUsed`, `ErrNotYetValid`, `ErrPayloadHashMismatch`,
`ErrPayloadSizeMismatch`, `ErrPayloadUnavailable`,
`ErrRetentionUnavailable`. For an error that matches several (for example
`ErrAnchorTooOld`, which also matches `ErrPayloadUnavailable`) the most
specific one is written. Operational failures are never written (AR5); a
decoder rejects them. A later revision that adds a verdict sentinel extends
this list in a new revision. Since `v0-draft.29` the list also holds the
thirteen policy deny names of `spec/policy-v1.md` section 12.3.

### 19.3 Keys

The store derives the key from the record; a writer never supplies a key
that the record does not determine, and a store whose API takes a key MUST
check it against the record. A reader MUST check that a record read under a
key carries that key (payload and evidence: `da`, `commitment`; decision:
`commitment_hash` recomputed from `envelope`; Authorization: its
`commitment_hash`; marker: `commitment_hash` and `error`), and otherwise
reports it corrupt.

| Kind | Logical key | Canonical path (RECOMMENDED for file and object stores) |
|---|---|---|
| Payload | `(da, payload_ref.commitment)` | `payload/<da>/<commitment hex>` |
| Evidence | `(da, payload_ref.commitment)` | `evidence/<da>/<commitment hex>` |
| Decision | `commitment_hash` | `decision/<commitment_hash hex>` |
| Authorization | `commitment_hash` | `authorization/<commitment_hash hex>` |
| Rejection | `(commitment_hash, error)` | `rejection/<commitment_hash hex>/<error>` |

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
| AW1 Write-once | A stored record is never overwritten or deleted in v0 (retention and cleanup are not specified). A write is atomic: the record is either fully present or absent, also after a crash (for files: temp file, fsync, rename, fsync of the directory). |
| AW2 Identity | A write of a record whose key is already stored compares identities: equal, the write succeeds and the stored record stays unchanged; different, `archive.ErrConflict` and nothing is written. Identity per kind: payload, every field except `intent_height`; evidence, `da`, `commitment`, `namespace`, `height`; decision, the whole record; Authorization, `signed_authorization`; rejection, the key (`commitment_hash`, `error`). |
| AW3 DA check | Before storing a payload, the store recomputes the DA commitment from `blob` (and, for `da = 2`, `namespace` and `signer`) with the committer for `da` (sections 10.4, 10.5) and compares it with `commitment`. Mismatch: `gate.ErrDACommitmentMismatch`, nothing written. A store has a committer for every `da` it accepts; a payload for any other `da` is refused with `gate.ErrArchiveRecomputeUnsupported`, nothing written. |
| AW4 Order | Evidence needs the payload record of its key; an Authorization or a marker needs the decision record of its `commitment_hash`. Otherwise `archive.ErrNotFound`, nothing written. An Authorization with K2 inputs whose `da` differs from the decision's `payload_ref.da` is refused with `archive.ErrCorrupt`, nothing written, before the identity comparison of AW2 (so also when a consistent Authorization is already stored): a reader would report the stored record corrupt (19.2). |
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
`commitment_hash`, never stored:

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

### 19.7 Not in format 0

- The header at `height + 1` and the results of block `height` (section
  10.7, SHOULD): planned with the `proven` settlement level, as a new format.
- The validator set at `height`: v0 checks no commit signatures (HT4).
- The Recorder's own retention readings: the K2 inputs that matter are the
  gate's, in the Authorization record.

A new field is a new `format` value, because strict decoding rejects unknown
keys; a reader of a later format keeps reading format 0.

Vectors: `spec/vectors/archive/records.json` and `state.json` (section 13).
Must-reject records too large to embed are in `reject_large`: the record is
`record_prefix_hex` followed by the `affine-7-3` pattern of the given size,
with `record_size` and `record_sha256_hex` of the whole. A reject with
several defects lists them in `defects`, the expected cause first; its cause
follows the stage order of 19.1. `state.json` `reads` places records in a
store without the write checks and reads them back with the reader checks.

## 20. Verifier online mode and the execution check (normative since `v0-draft.26`)

This section adds no wire bytes, tags or gate checks, and it changes none.
It defines what `verify` and `replay` report when they read the archive over
HTTP, take headers from online sources, and check the rail transaction named
by a receipt. Verdicts of the offline mode (an archive directory and a
trusted header file) do not change.

### 20.1 Report checks and verdict

The report is a list of named checks, each `pass`, `fail` or `unchecked`. A
`fail` and an `unchecked` carry the reason. The reference verifier
already used these names and this verdict rule before `v0-draft.26`. Since
`v0-draft.26` they are normative, so that two verifiers print the same
checklist.

| Check | What passes it |
|---|---|
| `decision` | The decision record is present, decodes (section 19.1) and carries its key. |
| `envelope` | Stages D, S and G of the signed envelope (sections 6 to 8.1). |
| `action` | The archived action bytes hash to `action.hash` (section 5.1). |
| `authorization` | The record state and the Authorization check of section 19.5 (AR8). |
| `payload` | P1 to P3 on the archived blob (sections 8.5, 10.7). |
| `anchor` | The inclusion evidence of the archived anchor, checked against the header at `payload_ref.height` (sections 10.5, 10.6.1). |
| `anchor_time` | K1 against `T_H` of that header (section 11.2). |
| `header_trust` | HT1 to HT7 (section 10.6.2), with an online checkpoint per 20.4. |
| `receipt` | Section 14.2 and its out-of-band checks against the decision. Present only when a receipt is given. |
| `retention_replay` | K2 replay (section 19.2). `replay` only. |
| `execution` | Section 20.2. Present only when the execution check is requested. |
| `policy` | `spec/policy-v1.md` section 13. Present when `RequirePolicy` is set or a `policy_allow` record exists for an authorized decision, and then required. |

Report field `gate_integrity` (since `v0-draft.29`), always present: `ok`,
`violated` (reason `gate_equivocation`, with the contradicting gate-signed
verdicts as evidence), `not_checked` or `unchecked` (with a reason), per
`spec/policy-v1.md` section 13.4. It is not a check: it says whether the
gate contradicted itself, not whether the decision is valid. Since
`v0-draft.30`, after a policy walk it is `ok` only when the walk checked
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
configuration and I/O errors, which give no verdict (as `edicta-verify` at
main `25ff856`), and since `v0-draft.29` 5: `unchecked` with `gate_integrity`
`violated`. Precedence: 4, then 1, then 5, then 3, then 2, then 0, so an
`invalid` decision at an equivocating gate exits 1. Whenever `gate_integrity`
is `violated`, the text output starts with the line `GATE INTEGRITY VIOLATED
(gate_equivocation)`, whatever the exit code, and JSON always carries the field. The output prints the reason of every check that is not
`pass`. For an `unchecked` caused by a source, it names the source and
suggests another one (EO2).

General rule (human decisions of 2026-10-07, normative since `v0-draft.27`,
no exceptions). `invalid` is issued only about the decision or the action,
and only from verified data. Every source problem gives at most `unchecked`.
Sources include the archive, a header or checkpoint source, a tx or results
source, and a receipt file, and their problems include a disagreement between
sources. A hostile source can never cause `valid` or `invalid`. The archive is
a source: it is trusted for availability only, and it only delivers bytes.
The boundary is this. Archived data that verifies (it hashes to the
commitment, carries a valid signature of the party it claims, or is proven
against a trusted header) and that itself proves a violation gives `fail`.
The execution check states the rule in detail (20.2.1).

Archive cases (human decision of 2026-10-07, "archive cases follow the
general rule"):

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
  Fibre rules CV1 to CV8 (10.6.1) and the anchor proof.
- An archived header at a needed height that does not link to the trusted
  chain is `unchecked` (`chain_mismatch`; HT3, HT5, OH6). So is evidence for
  another height than `payload_ref.height` (`source_corrupt`).
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
  contradicts the decision (AR8, section 15.3).
- `payload`: a payload whose bytes pass P1 to P3 and that a recipient opens
  (9.4) with an O-rule failure, for example O8 (the payload's action differs
  from the committed one).
- `receipt`: a receipt whose gate signature verifies, that belongs to this
  decision, and that breaks a receipt rule.
- `execution`: EO1 (20.2.1).
- `policy`: verified data proving the allow broke the mandate: a per-action
  rule, facts that differ from the re-extraction, or a rule broken on the
  gate-signed state (`spec/policy-v1.md` section 13.4).

Every other non-`pass` outcome is `unchecked`.

#### 20.1.1 Reasons

Every `unchecked` check carries exactly one machine-readable `reason` from
this enum. Every `fail` carries the rule or sentinel that failed. The text
output prints the reason, the meaning, the source it names (EO2), and the
advice. The enum is closed in this revision. A new reason is a revision
change.

| Reason | On checks | Meaning | Advice |
|---|---|---|---|
| `decision_unavailable` | `decision` | No decision record for the reference in any checked archive copy. | Another archive copy. |
| `payload_unavailable` | `payload` | The payload record is missing in every checked copy. It signals a retention failure of the operator and can feed an external accountability policy. It is not a verdict on the decision. | Another archive copy. |
| `evidence_unavailable` | `anchor` | The evidence record is missing in every checked copy. | Another archive copy. |
| `source_corrupt` | `decision`, `envelope`, `action`, `authorization`, `payload`, `anchor`, `receipt`, `policy`, `gate_integrity` | Bytes from a source fail a check that a genuine copy passes: strict decoding, the key check, a hash or DA commitment against the commitment, a signature that the commitment hash does not cover, or an archived proof (da = 2 commitment proof, Fibre CV1 to CV8, anchor proof forms 0 and 1). | Another copy. |
| `chain_mismatch` | `header_trust`, `anchor` | An archived header at a needed height does not link to the trusted chain (HT3, HT5, OH6), or the archived evidence names another height than the decision. | Another archive copy, or check the trusted header. |
| `da_unsupported` | `anchor` | The verifier has no anchor verifier for payload_ref.da. | A verifier build that supports this da. |
| `no_trusted_header` | `header_trust` | No trusted header file, explicit checkpoint or checkpoint source was given. | Supply a trusted header. |
| `header_above_checkpoint` | `header_trust`, `execution` | The checkpoint height T is below a needed height (OH4, EX5 (a)). | Retry later or with a newer checkpoint. |
| `header_not_linking` | `header_trust`, `execution` | An online header at a needed height does not link to the trusted chain, and no source gives one that does (OH6, EX5 (b)). | Another header source. |
| `header_source_unavailable` | `header_trust` | No header or checkpoint source answered. | Another header source. |
| `checkpoint_quorum` | `header_trust` | Fewer than quorum distinct sources agree on the checkpoint (OH5). | More checkpoint sources. |
| `header_disagreement` | `header_trust`, `execution` | header disagreement with trusted chain: possible bad trusted header, hostile source, or fork (OH5, OH7, HT6, EX5 (d)). | Check the trusted header against an independent source. |
| `blocked` | `anchor_time`, `header_trust`, `execution`, `retention_replay`, `policy` | The check needs another check that did not pass; the report names that check. | Fix the named check. |
| `receipt_mismatch` | `receipt` | A receipt that verifies but is not this decision's: another commitment_hash or gate_id, or a gate key that is not on record for gate_id. | The receipt of this decision. |
| `replay_inputs_missing` | `retention_replay` | The Authorization record carries no K2 inputs (repaired from the registry). | Another archive copy. |
| `replay_unconfirmed` | `retention_replay` | promise_created is earlier than the archived anchor's and the anchor proof is form 0, which shows no other candidate (19.2). | An archive copy with a form-1 anchor proof. |
| `replay_inconsistent` | `retention_replay` | K2 recomputed from the recorded inputs disagrees with the Authorization's path, or promise_created matches no candidate. The K2 inputs are unsigned archive data, so a gate error and an altered record look the same. | Another archive copy. |
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
| `policy_verdict_unavailable` | `policy` | No policy_allow record for an authorized decision while the policy check is required (RequirePolicy). | Another archive copy. |
| `policy_mandate_unavailable` | `policy` | The mandate record named by the verdict is missing. | Another archive copy. |
| `policy_principal_untrusted` | `policy` | The mandate verifies, but its principal is not among the trusted principal keys. | Pin the principal key, if it is the intended one. |
| `policy_no_extractor` | `policy` | The verifier has no extractor for action.type with the extractor ID the verdict names. | A verifier with that extractor. |
| `state_history_unavailable` | `policy`, `gate_integrity` | A closed set, a needed bucket, or a verdict or mandate the walk needs is missing. | Another archive copy. |
| `gate_equivocation` | `gate_integrity` only | Gate-signed verdicts contradict each other (fork, broken link, self-inconsistent transition, seq gap, version decrease or mandate change in one chain). The agent may be honest; the gate is at fault. Exit code 5. | Investigate the gate; the attached verdicts are the evidence. |
| `policy_walk_truncated` | `gate_integrity` only | Since `v0-draft.30`. The policy walk took its step cap (default or explicit) before it reached genesis, with no finding. The older part of the gate's chain was not read, so `gate_integrity` is never `ok` here. The report gives the walked seq range and the step count. The `policy` check, the verdict and the exit code do not change. | Raise `--max-walk-steps` above the target's seq. |

Vectors: `spec/vectors/verifier/reasons.json` holds the enum and one case
per reason, as overrides of a valid, authorized decision with references to
concrete bytes where a vector has them. It also lists the `fail` boundary
cases. The execution reasons point at `execution_outcomes.json`.

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
| `outcome` | `success` or `failure`: the rail's result as the tx source reported it. New in `v0-draft.27`. |
| `result` | What binds `outcome`: `proven` (a result proof against the trusted chain, F7), `cross-confirmed` (F6: sources agree, reported only) or `node-attested` (one source said so). Only `proven` binds it. |
| `cross_check` | `pass`, `mismatch`, `unavailable` or `off` (EX6). |
| `sources` | Every tx source asked, with its role and result (EX10). |

#### 20.2.1 Outcome rule (normative since `v0-draft.27`)

Human decisions of 2026-10-07: the execution check is tri-state, and a
general rule holds for the whole verifier (20.1). `pass` leads to the
verdict `valid` (if every other check passes), `fail` to `invalid`, and
`unchecked` to `unchecked`. `unchecked` is the INCONCLUSIVE outcome of those
decisions, exit code 2. Report and JSON names do not change, and a text
output MAY print `INCONCLUSIVE` for it.

A fact is *verified* when it holds no matter which source supplied it:

- F1: the action bytes, bound by `action.hash` (stage A);
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
  `fail` nor a `pass`. Until `v0-draft.27` it supported an interim `pass`
  (EX9), which held only until the reference verifier implemented the
  result proof (human decision of 2026-10-07).

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
| EX4 After the anchor | `height > payload_ref.height`, strictly. If the height is at or below the anchor height: `fail` when the height is verified (`inclusion = proven`, F5), otherwise `unchecked`, because the height is then only the claim of one or more sources. Why `fail`: a v0 gate signs an Authorization only after the anchor is in block `payload_ref.height` (strict mode, section 8.7), and the executor acts only on an Authorization. An honest execution therefore lands in a later block. A transaction at or below the anchor height was made before the decision was public. |
| EX5 Header | The header at `height` MUST pass header trust (section 10.6.2 with 20.4) under the same trusted header as the anchor before the checker compares anything with it (the chain id, the data root). So `T >= height`, and `header_hash` equals the hash HT3 reached at `height`. Outcomes: (a) `T < height`, after the optional wait of OH4: `unchecked`. (b) A header at `height` that an online source serves and that does not link is that source's fault (OH6): `unchecked`, naming the source. The checker never gets such a header (EX10 sets the candidate aside). (c) A `header_hash` from the checker that differs from the hash HT3 reached: `unchecked`, because the checker read a header that is not on the trusted chain. (d) A cross-check mismatch at `height` (OH7) is a disagreement between sources. Nothing tells whether the trusted header, the cross source or a fork is at fault, and none of them says anything about the decision. `header_trust` and `execution` are `unchecked` with the distinct reason "header disagreement with trusted chain: possible bad trusted header, hostile source, or fork", and the verdict is `unchecked` (exit 2). It is never `fail`. |
| EX6 Cross-check | The checker reports each cross source as `agree`, `disagree` or `fault` (the profile defines them). The aggregate `cross_check` is `off` if none is configured, `mismatch` if any disagrees, `unavailable` if none disagrees and any is at fault, and `pass` if all agree, which needs at least one. `cross_check = pass` is reported and never gives the check `pass` (EO3). `mismatch` is `unchecked` (since `v0-draft.27`; it was `fail` before): the answers contradict each other, one side lies, and nothing tells which. It names the disagreeing sources. The exception: when `height` and the result are verified (F5 and F7), a disagreeing cross source contradicts verified facts. It is reported, and the outcome does not change (EO4). `unavailable` and `off` never count as `pass`. |
| EX7 Proven | The report sets `proven_execution` only if `inclusion = proven` and EX5 passed. It says that the transaction bytes are in block `height` of the trusted chain. It says nothing about the result, whose binding is reported in `result` and `cross_check`. |
| EX8 Late | If the block time of `height` is after the Authorization's `expires`, the report carries the warning `execution_after_expires`. The verdict does not change: a rail can include a transaction after the Authorization expired, if it was signed while the Authorization was valid (bank-send profile 4.3, threat note on a halt). |
| EX9 Result | `outcome = failure`: `fail` if the result is verified (`result = proven`, F7), otherwise `unchecked`. `outcome = success`: `pass` needs `result = proven`, which needs `inclusion = proven`. Otherwise `unchecked` with the reason `result_unproven`, or the profile's result-proof reason, and the hint to configure a tx source that serves inclusion proofs and a source that serves `block_results`. `result = cross-confirmed` (F6) is no exception: the interim rule of `v0-draft.27` that let it give `pass` was removed in `v0-draft.28`, because the result proof is implemented. A profile defines its result proof (bank-send: RP1 to RP6, from `last_results_hash` of the trusted header at `height + 1`). |
| EX10 Sources and alternates | A checker reads its tx sources in configuration order: the primary, then the configured alternates. If a candidate's answer fails for an EO2 reason that rests on that answer (the transaction is not found, the source is unavailable, the bytes do not hash to `rail_ref`, a proof does not verify, the header at its `height` does not reach the trusted chain), the verifier MUST set the candidate aside, record why, and try the next alternate. The first usable answer is used. If an answer's bytes hash to `rail_ref` but fail the profile's byte rules, that is `fail` (EO1), and the check stops. Every source would serve the same bytes (F3). Cross sources are only compared with the used answer (EX6), and their agreement is reported only. They are never promoted to primary, because their independence is counted against the used source. If no candidate is usable, the check is `unchecked`. It names every candidate with its reason, and the reported cause is the last candidate's. Tx sources are distinct by OH3 among themselves and from the headers source. The report lists every source asked: name, role (`primary`, `alternate`, `cross`), result (`used`, `set_aside`, `agree`, `disagree`, `fault`) and reason. |

The report carries `execution` with the facts above, the `rail_ref`, the
block time of `height` and, for `unchecked`, the named sources. Errors of
this check are verifier or profile package errors. They are not section 12
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
  bad proof, serve wrong results, or claim a false height or code. In
  `v0-draft.26` such a source could make a valid execution `invalid`, and
  could make a transaction that was never included, or that failed, pass on
  its word alone. Both are closed.
- Fabricated height. Without a proof, `height`, and with it the ordering
  after the anchor (EX4), is only the source's claim. A source can put a
  transaction that landed before the anchor into a later block, or a later
  one at or below the anchor. Since `v0-draft.27` the ordering counts for
  `fail` and for `pass` only under F5. Under `v0-draft.26` one source's
  height was accepted, with only a warning, and under `v0-draft.27` the
  agreement of sources (F6) was enough for `pass`.
- The result proof (F7) needs the header at `height + 1` from the trusted
  chain, so a transaction in the newest block can be checked only once the
  next block exists and `T` reaches it.
- Not covered: a second execution of the same decision. EX checks the one
  transaction the receipt names. An executor that signs a second transaction
  with the same body (another `timeout_height` or fee) is not detected here.
  The executor rules (section 16) and the rail's sequence numbers are the
  defence.
- Without a receipt there is no `rail_ref`, and the check is `unchecked`. v0
  defines no search of the rail by `commitment_hash`.

### 20.3 HTTP archive read convention

A read-only archive over HTTP serves the records of section 19 under their
canonical paths (section 19.3). Any static file server over a format 0 file
tree conforms, if it meets HA2.

| Rule | Requirement |
|---|---|
| HA1 URL | A record is at `<base>/<path>`. `<base>` is an `http` or `https` URL without query, fragment or user info, with trailing slashes removed. `<path>` is the canonical path of 19.3, byte for byte: `payload/<da>/<commitment hex>`, `evidence/<da>/<commitment hex>`, `decision/<commitment_hash hex>`, `authorization/<commitment_hash hex>`, `rejection/<commitment_hash hex>/<error>`, and the policy paths of 19.3. `da` is decimal without leading zeros, hex is lower case, and `<error>` is one of the marker verdicts of 19.2. No escaping is needed. |
| HA2 Status | `GET`. `200`: the body is the record bytes, verbatim. `404` and `410`: the record is absent (`archive.ErrNotFound`). Anything else is an archive fault, never absent: another status (including `403` and `429`), a redirect (redirects are not followed), a transport error, a timeout, a body cut short. A client MAY retry a fault and SHOULD honour `Retry-After`. It ignores `Content-Type`. |
| HA3 Size | The client reads at most the cap of the kind it asked for, plus one byte (section 19.1: payload `2^27 + 4096`, evidence `2^25`, decision 69,632, Authorization 512, rejection 256; policy kinds per `spec/policy-v1.md` 12.1). A longer body is corrupt (`archive.ErrCorrupt` with cause `ErrTooLarge`). |
| HA4 Reader checks | Every body passes strict decoding (19.1) and the key check (19.3: the record carries the key it was asked under), exactly as a local read does. A body that fails is corrupt, never absent and never another record. The client does no DA recompute; the verifier does (P3, section 10.7). |
| HA5 State | The record state (19.5) is derived from reads only: decision, then Authorization, then, if the Authorization is absent, one read per marker verdict of 19.2 (26 names in this revision). The state is known only if each read the derivation needs answered `200` or `404`. A fault on any of these reads, or on any later record read, is an archive I/O error: the verification stops without a verdict (exit 4), and it is never reported as `pending`, `rejected` or absent. |
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
execution `height` (EX5). Since `v0-draft.26` that header comes from one of
three sources, in this precedence:

1. a trusted header file (HT1 as before);
2. an explicit checkpoint `T:HASH` obtained out of band, for example from an
   explorer;
3. an agreed checkpoint from online sources (OH3 to OH5).

The report names the mode (`file`, `explicit`, `agreed`).

| Rule | Requirement |
|---|---|
| OH1 Source | An online header source is a CometBFT RPC base URL. Reads: `/status` (latest height, `node_info.id`, network), `/header?height=h`, and optionally `/blockchain?minHeight=a&maxHeight=b` (at most 20 headers per call). The verifier builds the protobuf `Header` from the JSON and recomputes its hash (HT2). It never uses a hash the source reports. |
| OH2 At-height | Each header read is a block read (section 10.9): `header.height` MUST equal the requested height (AH1). The chain id of every header MUST equal that of the trusted header, and the configured chain id if one is configured. A header that fails this is a fault of that source. |
| OH3 Distinct sources | Checkpoint sources count once per normalized host (scheme and port ignored, lower case, one trailing dot dropped) and once per `/status` `node_info.id`: two host names that report the same node id count as one source. A source the verifier knows to be the gate's or the Recorder's own endpoint MUST NOT be counted. |
| OH4 Checkpoint height | `T` = the minimum of the latest heights reported by the sources that answered `/status`. If `T` is below the highest needed height, the verifier MAY wait for the chain and retry within its timeout (MUST before `v0-draft.27`; relaxed because not waiting is fail-safe). If it does not wait, or if time runs out, the check that needs the height is `unchecked`. For `payload_ref.height` or `promise.height` that check is `header_trust`. For the execution `height` it is `execution` (EX5 (a)), and `header_trust` is not affected. |
| OH5 Agreement | The verifier reads the header at `T` from every source and recomputes each hash. If two answering sources give different hashes, `header_trust` is `unchecked` with the reason "header disagreement with trusted chain: possible bad trusted header, hostile source, or fork" (`fail` before `v0-draft.27`). A disagreement between sources is a source problem, not a finding about the decision (20.1). If fewer than `quorum` distinct sources (OH3) answer with the agreed hash, `header_trust` is `unchecked`, never `pass`. `quorum` is configuration, at least 1. The default is 1 (human decision of 2026-10-07: one RPC operator is enough for the green line, and the report names it). |
| OH6 Chain links | Headers between `T` and the lowest needed height come from the configured header source, behind a preference for the archived headers. At a needed height (`payload_ref.height`, and for `da = 1` `promise.height`) the archived header is offered first. It is accepted only if it links (HT3, HT5). If it does not link, `header_trust` is `unchecked` with reason `chain_mismatch` (`fail` before `v0-draft.27`): the archive presents a header that the trusted chain does not have, which is a problem of the archive copy, not a finding about the decision. An online header that does not link is a fault of its source. The verifier MAY ask another configured source for that height. If no source gives a linking header, `header_trust` is `unchecked` and names the source. |
| OH7 Cross-check | Cross-check sources (HT6) read the header at `T` and at every needed height, the execution `height` included, and compare recomputed hashes with the trusted chain. A mismatch makes `header_trust` `unchecked` with the distinct reason "header disagreement with trusted chain: possible bad trusted header, hostile source, or fork", whatever the `quorum` (human decision of 2026-10-07, which supersedes the earlier "a mismatch fails" decisions; before `v0-draft.27` it was `fail`). The verifier cannot tell whether the trusted header, the cross source or a fork is at fault, and none of them proves anything about the decision. At the execution `height`, `execution` is `unchecked` too (EX5 (d)). An unreachable source is `unavailable`, never `pass`. Cross-check sources follow OH3 among themselves and against the checkpoint sources. A host that already counted for the checkpoint is not a cross-check. |
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
  `unchecked` with the header-disagreement reason (`fail` before `v0-draft.27`);
- an explicit checkpoint from an independent kind of source, such as an
  explorer's indexer;
- excluding the gate's own endpoints (OH3).

Distinct host names do not mean distinct operators. On 2026-10-07 two
host names of one Mocha provider reported one node, which the node-id rule
catches. One operator can still run several nodes, and no rule catches that.
A light client that verifies validator signatures forward from an older
trusted header removes this assumption and is planned after v0. OH6 keeps one
lying source from turning a valid decision into `invalid`: a header that does
not link is that source's fault, unlike an archived header, which is evidence.
Since `v0-draft.27`, OH5 and OH7 turn a contradiction between sources into
`unchecked`, with a reason that stands out in the report. A contradiction
must never pass, and it is never `invalid` either: the verifier cannot tell
which side is honest, and a fork or a bad trusted header looks the same. A
hostile cross-check source can therefore hold back `valid`, and it can never
cause `invalid`.
