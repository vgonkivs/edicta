# DecisionCommitment v1

Edicta — verifiable decision layer for autonomous agents.

Status: revision `v1-draft.4` (2026-10-09). Working draft, proposed for the
v1 freeze; subject to the human's approval. Wire version: `version = 1`.
Domain tags: `edicta/v1/...` for the commitment and the Authorization.

Built on the core spec `spec/decision-commitment-v0.md`, revision
`v0-draft.30`, frozen as `v0-format-freeze-2` (section numbers prefixed
"core" refer to it), and on `spec/policy-v1.md`, revision
`policy-v1-draft.7` ("policy"). This document defines only what v1 adds or
changes. Every core rule not named here applies to v1 unchanged, with
"commitment" read as "v1 commitment" and `T_H` read as `T_ref` (section 9).

Nothing here changes a v0 byte: the v0 commitment, envelope, Authorization,
receipt, record request, publish request, payload blob, every `edicta/v0/*`
tag and every vector under `spec/vectors/v0/` stay as they are, forever.

Keywords MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119. Items marked
`UNVERIFIED` are facts about Celestia, Fibre or wallets that a Celestia
protocol engineer must confirm; section 16 lists them. Everything else is
normative for v1.

## 0. Versioning of this document

| Change | Rule |
|---|---|
| Editorial | No version change. |
| Any change to wire bytes, a hash or signature preimage, a limit, or the outcome of any check, while in draft | Bump `v1-draft.N`, regenerate the vectors under `spec/vectors/v1/` (and any other file the change touches), record it below. |
| Defining a reserved value (section 4.4) after the freeze | Minor revision `v1.M` with the human's approval. It only turns a refusal into an acceptance; no byte string accepted before changes meaning (rule V6). |
| Any other such change after the freeze | New wire `version` (2) and new tags `edicta/v2/...`. |

| Revision | Date | Change | Vectors |
|---|---|---|---|
| `v1-draft.1` | 2026-10-09 | First draft (task 031), from the v1 design pack and the human's decisions of 2026-10-09: format v1 with `mandate_ref`, pending references and fast mode, Authorization v1 with `mode` and `anchor_deadline`, reference time `T_ref`, absence proofs, archive kinds 13 to 15, the reserved batch-leaf values and the reserved TEE attestation key. | To be generated (section 15). |
| `v1-draft.2` | 2026-10-09 | K-fast requires `window >= 1`, else `ErrAnchorWindowClosed` (8.1 F5, 8.2 B4, 8.3): a chain `payment_promise_height_window` of 0 would otherwise make the gate sign `anchor_deadline = h0`. 6.3 corrected: a v0-only executor refuses an Authorization v1 at stage D with `ErrUnknownKey` (key 7), not at Q1 (no outcome changes; the draft.1 text misnamed the sentinel). Vectors of task 031 phase P2. AB5 (P2): the candidate's result index is bound by the tail rule (`n - p + j`) or uniform codes, since a kind 14 record does not carry `data.txs` for the square rebuild that draft.1 named; kind 14 `results` is pinned to the JSON of `/block_results`. | `spec/vectors/v1/*` generated at this revision; `v1/anchor.json` gains `window_chain_zero`. |
| `v1-draft.3` | 2026-10-09 | Architect review of P2. (1) S2 also covers `payload_ref` key 6: `anchor = 2^63` is `ErrIntRange` (was `ErrInvalidEnum` by V1-3), as `da` and the Authorization `mode`. (2) AB5: the tail rule binds only when `header(h)` has the pinned `version.app` 10, otherwise only uniform codes; the results proof (RP1, RP3, RP4 of the bank-send profile) is restated inline; the tail rule is freeze-blocking until verified at the pins (section 16). (3) 11.1: `results` is JSON only (the contradicting protobuf clause removed); a writer MAY drop the JSON fields AB5 ignores. (4) 10.2: an `authorization` fail (A1 to A3) blocks a pending `anchor` check, as a missing record does. (5) 10.6: `anchor_height` and `publication: unknown` when an absence proof shows the anchor present without full evidence. Outcome changes: (1) the sentinel of `anchor = 2^63`; (2) an AB5 height of another app version with mixed codes is not proven (was bound by the tail rule). | `v1/reject.json`: `anchor_2pow63` (rule S2, `ErrIntRange`), file revision `v1-draft.3`. `da/absence.json`: new `candidate_other_app_version`, file revision and description. Every other case and file byte-identical. P3 (no bump: no byte, limit or outcome changes): AB5 tail rule VERIFIED at the pins (16.1, threat note in 10.4 updated); `da/absence.json` gains the live cases, `live_source`, `live_tail_rule` (revision stays `v1-draft.3`). |
| `v1-draft.4` | 2026-10-09 | Post-audit change list of task 031 (human decisions of 2026-10-09, Rounds 1 to 3). (1) Salted action hash: new tag `edicta/v1/action`, `ActionHashV1(type, salt32, bytes)` for v1 commitments (4.7), gate stage A0s/A1 and the retry rule with the salt (7.1), executor X2s/X3 (6.3), authorize wrapper key 3 and request limit 67,771 (13); V5 rewritten. (2) Payload plaintext v1 with `action_salt` (4.8, O8 v1, PV1 to PV3). (3) Decision record v1, kind 17, in two forms; kind 3 refuses a v1 envelope; kind 15 plaintext kind 5 (salt and action bytes) with its own envelope limit and cap 69,760; reveal on execution, kind 18, and gate config `RevealOnExecution` (11, 7.4); verifier rules for the decision and action checks, the reveal and salt equality (10.7). (4) K-fast slack: `MinFastSlackBlocks`, `MinPromiseSlackSeconds`, strict `MaxH0AgeBlocks` with the cross-field rule, provisional slack failures waived by an inclusion inside the window (7.4, 8.1 to 8.4). (5) Fast mode needs a mandate (7.2 C5a, 7.4) and makes the verifier's `policy` check required (10.1). (6) AB5: `n >= p >= 1`, no uniform-code path at the pinned app version, other versions only "every code 0" (presence); AB4 note on older promises (10.4). (7) Kind 14 part limits (11.1). (8) Section 1.1, the invariants index (the source of truth for `CLAUDE.md`); executor default and logging of mode and deadline (6.3, 6.4); new tag `edicta/v1/auditor-kid` (2). Outcome changes: every v1 action hash and commitment hash; `window_at_bound` refused; a pending reference at a gate without a mandate refused; a v1 decision in kind 3 corrupt; AB5 mixed or nonzero codes at another app version not proven. | Every file under `spec/vectors/v1/` regenerated at `v1-draft.4` (salted action hashes); new `v1/action.json`, `v1/payload.json`, `v1/gate.json`. Existing files changed: `v1/*` (salt), `da/absence.json` (three new synthetic cases, the expectation text of `candidate_other_app_version`), `verifier/reasons.json` (checks of two reasons, two cases), `api/errors.json` (salt examples, request limit, the v1 example requests carry key 3), and the policy and principal files listed in policy `policy-v1-draft.7`. Every v0 file byte-identical. |

## 1. Threat model additions

Core section 1 and policy section 1 apply. v1 adds:

| Mechanism | Defends against | Assumes |
|---|---|---|
| New tags for every v1 signed object (section 2) | A v0 signature verifying over v1 bytes or the reverse; a v0 executor accepting a v1 Authorization whose `mode` it cannot read | Tags differ inside the signed message; the `version` field differs inside the hashed bytes |
| `mandate_ref` in the agent-signed commitment (4.2, 7.3) | A gate authorizing under a mandate the agent did not commit to; an allow after a silent mandate change | The agent knows the hash of the mandate it acts under (the principal CLI prints it); the gate's refusal and the verifier's `mandate_ref_mismatch` both read signed data |
| `h0` inside the agent-signed commitment, plus `MaxH0AgeBlocks` (5.2, 8) | A gate or Recorder choosing or shifting the reference height (and so `T_ref`, the policy clock and the deadline) after the agent signed; a stale `h0` used to land spend in an old window | The agent signs only after verifying the anchor intent (W5-P); the gate's head is honest within the gate's own node; the verifier checks `H >= h0` |
| K-fast: verified anchor intent before a fast-mode Authorization (8) | Authorizing a payload that was never made available, in exchange for latency | Fibre: the 2/3 certificate under the network's quorum rule against the validator set at `h0` (core 10.6.1); blob: the gate's own node accepted the signed PFB for exactly this blob. Both are gate-attested at authorization; the verifier only sees the anchor or its absence later |
| `mode` and `anchor_deadline` in the gate-signed Authorization (6) | An executor or auditor unable to tell an anchored decision from an only attested one; a gate that never states when the anchor was due | Executors read the Authorization alone; the deadline is a height, not a tx hash (invariant 6) |
| Absence proof over `[h0, anchor_deadline]` (10.4) | A fast-mode decision whose anchor never landed passing as valid | Header trust (core 10.6.2) reaches `anchor_deadline` (or `anchor_deadline + 1`); SHA-256 and NMT completeness. A hostile source can only withhold (`absence_unproven`), never forge absence |
| Mandate consent `fast_mode_max_delay` (policy 6.1, 8.2) | An operator enabling fast mode for a principal who never accepted the weaker guarantee | The principal signed the bound; the gate clamps the deadline to it; the verifier checks it from signed data |
| Reserved values refused (4.4) | A v1.0 reader silently accepting a future batch-leaf or attestation reference under a meaning it does not implement | Readers implement the refusal; defining a value later needs the human's approval |
| K-fast slack: `anchor_deadline >= head + MinFastSlackBlocks`, and for Fibre a promise that does not expire within `MinPromiseSlackSeconds` (8.1, 8.3) | A fast-mode Authorization whose anchor can no longer land in `[h0, anchor_deadline]` (deadline at or below the head, promise about to expire) | The slack covers mempool latency of the gate's own node; a tx already included in the window waives it (8.3) |
| Fast mode only with a mandate (7.2 C5a, 7.4) | An operator enabling fast mode at a gate where no principal consented | A gate with `FastMode` refuses to start without a mandate; the verifier requires the `policy` check for `mode = 2` (10.1) |
| Salted action hash (4.7) | A dictionary search of low-entropy actions (order parameters, amounts) against the public `action_hash` | The 32-byte salt is fresh from a CSPRNG per commitment and stays wherever the action bytes are secret (payload, gate, executor, auditors); SHA-256 preimage resistance |
| Action salt inside the payload v1 (4.8) | A payload recipient unable to check that the payload's action is the committed one (O8) | The payload is the agent's, bound by `plaintext_hash`; the opener selects the payload schema by the commitment version |
| Decision record v1, private form (11.1 kind 17, 10.7) | The action bytes of a private-mode decision read from a shared archive | Private form stores the action only HPKE-encrypted to the auditors (kind 15 plaintext 5); the gate gets the bytes from the integrator, never from the archive |
| Reveal on execution (11.1 kind 18, 10.7) | A keyless verifier unable to tie a public on-chain execution to the salted `action_hash` | The tx is public anyway and the receipt links it to the decision; the revealed salt is self-verifying against the agent-signed `action_hash`; only actions with a receipt and a `public_execution` profile are revealed |
| Private mode (policy 9.6) | Everyone reading the mandate's rules and the decision content from a shared archive | What private mode does not hide is listed normatively in policy 9.6 (residual leakage) |
| Nothing (accepted) | A fast-mode anchor that misses its deadline: the action may already have run | The executor MAY refuse `mode = 2` (profile rule) and SHOULD act only while its own head is below `anchor_deadline` (profiles); the mandate bounds the window; the decision is provably `invalid` afterwards (`anchor_absent`, `publication: failed`) |

### 1.1 Invariants (source of truth)

The gate invariants of the project, one line each. `CLAUDE.md` copies this
block verbatim; any change to an invariant here updates `CLAUDE.md` in the
same commit, and the auditor checks that both agree. "core" is
`spec/decision-commitment-v0.md`, "CV1" this document, "POL"
`spec/policy-v1.md`.

1. Agent signature over `commitment_hash` is valid (core 5, 8.7 stage 1; CV1 4.5).
2. Payload available (Fibre or archive) and its hash matches; a pending reference also needs a verified anchor intent (core 8.7 stage P; CV1 7.1 stage 9, 8).
3. Presented action bytes are exactly the committed ones, no semantics, and `action_type` is allowlisted: v1 `action_hash = H(tag("edicta/v1/action") || uint8(len(type)) || type || salt32 || action_bytes)` with the agent's 32-byte salt presented alongside (missing salt refused, wrong salt `ErrActionMismatch`); v0 unchanged, `H(tag("edicta/v0/action") || uint8(len(type)) || type || action_bytes)` (core 5.1, 8.4; CV1 4.7, 7.1 stage A, 6.3 X3).
4. `now < valid_until`, `valid_until` well below Fibre retention measured from `T_ref`, Authorization `expires <= valid_until` (core 11.2, 15.1; CV1 9).
5. Nonce unused; marked used atomically and durably before the Authorization leaves; at most one per `(agent_pubkey, nonce)` (core 8.7 stage 12; POL 11.4).
6. `commitment_hash` over canonical encoding, never a field of what it hashes; no signed object carries a tx hash or rail reference (`anchor_deadline` is a height) (core 5; CV1 4.5, 6.1; POL 10.2).
7. The gate signs only after 1-6, 8, 9 hold, under its own per-version tags; four signing roles never overlap: agent, gate, executor, principal keys, compared as `(sig_type, bytes)`; auditor keys only encrypt, never sign (core 8.7; CV1 2, 7.1; POL 2.1, 6.1).
8. With a mandate: issue only if the verdict for exactly the committed action allows; facts by the registered extractor, else deny; rules on the policy clock `T_ref` (header time at `h0` for a pending fast-mode reference, else `T_H`); counter update in the nonce transaction; deny-only, fail-closed; mandate principal-signed under its `sig_type`, bound to `gate_id`, version not lower; `mandate_ref` equals the mandate in force (POL 8, 11.2; CV1 7.3, 9).
9. Authorization v1 states `mode` (strict iff the reference is included, fast iff pending) and, in fast mode, the `anchor_deadline` height; fast mode only with principal consent (mandate `fast_mode_max_delay` present; no mandate, no fast mode), deadline within that bound and at least `MinFastSlackBlocks` above the head; a missing anchor by the deadline is provable by absence proofs (CV1 6.1, 7.2, 7.4, 8.3, 10.4; POL 8.2 P15).

Process rule: any change to an invariant in the spec updates this block and
the `CLAUDE.md` block in the same commit; the auditor checks that the spec
and `CLAUDE.md` agree.

## 2. Notation and tags

Notation as core section 2: `tag(t) = uint8(len(t)) || ASCII(t)`, `H =
SHA-256`, `canon(x)` = canonical CBOR in the core section 3 profile.

New tags. A tag is never reused. The v1 commitment and Authorization tags
have the lengths of the v0 tags they succeed and differ at byte 9 (`v1`
versus `v0`).

| Tag | ASCII (length, `tag(t)` first byte) | Use |
|---|---|---|
| `TagCommitmentV1` | `edicta/v1/decision-commitment` (29, `0x1d`) | `commitment_hash = H(tag \|\| canon(Commitment))` |
| `TagSigV1` | `edicta/v1/sig` (13, `0x0d`) | agent signature over `tag \|\| commitment_hash` (46 bytes) |
| `TagAuthorizationV1` | `edicta/v1/authorization` (23, `0x17`) | `authorization_hash = H(tag \|\| canon(Authorization))` |
| `TagAuthorizationSigV1` | `edicta/v1/authorization-sig` (27, `0x1b`) | gate signature over `tag \|\| authorization_hash` (60 bytes) |
| `TagBatchLeaf` (reserved) | `edicta/v1/batch-leaf` (20, `0x14`) | reserved for a batch leaf hash; not used in v1.0 |
| `TagActionV1` | `edicta/v1/action` (16, `0x10`) | `action_hash = H(tag \|\| uint8(len(type)) \|\| type \|\| action_salt \|\| action_bytes)` of a v1 commitment (4.7); hash only |
| `TagAuditorKid` | `edicta/v1/auditor-kid` (21, `0x15`) | `kid = H(tag \|\| auditor X25519 pubkey)[0..16]` (policy 6.1); hash only, never signed |

The policy tags (`TagPrivatePart`, `TagPrivateAEAD`, `TagPrivateDEK`,
`TagStateBlind`, `TagBlindKey`) are defined in policy section 2.2.

`edicta/v0/action` is used by v0 commitments only; v1 commitments use
`TagActionV1` (4.7). Unchanged and used by v1: every other `edicta/v0/*` tag
of the receipt, the record request, the publish request and the payload blob
(the blob layout and its AEAD and HPKE tags serve payload version 1 as well,
4.8).

Threat note (tags). A v1 signed message has the length of its v0
counterpart (46 and 60 bytes) and differs in the tag bytes inside it, so a
v0 signature never verifies under a v1 tag or the reverse (vectors
`v1_signed_under_v0_tags`, `v0_signed_under_v1_tags`). The tag lengths 29,
13, 23, 27 equal v0 lengths; harmless, because the ASCII differs after the
length byte and every hashed v1 object also carries `version = 1`.
`TagActionV1` has the length of `edicta/v0/action` (16) and differs at byte
9; it is a new tag and not a reuse, because under the v0 tag the v1 preimage
`type || salt || bytes` is also the v0 preimage of type `type` and bytes
`salt || bytes`, so a v0 action hash over salt-prefixed bytes would equal a
v1 action hash (vector `action_v0_salt_prefixed_bytes`). `TagAuditorKid` has
the length of `edicta/v0/receipt-sig` (21); the ASCII differs, and the kid
tag is never part of a signed message.

## 3. Versioning and coexistence

| Rule | Statement |
|---|---|
| V1 | A commitment with `version = 1` is a v1 commitment, decoded by the schema of section 4. A frozen v0 reader refuses every v1 commitment: with `ErrUnsupportedVersion` (core S1), or with `ErrUnknownKey` at stage D when it carries key 14 or `payload_ref` key 6 (core D15 precedes S1). |
| V2 | v0 commitments, Authorizations, receipts, record and publish requests, their tags and vectors are frozen forever (`v0-format-freeze-2`). A v1 verifier verifies both versions. |
| V3 | The gate accepts a v0 commitment only when `AcceptV0` is set (default false once v1 is frozen). A gate with a mandate refuses v0 whatever the setting (`ErrVersionNotAccepted`), because v0 cannot carry `mandate_ref`. |
| V4 | A v1 commitment always gets an Authorization v1; a v0 commitment an Authorization v0. |
| V5 | `ActionHash` (core 5.1) serves v0 commitments only; v1 commitments use `ActionHashV1` (4.7). The hash function is chosen by the version of the signed object at hand, never by a request field or path: the gate by the commitment version, the executor by the Authorization version, the verifier by the envelope version. The receipt, the record request, the publish request and the payload blob layout (core 9, 9.1, 9.2) are version-independent and unchanged; their tags stay `edicta/v0/...`, and they bind `commitment_hash`, whichever tag produced it. The payload plaintext has `version = 1` under a v1 commitment (4.8). |
| V6 | Reserved values (section 4.4) are refused by v1 readers with the listed sentinel and are never given another meaning. Defining one later is a minor revision of v1 that only turns that refusal into an acceptance. |

### 3.1 Decoding dispatch

One function decodes envelopes of both versions:

1. Pass 0 (core D0) and pass 1 (core D1 to D13) on the whole input, with the
   core limits.
2. Read the envelope's key 1 value (the commitment map) and, in it, the
   value of key 1. If that value is the uint `1`, apply the v1 schema
   (section 4) and the rest of the v1 pipeline. Otherwise, whatever it is
   (absent, another type, `0`, any other uint), take the frozen v0 path,
   which reports the v0 sentinel (`ErrMissingField`, `ErrWrongType`,
   `ErrUnsupportedVersion`, or a stage D sentinel of the v0 schema).
3. Dispatch reads only bytes that pass 1 has accepted, so it is total and
   needs no extra sentinel.

A v1 reader therefore reports, for `version = 2` with only v0-defined keys,
`ErrUnsupportedVersion` (vector `version_2`), and for a v0 commitment
exactly the v0 outcome.

## 4. DecisionCommitment v1

### 4.1 Wire format

```
SignedCommitment = { 1: Commitment, 2: signature bstr 64 }
Commitment = {
  1:  version         uint = 1,
  2:  agent_id        tstr 1..64, ID charset,
  3:  agent_pubkey    bstr 32,                    ; G0
  4:  nonce           bstr 16,
  5:  issued_at       uint > 0,
  6:  valid_until     uint > issued_at, TTL <= MaxTTL(da),
  7:  scope           { 1: gate_id tstr 1..64 },  ; keys 2..4 retired
  8:  action          { 3: type tstr 3..128, 4: hash bstr 32 },   ; keys 1, 2 retired
  ;   9 retired (constraints)
  10: payload_ref     PayloadRef,
  11: ciphertext_hash bstr 32,
  12: plaintext_hash  bstr 32,
  13: payload_size    uint 1..2^27,
  ? 14: mandate_ref   bstr 32
  ;   15 reserved (TEE attestation reference), refused in v1.0
}
PayloadRef = {
  1: da          uint enum {1 fibre, 2 celestia_blob},   ; 3 reserved (batch leaf), refused
  2: namespace   bstr 29, S8,
  3: commitment  bstr 32,
  4: height      uint > 0,       ; included: anchor height H; pending: reference height h0
  ? 5: signer    bstr 20,        ; required iff da = 2, as v0
  ? 6: anchor    uint enum {2 pending}   ; absent = included; a present 1 is refused
  ;  7, 8 reserved (batch leaf), refused
}
```

Keys 1 to 13 and `payload_ref` keys 1 to 5 have the types, limits and
semantics of core 4.1 to 4.5, except where section 4.2 says otherwise.
Every core rule D (core 6), S (core 7), G, T, C, A (core 8) applies to them
unchanged, except S1, which v1 replaces by V1-1. S2 also covers
`payload_ref` key 6 (`anchor`): `anchor = 2^63` is `ErrIntRange` (S2 runs
before V1-3), as for `da` and for the Authorization `mode` (Q2).

### 4.2 New and changed fields

| Key | Name | Type | Limit | R/O | Semantics | Inv. |
|---|---|---|---|---|---|---|
| 1 | `version` | uint | `= 1` | R | Wire version (rule V1-1). | 6 |
| 5 | `issued_at` | uint | `> 0` | R | As core; for a pending reference, after the anchor intent was archived: K1 compares it with `T_ref` (section 9). | 4 |
| 8 | `action.hash` | bstr | exactly 32 | R | `ActionHashV1(action.type, action_salt, action_bytes)` (4.7), the salted hash; core 5.1 for `version = 0` only. The salt is not a commitment field. | 3 |
| 14 | `mandate_ref` | bstr | exactly 32 | O | `mandate_hash` (policy 6.2) of the mandate the agent acts under. Absent when the agent acts under no mandate. The gate compares it with the mandate in force (section 7.3); the verifier with the gate-signed verdict (section 14.2). | 8 |
| `payload_ref` 4 | `height` | uint | `> 0` | R | Included reference: the anchor height `H` (v0 meaning). Pending reference: the reference height `h0` (section 5.1). | 2 |
| `payload_ref` 6 | `anchor` | uint enum | `{2}` | O | Absent: included reference, every field with its v0 meaning. `2`: pending reference (section 5). | 2, 9 |

### 4.3 Rules

In addition to the core rules applied to keys 1 to 13.

| Rule | Stage | Statement | Sentinel |
|---|---|---|---|
| V1-1 | S (replaces S1) | `version = 1` on the v1 path. | `ErrUnsupportedVersion` |
| V1-2 | D (D18) | `mandate_ref`, when present, is exactly 32 bytes. Its value is not checked statelessly. | `ErrFieldSize` |
| V1-3 | S, after S3 | `anchor` (already `<= 2^63-1` by S2) is absent or `2`. A present `1` is refused so that "included" has one encoding (the absent key). | `ErrInvalidEnum` |
| V1-4 | gate K-fast | With `anchor = 2`, `height` is `h0` and is fixed by the agent's signature: it MUST equal `PaymentPromise.height` of the anchor intent (`da = 1`) or the intent record's `ref_height` (`da = 2`). | `ErrAnchorIntentInvalid` (gate) |
| V1-5 | D (D15), S (S3) | Reserved values: `da = 3`; `payload_ref` keys 7 and 8; commitment key 15. | `ErrInvalidEnum` (`da = 3`), `ErrUnknownKey` (keys) |
| V1-6 | gate K-fast; verifier | At authorization the gate refuses `head - h0 > MaxH0AgeBlocks` (section 7.4; default 10 blocks; 30 s at 3 s blocks is a per-network example). The bound is the gate's, not signed. The verifier checks that the final anchor height satisfies `H >= h0`. | `ErrH0TooOld` (gate); `source_corrupt` (verifier) |

Order within stage D: as core 6.3 (keys in ascending order, D15, D16, D18,
D19 per key, D17 after the map); within stage S: S2, S3, V1-3, S6, S7, S8,
S12, S14 after V1-1. The anchor key is read after `da`, so `da = 3` with
`anchor = 2` is `ErrInvalidEnum` from S3.

### 4.4 Reserved values

| Item | Reserved for | v1.0 reader | Intended meaning (not normative) |
|---|---|---|---|
| `payload_ref.da = 3` | batch leaf | `ErrInvalidEnum` | `commitment` names a Fibre batch blob; the payload is one leaf of it |
| `payload_ref` key 7 | `leaf_hash` bstr 32 | `ErrUnknownKey` | `H(tag("edicta/v1/batch-leaf") \|\| blob)` |
| `payload_ref` key 8 | `leaf_index` uint | `ErrUnknownKey` | position of the leaf in the batch |
| `TagBatchLeaf` | batch leaf hash | not used | |
| archive kind 16 | `batch` record | not defined (a reader refuses it as an unknown kind) | the batch blob and its leaf list |
| commitment key 15 | TEE attestation or code-measurement reference | `ErrUnknownKey` | a hash naming an attestation held in the agent's registration (a new tagged object, designed after v1.0) |

Only the reservations are frozen: these values mean nothing else, ever. The
intended meanings may change when the features are designed. zkTLS needs no
reservation: its proofs live in the opaque payload.

Threat note. A reader that ignored an unknown key or enum would accept a
commitment whose author meant something it does not check (for example a
batch leaf it never locates, or an attestation it never verifies). Refusal
keeps v1.0 readers fail-closed until the feature exists.

### 4.5 Hash and signature

```
commitment_hash = H( 0x1d || "edicta/v1/decision-commitment" || canon(Commitment) )
signed_message  = 0x0d || "edicta/v1/sig" || commitment_hash             ; 46 bytes
signature       = Ed25519-Sign(agent_sk, signed_message)                  ; core G0, G1 (cofactorless), G2
```

`canon(Commitment)` is the envelope's key 1 value spliced verbatim, as core
section 5. `commitment_hash` is not a field of anything it hashes
(invariant 6).

### 4.6 Limits

`MaxSignedSize` 2176, `MaxCommitmentSize` 2048, nesting depth 4, 16 entries
per map, charsets: unchanged (core 3). A maximal schema-valid v1 commitment
is 596 bytes (v0 559, plus 35 for key 14, plus 2 for `payload_ref` key 6;
the map heads stay one byte), its envelope 665 bytes.

### 4.7 Action hash v1

```
ActionHashV1(action_type, action_salt, action_bytes) -> action_hash
action_hash = H( 0x10 || "edicta/v1/action"
                 || uint8(len(action_type)) || action_type
                 || action_salt                                ; exactly 32 bytes
                 || action_bytes )                             ; to the end, as supplied
```

Core AH1 to AH4 (core 5.1) apply unchanged: the type is inside the preimage
with its length byte; the action bytes come last and are never parsed or
re-encoded; `1 <= len(action_bytes) <= 65536` and the type grammar are
checked first; the comparison is constant-time.

| Rule | Statement |
|---|---|
| AH5 | `action_salt` is exactly 32 bytes and sits between the type and the bytes; its fixed width makes the preimage split one way only. |
| AH6 (producer) | The salt is 32 bytes from a CSPRNG, fresh per commitment, never reused. A reused salt makes equal actions of two decisions hash equal and lets one dictionary run test both. The SDK writes it into the payload (4.8) and hands it, with the action bytes, to the gate and to the executor. No production API takes it from the caller; vectors fix it from labels (core 13). |
| AH7 (dispatch) | Commitment key 8 of a `version = 1` commitment is `ActionHashV1`; of a `version = 0` commitment it is core 5.1, unchanged (V5). |

Threat note (replaces the core 5.1 note "the hash is not hiding" for v1).
Under a secret 256-bit salt the public `action_hash` is not a dictionary
oracle for low-entropy actions such as order parameters. Whoever holds the
salt (the payload's recipients, the gate, the executor, the auditors; in
public mode every archive reader, 11.1 kind 17 form 1) can test candidates,
but each of them also holds or can read the action bytes, so nothing new
leaks. The salt must stay secret wherever the bytes are secret: in private
mode it is stored only encrypted (kind 15 plaintext 5), until a reveal on
execution (kind 18) for a public-rail action whose bytes are public anyway.
The public `action_hash` in a private-form PolicyVerdict (policy 10.1) is
safe only because it is salted (policy 9.6).

### 4.8 Payload plaintext v1

A v1 commitment's payload plaintext (core 9.3) has `version = 1` and carries
the action salt next to the action bytes, so every party that opens the
payload can run O8:

```
Payload v1    = core 9.3 Payload with 1: version uint = 1 and 5: action PayloadActionV1
PayloadActionV1 = { 3: type tstr 3..128 (media-type grammar), 4: data bstr 1..65536, 5: action_salt bstr 32 }
```

Every other field, limit and rule of core 9.3 applies unchanged; the blob
layout, its version (`0`), the AEAD and HPKE tags (`edicta/v0/payload`,
`edicta/v0/payload-dek`), `ciphertext_hash` and `plaintext_hash` are core 9,
9.1 and 9.2 verbatim. `PayloadActionV1` key 5 is required in payload version
1 and not defined in version 0.

| Rule | Statement | Sentinel |
|---|---|---|
| PV1 | The opener selects the payload schema by the version of the verified commitment, never by the payload's own `version` field: a v0 commitment opens with core 9.3 verbatim (an action key 5 is an unknown key), a v1 commitment with Payload v1. | - |
| PV2 | Under a v1 commitment, a payload that is well-formed and canonical except that `version != 1` is refused. | `payload.ErrVersion` |
| PV3 | Under a v1 commitment, action key 5 missing, of another type, or not exactly 32 bytes; any other core 9.3 failure. | `payload.ErrMalformed` |
| O8 v1 | Replaces core O8 for a v1 commitment: `aead_plaintext[32:]` decodes as Payload v1 (PV2, PV3); then `payload.action.type == c.action.type` (bytewise) and `ActionHashV1(payload.action.type, payload.action.action_salt, payload.action.data) == c.action.hash`. | `payload.ErrMalformed`, `payload.ErrVersion`, then `sdk.ErrPayloadMismatch` |

Core O1 to O7 run first, unchanged. An O8 v1 failure is a `payload` fail of
the verifier (core 20.1): the agent's own signed payload contradicts its own
commitment, whatever any archive copy holds. Salt equality with an archive
copy is a separate, later check of the verifier (10.7) and never blames the
agent.

Producer rule (core 9.5 addition). The SDK checks before signing that the
payload's `action_salt` is the salt it used for `action.hash`, and that the
payload's `version` is the commitment's. Under a private mandate (policy 9.5)
the agent MUST include every auditor of the mandate among the payload's
recipients, and gives the salt, outside the payload, only to the gate and
the executor: every payload recipient learns the action and its salt.

Threat note. Payload and commitment versions cannot be mixed up: the
commitment's `plaintext_hash` fixes the payload bytes, including their
`version`, and PV1 takes the schema from the signed commitment. A frozen v0
reader refuses a payload v1 (`payload.ErrVersion` or `payload.ErrMalformed`,
core 9.3: an input with several defects may yield either). A salt derived
from the payload key or the AEAD salt was rejected (human decision of
2026-10-09): it would make keyless execution checks in public mode
impossible.

## 5. Pending reference

### 5.1 Meaning

A pending reference (`payload_ref.anchor = 2`) says: the payload blob is
durable in the archive and its availability evidence exists, the anchor tx
is signed and archived as an anchor intent (kind 13), and the anchor is
expected on L1 at a height in `[h0, anchor_deadline]`, where `h0 =
payload_ref.height` and `anchor_deadline` is stated by the gate in the
Authorization v1 (section 6).

| `da` | `h0` | Anchor intent (`tx` of kind 13) |
|---|---|---|
| 1 (Fibre) | `PaymentPromise.height` of the upload: the height whose validator set signs the certificate | the signed `MsgPayForFibre` tx carrying the promise and the validator signatures |
| 2 (celestia_blob) | the chain head the Recorder read before it built and archived the PFB | the signed tx holding one `MsgPayForBlobs` for the blob, without the blob |

`h0` is inside the agent-signed commitment, so neither the gate nor the
Recorder can change it after the agent signed (decisions.md 4).

On chain, the anchor of a Fibre pending reference lands at `H >= h0`: the
keeper verifies the certificate against `HistoricalInfo` at
`promise.height`, which does not exist above the current block (core CV2,
`v0-draft.24`), and it refuses `H - promise.height >
payment_promise_height_window` (section 8.1, F5). For `da = 2`, `h0` was the
head when the tx was built, so any inclusion is at `H > h0`.

Pending references are accepted only by a gate in fast mode, which needs a
mandate (7.4); a strict gate, or one without a mandate, refuses them with
`ErrAnchorPending` (decisions.md 3). An agent whose
payload is already anchored signs an included reference and gets a strict
Authorization at any gate.

### 5.2 Producer rule W5-P (pending references)

Core W5 (independent inclusion check) applies to included references. For a
pending reference the agent, before signing, MUST verify the anchor intent
the way the gate does (section 8, F2 to F4 for `da = 1`, B2 for `da = 2`)
against an endpoint independent of the Recorder when the Recorder is another
party, and MUST check that `payload_ref.height` equals `h0` of that intent.
For `da = 2` the agent cannot check mempool acceptance independently of the
gate; the gate does it (B5).

Threat note. Without W5-P, a dishonest Recorder could hand the agent a
reference to an intent that never verifies; the gate would refuse it
(K-fast), so the risk is liveness, not safety. W5-P matters for the
agent's own record: it signs only a reference it has checked.

### 5.3 Recorder (normative points)

The Recorder MUST write the payload record (kind 1) and then the anchor
intent (kind 13) durably before it returns a pending reference and before it
broadcasts the anchor tx; the intent's `created_at` for `da = 1` is
`floor(PaymentPromise.creation_timestamp)`. After broadcast it continues its
v0 confirmation loop and writes the evidence record (kind 2, `height = H`)
when the anchor lands. It MUST NOT write a second, different intent under
the same `(da, commitment, ref_height)` (archive identity, section 11);
after a refused PFB it re-intents at a new `h0`, which needs a new
commitment.

`UNVERIFIED`: whether celestia-node's Fibre service at the pin exposes the
upload without the submit; otherwise the Recorder uses the celestia-app
Fibre client library directly (research item of task 035).

## 6. Authorization v1

### 6.1 Wire format

```
Authorization = { 1: version         uint = 1,
                  2: commitment_hash bstr 32,
                  3: action_hash     bstr 32,
                  4: gate_id         tstr 1..64, ID charset,
                  5: expires         uint 1..2^63-1,
                  6: path            uint enum {1 da, 2 archive},
                  7: mode            uint enum {1 strict, 2 fast},
                  ? 8: anchor_deadline uint 1..2^63-1 }
SignedAuthorization = { 1: Authorization, 2: signature bstr 64 }
```

| Key | Name | Rule | Inv. |
|---|---|---|---|
| 1 | `version` | `= 1`. | 6 |
| 2 to 6 | | As core 15.1. `commitment_hash` is the v1 hash (section 4.5). | |
| 7 | `mode` | Required. `1` iff the commitment's reference is included, `2` iff it is pending. The gate derives it from the commitment, never from a request field or path. | 9 |
| 8 | `anchor_deadline` | Present iff `mode = 2`. The absolute L1 height by which the anchor must be included: the anchor must land at a height in `[h0, anchor_deadline]`. Computed by K-fast (section 8.3). It is a height, not a tx hash or rail reference (invariant 6). | 2, 9 |

The Authorization still carries no agent key, no action type, no
`authorized_at`, no `h0` (the executor does not need it; the commitment
holds it) and no rail reference.

### 6.2 Tags and exact bytes

```
auth_canon          = canonical CBOR of Authorization
authorization_hash  = H( 0x17 || "edicta/v1/authorization" || auth_canon )
signed_message      = 0x1b || "edicta/v1/authorization-sig" || authorization_hash     ; 60 bytes
signature           = Ed25519-Sign(gate_sk, signed_message)
SignedAuthorization = canonical CBOR of { 1: <auth_canon spliced verbatim>, 2: signature }
```

`MaxAuthorizationSize` 256 unchanged; the largest v1 SignedAuthorization that
passes every rule is 233 bytes (v0 221, plus 2 for key 7, plus 10 for key 8).

### 6.3 Verification (executor side)

`VerifyAuthorization(bytes, check)` handles both versions. It runs pass 0
(256 bytes) and pass 1, reads key 1 of the Authorization map like section
3.1, and applies the v0 rules of core 15.3 when it is not `1`. For `version =
1`, core 15.3 applies with these changes:

| Stage | Rule | Check | Sentinel |
|---|---|---|---|
| D | D15 to D19 | The v1 schema of 6.1. Key 8 is not defined when `mode == 1` (D15) and required when `mode == 2` (D17); `mode` (key 7) precedes key 8 in canonical order, so this is decided in one pass, as core D15/D17 do for `signer` and `da`. For any other `mode` value key 8 is optional at stage D and Q5 refuses the value | stage D sentinels; `ErrUnknownKey` (deadline with `mode = 1`), `ErrMissingField` (`mode = 2` without deadline, or `mode` absent) |
| S | Q1 | `version == 1`, and `1` is in `check.accept_versions` (default `{0, 1}`) | `ErrUnsupportedVersion` |
| S | Q2 | `version`, `expires`, `path`, `mode`, `anchor_deadline` `<= 2^63-1` | `ErrIntRange` |
| S | Q3 | `path in {1, 2}` | `ErrInvalidEnum` |
| S | Q5 | `mode in {1, 2}` | `ErrInvalidEnum` |
| S | Q4 | `expires != 0` | `ErrZeroValue` |
| S | Q6 | `anchor_deadline != 0` when present | `ErrZeroValue` |
| G | G0, G2, G1 | As core 15.3 with `TagAuthorizationSigV1` and the v1 `authorization_hash` | `ErrInvalidPublicKey`, `ErrSignatureInvalid` |
| X | X1, X2 | As core 15.3 | as core |
| X | X2s | `check.action_salt` is present and exactly 32 bytes | `ErrMissingField` (absent), `ErrFieldSize` (other length) |
| X | X3 | `ActionHashV1(check.action_type, check.action_salt, action_bytes) == action_hash` (4.7), constant-time | `ErrActionMismatch` (wrong bytes, wrong type or wrong salt) |
| X | X4 | As core 15.3 | `ErrExpired` |

Order: D, then Q1, Q2, Q3, Q5, Q4, Q6, then G, then X1, X2, X2s, X3, X4. For
`version = 0`, `check.accept_versions` applies to core Q1 the same way, and
X2s requires `check.action_salt` to be empty (else `ErrUnknownKey`: a v0
commitment has no salt, and a salt there shows an integration that mixed up
versions); X3 is core 15.3 verbatim.

`check` gains `action_salt` (bytes). The executor's input is the
SignedAuthorization, the action type, the exact action bytes and the salt;
the integrator carries the salt next to the bytes from the agent, and the
executor never derives it. The function stays pure (no I/O). A missing salt
is a separate error from a wrong one because it is an integration fault;
the salt's presence is not secret, so the distinction leaks nothing.

A v0-only executor (core 15.3 verbatim) refuses every Authorization v1 at
stage D with `ErrUnknownKey`: every Authorization v1 carries key 7 (`mode`),
which the v0 schema does not define, and core D15 runs before Q1 (vector
`v0_executor_refuses_v1`). The refusal is the same whatever key 7 holds, so
no Authorization v1 is ever accepted by a v0 executor. A v1 executor
configured with `check.accept_versions = {0}` refuses it at Q1 with
`ErrUnsupportedVersion` (vector `executor_accept_v0_only`). Fast mode
and v1 commitments therefore need executors that accept Authorization v1.

An executor MAY refuse `mode = 2` by configuration; the profile defines the
sentinel (`ErrFastModeRefused`, profile documents). The default accepts fast
mode: fast mode exists only under a mandate whose principal stated
`fast_mode_max_delay` (7.2 C5a, policy P15), and an executor default must
not silently override that consent; refusing is the explicit strict-only
setting. An executor that accepts `mode = 2` logs `mode` and
`anchor_deadline`, and MAY keep them in its dedupe record; the source of
truth is the gate-signed Authorization (one per nonce, archived as kind 4,
reached by `commitment_hash`). The receipt is unchanged.

### 6.4 Threat notes

- Mode confusion: `mode` is signed, and the verifier checks it against the
  commitment's reference form (section 10.1); an Authorization that says
  `strict` for a pending reference is a gate-signed contradiction.
- A fast-mode Authorization is a bearer token exactly like a strict one
  (core 15.5). What differs is the publication guarantee: "available
  (Fibre: validators' custody certificate; blob: accepted by the gate's
  node) before the action, anchored no later than `anchor_deadline`". An
  executor that needs "anchored before the action" refuses `mode = 2`.
- `anchor_deadline` cannot extend the decision: `expires <= valid_until` as
  in v0, and K2 still covers `valid_until`.
- Acting after the deadline: an executor that accepts `mode = 2` SHOULD act
  only while its own chain head is below `anchor_deadline`; one without a
  chain head source relies on `expires` (profile rule, profiles T1a/X1a). No
  core sentinel is mandated.
- Signature confusion: v0 and v1 Authorizations are signed under different
  tags; neither verifies as the other (vectors `auth_v1_under_v0_tags`,
  `auth_v0_under_v1_tags`).

## 7. Gate

### 7.1 Authorization order (v1)

Core 8.7 and policy 11.1, with the stages below added or changed. An
implementation MUST NOT report a later stage's sentinel when an earlier
stage fails.

| # | Stage | Change |
|---|---|---|
| 1 | D, S, G, T, C | Dispatch (3.1). After `VerifyForGate`, C3 and C4 as core, then **V0** and **C5** (7.2). |
| 2, 3 | E, L | Unchanged. |
| 4 | A | v1 rules A0, A0s, A1 below (4.7). |
| 4m | Mandate reference | New, only with a mandate configured (7.3). |
| 4p | Admission | Policy 8.2, now with P15 (fast-mode consent). |
| 4a | AR | As core, but a v1 commitment's decision record is kind 17 (11.1), never kind 3: form 2 (private) iff the mandate in force has `auditors`, then the kind 15 `(5, action_hash)` record is written first; otherwise form 1. Also runs after a 4m refusal, as after a 4p deny. |
| 5 | N0 | Unchanged. |
| 6 | K or **K-fast** | Included reference: K (core K0), `T_ref = T_H`. Pending reference: K-fast (section 8). |
| 7 | K1 | On `T_ref` (section 9). |
| 8 | K2 | On `T_ref` and, for a Fibre pending reference, the intent's `created_at` (section 9). |
| 9 | P | Unchanged. For a pending reference the payload comes from the archive (`da = 2`) or the Fibre download and then the archive (`da = 1`); P3 is always computed locally. |
| 10 | T' | Unchanged. |
| 10p | Evaluation | Policy 8.3, 8.4 on `T_ref`. |
| 11 | Z | Build the Authorization of the commitment's version (V4). For v1: `mode` from the reference form; `anchor_deadline` from K-fast when `mode = 2`. |
| 12, 13 | N, R | As core. The nonce entry of a v1 allow also keeps `action_salt` (gate-local, in clear, like the PrivatePart bytes of policy 11.4), for the reveal on execution (11.4). Nothing fast-mode-specific is written before stage 12 (invariant 5). |

Stage A for a v1 commitment, in this order:

| Rule | Check | Sentinel |
|---|---|---|
| A0 | As core | `ErrActionSize` |
| A0s | v1 commitment: a salt was presented; v0 commitment: no salt was presented | `ErrMissingField` (v1, absent); `ErrUnknownKey` (v0, present) |
| A1 | v1: `ActionHashV1(c.action.type, action_salt, action_bytes) == c.action.hash`, constant-time; v0: core A1 | `ErrActionMismatch` (wrong bytes, wrong type or wrong salt) |

A0s runs after stage 1 (the envelope verified), so salt presence is never an
oracle for unsigned input. All three refuse before stage 4a, so no decision
record and no marker are written (as core A0, A1). The gate receives the
action bytes and the salt from the integrator, never from the archive.

The retry rule of core 8.7 is unchanged, except that condition 2 reads, for
v1: "the presented action bytes **and salt** give `ActionHashV1` equal to
the stored `action_hash`". A stored entry returns its stored Authorization
(same mode and deadline), and a retry never re-runs K-fast's deadline
computation.

### 7.2 Version acceptance and the pending reference (stage 1)

| Rule | Check | Sentinel |
|---|---|---|
| V0 | The commitment's version is accepted: `version = 1`, or `version = 0` with `AcceptV0` set and no mandate configured | `ErrVersionNotAccepted` |
| C5a | `anchor = 2` only at a gate with `FastMode` on **and** a mandate configured (defence in depth for library gates; 7.4 already refuses `FastMode` without a mandate) | `ErrAnchorPending` |
| C5b | `anchor = 2` only with `payload_ref.namespace` in `PendingNamespaces` (bytewise) | `ErrNamespaceNotAllowed` |

V0 and C5 run after `VerifyForGate`, so they are never an oracle for
unsigned input, and before stage 4a, so they write no decision record and no
marker (as every stage 1 refusal in v0).

Threat note (C5b). The allowlist bounds which namespaces a gate will look
up and rebroadcast for; without it any party could make the gate's node
carry PFBs for arbitrary namespaces.

A mandate in force without key 16 does not stop the gate from starting
with `FastMode`: it logs a warning, and every pending reference is denied
by P15 with a signed verdict (policy 8.2). Invariant test: a fast-mode
Authorization is issued only under a mandate whose key 16 is present.

### 7.3 Mandate reference (stage 4m)

Only with a mandate configured. Runs after stage 4 (A) and before 4p.

| Rule | Condition | Result |
|---|---|---|
| M1 | v1 commitment without key 14 | `ErrMandateRefMissing` |
| M2 | key 14 differs from `mandate_hash` of the mandate in force (the hash the verdict will carry), compared in constant time | `ErrMandateMismatch` |
| | equal | continue |

Without a mandate, key 14 is not read by the gate.

Before refusing under M1 or M2 the gate runs the stored-retry check of
policy 11.1 (read the nonce entry of `(agent_pubkey, nonce)`; if it holds
this `commitment_hash`, answer the stored Authorization with `ErrNonceUsed`
under the same conditions, and write nothing). Otherwise it refuses, runs
stage 4a, and writes the rejection marker. No policy verdict is signed for
an M1 or M2 refusal: the gate never signs a verdict under a mandate the agent
did not commit to.

Reasoning. After a mandate version bump, in-flight v1 decisions carry the
old hash and are refused (decisions.md 5); the agent re-signs under the new
hash (same payload reference, new nonce). The stored-retry check keeps the
v0 crash-liveness of a decision that was already authorized before the
bump.

### 7.4 Configuration

| Field | Rule |
|---|---|
| `AcceptV0` | bool; default false once v1 is frozen; treated as false with a mandate. |
| `FastMode` | bool; default false. Requires `PendingNamespaces` non-empty and an archive (`ErrInvalidConfig`), and a mandate (constructor check, `ErrInvalidConfig` with cause `fast_mode_without_mandate`: no mandate, no fast mode). |
| `FastWindowBlocks` | `1..1000`, default 100 (100 blocks is about 5 minutes at 3 s blocks, a per-network example). Upper bound of `anchor_deadline - h0`. |
| `MaxH0AgeBlocks` | `1..FastWindowBlocks - 1`, default 10. Upper bound of `head - h0` at authorization (V1-6). |
| `MinFastSlackBlocks` | `1..100`, default 3. Least `anchor_deadline - head` at authorization (8.3). |
| `MinPromiseSlackSeconds` | `1..600`, default 15. Least time left before the Fibre promise expires at authorization (8.1 F5). |
| `PendingNamespaces` | list of 29-byte namespaces, each passing S8. |
| `RebroadcastIntent` | bool, default true; applies to `da = 1` only (F6). For `da = 2` the broadcast check B5 always runs. |
| `RevealOnExecution` | list of action types whose profile has `public_execution = true` (11.4); each MUST be in the action-type allowlist (core C2). Default empty. |

Cross-field rule: `MaxH0AgeBlocks + MinFastSlackBlocks <= FastWindowBlocks`,
so that a fresh `h0` can always pass (`ErrInvalidConfig`, cause
`age_plus_slack`). Defaults are applied before validation by a separate step
(project convention); validation (`ValidateBasic`) holds every stateless
check above, in table order, then the cross-field rule; the mandate check
needs the dependency and runs in the constructor. Vectors:
`spec/vectors/v1/gate.json`.

## 8. Stage K-fast

Replaces stage 6 (K) for a pending reference. Inputs: the verified
commitment, the archive, the chain, the mandate (if any). First failure wins.
Every read at a height follows the at-height rules of core 10.9 (AH1 to AH5).

### 8.1 Fibre (`da = 1`)

| # | Check | On failure |
|---|---|---|
| F1 | The intent record for `(1, payload_ref.commitment, h0)` is read from the archive and decodes (kind 13). | `ErrAnchorIntentUnavailable` (503) |
| F2 | `tx` parses with upstream `TryParseFibreTx` as exactly one `MsgPayForFibre`. Its promise passes core CV2 with `promise.height == h0` in place of `promise.height <= payload_ref.height` (namespace, commitment, `blob_version = 0`, the gate's `chain_id`, `blob_size` by the CV2 upload-size arithmetic from `payload_size`) and CV3 (well-formed, owner-signed). The record's `namespace` equals `payload_ref.namespace` and its `created_at` equals `floor(promise.creation_timestamp)`. | `ErrAnchorIntentInvalid` (422) |
| F3 | Header at `h0` from the consensus endpoint (core NA1 with `h0`): `T_ref` and the header needed by CV7. `HistoricalInfo` at `h0` (core CV4 rules). The head `h` is read; `h >= h0` (a head below `h0` means the endpoint is behind). | `ErrChainUnavailable` (503) |
| F4 | Certificate: core CV4 to CV7 against the validator set at `h0`, with the network quorum rule of core 10.6.1. | `ErrCertInvalid` (422) |
| F5 | In this order: (1) age, `h - h0 <= MaxH0AgeBlocks`; (2) `window >= 1` (8.3); (3) slack, `anchor_deadline >= h + MinFastSlackBlocks` with `anchor_deadline` of 8.3; (4) promise slack, `T(h) + MinPromiseSlackSeconds < creation_timestamp + payment_promise_timeout` (core 10.2), parameters read at `h`. A failure of (3) or (4) is **provisional**: F6 decides it. | `ErrH0TooOld` (410) for (1); `ErrAnchorWindowClosed` (410) for (2) |
| F6 | Lookup `GetTx(SHA-256(tx))` on the gate's node, with `RebroadcastIntent` or after a provisional F5 failure (lookup only, never a broadcast, when `RebroadcastIntent` is off): included with code 0 at `h0 <= H <= anchor_deadline`: done, and a provisional F5 failure is waived; included elsewhere or with a nonzero code: `ErrAnchorWindowClosed`; not found after a provisional F5 failure: `ErrAnchorWindowClosed`; not found otherwise: `BroadcastTxSync(tx)`, and accepted or already known: done. | `ErrAnchorWindowClosed` (410); `ErrAnchorIntentRejected` (503) for a refused broadcast |

`UNVERIFIED` (F5, window origin). The x/fibre keeper refuses a PFF whose
promise is too old with `currentHeight - promise.height >
PaymentPromiseHeightWindow` (default 1000), so the chain accepts inclusion
at `H <= h0 + payment_promise_height_window`. VERIFIED (code) in local
celestia-app checkouts `f08d07c` and celestia-app-fibre `b515db4`
(`x/fibre/keeper/keeper.go`); not checked at the core pin `5187d2f`. The same
code allows `promise.height <= currentHeight + 1`; the certificate check
against `HistoricalInfo` at `promise.height` is what keeps `H >= h0` (5.1).

### 8.2 celestia_blob (`da = 2`)

| # | Check | On failure |
|---|---|---|
| B1 | The intent record for `(2, payload_ref.commitment, h0)` is read and decodes. | `ErrAnchorIntentUnavailable` (503) |
| B2 | `tx` decodes as a Cosmos `TxRaw` whose body holds exactly one message, a `MsgPayForBlobs` with, at one index `i`, `namespaces[i] = payload_ref.namespace`, `share_commitments[i] = payload_ref.commitment`, `share_versions[i] = 1`; its `signer` decodes to `payload_ref.signer`; `timeout_height` is 0 or `> h0`; `auth_info` has at least one signer and `signatures` at least one entry. The record's `namespace` and `signer` equal the reference's. | `ErrAnchorIntentInvalid` (422) |
| B3 | Header at `h0` (as F3): `T_ref`. Head `h >= h0`. | `ErrChainUnavailable` (503) |
| B4 | In this order: (1) age, `h - h0 <= MaxH0AgeBlocks`; (2) `window >= 1`; (3) slack, `anchor_deadline >= h + MinFastSlackBlocks` (8.3), after the lowering to `timeout_height`. A failure of (3) is **provisional**: B5 decides it. | `ErrH0TooOld` (410) for (1); `ErrAnchorWindowClosed` (410) for (2) |
| B5 | Mandatory. `GetTx(SHA-256(tx))`: found with code 0 at `h0 <= H <= anchor_deadline`: done, and a provisional B4 failure is waived; found elsewhere or with a nonzero code: `ErrAnchorWindowClosed`; not found after a provisional B4 failure: `ErrAnchorWindowClosed`; not found otherwise: `BroadcastTxSync(BlobTx{tx, [NewV1Blob(namespace, blob, signer)]})` with the archived blob (read under the stage P fetch budget); accepted or already known: done. This is the only check that the tx is valid (signature, fee, sequence): the gate relies on its own node's CheckTx. | `ErrAnchorWindowClosed` (410); `ErrAnchorIntentRejected` (503) |

`UNVERIFIED`: the exact "already in cache" result of CometBFT
`BroadcastTxSync` at the pin (`ErrTxInCache`); the gate treats it as
accepted.

### 8.3 Window and deadline

All values in blocks.

```
window          = min( FastWindowBlocks,
                       mandate.fast_mode_max_delay,
                       payment_promise_height_window(h) if da = 1 )
anchor_deadline = h0 + window
                  lowered to timeout_height when da = 2 and 0 < timeout_height < h0 + window
slack           : anchor_deadline >= h + MinFastSlackBlocks       ; h = the head read in F3 or B3
```

A mandate is always configured in K-fast (7.2 C5a, 7.4). `window >= 1` is
required; a `window` of 0 (only possible when the chain's
`payment_promise_height_window` read at `h` is 0) is `ErrAnchorWindowClosed`
(F5, B4 for symmetry). Otherwise the gate would sign `anchor_deadline = h0`,
which the verifier fails under A3 and which K2 input key 9 (`1..1000`) cannot
encode.

The slack is checked after the deadline is computed and lowered. It replaces
the comparison `h - h0 <= window` of `v1-draft.3`, which it implies
(`anchor_deadline >= h + 1` and `anchor_deadline <= h0 + window`). A slack
failure, and for Fibre a promise-slack failure (F5 (4)), is provisional: the
lookup of F6 or B5 runs, and a tx already included with code 0 in `[h0,
anchor_deadline]` waives it (K-fast is done: the anchor has landed in the
window); otherwise `ErrAnchorWindowClosed`.

With a mandate whose key 16 is absent, stage 4p has already denied
(`ErrFastModeNotAllowed`, policy P15), so K-fast never runs without a
mandate bound. `anchor_deadline` is recorded for stage Z and in the K2
inputs (`fast_window = anchor_deadline - h0`, section 11.4).

### 8.4 Then

K1 and K2 on `T_ref` (section 9); P; T'; 10p on `T_ref`; Z with `mode = 2`
and `anchor_deadline`; N as v0. A gate's sweep MAY list fast-mode entries
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

## 9. Reference time, K1 and K2

```
T_ref = header time at payload_ref.height, floor seconds       ; both anchor forms, both da
K1    : issued_at + skew_s >= T_ref                             ; ErrIssuedBeforeAnchor
start = da = 1, included: min(T_ref, floor(PaymentPromise.creation_timestamp))   ; core 11.2
        da = 1, pending:  min(T_ref, created_at of the intent)                    ; = floor(promise.creation_timestamp) by F2
        da = 2:           T_ref
K2    : valid_until + margin <= start + r                       ; r, margin as core 11.2
```

For an included reference `T_ref = T_H` and K1, K2 are core 11.2 verbatim.
The policy clock is `T_ref` (policy 8.1). The verifier reads `T_ref` from a
header at `payload_ref.height` that passed header trust.

Invariant 4 is unchanged in text; the retention window and K1 are measured
from `T_ref` (and, for Fibre, the promise creation time).

`UNVERIFIED`: that Fibre servers keep unsettled shards until
`max(promise expiry, creation + retention)` (core 10.2 `pruneAt`, VERIFIED
for the upload path, not for shards whose promise is never settled). If they
prune earlier, the archive path still serves the payload, and fast mode
requires an archive.

## 10. Verifier

### 10.1 Authorization record (core 19.5, AR8)

For a v1 decision, `authorized` also requires, from the Authorization's
signed bytes and the verified envelope:

| Rule | Check | On failure |
|---|---|---|
| A1 | Authorization `version` equals the commitment's `version` (V4) | `authorization` fail |
| A2 | `mode = 1` iff the reference is included, `mode = 2` iff pending | `authorization` fail |
| A3 | `mode = 2`: `h0 < anchor_deadline <= h0 + 1000` (no gate configuration allows more) | `authorization` fail |

These are gate-signed contradictions with the agent-signed decision, so
they are `fail` under the general rule of core 20.1.

Fast mode needs consent, so an Authorization v1 with `mode = 2` makes the
`policy` check required for the decision (as `RequirePolicy` does, policy
13.1): without a `policy_allow` record it is `unchecked`
(`policy_verdict_unavailable`) and the decision is never `valid`. This is
the verifier side of "fast mode only with consent" (invariant 9).

### 10.2 The `anchor` check for a pending reference

`h0 = payload_ref.height`; `D = anchor_deadline` of the verified
Authorization. Without an `authorized` record the window is undefined and
`anchor` is `unchecked` (`blocked`, naming `authorization`); the verdict is
`not_authorized` or `unchecked` by core 20.1 anyway. The same holds when the
`authorization` check fails A1, A2 or A3 (14.2): there may be no deadline
(A1, A2) or one out of range (A3), and a deadline the verifier has just
rejected is not verified data. The verdict is already `invalid` by that
fail, so nothing is hidden.

Evidence (kind 2) for a pending reference names the anchor height `H` in its
`height` field. It is checked with the core rules for `payload_ref.height =
H` (core 10.4 NA1 to NA7 and CV1 to CV8 for `da = 1`, with `promise.height ==
h0` in CV2; core 10.5 for `da = 2`), against a header at `H` that passed
header trust.

| Situation | `anchor` | Report |
|---|---|---|
| Evidence verifies, `h0 <= H <= D` | pass | `mode: fast`, `h0`, `anchor_height: H`, `anchor_deadline: D`, `publication: anchored`, assumptions (10.5) |
| Evidence verifies, `H < h0` | unchecked `source_corrupt` | a PFF cannot precede its reference height (V1-6) |
| Evidence verifies, `H > D`, absence over `[h0, D]` proven | **fail** `anchor_absent` | the late `H` is reported; `publication: failed`; attribution (10.6) |
| Evidence verifies, `H > D`, absence not proven | unchecked `absence_unproven` | names the first height not proven |
| No evidence (or evidence that does not verify), trusted header `T < D` (or `T < D + 1` when an AB5 results proof is needed) | unchecked `anchor_pending` | retry later with a newer checkpoint |
| No usable evidence, absence proven for every height of `[h0, D]` | **fail** `anchor_absent` | `publication: failed`; attribution |
| No usable evidence, a height of `[h0, D]` not proven absent | unchecked `absence_unproven` | names the first height not proven; advice `--absence-source` or another archive copy |

Evidence that does not verify is a source problem (`source_corrupt`, as
core) and the verifier goes on with the rows for "no usable evidence". An
absence proof that shows the anchor present at some `h` in the window
(AB5, AB6) is used as evidence at `H = h`; if the verifier cannot build the
full evidence from it, the result is `evidence_unavailable`.

`anchor_time` (K1) uses `T_ref` from the header at `h0`. `header_trust` must
reach `max(D, H)` (and `D + 1` for an AB5 results proof); HT3 gives every
header of the window from one backward chain.

For an included v1 reference the `anchor` check is core 20.1 verbatim.

### 10.3 `retention_replay`

Recomputes K2 with `block_time = T_ref` (K2 input key 3). When K2 input key
9 (`fast_window`) is present, also checks `anchor_deadline - h0 <=
fast_window`; a mismatch is `replay_inconsistent` (unsigned inputs, as core).

### 10.4 Absence proof

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
| AB1 | `header(h)` has height `h` and its recomputed hash equals the hash header trust reached at `h` (core HT3, one chain from `T >= D` serving every height of the window). |
| AB2 | `dah(h)` passes `ValidateBasic` and its `Hash()` equals `data_hash` of `header(h)` (core NA2). |
| AB3 | `namespace_data` passes `NamespaceData.Verify(dah, NS)` (core NA3, nmt `v0.24.5`, completeness included): with `R` the original rows whose root range contains `NS`, exactly `len(R)` entries, each a complete NMT namespace proof against `row_roots[R[j]]`. `R` empty with no entries is a valid proof. |
| AB4 (`da = 1`) | `S` = all shares of the entries, in order. `S` empty: **absent at `h`**. Else core NA4 reassembly (`ParseTxs`; re-split equals `S`) and NA5 candidates with `promise.height <= h` (same namespace, commitment, `blob_version = 0`, expected `chain_id`). No candidate: **absent at `h`**. Threat note: a candidate with `promise.height < h0` (another party re-anchoring the same blob inside the window under an older promise) is a candidate like any other; if it settles, `anchor_absent` is unreachable for the window. Safe direction: the blob is then published. |
| AB5 (`da = 1`, candidates) | For every candidate the result code is proven: `results(h)` hash to `last_results_hash` of `header(h + 1)`, which header trust ties to the chain, and the result at the candidate's index has `code != 0`. Results proof: read `txs_results[]` of `results(h)` and only its `code` (number), `data` (base64), `gas_wanted`, `gas_used` (decimal strings, int64); the leaf of result `i` is the protobuf of `ExecTxResult` with only field 1 `code` (varint uint32), 2 `data` (bytes), 5 `gas_wanted`, 6 `gas_used` (varint int64, a negative value as 64-bit two's complement), in this order, a zero or empty field omitted (gogoproto `Marshal` of the deterministic fields of CometBFT `types.NewResults`); the root is CometBFT `merkle.HashFromByteSlices` (RFC 6962) over the leaves and MUST equal `last_results_hash` of `header(h + 1)` (the state after block `h` stores the hash of block `h`'s results, and the header of `h + 1` carries it). These are the rules RP1, RP3, RP4 of the bank-send profile, restated so that core does not depend on a profile. With `n` results and `p` units reassembled from `PFF_NS` at `h` (AB4), `n >= p >= 1` MUST hold, else the height is not proven. When the trusted `header(h)` has `version.app` equal to the pinned `appconsts.Version` (10), the index is bound by the tail rule only: with `j` the candidate's position among the `p` units, the index is `n - p + j`; there is no uniform-code path at the pinned version. For any other app version only uniform codes apply, and only in the safe direction: every result code 0 proves the anchor **present at `h`**; any other pattern (all nonzero, or mixed) is not proven. Threat note: a block of another app version may follow other square rules, so it can never yield "absent" (fail-closed against a false `anchor_absent`); "every code 0" is safe whatever the index, because the root fixes every result. Why the tail rule binds: go-square `Construct` refuses a normal or blob tx after a Fibre tx (`validateTxOrdering`), so the Fibre txs are the last `p'` elements of `data.txs`; it appends each Fibre tx, in block order, as one unit of the `PFF_NS` compact sequence, so `p' = p` and the order is the same; the block has one result per tx (celestia-core `FinalizeBlock`, VERIFIED in the bank-send rail facts). The proof needs neither `data.txs` nor a square rebuild. Threat note: a wrong binding is not fail-safe (it could read another tx's nonzero code and give a false `anchor_absent`), so the rule is limited to the pinned app version; it is VERIFIED at the pins by code and on live Mocha blocks (section 16.1). Assumption: the block was accepted by validators running `ProcessProposal` of the pinned app (the >2/3 honest assumption of core 1), which refuses any block whose `data.txs` do not rebuild the square under these rules. Every candidate proven nonzero: **absent at `h`**. A candidate with proven code 0: the anchor **is present at `h`**. Any candidate whose code is not proven: not proven. |
| AB6 (`da = 2`) | `S` empty: **absent at `h`**. Else `ParseBlobs(S)` (go-square sparse shares). For each blob of share version 1, `CreateCommitment(blob, RFC 6962 root, 64)`; a blob whose commitment equals `payload_ref.commitment` and whose signer equals `payload_ref.signer` **is present at `h`**; none: **absent at `h`**. Shares that do not parse: not proven. |

Absence over the window: absent at every `h` in `[h0, D]`. Then and only
then `anchor` fails with `anchor_absent`.

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
verified data, so `invalid` satisfies the general rule of core 20.1.

### 10.5 Assumptions printed for a valid fast-mode decision

```
mode: fast. The gate authorized before the L1 anchor. The anchor landed at height H (window h0..deadline, in blocks).
Proven: payload bytes match the commitment; anchored on L1 no later than T_H; policy evaluated on T_ref (header h0).
Attested by the gate (not proven): the availability evidence was verified before the Authorization
  (Fibre: validators' custody certificate; celestia_blob: the signed anchor tx accepted by the gate's node).
```

### 10.6 Report fields and attribution

New report fields, present for every v1 decision: `version`; `mode`
(`strict` or `fast`, from the verified Authorization); for `fast`: `h0`,
`anchor_deadline`, `anchor_height` (when evidence verified, or an absence
proof shows the anchor present at `H`), `publication` (`anchored`, `failed`
with `anchor_absent`, or `unknown`) and `assumptions`. When an absence proof
(AB5, AB6) shows the anchor present at `H` but the full evidence is not
available (`evidence_unavailable`), the report gives `anchor_height: H` and
`publication: unknown`.

With `anchor_absent` the report names the **intent signer**: the address
that signed the anchor intent tx, taken from chain data, never from a gate
or Recorder claim (decisions.md 2): the `signer` of the `MsgPayForFibre`
(`da = 1`) or of the `MsgPayForBlobs` (`da = 2`, equal to
`payload_ref.signer`, which the agent signed), read from the archived intent
whose binding to the reference passes F2 or B2. In fast mode this is usually
the gate operator's Recorder key. The report also states that the gate issued
a fast-mode Authorization with this deadline (signed data). Without an intent
record that passes F2 or B2, `da = 1` reports the signer as `unknown`; `da =
2` reports `payload_ref.signer`. The attribution is information only: the
verdict stays about the decision.

### 10.7 v1 decision record, the action check and the reveal

`decision` (core 20.1): for a v1 reference the record under
`decision/<commitment_hash hex>` MUST be kind 17 (11.1). A kind 3 record
whose envelope is v1, or a kind 17 record whose envelope is not, is
`unchecked` (`source_corrupt`). For a v0 reference the record is kind 3, as
core.

`action` (core 20.1) for a v1 decision, first match:

| Situation | `action` | Bytes used by later checks |
|---|---|---|
| Form 1 | `ActionHashV1(c.action.type, key 6, key 5) == c.action.hash`: pass; else `unchecked` (`source_corrupt`) | key 5 |
| Form 2, a configured auditor key opens kind 15 `(5, c.action.hash)` (policy 9.5) | the reader recomputes `H(tag("edicta/v1/action") \|\| uint8(len(type)) \|\| type \|\| plaintext)` with `type = c.action.type`; equal to `c.action.hash`: pass; else, or an envelope failure with a listed key: `unchecked` (`source_corrupt`) | `plaintext[32:]` |
| Form 2, kind 15 `(5, c.action.hash)` absent in every checked copy | `unchecked` (`decision_unavailable`, naming the kind 15 record) | none |
| Form 2, no configured key opens kind 15, and the reveal path below gives bytes `A'` | pass | `A'` |
| Form 2, the reveal path runs and `ActionHashV1(c.action.type, salt, A') != c.action.hash` | `unchecked` (`source_corrupt`, naming the kind 18 record): a wrong salt and a tx that is not the action cannot be told apart | none |
| Form 2, otherwise | `unchecked` (`policy_private`) | none |

No `fail` comes from a missing or unopened action record. Checks that
consume the action bytes (`execution` F1 of core 20.2, the `policy` facts
re-extraction of policy 13.2 step 3) are `unchecked` (`policy_private`) when
`action` is; for any other `action` outcome they behave as core.

Reveal path (private mode, public-rail profiles). It runs only when all of
these hold: the execution check is requested (core 20.2); a kind 18 record
of this `commitment_hash` exists in a checked copy and decodes; its receipt
passes core 14.2 and the out-of-band checks there (gate key on record for
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

Salt equality (human decision of 2026-10-09). When the verifier has opened
the payload and O8 v1 passed (4.8), and it also holds an archive copy of the
salt that passed its own hash check (kind 17 key 6, kind 15 `(5, ...)`
opened, or kind 18), it compares the two salts bytewise. Any difference is
`action` `unchecked` (`source_corrupt`, naming the archive record): a source
problem, never an agent violation. Given both hash checks pass, a
difference needs a SHA-256 collision; the rule is defence in depth. An O8 v1
failure stays a `payload` fail (4.8).

Report: `action_source` (`decision_record`, `private_blob`, `reveal`, or
absent when `action` did not pass).

Threat notes:
- A form 2 record holds nothing of the action; the salt and the bytes are
  only inside kind 15 `(5, ...)`, encrypted to the mandate's auditors. A
  record of the other form than the mandate's is a privacy loss for that
  record, never a verification change: the verifier reads whichever form it
  finds.
- On a public rail in private mode the on-chain tx gives the bytes but not
  the salt; without a reveal it cannot be tied to `action_hash`, so the
  keyless verifier stays `unchecked` (`policy_private`). Denied or never
  executed decisions are never revealed, so their actions stay hidden (no
  limit probing, policy 9.6).

## 11. Archive records (format 0, additive)

Kinds 13 to 15, 17 and 18 extend archive format 0 (core 19) as the policy
kinds 7 to 12 did; kind 6 stays reserved, kind 16 is reserved (4.4). Record
step 3 of core 19.1 (the kind enum) gains 13, 14, 15, 17 and 18. Every record is `{1:
format = 0, 2: kind, ...}` under core 19.1. A frozen v0 reader refuses these
kinds as unknown, which is correct: it cannot verify what they serve.

### 11.1 Kinds

| Kind | Name | Fields (key: name, type) | Logical key | Path | Cap (bytes) | Identity (AW2) | Writer |
|---|---|---|---|---|---|---|---|
| 13 | `anchor_intent` | 3: `da` uint {1, 2}; 4: `commitment` bstr 32; 5: `namespace` bstr 29; 6: `ref_height` uint > 0; 7: `tx` bstr 1..65536; 8: `signer` bstr 20 (R iff `da = 2`, else not defined); 9: `created_at` uint > 0 (Fibre: `floor(creation_timestamp)`; blob: the Recorder clock) | `(da, commitment, ref_height)` | `intent/<da>/<commitment hex>/<ref_height>` | 65,600 | whole record | Recorder, before broadcast |
| 14 | `absence_proof` | 3: `da` uint {1, 2}; 4: `commitment` bstr 32; 5: `namespace` bstr 29; 6: `height` uint > 0; 7: `header` bstr `1..2^22` (SignedHeader at `height`); 8: `dah` bstr `1..2^22` (proto DAH); 9: `namespace_data` bstr `0..2^24` (shwap `NamespaceData.WriteTo` of `NS`, section 10.4; empty when no row holds `NS`); ? 10: `results` bstr `1..2^22` (block results of `height`: the JSON `result` object of CometBFT `/block_results?height=<height>`, of which only `txs_results[]` `code`, `data`, `gas_wanted`, `gas_used` are read (AB5); `da = 1` only, present iff a candidate exists); ? 11: `next_header` bstr `1..2^22` (SignedHeader at `height + 1`; present iff 10 is) | `(da, commitment, height)` | `absence/<da>/<commitment hex>/<height>` | 16,777,216 | the key (first write stays) | an auditor's tool or a gate sweep after the deadline; never required for `valid` |
| 15 | `private_blob` | 3: `plaintext_kind` uint {1 mandate, 2 bucket, 3 closed_set, 4 private_part, 5 action}; 4: `hash` bstr 32; 5: `envelope` bstr `1..65536` for plaintext kinds 1 to 4, `1..69632` for kind 5 (policy 9.5) | `(plaintext_kind, hash)` | `private/<plaintext_kind>/<hash hex>` | 69,760 | the key (first write stays) | gate (adoption, stage 4a, stage 13) |
| 17 | `decision_v1` | 3: `envelope` bstr `1..2176` (strict decoding, a v1 envelope); 4: `form` uint {1 public, 2 private}; 5: `action` bstr `1..65536`, exactly as presented (R iff `form = 1`, else not defined); 6: `action_salt` bstr 32, exactly as presented (R iff `form = 1`, else not defined) | `commitment_hash` (v1 tag, from `envelope`) | `decision/<commitment_hash hex>` (shared with kind 3) | 69,632 | whole record | gate, stage 4a (also after a 4m refusal or a 4p deny) |
| 18 | `execution_reveal` | 3: `signed_receipt` bstr `1..512` (core 14.2 stages D and S); 4: `action_salt` bstr 32 | `commitment_hash` (receipt key 2) | `reveal/<commitment_hash hex>` | 640 | whole record | gate, after `Record` attached the receipt (11.4) |

Heights in paths are decimal without leading zeros. Encodings of `header`,
`dah`, `namespace_data`: as core 19.2 (the same `UNVERIFIED` status for the
protobuf package names at the pin). `results` is JSON as the table says. A
writer MAY drop every field the results proof of AB5 ignores; the reader
reads only `txs_results[]` `code`, `data`, `gas_wanted`, `gas_used`.

Kind 15 plaintext kind 5 (`action`): plaintext = `action_salt (32) ||
action_bytes`; `hash` = the commitment's `action_hash`. A reader with a key
recomputes `H(tag("edicta/v1/action") || uint8(len(type)) || type ||
plaintext)` with `type` from the kind 17 envelope, which is exactly
`ActionHashV1` because the plaintext is the tail of its preimage; a mismatch
is corrupt. The larger envelope limit fits a 65,536-byte action plus the two
salts, the AEAD tag and 16 recipient entries, which 65,536 does not.

Kind 17 reader rules, after core 19.1: the envelope decodes as a v1 envelope
(a v0 envelope: corrupt, cause `ErrUnsupportedVersion`); `form` outside
`{1, 2}` is `ErrInvalidEnum`; keys 5 and 6 with `form = 2` are
`ErrUnknownKey`, absent with `form = 1` `ErrMissingField`; `action_salt` of
another length is `ErrFieldSize`. A kind 3 record whose envelope is v1 is
corrupt (cause `ErrUnsupportedVersion`): kind 3 is frozen and has no field
for the salt, so a v1 decision is never stored in it. Path sharing: v0 and
v1 commitment hashes come from different tags, so they never collide; a
reader fetches one path and dispatches on `kind`. A frozen v0 reader refuses
kind 17 as an unknown kind, which is correct.

Kind 18 reader rules: the receipt decodes (core 14.2 D, S); its key is the
receipt's `commitment_hash`. Its signatures are checked by the verifier
(10.7), not at decoding, as for every signed nested object.

Preconditions (AW4): none for 13, 14, 15. Kind 17 with `form = 2` needs the
kind 15 `(5, action_hash)` record durable first. Kind 18 needs the kind 17
record of its `commitment_hash`. The core preconditions on "the decision
record" (an Authorization, a marker; policy kinds 8, 9) are met by kind 17
for a v1 decision. A reader recomputes the key from fields 3 to 6 (13, 14),
3 and 4 (15), the envelope (17) or the receipt (18), and reports a mismatch
as corrupt.

Form (kind 17). `form = 2` iff the mandate in force at stage 4a has
`auditors`; otherwise `form = 1`. The gate never writes `form = 1` in
private mode (a test of task 037). Form 1 holds the salt in clear (public
mode: the salt hides nothing the bytes beside it do not show).

Identity reasoning. Kind 13 is the whole record: two different intents
under one key would let the gate and the verifier see different txs for one
reference. Kind 14 is the key, not the whole record (a precision over the
design pack): protobuf parts need not be canonical and two honest tools may
serialize one proof differently; every proof is re-verified, so the first
durable one serves. Kind 15 is the key: two envelopes of one plaintext differ
in their randomness and open to the same bytes, which the reader checks by
hash. Kind 17 is the whole record, as kind 3. Kind 18 is the whole record:
the gate writes it from its stored receipt, so a second, different record
for one decision would show two receipts, which the gate never issues.

### 11.2 Authorization record (kind 4)

`signed_authorization` is decoded by its own version: core 15 for `version
= 0`, section 6 for `version = 1` (dispatch as 6.3). The cap `1..256` holds.

K2 inputs (kind 4 key 5) gain:

| Key | Name | Type | Presence | Semantics |
|---|---|---|---|---|
| 9 | `fast_window` | uint `1..1000` | R iff the Authorization has `mode = 2`; else not defined | `anchor_deadline - h0` as the gate computed it (8.3) |

`block_time` (key 3) holds `T_ref`. Format stays 0: key 9 appears only in
records whose `signed_authorization` is v1, which a frozen v0 reader already
refuses (core 15.3 Q1), so no record a v0 reader accepted changes meaning.

### 11.3 Rejection markers (kind 5)

The verdict list of core 19.2 gains: `ErrMandateRefMissing`,
`ErrMandateMismatch` (stage 4m), `ErrAnchorIntentInvalid`, `ErrCertInvalid`,
`ErrH0TooOld`, `ErrAnchorWindowClosed` (stage 6, K-fast), and, through
policy 12.3, `ErrFastModeNotAllowed` and, in private mode only, `ErrDenied`.
Not markers either: the stage A refusals A0s and A1 (before stage 4a, as core
A0 and A1). Not markers: `ErrVersionNotAccepted`,
`ErrAnchorPending`, `ErrNamespaceNotAllowed` (stage 1, before any decision
record exists), and the operational 503s `ErrAnchorIntentUnavailable`,
`ErrAnchorIntentRejected` (AR5).

### 11.4 Writers

Recorder: kind 1, then kind 13, before returning a pending reference or
broadcasting (5.3); kind 2 when the anchor lands. Gate: as core 8.7 and
policy 12.2, with kind 17 in place of kind 3 for every v1 decision (stage
4a; in private form the kind 15 `(5, action_hash)` envelope first); in
private mode kind 15 replaces kinds 7, 10, 11 (policy 12.2). Kind 14:
written by `edicta-verify absence <ref>` into a local or shared archive
copy; never written by the Recorder.

Reveal on execution (kind 18). The gate writes it in `Record` (core 14.3),
after step 8 attached the receipt, iff the decision's record is kind 17 with
`form = 2` and `action.type` is in `RevealOnExecution` (7.4); it takes the
salt from the nonce entry (RQ5 already requires that entry, so the salt is
there whenever a receipt can be issued) and the receipt it stored. The
gate's repair rewrites it from the entry like the other records. A failed
write does not change the answer to the executor. Nothing else reveals a
salt: a denied or never-receipted decision keeps its salt encrypted.
Threat note: an allowlisted executor that requests a receipt without
executing makes the gate reveal the salt of an action that never ran; that
executor already holds the action bytes and the salt, so no new trust is
placed in it (core 14.5: a receipt is the executor's claim).

## 12. Sentinels

Additive to core 12 and policy 14. Package `gate` unless noted; HTTP in
section 13.

| Sentinel | Stage | Meaning |
|---|---|---|
| `ErrVersionNotAccepted` | 1 (V0) | v0 at a gate that requires v1 (mandate configured, or `AcceptV0` false) |
| `ErrAnchorPending` | 1 (C5a) | pending reference at a gate whose `FastMode` is off or that has no mandate |
| `ErrNamespaceNotAllowed` | 1 (C5b) | pending reference whose namespace is not in `PendingNamespaces` |
| `ErrMandateRefMissing` | 4m (M1) | mandate configured, v1 commitment without key 14 |
| `ErrMandateMismatch` | 4m (M2) | key 14 differs from the hash of the mandate in force |
| `ErrAnchorIntentUnavailable` | 6 (F1, B1) | no intent record for `(da, commitment, h0)` yet, or the archive failed (operational) |
| `ErrAnchorIntentInvalid` | 6 (F2, B2) | the intent does not decode, names other values than the reference, or is not a PFF/PFB for exactly this blob |
| `ErrCertInvalid` | 6 (F4) | the Fibre certificate fails CV4 to CV7 (reserved in v0, defined now) |
| `ErrH0TooOld` | 6 (F5, B4) | `head - h0 > MaxH0AgeBlocks` |
| `ErrAnchorWindowClosed` | 6 (F5, F6, B4, B5) | `window = 0`; `anchor_deadline < head + MinFastSlackBlocks`, or the Fibre promise expires within `MinPromiseSlackSeconds`, and the tx is not already included with code 0 in `[h0, anchor_deadline]`; or the intent is already included outside the window or with a nonzero code |
| `ErrAnchorIntentRejected` | 6 (F6, B5) | the gate's node refused the (re)broadcast (operational) |
| `ErrUnsupportedVersion`, `ErrInvalidEnum`, `ErrUnknownKey`, `ErrFieldSize`, `ErrMissingField`, `ErrZeroValue`, `ErrWrongType` (package `commitment`, existing) | D, S, A, X, HTTP | reused by V1-1 to V1-5, Q1 to Q6, A0s (missing salt `ErrMissingField`, salt with a v0 commitment `ErrUnknownKey`), X2s (and `ErrFieldSize` for a salt of another length), and the authorize wrapper key 3 (13) |
| `ErrActionMismatch` (package `commitment`, existing) | A1, X3 | also a wrong salt |
| `ErrInvalidConfig` (existing) | gate start | new causes: `fast_mode_without_mandate`, `age_plus_slack`, the range checks of 7.4, a `RevealOnExecution` type outside the allowlist |
| `policy.ErrFastModeNotAllowed` | 4p (P15) | policy section 8.2 |
| `ErrFastModeRefused` (profile packages) | executor | profile documents |

Verifier fail rules (not sentinels of the gate): `anchor_absent`
(`anchor`), `mandate_ref_mismatch` and `fast_mode_delay` (`policy`, policy
13.2).

## 13. HTTP (additive to core 18)

- `POST /v1/authorize` is an alias of `POST /v0/authorize`: same handler,
  same request and response shapes, same behavior. The server takes the
  version from the commitment inside the signed envelope, never from the
  path, and answers with the Authorization of that version (decisions.md
  19). A v1 envelope on `/v0/authorize` gets an Authorization v1; a v0
  envelope on `/v1/authorize` gets the v0 answer or `ErrVersionNotAccepted`.
- Request: `{1: envelope bstr, 2: action bstr, ? 3: action_salt bstr}`
  (both paths). Wrapper decoding (400): key 3 not a bstr is `ErrWrongType`,
  a length other than 32 is `ErrFieldSize`. Presence is judged at stage A0s
  (missing for a v1 envelope: 400 `ErrMissingField`; present for a v0
  envelope: 400 `ErrUnknownKey`). A wrong salt is 422 `ErrActionMismatch`.
  The request limit becomes `67736 + 35 = 67771` bytes. No new code.
- Error mapping. The codes below wrap no core sentinel and are matched after
  every existing code of their status, in this order:

| Status | Codes, in match order | `retryable` |
|---|---|---|
| 403 | `ErrVersionNotAccepted`, `ErrAnchorPending`, `ErrNamespaceNotAllowed`, `ErrMandateRefMissing`, `ErrMandateMismatch` | 0 |
| 410 | `ErrH0TooOld`, `ErrAnchorWindowClosed` | 0 |
| 422 | `ErrAnchorIntentInvalid`, `ErrCertInvalid` | 0 |
| 503 | `ErrAnchorIntentUnavailable`, `ErrAnchorIntentRejected` (both with `Retry-After`) | 1 |
| 403 | `policy.ErrFastModeNotAllowed` (policy 11.3, matched with the policy codes) | 0 |

A 503 here means no nonce was consumed and nothing was signed (K-fast runs
before stage 11). `spec/vectors/api/errors.json` is regenerated additively.

## 14. Verifier reasons and fail rules

### 14.1 New reasons (additive to the closed enum of core 20.1.1)

| Reason | On checks | Meaning | Advice |
|---|---|---|---|
| `anchor_pending` | `anchor` | Pending reference, no usable evidence, and the trusted header is below `anchor_deadline` (or `anchor_deadline + 1` when a results proof is needed): not decidable yet. | Retry later or with a newer checkpoint. |
| `absence_unproven` | `anchor` | Pending reference, no evidence inside the window, and the absence proofs for `[h0, anchor_deadline]` are missing, incomplete or fail. Names the first height not proven. | Another archive copy or `--absence-source`. |
| `policy_private` | `policy`, `gate_integrity`, `action`, `execution` | The record needed is a private blob (kind 15) and no configured auditor key opens it. Names the first record. On `action` and `execution`: a form 2 decision record (10.7) without a reveal that applies. | An auditor key of the mandate. |
| `principal_scheme_unsupported` | `policy` | The verifier build lacks the principal signature scheme the mandate names. | A verifier build with that scheme. |

`blocked` gains the check `anchor` (pending reference without an authorized
record). The enum stays closed; these four are its v1 additions (`v1-draft.4`
adds no reason: the private action check reuses `policy_private`, and the
round-1 proposal `action_private` was dropped). `policy_verdict_unavailable`
also covers a fast-mode Authorization without a policy allow record (10.1).
`decision_unavailable` also covers a form 2 decision whose kind 15 `(5,
...)` record is absent (10.7).

### 14.2 New fail rules (additive to the closed `fail` list of core 20.1)

| Check | Rule | From verified data |
|---|---|---|
| `anchor` | `anchor_absent`: absence proven for every height of `[h0, anchor_deadline]`. The report carries `publication: failed` and the intent signer (10.6). | the agent-signed reference, the gate-signed deadline, proofs against trusted headers |
| `authorization` | A1 to A3 (10.1) | the gate-signed Authorization and the agent-signed envelope |
| `policy` | `mandate_ref_mismatch`: the envelope's `mandate_ref` differs from the allow verdict's `mandate_hash` | the agent-signed envelope and the gate-signed verdict |
| `policy` | `ErrFastModeNotAllowed`, `fast_mode_delay` (policy 13.2 step 4) | the gate-signed Authorization and the principal-signed mandate |

Every other new non-`pass` outcome is `unchecked`.

## 15. Vectors (produced in task 031 phases P2 and P3, revised in `v1-draft.4`)

JSON conventions as core 13. New directory `spec/vectors/v1/`; every file
carries `"format": "edicta-vectors/v1"` and the revision of its last
content change: `v1-draft.4` for every file of `spec/vectors/v1/` and for
`da/absence.json` (every v1 action hash is salted since `v1-draft.4`, so
every v1 commitment hash changed). Action salts of vectors are
`SHA-256("action-salt/" || label)`, the label being the case id unless the
file says otherwise.
Keys: core `keys.json` (`agent1`, `agent2`, `gate1`) by reference, no copy.
Generators and checkers extend `spec/vectors/check/` (`gen_vectors_v1.py`,
`check_vectors_v1.py`, run by `check_vectors.py` without arguments). No file
under `spec/vectors/v0/` changes.

| File | Contents and case names |
|---|---|
| `v1/valid.json` | As core `valid.json`, v1 schema. Cases: `v1_minimal_included_fibre`, `v1_minimal_included_blob`, `v1_pending_fibre`, `v1_pending_blob`, `v1_mandate_ref`, `v1_pending_fibre_mandate_ref`, `v1_pending_blob_mandate_ref` (since `v1-draft.4`: fast mode needs a mandate), `v1_maximal` (596-byte commitment, 665-byte envelope). Each with `commitment_cbor_hex`, `commitment_hash_hex`, `signed_message_hex`, `signature_hex`, `envelope_hex`, `action_salt_hex`, `action_preimage_prefix_hex` (`tag || uint8(len(type)) || type`; the salt and the bytes follow) and `action_hash_hex` (4.7). |
| `v1/action.json` | Section 4.7. `action_v1_minimal` (the core `minimal_lmt` action, salt of label `minimal`: `preimage_hex`, `action_hash_hex`), `action_v1_max` (128-byte type, 65,536 action bytes as a pattern: preimage size and hash). Rejects with `committed_action_hash_hex` (and `committed_preimage_hex` where it is not the v1 formula), `stage` A, `rule`, `expect_error`: `action_v1_wrong_salt`, `action_v1_v0_tag`, `action_v1_unsalted`, `action_v1_salt_after_bytes` (`ErrActionMismatch`), `action_v1_salt_missing` (`ErrMissingField`), `action_v1_salt_31`, `action_v1_salt_33` (`ErrFieldSize`), `action_v0_with_salt` (`ErrUnknownKey`), `action_v0_salt_prefixed_bytes` (core `ActionHash(type, salt \|\| bytes)` differs from `ActionHashV1(type, salt, bytes)`: the tag separation). |
| `v1/payload.json` | Section 4.8. `payload_v1_minimal`: a Payload v1 sealed with the unchanged blob layout to one recipient (all randomness from labels), O1 to O7 as core, O8 v1. Rejects on the AEAD plaintext with `commitment_version`: `payload_v1_salt_missing`, `payload_v1_salt_31`, `payload_v1_salt_tstr`, `payload_v0_under_v1_commitment`, `payload_v0_with_salt`, `payload_v1_under_v0_commitment` (`payload.ErrMalformed`), `payload_v1_version_0` (`payload.ErrVersion`), `payload_v1_wrong_salt`, `payload_v1_unsalted_commitment` (`sdk.ErrPayloadMismatch`). |
| `v1/gate.json` | Section 7.4 configuration: `defaults`, the action-type allowlist, and cases with `config`, `mandate` and `expect` (`ok`, or `ErrInvalidConfig` with its cause): `fast_mode_without_mandate`, `fast_mode_without_namespaces`, `max_h0_age_equals_window`, `age_plus_slack_over_window`, `age_plus_slack_at_window`, `min_fast_slack_0`, `min_fast_slack_101`, `min_promise_slack_0`, `min_promise_slack_601`, `fast_window_1001`, `reveal_type_not_allowlisted`, and accepted controls. |
| `v1/reject.json` | One defect each, `stage`, `rule`, `expect_error`. Cases: `da_3_reserved` (`ErrInvalidEnum`), `payload_ref_key_7_reserved`, `payload_ref_key_8_reserved`, `commitment_key_15_reserved` (`ErrUnknownKey`), `anchor_1` (`ErrInvalidEnum`), `anchor_3` (`ErrInvalidEnum`), `anchor_tstr` (`ErrWrongType`), `mandate_ref_31_bytes`, `mandate_ref_33_bytes` (`ErrFieldSize`), `mandate_ref_tstr` (`ErrWrongType`), `version_2` (`ErrUnsupportedVersion`), `v1_signed_under_v0_tags`, `v0_signed_under_v1_tags` (`ErrSignatureInvalid`), `v1_bytes_v0_reader_minimal` (v0 reader: `ErrUnsupportedVersion`), `v1_bytes_v0_reader_key_14` (v0 reader: `ErrUnknownKey`), `retired_key_9`, `signer_on_fibre_pending`, `missing_signer_blob_pending`. |
| `v1/authorization.json` | As core `authorization.json`. Cases: `auth_v1_strict_da`, `auth_v1_strict_archive`, `auth_v1_fast_fibre`, `auth_v1_fast_blob_timeout_lowered`, `auth_v1_max_size` (233 bytes). Rejects: `auth_v1_fast_without_deadline` (`ErrMissingField`), `auth_v1_strict_with_deadline` (`ErrUnknownKey`), `auth_v1_mode_3` (`ErrInvalidEnum`), `auth_v1_mode_0` (`ErrInvalidEnum`), `auth_v1_missing_mode` (`ErrMissingField`), `auth_v1_deadline_0` (`ErrZeroValue`), `auth_v1_under_v0_tags`, `auth_v0_under_v1_tags` (`ErrSignatureInvalid`), `v0_executor_refuses_v1` (v0 schema: `ErrUnknownKey`, key 7), `executor_accept_v0_only` (`check.accept_versions = {0}`, `ErrUnsupportedVersion`), and since `v1-draft.4` the executor salt rules: every `check` carries `action_salt_hex` for a v1 Authorization; `exec_v1_salt_missing` (`ErrMissingField`), `exec_v1_salt_31` (`ErrFieldSize`), `exec_v1_wrong_salt` (`ErrActionMismatch`), `exec_v0_salt_present` (`ErrUnknownKey`). `auth_v1_fast_blob_timeout_lowered` is for `v1_pending_blob_mandate_ref`. |
| `v1/limits.json` | Maximal and over-limit envelopes and Authorizations under the unchanged caps. |
| `v1/anchor.json` | `k1` and `k2` on `T_ref` for both forms and both `da` (including `start = min(T_ref, created_at)`); `window`: inputs (`fast_window_blocks`, `fast_mode_max_delay` (always present: K-fast runs only under a mandate), `chain_window`, `h0`, `head`, `timeout_height`, `max_h0_age`, `min_fast_slack_blocks`, optional `included_at`/`included_code` for the F6/B5 lookup, optional `promise` with `t_head`, `creation`, `timeout`, `min_slack`) and `expect` (`anchor_deadline` or `ErrH0TooOld` / `ErrAnchorWindowClosed` / `ErrChainUnavailable`). Cases: `window_gate_min`, `window_mandate_min`, `window_chain_min`, `window_blob_gate_min`, `timeout_lowers_deadline`, `timeout_above_window`, `timeout_zero_ignored`, `h0_age_at_bound`, `h0_too_old`, `window_closed`, `window_at_bound` (refused since `v1-draft.4`), `window_slack_at_bound`, `window_slack_one_short`, `timeout_below_head`, `timeout_at_head_plus_slack`, `slack_waived_included`, `slack_not_waived_nonzero`, `promise_slack`, `promise_slack_ok`, `window_chain_zero`, `head_below_h0`. |
| `v1/archive.json` | Records of kinds 13, 14 (small synthetic proof parts; the record layer does not verify them), 15 (the bytes of `policy/private.json`, plaintext kinds 4 and 5), 17 (both forms; the fast-mode decisions are the `*_mandate_ref` cases), 18, Authorization records of v1 decisions, the kind 4 K2 input key 9, and v1 rejection markers; each case also gives `v0_reader`, the result of the frozen v0 record decoder. Rejects (`signer_on_fibre_intent`, `fast_window_on_strict`, `fast_window_missing_on_fast`, `fast_window_0`, `fast_window_1001`, over cap, `kind_16_reserved`, kind 14 `results`/`next_header` pairing, `header_empty`, kind 15 `private_envelope_empty`, `private_envelope_65537` (plaintext kind 4), `private_action_envelope_69633`, `private_plaintext_kind_6`, kind 17 `decision_v1_form1_missing_salt`, `decision_v1_form1_missing_action`, `decision_v1_form2_with_action`, `decision_v1_salt_31`, `decision_v1_form_3`, `decision_v1_v0_envelope`, `kind3_with_v1_envelope`, kind 18 `reveal_salt_33`, `reveal_receipt_garbage`, others); `reject_large` (given by size and SHA-256 with the construction recipe): `header_over_2p22`, `header_at_2p22` (control), `namespace_data_over_2p24`; `reads`: key mismatch (`intent_key_mismatch`, `private_key_mismatch`, `absence_key_mismatch`, `decision_v1_key_mismatch`, `reveal_key_mismatch`). Generator `gen_archive_v1.py`, checker `check_archive_v1.py`. |
| `v1/verify.json` | Verifier cases on synthetic records: `fast_pass_in_window`, `fast_h_below_h0` (`source_corrupt`), `fast_late_absence_proven` (fail `anchor_absent`), `fast_late_absence_unproven`, `fast_pending` (`anchor_pending`), `fast_absent_proven` (fail), `fast_absence_missing_height`, `auth_mode_mismatch` (fail, A2), `auth_deadline_over_1000` (fail, A3), `auth_version_mismatch` (fail, A1), `replay_fast_window_inconsistent`; also `fast_pass_at_deadline`, `fast_pending_results_needed`, `fast_absent_proven_blob` (intent signer = `payload_ref.signer`), `fast_absence_shows_present` (`evidence_unavailable`), `fast_evidence_not_verifying`, `auth_strict_included`, `replay_fast_window_consistent`. Decision and Authorization are archive records; evidence and absence are given as verification results per height (their bytes are in the core evidence vectors and `da/absence.json`). With an `authorization` fail the `anchor` check of a pending reference is `unchecked` (`blocked`, naming `authorization`): the deadline is not verified data. `action_cases` (10.7): `decision_v1_public_pass`, `decision_v1_public_wrong_salt` (`source_corrupt`), `decision_v1_private_without_key` (`policy_private`), `decision_v1_private_with_key` (pass), `decision_v1_private_blob_missing` (`decision_unavailable`), `reveal_public_execution_pass`, `reveal_wrong_salt`, `reveal_tx_not_action` (`source_corrupt`), `reveal_offchain_profile` (`policy_private`), `payload_archive_salt_equal`, `payload_archive_salt_mismatch` (`source_corrupt`), `kind3_with_v1_envelope` (`decision` `source_corrupt`). |
| `principal/adr036.json`, `principal/eip712.json` | Policy section 6.2 and 15. |
| `da/absence.json` | Section 10.4. Live Mocha cases (P3, `live`, `mocha-5`, one height each, kind 14 records built from read-only captures so every check runs offline): `fibre_no_pff_row` (1,403,118: no PFF, row 0's entry is an NMT absence proof), `fibre_other_pffs_only` (1,439,495: eight PFFs, none a candidate), `fibre_present_live` (1,197,863: candidate bound by the tail rule to result 3, code 0, while result 0 has code 4), `blob_empty_namespace` (1,403,105), `blob_other_blobs` (1,385,832: another share-version-1 blob of the same signer), `blob_present` (1,403,104), with `trusted_headers` from two consensus RPC operators; `live_source` (endpoints, capture time, reads) and `live_tail_rule` (16.1). Capture tool `spec/vectors/tools/absence-gen` (own module; `-check` rebuilds the live sections offline with upstream code; not run by `check_vectors.py`); `gen_absence.py` carries the live sections over unchanged. Synthetic (P2), kind 14 records over one synthetic chain (`edicta-synth-1`, heights 4,200,201 to 4,200,206) with the trusted header hashes as a case input: `fibre_candidate_nonzero_code`, `fibre_present`, `window_three_heights_proven`, `window_one_height_missing`, `tampered_row_root` (fails AB2), `cut_namespace_entry` (fails AB3); also `header_not_trusted` (AB1), `results_root_mismatch` and `candidate_without_results` (AB5); `candidate_other_app_version` (AB5, since `v1-draft.3`: the case's own chain gives `header(h)` `version.app = 11`, listed in the case's `app_versions`, with its own `trusted_headers`; at another app version only every code 0 proves anything, so the height is not proven); since `v1-draft.4` also `candidate_other_app_version_all_nonzero` (not proven), `candidate_other_app_version_all_zero` (present) and `tail_n_less_than_p` (pinned version, one result for two `PFF_NS` units: not proven; case key `results_counts`, its own trusted headers). The blocks cover no row holding `PFF_NS`, an NMT absence proof inside a row range, PFFs without a candidate (other commitment, other `chain_id`, `blob_version = 1`, `promise.height > h`) and the tail rule of AB5 (in both candidate blocks a binding by PFF position alone gives the wrong answer). Synthetic parts no AB rule reads: the parity quadrants (pseudo-random, not Reed-Solomon), commit and PFF signatures (placeholders), the system blobs of the PFFs (left out). Generator `gen_absence.py`; checker `check_absence.py` runs AB1 to AB5 on the bytes with the v0 anchor-proof and result-proof code and checks the refs of `v1/verify.json`. AB6 (`da = 2`) has only the live cases; `check_absence.py` implements go-square `ParseBlobs` and `CreateCommitment` and first reproduces every commitment of `v0/da_blob.json`. |
| `policy/private.json`, regenerated `policy/render.json`, `policy/verify.json`, `policy/mandate.json`, `policy/archive.json`, `policy/api.json` | Policy section 15. |
| `verifier/reasons.json` | Regenerated additively: the four reasons of 14.1 appended to the enum, one case each (`anchor_pending`, `absence_unproven`, `policy_private` and `policy_private_walk`, `policy_principal_scheme_unsupported`), `blocked` gains the check `anchor`, and the fail rules of 14.2 appended to `boundary` (`anchor_absent`, `authorization_*` for A1 to A3, `policy_mandate_ref_mismatch`, `policy_fast_mode_not_allowed`, `policy_fast_mode_delay`); since `v1-draft.4` `policy_private` lists the checks `action` and `execution`, `decision_unavailable` the check `action`, and the cases `policy_private_action`, `decision_unavailable_private_action` are added; refs point at `v1/verify.json` (also its `action_cases`), `policy/verify.json` and `policy/private.json`. `format` stays `edicta-vectors/v0`, `revision` `v1-draft.4`. |
| `api/errors.json` | Regenerated additively: the section 13 codes inserted after the last existing code of their status, `ErrCertInvalid` moved from `not_api_visible` to the mapping, `ErrFastModeRefused` and (since `v1-draft.4`) `ErrInvalidConfig` listed as not API-visible, the alias endpoint `/v1/authorize`, examples (a v1 envelope on both paths with its key 3 salt, a v0 envelope on the alias, a pending reference at a strict gate and at a gate without a mandate, a v1 request without key 3, a v0 request with key 3, a 31-byte key 3, a wrong salt); request limit 67,771. `format` stays `edicta-vectors/v0`, `revision` `v1-draft.4`. The policy codes stay in `policy/api.json`. |

Acceptance of P2 and P3 (task 031): every v0 vector file byte-identical;
the checker passes on v0, v1, policy, principal, absence and reasons files.
`check_vectors.py` ends with one line listing the revision of every vector
file outside `spec/vectors/v0/`.

## 16. `UNVERIFIED` items

| Item | Section | How to settle |
|---|---|---|
| celestia-node Fibre service exposes the upload without the submit | 5.3 | task 035 research |
| CometBFT `BroadcastTxSync` "already in cache" result at the pin | 8.2 | task 035 research |
| Fibre keeper window rule `currentHeight - promise.height <= PaymentPromiseHeightWindow` at the pin `5187d2f` (VERIFIED in newer local checkouts) | 8.1 | read the pin |
| Unsettled Fibre shards kept until `max(promise expiry, creation + retention)` | 9 | read `fibre/server_upload.go` and the pruner at the pin |
| Protobuf package names of `SignedHeader`, DAH, block results at the pin (inherited from core 19.2) | 11.1 | as core |
| Keplr `signArbitrary` limits and exact sign document; MetaMask acceptance of a domain without `chainId` | policy 6.2 | live checks, task 032 |

### 16.1 Verified in task 031 P3 (2026-10-09)

The tail rule of AB5 (10.4), formerly freeze-blocking. VERIFIED by code at
go-square `v4.0.1` (commit `948e812`) and celestia-app `v10.4.0-mocha`
(commit `5187d2f`, the core pin), and on live Mocha blocks.

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
