# Edicta policy v1 (mandate, facts, rule engine, verdicts)

Status: revision `policy-v1.0` (2026-10-09). Frozen. Built on the core spec
`spec/decision-commitment-v1.md`, revision `v1.0`. Section numbers prefixed "core" refer to that document.

Keywords MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119. Items marked
`UNVERIFIED` are facts about Celestia or Fibre that a Celestia protocol
engineer must confirm. Everything else is normative for policy v1.

A gate operator attaches one principal-signed **mandate** to a gate. The gate
then authorizes only actions whose **facts**, extracted deterministically from
the exact action bytes, satisfy the mandate's rules. The rules are evaluated on
the reference time `T_ref` (the header time at the commitment's
`payload_ref.height`: the anchor height for an included reference, the
reference height `h0` for a pending one, core section 12.2), over a
hash-linked state of hourly buckets that is
updated atomically with the nonce mark. Every verdict is signed by the gate,
carries the state it was evaluated on, and chains to the previous one, so a
verifier can check an allow from archived data and detect a gate that forks or
rewrites its own history.

Policy is configured, not written: there is no per-agent code. The policy
never evaluates the agent, the truth of its inputs or the quality of its
decision; it bounds what may be authorized.

The policy changes no core byte: DecisionCommitment, the envelope, the
Authorization, the receipt, the record request, the publish request and the
core tags are as the core defines them. A gate without a mandate behaves
exactly as core section 8.7 says, which includes refusing a commitment that
carries `mandate_ref` (core section 8.8, rule M0). A gate with a mandate
requires the commitment's `mandate_ref` to name the mandate in force (core
section 8.8).

## 0. Versioning

| Change | Rule |
|---|---|
| Editorial | No version change. |
| Any change to an encoding, a hash or signature preimage, a limit, the engine, or the outcome of a check, while in draft | Bump `policy-v1-draft.N`, regenerate the vectors under `spec/vectors/policy/`, record the change below. |
| Any such change after freeze | New family version: tags `edicta/policy/v2/*`, `format = 2` in every structure. A v1 reader rejects `format != 1`. |

The freeze turns `policy-v1-draft.9` into `policy-v1.0`, `format = 1`, tags
`edicta/policy/v1/*`, at the same tag as format v1 of the core.

| Revision | Change | Vectors |
|---|---|---|
| `policy-v1-draft.1` | First draft (task 028). | Initial set in `spec/vectors/policy/`; `spec/vectors/profiles/bank-send/tia_transfer_facts.json`. |
| `policy-v1-draft.2` | Asset scale is immutable per counter: the counter cell keeps the scale of every asset any adopted version listed, adoption refuses a change (6.3), and walk rule L4 checks the same rule across every mandate the walk reaches (13.3). Closed bucket and ClosedSet bytes are stored in the registry entry of the allow that closed the hour (11.1, 11.4, 12.2). No encoding, hash or signature preimage changed. | `mandate.json` gains `adoption`; `verify.json` gains three cases and their records. Both files now carry `policy-v1-draft.2`; every other file and every existing case and record is byte-identical. |
| `policy-v1-draft.3` | The scale map of a counter cell holds at most 1024 assets; adoption that would exceed it is refused with cause `scales_full` (6.3, 11.4). On a stage 4p deny the gate first reads the nonce entry, and a same-commitment retry gets the stored Authorization with `ErrNonceUsed`, no deny signed (11.1). Repair orders its writes within each entry only (12.2). The walk's default depth is 10000 hops, and a walk that the default cuts short reports `gate_integrity` `unchecked` with reason `policy_walk_truncated` (13.3, 13.4). No encoding, hash or signature preimage changed. | `mandate.json` gains the adoption case `adopt_scales_full` and the optional per-case `start` cell, and carries `policy-v1-draft.3`; every other file and every existing case is byte-identical. |
| `policy-v1-draft.4` | Walk truncation (human decision of 2026-10-08, which supersedes the explicit-depth exception of draft.3). `gate_integrity` after a walk is `ok` only when the walk reached genesis, the start of the counter's history; `violated` on a signed contradiction; `unchecked` otherwise. A walk cut short by the step cap is `unchecked` with reason `policy_walk_truncated` whether the cap is the default or set explicitly, and the retention horizon no longer ends the walk (13.3). The bound is renamed `MaxWalkSteps`, CLI `--max-walk-steps N`, default 10000 (was `PolicyDepth`, `--policy-depth`). The report gains `gate_integrity.walk`: the step cap, the steps taken, the walked seq range, the chain length and why the walk ended (13.4, 13.5). The reason is registered in the core enum (`v0-draft.30`). Outcome changes, only in `gate_integrity`: a walk cut by an explicit bound is `unchecked` (was `ok`), and a walk that stopped at the horizon before genesis now goes on, so it ends `ok` at genesis, `unchecked` or `violated` by what it finds (was `ok`); the `policy` check, the decision verdict and the exit code do not change. No encoding, hash or signature preimage changed. | `verify.json` carries `policy-v1-draft.4`: `config.policy_depth` is renamed `max_walk_steps`, every case whose walk ran gains `expect.gate_integrity.walk`, `pass_depth_1` now expects `gate_integrity` `unchecked` (`policy_walk_truncated`) with verdict `valid`, exit 0, and two cases are new: `walk_cap_reaches_genesis` (`ok`) and `walk_truncated_cap_2` (`unchecked`). Every record and every other file is byte-identical. |
| `policy-v1-draft.5` | Freeze revision with format v1 (task 031; human decisions of 2026-10-09). (1) Mandate keys 14 `sig_type` (absent = Ed25519; 2 Cosmos ADR-036; 3 EIP-712), 15 `principal_hrp`, 16 `fast_mode_max_delay` (blocks, `1..1000` when present; absent = fast mode off; a present 0 is refused, so "off" has one encoding), 17 `auditors` (private mode); `principal` and the signature size per `sig_type` (6.1). (2) Principal signature dispatch; ADR-036 signs the rendered text ending in the mandate hash (6.2). (3) Typed counter key for types 2 and 3; Ed25519 unchanged (6.2). (4) `T_H` becomes `T_ref` throughout (8, 10, 11, 13); `anchor_time` holds `T_ref`. (5) New stage 4p rule P15 and deny `ErrFastModeNotAllowed` (8.2, 10.2, 11.3, 12.3, 14). (6) PolicyVerdict keys 19 `private_hash` and 20 `prev_state_hash`, PrivatePart, the private envelope and archive kind 15 (9.5, 10, 12). (7) Rendered text: `principal:` line by scheme, moved after `gate:`; new `fast mode:` and `auditors:` lines; the first note names the reference time; one new note (7). (8) Verifier: `mandate_ref_mismatch`, the fast-mode consent and delay checks, private-mode outcomes (`policy_private`), `principal_scheme_unsupported`, L4 compares `sig_type` (13). Existing Ed25519 mandates without keys 14 to 17 keep their bytes, hashes, signatures and counter keys. | New: `private.json`; `spec/vectors/principal/adr036.json`, `eip712.json`. Regenerated: `render.json` (every text changes), `verify.json` (new outcomes), `mandate.json` (cases per scheme, keys 14 to 17, rejects), `archive.json` (kind 15, marker name), `api.json` (new code). `facts.json`, `state.json`, `engine.json` byte-identical; every existing case of the regenerated files keeps its bytes except `render.json` texts. |
| `policy-v1-draft.6` | Vectors of task 031 phase P2. No encoding, hash, preimage or limit changes. 6.1: the scheme rule is checked before the principal rule (the principal's size depends on the scheme; only multi-defect inputs see a difference), the signature size is a decoding check reported first, and the parenthesized labels are the vectors' `rule` field. Section 15: the vector field `t_h` carries `T_ref`; the ADR-036 rejects gain `d_without_empty_line` and `d_trailing_lf` (the exact `D` of 6.2: one empty line before the hash line, no LF after the hex); `spec/vectors/principal/ed25519.json` is listed. Vector conventions for the verifier files (section 15): a draft.5 case's `decision` is a v1 decision (`version`, `mandate_ref_hex`, `mode`, `h0`, `anchor_deadline`), and only such cases carry the report fields `policy.mode`, `policy.mandate_ref` and `policy.auditor_kid` in `expect`, so every draft.4 case keeps its bytes; `config.principal_keys` entries use the CLI forms of 13.1 (bare hex is Ed25519); optional `config.principal_schemes` and `config.auditor_keys`. | The files produced in P2 (`mandate.json`, `render.json`, `verify.json`, `archive.json`, `api.json`, `private.json`, `spec/vectors/principal/*`) carry `policy-v1-draft.6`; `facts.json`, `state.json`, `engine.json` stay byte-identical at `policy-v1-draft.1`. |
| `policy-v1-draft.7` | Post-audit change list of task 031 (human decisions of 2026-10-09). (1) Auditor kid derived from the key (`edicta/v1/auditor-kid`), Auditor key 3 `label` with its charset and value rules, auditor value-rule order with `auditor_kid` (`ErrAuditorKidMismatch`) and `auditor_label_duplicate` (6.1). (2) Mandate key 18 `state_salt`, present iff auditors; adoption refuses a changed salt (`state_salt_changed`), so a counter keeps one mode (6.3). (3) Render: auditor lines with the unverified label and the full 128-bit fingerprint, the label note, the general label rule and tool rule (7). (4) Private form of the PolicyVerdict: public part = hashes, links, outcome bit (denies: keys 1 to 7, 19 only); PrivatePart = the moved keys plus a per-verdict salt; merge; key 17 absent in private form (10.1, 10.2). (5) Blinded state hashes `state_hash_p` and blinded kind 15 keys for buckets and ClosedSets (9.1, 9.5). (6) Kind 9 private path segment, marker `ErrDenied` in private mode, a kind 15 PrivatePart for every private verdict, kind 15 plaintext kind 5 and cap 69,760 (12). (7) Verifier: without a key only step 1 and the hash checks run (facts and `anchor_time` no longer); with a key the merged verdict and blinded recomputations; `mode = 2` requires the policy check (13). (8) Residual leakage list 9.6; threat rows for private mode, fingerprints and wallet display (1); producer rule for a CSPRNG `mandate_id` and `state_salt` (6.1); EIP-712 range checks named (6.2). Outcome changes: private-mode outcomes without a key (facts and anchor-time mismatches are `policy_private`); every private-form encoding; kind 15 plaintext kind 5 accepted; a fast-mode decision without an allow record is `unchecked`. | Regenerated: `mandate.json` (m_private, draft.5 auditor rejects, new rejects, adoption case), `render.json` (`render_m_private`, new two-auditor case), `verify.json` (draft.5 v1 decisions salted, new case), `private.json` (rewritten), `archive.json` (kind 15 cases and rejects, private deny, reads, `ErrDenied`), `api.json` (alias example, private deny), `spec/vectors/principal/adr036.json`, `eip712.json` (new case and rejects). Changed existing rejects: `private_kind_5` replaced by `private_kind_6`, `private_over_cap` resized (archive.json). Every draft.4 case and record keeps its bytes; `facts.json`, `state.json`, `engine.json`, `principal/ed25519.json` byte-identical. |
| `policy-v1-draft.8` | Core-only rebase on `spec/decision-commitment-v1.md` `v1-draft.5` (human decisions of 2026-10-09, Rounds 5 and 6). (1) Section references are to the one core document; the version gate at stage 1 (`ErrVersionNotAccepted`) and the `/v0/` paths and alias are gone (11.1, 11.3). (2) Policy records are kinds of archive format 1 (12). (3) A PrivatePart that hashes to the gate-signed `private_hash` but breaks the presence rule is a gate fault, not `source_corrupt`: `gate_integrity` violated with reason `gate_signed_inconsistent_private_part`, and the policy is judged on the verifier's own derivation, so a deny there is a fail and the decision `invalid` (10.2, 13.2, 13.4, 13.5). (4) A counter keeps its mode; switching between public and private needs a new `mandate_id`, which restarts the counters; principal tools warn (6.3). Outcome changes: the two PrivatePart presence cases move from `source_corrupt` (exit 2) to `gate_integrity` violated (exit 5) or `policy` fail (exit 1); every archive record changes its format byte. | Regenerated: `verify.json`, `archive.json`, `api.json`, `private.json` (format 1 records, the alias example removed, new case `private_part_missing_facts_denies`). `mandate.json`, `render.json`, `facts.json`, `state.json`, `engine.json` and the principal files byte-identical. |
| `policy-v1-draft.9` | Pre-freeze re-audit fixes (task 031, `audit-2.md`), on core `v1-draft.6`. Later note, fix verification (`audit-2.md` F2, F5), no new revision: a private deny is archived only once per `(commitment_hash, reason)` through a gate-local dedup index, so a retry refused for the same reason writes no kind 9 or kind 15 (the marker write is repeated and is a no-op when present; G2 of the final check) (12.1, 12.2, 11.4), and residual leakage item 4 is the number of distinct deny reasons, not of attempts (9.6) (F2; new `private.json` entry `private_deny.same_reason_retry`, other entries byte-identical); 13.2 step 2 names steps 5 and 6 as the unchecked ones for an unverified `T_ref` (F5). (1) The `policy` check also runs, and is required, when the verified envelope has `mandate_ref` (13.1); a gate without a mandate refuses such a commitment (core 8.8 M0); threat rows (1). (2) Section 1 private-mode row no longer claims to hide the `seq` position or times. (3) Freeze sentence names this revision. (4) The private envelope text shows `version = 1`, as core B2 and the vectors already had (9.5, editorial). (5) A private deny is keyed `(commitment_hash, private_hash)`, path `policy-deny/<hex>/private-<private_hash hex>` (12.1), so later denies of one decision are kept; residual leakage item 4 notes the count. (6) A PrivatePart that breaks the presence rule: missing `extractor`, `anchor_time` and `eval_time` are derived by the verifier, and a missing `prev_state` makes steps 5 and 6 `unchecked` (`blocked`) (13.2). (7) The `--policy-depth` alias is gone (13.3). Outcome changes: an authorized decision with `mandate_ref` and no allow record is `unchecked` without `RequirePolicy`; an allow whose PrivatePart lacks the times is judged on the derived values (was `unchecked` `blocked`); every private-deny path. | `verify.json` (new case `mandate_ref_without_verdict`); `private.json` (`second_deny`, new cases `private_part_allow_missing_prev_state`, `private_part_allow_missing_times`, kind 9 paths); `archive.json` (the private-deny case path and the two read cases); every other file byte-identical. |
| `policy-v1.0` | v1.0: frozen; identical rules to `policy-v1-draft.9` plus later notes (dedup-hit marker rule in 12.1 and 12.2; the no-record clause row in 11.2). Revision labels of the policy vector files are `policy-v1.0`. | all policy vectors |

## 1. Threat model

| Mechanism | Defends against | Assumes |
|---|---|---|
| Principal signature over the mandate under the scheme its `sig_type` names (section 6) | An operator or gate inventing or loosening the rules; a mandate of one gate configured at another (`gate_id` inside the signed bytes); one signature read under two schemes | The principal's key is secret; the verifier pins the principal identities it trusts, typed by scheme (`PrincipalKeys`). `sig_type` is inside `mandate_hash`, so a key is read under exactly one scheme. Key roles never overlap, compared as `(sig_type, bytes)` (core invariant 7) |
| ADR-036 signs the rendered text ending in the mandate hash (sections 6.2, 7) | A wallet user signing rules they were never shown | The renderer is part of the trust base for `sig_type = 2`: two renderers MUST produce the same bytes (vectored); a verifier whose re-render differs rejects (fail closed). The hash line binds the text to the CBOR. Keplr display limits are `UNVERIFIED` |
| Fast-mode consent `fast_mode_max_delay` (sections 6.1, 8.2) | An operator enabling fast mode for a principal who never accepted the weaker publication guarantee, or with a longer anchoring delay than the principal accepted | The gate clamps the deadline to the bound (core 13.3); the verifier checks consent and the bound from the gate-signed Authorization and the principal-signed mandate (13.2) |
| Private mode: auditors in the mandate, encrypted mandate, state and decision content, public hash links (sections 9.5, 9.6, 10, 13; core 20.11) | Everyone reading, from a shared archive, the mandate's rules (limits, allowlists, auditor list) and the decision content: facts, deny reasons, amounts, state contents (sums, counts, open buckets), and on off-chain rails the action bytes. Not hidden: the `seq` position (derivable by walking the public links), `T_ref`, anchor heights and the other items of 9.6 | The action bytes are not public (core kind 17 form 2; the payload is encrypted to the auditors); the public `action_hash` is salted (core 5.1); state hashes and kind 15 keys are blinded with the counter's `state_salt` (9.1); HPKE and ChaCha20-Poly1305 as core 9.1; the auditor's private key is secret. Integrity comes from hashes the gate signs or the record keys, never from the AEAD (non-committing). Without the key, hash links and forks stay checkable, the rules and the facts do not. What stays visible is listed in 9.6 |
| Auditor key fingerprints in the rendered text (sections 6.1, 7) | An operator's tool swapping auditor keys under the principal's labels | The kid is derived from the key; the principal checks each full 128-bit fingerprint out of band (labels are untrusted); the principal CLI keeps an address book of auditor keys and warns loudly when a known label maps to another key (tooling rule, SHOULD) |
| Wallet display for `sig_type` absent or 3 (section 6.2) | Nothing beyond the hash: the wallet shows only the hash (EIP-712: `mandateHash`, `mandateId`, `version`, `gateId`) | Consent rests on the CLI render being exactly what was hashed (trusted tooling); for ADR-036 the wallet shows the rendered text itself |
| `mandate_id` and monotonic `version` (section 6.3) | Rolling a mandate back to a looser version; resetting the counters by re-signing the same rules | The gate's registry keeps the counter cell (never pruned); the verifier's walk checks versions along the chain. A new `mandate_id` is a fresh counter by the principal's explicit choice |
| Bounded scale map (section 6.3) | A counter whose cell no longer decodes, which would refuse every authorization until a new `mandate_id` | Adoption refuses a union above 1024 assets before it writes, so the gate never stores a cell its own decoder refuses. Only principal-signed versions grow the map, so reaching the bound is the principal's doing; it costs new assets on that counter, never safety |
| Immutable asset scale per counter (section 6.3, L4) | Fresh headroom from a rescaled asset: sums are kept per `(asset, scale)`, so a version that lists an asset at a new scale would count it from zero; an honest gate falsely reported as equivocating when a version rescales an asset the retained state does not hold | The gate refuses at adoption, from the scale map in the counter cell, not from the retained ledger (which forgets aged-out or never-used assets). The verifier applies the same rule to the mandates the walk reaches; a version adopted but never used is invisible to it, which only makes the gate stricter than what the verifier can see, never the reverse |
| Deterministic extractor, strict decoding (sections 4, 5) | One action byte string read as two different transfers by the gate and by the verifier; an action type the policy cannot read slipping through | Every reader uses the same extractor (same ID). No extractor, or bytes it cannot parse, is a deny. Extractors are code, reviewed per profile: a wrong extractor gives wrong facts everywhere at once, which shared vectors guard against |
| Rules on the reference time `T_ref` (section 8) | Gate clock manipulation moving spend between windows | `T_ref` is the header time at `payload_ref.height`, checked by the gate (K0 or K-fast) and by the verifier (header trust). For a pending reference that height is `h0`, inside the agent-signed commitment, so the gate cannot choose it, and its age is bounded by `MaxH0AgeBlocks` (core 11.1). Only rule P9 reads the gate clock; it is deny-only and marked gate-attested |
| Anchor-age cap P9 (section 8.3) | An old anchor or reference height (up to the Fibre retention) used to land spend in an old window; stale decisions | The gate clock (core: within 30 s of true time). The verifier cannot check it, so it is deny-only |
| Conservative hourly buckets (section 8) | Allowing more than `max` in any rolling window | Exact integer arithmetic; buckets partly inside a window count fully. Cost: a window of `h` hours may count up to `h + 1` hours, so the gate may deny early |
| Counter update in the nonce transaction (section 11.4) | Two authorizations both counted against the same headroom; a crash leaving a counted spend without an Authorization or the reverse | The registry is atomic and durable (core stage 12) |
| Signed verdict with `prev_state` and `new_state_hash` (section 10) | A gate that authorizes over its own limits and denies it later; a gate that silently drops, understates or rewrites spends | The gate key is secret and pinned. The verifier's fast check proves consistency with the state the gate signed; the walk and external evidence prove the chain has no contradiction. Allows the gate keeps outside every chain and every piece of evidence are not detected (section 13.6) |
| Walk to genesis with a step cap, `ok` only at genesis (section 13.3) | A verifier reading `ok` as "the gate's history is clean" when its older part was never read; a gate hiding an old fork behind a long history | `ok` needs every link from the target back to genesis checked. A cut walk is `unchecked` (`policy_walk_truncated`) with the walked range, never `ok`. A gate that pads its history only makes full walks `unchecked` or costlier, never `ok`. The cap bounds the verifier's memory; the archive must keep every allow record and ClosedSet back to genesis, or the walk is `unchecked` (`state_history_unavailable`) |
| Archive of closed buckets, sets, verdicts and successor index (section 12) | Losing the data a verifier needs | The archive is trusted for availability only: every record is bound to a hash or a signature. A withheld record gives `unchecked`, never `valid` or `invalid` |
| `ErrHistoryFull` (section 8.4) | Unbounded state | Capacity is independent of action frequency (768 buckets per counter); the bound that remains is per-bucket assets and integer widths |
| `mandate_ref` makes the check required (section 13.1; core 8.8 M0, 20.5) | An operator who drops the mandate from a gate while its agents still commit under it: the gate refuses (M0), and an Authorization from a gate that skipped M0 is never `valid` without an allow verdict, even when the auditor did not set `RequirePolicy` | The agent sets `mandate_ref` whenever it acts under a mandate; the verifier reads it from the agent-signed envelope |
| Nothing (open gap) | An operator who runs a gate without a mandate for agents that do not set `mandate_ref`, or edits its own executor to skip the Authorization | Core section 16: enforcement is the integrator's. An auditor relying on a mandate for such agents sets `RequirePolicy` (section 13.1) |
| Nothing (out of scope) | Cross-asset or fiat totals; whether the facts' recipient is a good counterparty | Needs an oracle; v1 has per-asset limits only |

## 2. Notation and tag namespace

Notation as core section 2: `||` concatenation, `H(x) = SHA-256(x)`, hex lower
case, times are Unix seconds, `tag(t) = uint8(len(t)) || ASCII(t)`.
`k(t) = floor(t / 3600)` is the bucket index of time `t`. `canon(x)` is the
canonical encoding of section 3.

### 2.1 Namespace (normative for every Edicta tag family)

- Form `edicta/<family>/v<N>/<name>`, ASCII `[a-z0-9/-]`, lower case, at most
  64 bytes, applied as `tag(t)`. The DecisionCommitment core keeps its
  `edicta/v<N>/<name>` form (`edicta/v1/...`). The family
  segment keeps policy tags apart from the DecisionCommitment tags.
- A tag is never reused, for any purpose. A wire change gets a new `v<N>`.
- Hash tags and signature tags are distinct, and no two tags of any family
  are equal.
- No key signs under the tags of two roles. The principal signs only its
  mandate: `M` under `mandate-sig` (Ed25519), the ADR-036 document of section
  6.2 (Cosmos) or the EIP-712 digest of section 6.2 (Ethereum). The gate key
  signs Authorizations, receipts and verdicts, each under its own tag.
  Auditor keys (private mode) are X25519 encryption keys and never sign.

### 2.2 Policy v1 tags

| Tag | ASCII (length, `tag(t)` first byte) | Use |
|---|---|---|
| `TagMandate` | `edicta/policy/v1/mandate` (24, `0x18`) | `mandate_hash = H(tag \|\| canon(Mandate))` |
| `TagMandateSig` | `edicta/policy/v1/mandate-sig` (28, `0x1c`) | principal signature over `tag \|\| mandate_hash` (61 bytes) |
| `TagVerdict` | `edicta/policy/v1/verdict` (24, `0x18`) | `verdict_hash = H(tag \|\| canon(PolicyVerdict))` |
| `TagVerdictSig` | `edicta/policy/v1/verdict-sig` (28, `0x1c`) | gate signature over `tag \|\| verdict_hash` (61 bytes) |
| `TagBucket` | `edicta/policy/v1/bucket` (23, `0x17`) | `bucket_hash = H(tag \|\| canon(Bucket))` |
| `TagClosed` | `edicta/policy/v1/closed` (23, `0x17`) | `closed_root = H(tag \|\| canon(ClosedSet))` |
| `TagState` | `edicta/policy/v1/state` (22, `0x16`) | `state_hash = H(tag \|\| canon(State))` |
| `TagCounter` | `edicta/policy/v1/counter` (24, `0x18`) | `counter_key`, section 6.2 (Ed25519: `H(tag \|\| principal \|\| mandate_id)`, 32 and 16 bytes; typed for the other schemes) |
| `TagSuccessor` | `edicta/policy/v1/successor` (26, `0x1a`) | `successor_key = H(tag \|\| uint8(len(gate_id)) \|\| gate_id \|\| counter_key \|\| state_hash)` (archive key, section 12) |
| `TagPrivatePart` | `edicta/policy/v1/private-part` (29, `0x1d`) | `private_hash = H(tag \|\| canon(PrivatePart))` (section 10.1) |
| `TagPrivateAEAD` | `edicta/policy/v1/private` (24, `0x18`) | AEAD `aad` of a private envelope (section 9.5); never hashed or signed |
| `TagPrivateDEK` | `edicta/policy/v1/private-dek` (28, `0x1c`) | HPKE `info` of the DEK wrap of a private envelope (section 9.5) |
| `TagStateBlind` | `edicta/policy/v1/state-blind` (28, `0x1c`) | `state_hash_p(S) = H(tag \|\| state_salt \|\| canon(S))` in private mode (section 9.1); hash only |
| `TagBlindKey` | `edicta/policy/v1/blind-key` (26, `0x1a`) | kind 15 key of a bucket or ClosedSet in private mode (section 9.5); hash only |

The auditor kid tag `edicta/v1/auditor-kid` (21, `0x15`) is registered in core
section 2 (`TagAuditorKid`): `kid = H(tag || pubkey)[0..16]` (6.1).

Threat note (tags). Length prefixes equal to core tags (23, 24) are harmless:
the ASCII differs from the first byte after the prefix on (`edicta/p` versus
`edicta/v`). The two signed messages are 61 bytes and start with `0x1c`, which
no core signed message does (`0x0d`, `0x15`, `0x1b`, and the record and
publish requests `0x18`, `0x19` signed directly). The tags of the superseded
`v0` core drafts are never accepted anywhere, so their prefixes need no
separate argument. A
verdict signature can never verify as an Authorization or receipt signature,
and a principal signature is over a different tag and a different hash.
`TagPrivatePart` has the length of the commitment tags (29) and
`TagPrivateAEAD`, `TagPrivateDEK` the lengths of `TagMandate`, `TagMandateSig`;
harmless for the same reason, and the two AEAD tags are never hashed or
signed. `TagStateBlind` has the length of `TagPrivateDEK` and `TagMandateSig`
(28), `TagBlindKey` that of `TagSuccessor` (26); the ASCII differs and neither
is part of a signed message.

## 3. Encoding profile and strict decoding

Every policy structure is canonical CBOR in the core section 3 profile with
these differences: arrays (major 4) are allowed where the schema says so, and
the limits below replace the commitment limits.

| Point | Rule |
|---|---|
| Data items | Major 0, 2, 3, 4, 5. No negative integers, tags, floats, simple values or indefinite lengths. Shortest heads. |
| Maps | uint keys in `1..23`, strictly ascending, no duplicates. Optional fields absent when unset, never `null` or empty. Required fields always present. |
| Integers | Every uint `<= 2^63 - 1`. |
| Amounts | `bstr`, unsigned big-endian, 1..32 bytes, minimal: the first byte is nonzero unless the length is 1 (zero is `h'00'`). Compared as integers. |
| Text | ASCII, charset per field. |
| Depth | At most 6 (the outermost item is depth 1). |
| Entries | At most 1024 per map or array before the schema applies its own limits. |
| `format` | Key 1 of every top-level structure, `= 1`. |

Size caps, checked before parsing:

| Structure | Cap (bytes) |
|---|---|
| `Facts` | 512 |
| `SignedMandate` | 16,384 |
| `SignedPolicyVerdict` | 16,384 |
| `Bucket`, `State`, `PrivatePart` | 16,384 |
| `ClosedSet` | 36,864 (767 refs of at most 46 bytes plus the header: 35,289) |
| private envelope (section 9.5) | 65,536 for plaintext kinds 1 to 4; 69,632 for plaintext kind 5 (action) |

Strict decoding, in this order; the first failure decides: (1) size cap;
(2) generic well-formedness as core section 6.2 with the limits above;
(3) schema, per map in encoded key order and depth first: unknown key, wrong
major type, length, charset; then missing required keys; (4) value rules of
the structure's section; (5) re-encoding gives the input bytes. Every failure
is the structure's sentinel (section 14): `ErrFactsInvalid`,
`ErrMandateInvalid`, `ErrVerdictInvalid` (verdicts and PrivateParts) or
`ErrStateInvalid` (Bucket, ClosedSet, State and ledgers). Vectors also give the first failing rule as an
informational `cause` (a core section 21 name or a value-rule label).
Implementations SHOULD report it; the sentinel is normative.

Structures are encoded only from validated values, so an encoder never
emits bytes the decoder refuses.

## 4. Facts

```
Facts = { 1: kind      tstr,   ; 1..32 bytes, [a-z][a-z0-9-]*; profiles define the values
          2: asset     tstr,   ; 1..128 bytes, 0x21..0x7e
          3: amount    bstr,   ; amount rule (section 3)
          4: scale     uint,   ; 0..255
          ? 5: recipient tstr }; 1..128 bytes, 0x21..0x7e
```

| Field | Rule and reasoning |
|---|---|
| `kind` | What the action does, named by the profile that defines the extractor (tia-transfer: `transfer`). The core checks only the grammar, so that the kind allowlist (P5) can tell profiles' kinds apart without a core change per kind. |
| `asset` | Domain-qualified by the profile so that one string names one asset on one chain (tia-transfer: `cosmos:<chain_id>/utia`). Compared bytewise. |
| `amount` | An integer in the asset's smallest unit. No floats anywhere. |
| `scale` | Decimal places of the unit, for display only. Compared for equality, never used to convert. |
| `recipient` | Domain-qualified (tia-transfer: `cosmos:<chain_id>:<bech32>`). Compared bytewise. Absent when the action has no single recipient; then no recipient allowlist matches. |

Validation failures and decoding failures are `ErrFactsInvalid`. Vectors:
`spec/vectors/policy/facts.json`.

## 5. Extractors

An extractor turns the exact action bytes of one action type into facts.

| Rule | Requirement |
|---|---|
| X1 Identity | Each extractor has an ID, 1..64 bytes, `[a-z0-9][a-z0-9./-]*`, of the form `<namespace>/<name>/v<N>` (for example `celestia/tia-transfer/v1`), and serves exactly one action type (core 4.3). Any change of its output for any input is a new ID. |
| X2 Pure | Deterministic and total: no I/O, no clock, no configuration other than constants fixed by the ID. Same bytes, same facts or the same refusal, in every implementation. |
| X3 Strict | It accepts only the canonical encoding of its action format, so one byte string is never read as two actions and two parsers never disagree (the profile's strict decoder). |
| X4 Refusal | An error, a recovered panic, or facts that fail section 4 validation are `ErrFactsInvalid`. A parse failure is a deny, never an allow and never an operational error. |
| X5 Registry | One extractor per action type; a duplicate type or ID is a configuration error. A type without an extractor is `ErrNoExtractor`. The gate and the verifier use the same registry contents. |
| X6 Coverage | A gate with a mandate refuses to start if any action type in its allowlist (rule C2) has no extractor. |
| X7 Vectors | Each extractor has vectors: action bytes, the facts (or `ErrFactsInvalid`), and the must-deny cases. |

The verdict records the extractor ID; a verifier uses the extractor with that
ID or reports `policy_no_extractor` (section 13).

Test extractor (vectors only, MUST NOT be registered in production):
`edicta/test-facts/v1` for type `application/vnd.edicta.test-facts.v1+cbor`.
Its action bytes are the canonical `Facts` encoding; it returns them after
strict decoding.

Production extractors are specified by their profile. The first is
`celestia/tia-transfer/v1`, bank-send profile section 2.4.

## 6. Mandate

### 6.1 Schema

```
Mandate = {
  1: format           uint,               ; 1
  2: principal        bstr,               ; 32 (sig_type absent), 33 (2) or 20 (3) bytes
  3: gate_id          tstr,               ; 1..64, core ID charset
  4: agents           [+ bstr .size 32],  ; 1..64, strictly ascending bytewise
  5: not_before       uint,               ; >= 1; compared with T_ref
  6: not_after        uint,               ; > not_before, <= 253402300799; compared with valid_until
  7: assets           [+ AssetRule],      ; 1..16, strictly ascending by asset
  ? 8: count_limits   [+ CountLimit],     ; 1..4, strictly ascending by hours
  9: mandate_id       bstr .size 16,
  10: version         uint,               ; >= 1
  ? 11: max_decision_age uint,            ; 1..86400 s; absent: MaxTTL(da)
  ? 12: min_spacing   uint,               ; 1..2678400 s
  ? 13: kinds         [+ tstr],           ; 1..8, Facts.kind grammar, strictly ascending; absent: any
  ? 14: sig_type      uint,               ; 2 adr036, 3 eip712; absent: Ed25519
  ? 15: principal_hrp tstr,               ; 1..16, [a-z0-9]; present iff sig_type = 2
  ? 16: fast_mode_max_delay uint,         ; 1..1000 blocks; absent: fast mode not allowed
  ? 17: auditors      [+ Auditor],        ; 1..16, strictly ascending by kid; present: private mode
  ? 18: state_salt    bstr .size 32       ; present iff auditors; per counter, never rendered
}
AssetRule = { 1: asset tstr,              ; as Facts.asset
              2: scale uint,              ; 0..255
              ? 3: per_action_max bstr,   ; amount rule, value >= 1
              ? 4: periods [+ PeriodLimit],  ; 1..4, strictly ascending by hours
              ? 5: recipients [+ tstr] }  ; 1..256, as Facts.recipient, strictly ascending bytewise; absent: any
            ; at least one of keys 3 and 4
PeriodLimit = { 1: hours uint,            ; 1..744
                2: max bstr }             ; amount rule, value >= 1
CountLimit  = { 1: hours uint,            ; 1..744
                2: max_count uint }       ; 1..2^32
Auditor     = { 1: kid bstr .size 16,     ; SHA-256(tag("edicta/v1/auditor-kid") || pubkey)[0..16]
                2: pubkey bstr .size 32,  ; X25519 public key, RFC 7748 encoding
                3: label tstr }           ; 1..64 bytes of 0x20..0x7e without '"' (0x22) and '\' (0x5c)
SignedMandate = { 1: mandate Mandate, 2: signature bstr }   ; 64 bytes (sig_type absent or 2), 65 bytes (3)
```

Value rules (`ErrMandateInvalid`), with the rule label in parentheses (the
`rule` field of a draft.5 or later reject vector; the vector's `cause` keeps
the decoding-style cause of earlier drafts, for example `ErrIntRange`):

| Rule | Statement |
|---|---|
| Scheme (`sig_type`) | Absent, `2` or `3`. A present `1` is refused: Ed25519 has one encoding, the absent key, so every existing mandate keeps its bytes. Values `0` and `4..2^63-1` are refused (reserved: BIP-322, Solana off-chain messages, WebAuthn are candidates). |
| Principal by scheme (`principal`) | `sig_type` absent: 32 bytes passing core G0. `sig_type = 2`: 33 bytes, first byte `0x02` or `0x03`, decoding to a point on secp256k1. `sig_type = 3`: 20 bytes. |
| HRP (`principal_hrp`) | Present iff `sig_type = 2`; 1..16 bytes of `[a-z0-9]`. |
| Signature size (`signature`) | 64 bytes for `sig_type` absent or 2, 65 bytes for 3. Checked at decoding, before the signature is verified. |
| Agents (`agents`) | Every agent key passes core G0; `principal` is not in `agents` (key roles, core invariant 7; a 20- or 33-byte principal cannot be). |
| Fast mode (`fast_mode_max_delay`) | `1..1000` when present. A present `0` is refused, so "fast mode not allowed" has one encoding, the absent key (two encodings of one meaning would give two `mandate_hash` values for the same consent). A gate with `FastMode` on refuses to start with, or to adopt, a mandate whose value is below its `MinFastSlackBlocks + 1` (core 8.9, cause `fast_delay_below_slack`): such a bound would refuse every pending reference. Principal tools SHOULD warn below 4 (the default slack plus one). |
| Auditors (`auditors`, `auditor_label`, `auditor_kid`, `auditor_label_duplicate`) | 1..16 entries (decoding); `kid` exactly 16 bytes and `label` 1..64 bytes of its charset (decoding). Then, in order: for each entry in mandate order, the label has no leading or trailing space (`auditor_label`) and `kid == SHA-256(tag("edicta/v1/auditor-kid") \|\| pubkey)[0..16]` (`auditor_kid`; Go sentinel `policy.ErrAuditorKidMismatch`, wrapping `ErrMandateInvalid`); the entries are strictly ascending by `kid` bytewise (`auditors`); the labels are pairwise distinct (`auditor_label_duplicate`); each `pubkey` is not a low-order X25519 point (`auditors`): `X25519(s, pubkey)` is not the all-zero string, with `s` the 32 bytes `0x01` (clamped, a multiple of 8, so exactly the low-order points give zero; the all-zero shared secret rule of core 9.1). Gate start: `gate.ErrInvalidConfig` wrapping the failure; verifier: `source_corrupt`, as any mandate decode failure. |
| State salt (`state_salt`) | Present iff `auditors` is present (missing: `ErrMissingField`; on a public mandate: `ErrUnknownKey`); exactly 32 bytes (decoding). |
| Validity (`not_after`) | `not_after <= 253402300799` (9999-12-31T23:59:59Z, so the rendered text is RFC 3339). |

Producer rules (no byte change): `mandate_id` and `state_salt` MUST come from a
CSPRNG when `auditors` is present. Threat note: `mandate_hash` is public in
every private verdict; with a low-entropy `mandate_id` a dictionary search
over plausible limits could test candidate mandates against it. The 256-bit
`state_salt` inside `mandate_hash` closes that too.

`kinds` (P5) lists the kinds the agents may perform; together with the asset
(P6) and recipient (P7) allowlists it is the allowlist part of the catalog.
The order of the value rules above is the order in which an implementation
reports the first failing one (vectors carry the rule). The scheme comes
first because the principal and signature sizes depend on it. The signature
size is enforced while decoding the SignedMandate (key 1, and so `sig_type`,
precedes key 2), so it is reported before every value rule; at decoding, 65
bytes are required iff `sig_type = 3` and 64 otherwise (a refused `sig_type`
then fails the scheme rule). The rules of
earlier drafts not listed here (format, `agents` order and size, asset,
period, count, kind and time rules) keep their draft.4 checks and run after
the principal and HRP rules, in the order of the reference implementation
`spec/vectors/check/policy_v1.py`; every draft.4 reject vector has a single
defect, so its outcome does not depend on that order.

### 6.2 Hash, principal signature and counter key

```
mandate_hash = H(tag("edicta/policy/v1/mandate") || canon(Mandate))
M            = tag("edicta/policy/v1/mandate-sig") || mandate_hash        ; 61 bytes
```

`mandate_hash` covers keys 14 to 18. A mandate without them has exactly the
bytes and hash it had in earlier drafts. `mandate_hash` is never a field of
the mandate.

Principal signature, by `sig_type` (byte-exact definitions:
`docs/design/v1-pack/12-principal-signatures.md`, sections 2.3 and 3.3,
reproduced here as the normative text):

| `sig_type` | Signed data | Verification |
|---|---|---|
| absent (Ed25519) | `signature = Ed25519(principal_priv, M)` | core G2 (`S < L`), cofactorless G1, on the G0-checked `principal` |
| 2 (Cosmos ADR-036) | `signature = r \|\| s` = ECDSA-secp256k1 over `SHA-256(signdoc)`, low-s | `r, s` in `[1, n-1]`; `s <= n/2`; the verifier rebuilds `D` and `signdoc` from the mandate (never from the request) and verifies with `principal` |
| 3 (EIP-712) | `signature = r \|\| s \|\| v` over `digest`, `v` in `{27, 28}`, low-s | `r, s` in `[1, n-1]`, `s <= n/2`, `v` in `{27, 28}`, all checked before recovery; recover the public key from `(digest, r, s, v - 27)`; `keccak256(uncompressed key without 0x04)[12..32] == principal`, compared in constant time |

ADR-036 sign document:

```
D       = Render(mandate) || "\n" || "mandate hash: " || hex(mandate_hash)
signdoc = {"account_number":"0","chain_id":"","fee":{"amount":[],"gas":"0"},"memo":"",
           "msgs":[{"type":"sign/MsgSignData","value":{"data":"<B64>","signer":"<SIGNER>"}}],
           "sequence":"0"}
B64     = standard base64 with padding (RFC 4648 section 4) of D
SIGNER  = bech32(principal_hrp, RIPEMD-160(SHA-256(principal)))        ; BIP-173 bech32, not bech32m
```

`Render(mandate)` (section 7) ends with an LF, so `D` contains one empty line
before its last line, `mandate hash: <64 hex>`, and `D` itself has no
trailing LF. `signdoc` is the Cosmos SDK legacy amino JSON form: keys sorted
at every level, no whitespace, `<`, `>`, `&` escaped as `\u003c`, `\u003e`,
`\u0026`; it has exactly two variable substrings, `<B64>` and `<SIGNER>`.
The wallet shows `D`, so the principal reads the rules and the hash it
signs. The verifier re-renders deterministically, builds `D`, and verifies
the signature over the rebuilt `signdoc`; a signature over any other text
(one byte differs) does not verify and is `ErrMandateSignature`.
`UNVERIFIED`: Keplr `signArbitrary` at a pinned version accepts a multi-line
`D` of several KB, displays newlines unchanged, and produces exactly this
`signdoc` (live check of task 032). If it does not, the human decides; the
text is not replaced by `M` without that decision.

EIP-712 digest:

```
domain_separator = keccak256( keccak256("EIP712Domain(string name,string version)")
                              || keccak256("Edicta Mandate") || keccak256("1") )
type_hash        = keccak256("Mandate(bytes32 mandateHash,bytes16 mandateId,uint64 version,string gateId)")
hash_struct      = keccak256( type_hash || mandate_hash || mandate_id || 0x00 * 16
                              || uint256_be(version) || keccak256(gate_id) )
digest           = keccak256( 0x19 || 0x01 || domain_separator || hash_struct )
```

`keccak256` is Keccak-256 as Ethereum uses it, not SHA3-256. The domain has
no `chainId`, `verifyingContract` or `salt`: a mandate binds a gate, not a
chain. `UNVERIFIED`: MetaMask `eth_signTypedData_v4` at a pinned version
accepts this domain (live check of task 032).

Verification order: strict decoding with the value rules (`ErrMandateInvalid`),
then the signature (`ErrMandateSignature` for a failure of the signature
alone, including a high-s value, `v` outside `{27, 28}`, a recovered address
that differs, or an ADR-036 signature over another text). A verifier build
without a scheme reports `principal_scheme_unsupported` (13.2); a gate
without it refuses to start (`ErrInvalidConfig`).

Counter key:

```
sig_type absent:  counter_key = H(tag("edicta/policy/v1/counter") || principal || mandate_id)
sig_type 2 or 3:  counter_key = H(tag("edicta/policy/v1/counter") || uint8(sig_type)
                                  || uint8(len(principal)) || principal || mandate_id)
```

After the tag the preimage is 48 bytes for Ed25519, 51 for type 2 and 38 for
type 3, so the forms never collide and every existing counter key stands. A
principal who re-signs the same `mandate_id` under another scheme starts a
new counter: another scheme is another principal identity.

Threat notes:
- Low-s is required for both secp256k1 schemes: the Cosmos SDK and Ethereum
  nodes refuse high-s, and accepting both would give two encodings of one
  signature.
- The same raw secp256k1 key under both schemes gives two mandates with
  different hashes and counters; two identities by the principal's choice.
- A different valid signature over the same document gives another
  SignedMandate with the same `mandate_hash` (the hash does not cover the
  signature), as for Ed25519.

### 6.3 Counter, versions and adoption

- **Counter.** A counter belongs to `(sig_type, principal, mandate_id)` at
  one gate and is stored in the gate's registry under `counter_key` (6.2).
  All agents of a mandate share it.
- **Versions.** A new `version` of the same `mandate_id` continues the
  counter: its state, chain head and history. A version lower than the
  current one is refused. The same version with another `mandate_hash` is
  refused. A new `mandate_id` starts a fresh counter at genesis; that is the
  principal's explicit choice.
- **Asset scale is immutable per counter.** Once any adopted version of a
  counter lists an asset, every later version that lists it MUST give it the
  same scale. It does not matter whether the asset was ever spent, has aged
  out of the retained state, or was dropped by an intermediate version: the
  scale is fixed for the life of the counter. To change a scale the principal
  starts a new `mandate_id`.
- **Scale map.** The counter cell holds `scales`, a map from asset to scale:
  the union of the AssetRules of every version adopted on this counter.
  Genesis sets it from the first mandate; a version switch checks the new
  mandate against it and then adds the new mandate's assets. Entries are
  never removed. It is gate-local registry data (11.4): it has no wire
  encoding, is not part of State, and does not enter `state_hash`, a verdict
  or any archive record. Rationale: the verifier derives the same constraint
  from the principal-signed mandates on the chain (L4), so a hash commitment
  to the map would add bytes to every verdict and prove nothing more; and
  keeping it out of State leaves every state and verdict encoding unchanged.
  The map grows only with principal-signed versions (at most 16 new assets
  per version).
- **Scale map bound.** `scales` holds at most 1024 entries. That is the
  per-map entry limit of the strict decoder (section 3), so every map the
  gate may write is one its decoder accepts. It is far above what one
  version uses (at most 16 assets per mandate; a bucket holds at most 64
  `(asset, scale)` pairs, P14) and allows about 64 versions that each bring
  16 new assets. Assets dropped by later versions still count, because
  entries are never removed. A version whose union would exceed 1024 is
  refused (cause `scales_full`); versions that list only known assets can
  still be adopted. A principal who needs more assets starts a new
  `mandate_id`.
- **Adoption at gate start.** Decode and verify the mandate; its `gate_id`
  MUST equal the gate's. The principal key MUST NOT equal the gate key, an
  executor key or an allowlisted agent key (`commitment.ErrKeyRole`); keys
  are compared as `(sig_type, bytes)`, so only an Ed25519 principal can
  collide. The gate MUST support the mandate's scheme. In private mode the
  gate encrypts the SignedMandate to the auditors and writes kind 15 instead
  of kind 7 (12.2). Every
  action type the gate allows MUST have an extractor (X6). Then read the cell
  under `counter_key`:

  | Stored cell | Action |
  |---|---|
  | absent | write genesis (section 9.4) with this mandate; `scales` from its AssetRules |
  | version above the configured one | refuse to start |
  | same version, different `mandate_hash` | refuse to start |
  | same version, same hash | use it |
  | version below the configured one | the configured mandate's `state_salt` (absent for a public mandate) differs from the one the cell keeps: refuse to start (cause `state_salt_changed`); check every AssetRule against `scales`: an asset in the map with another scale refuses to start (cause `scale`); then a union of more than 1024 entries refuses to start (cause `scales_full`); otherwise switch the cell to this mandate and set `scales` to the union, in one compare-and-swap, keeping head, state and `state_salt` |

  Any refusal is a configuration error (`gate.ErrInvalidConfig`), decided
  before anything is written, so a refusal leaves the cell unchanged and the
  gate does not run (fail-closed). The causes are distinct so that an
  operator can tell them apart: `version` (the stored version is above the
  configured one), `same_version_other_hash`, `state_salt_changed`, `scale`
  and `scales_full`. The cell keeps the `state_salt` of genesis: a counter's
  public chain links cross versions (`prev_state_hash(n) =
  new_state_hash(n-1)`), so every version must blind with one salt. A counter
  therefore cannot switch between public and private mode; a principal who
  wants that starts a new `mandate_id`. A new `mandate_id` starts every
  counter of the mandate at zero, so switching mode in the middle of a period
  forgets what was already spent in it; that is the principal's explicit
  choice. Tool rule (normative for Edicta tools): a principal tool that signs
  a mandate whose `mandate_id` is new, or whose `auditors` presence differs
  from the version it replaces, MUST warn before signing that the counters
  restart at zero and the period's spent amounts are not carried over.
  Genesis cannot reach the bound (at most 16 assets). Every later
  state update (stage 12) compares the stored mandate hash too, so a lower
  version can never be adopted by a concurrent writer.

Vectors: `spec/vectors/policy/mandate.json` (encodings, hashes, signatures,
counter keys, rejects, and `adoption`: sequences of signed mandates applied to
one cell, absent or given as a `start` cell, with each step's action, refusal
cause, version, `scales` and, for a private counter, `state_salt` after it).

## 7. Rendered text (normative)

`Render(mandate)` is the text a wallet or CLI shows before the principal
signs. Two implementations MUST render the same bytes. For `sig_type`
absent and `3` the signature covers the CBOR (through `M` or the EIP-712
hash) and the text is what the CLI shows; for `sig_type = 2` the text itself,
followed by the hash line, is what the wallet signs (6.2), so a renderer
difference makes a valid mandate unverifiable (fail closed).

Format: ASCII; LF line ends; no trailing spaces; one final LF; the line order
below; lists in mandate order; hex lower case; times RFC 3339 UTC with
seconds (`2026-10-07T00:00:00Z`). Amounts exact: the integer value in
decimal, with a `.` inserted so that exactly `scale` digits follow it (left
padded with zeros, at least one digit before the `.`); no `.` when `scale =
0`; no rounding, no separators. Example: `1500000` at scale 6 is `1.500000`;
`5` at scale 6 is `0.000005`.

```
Edicta mandate v1
mandate_id: <hex16>
version: <n>
gate: <gate_id>
principal: ed25519 <hex32>                                | principal: cosmos <bech32 address> (adr-036)   | principal: ethereum 0x<hex20> (eip-712)
fast mode: not allowed                                    | fast mode: allowed, anchor at most <n> blocks after the reference height
auditors: none (public mandate)                           | auditors: <k> (private mandate)   then one auditor line per auditor (below)
valid: reference time from <not_before> ; decision valid_until up to <not_after>
max decision age: <n>s                                    | max decision age: default (MaxTTL of the payload's DA)
min spacing: <n>s                                         | min spacing: none
agents (<k>, shared counter):
  - <hex32>                                               (one line per agent)
kinds: any                                                | kinds: <kind>, <kind>   (mandate order, ", " between)
asset <asset> (scale <s>):                                (one block per asset)
  per action: max <amount>                                | per action: no limit
  period: max <amount> per rolling <h>h (may count up to <h+1>h)   (one line per period; "period: no limit" if none)
  recipients: any                                         | recipients:  then "    - <recipient>" per entry
count: max <n> actions per rolling <h>h (may count up to <h+1>h)   (one line per count limit) | count: no limit
notes:
  - Limits are measured on the reference time of each decision (block time at its payload reference height), not on execution time.
  - Limits use hourly buckets; a bucket partly inside a window counts fully, so a limit may cover up to one extra hour (a "per 1h" limit may span up to 2h): the gate may deny early, never allow extra.
  - Limits count authorizations, not executions.
  - Counters continue across versions of this mandate_id; a new mandate_id starts from zero.
  - In fast mode the gate may authorize before the payload is anchored on L1; the anchor must land within the stated number of blocks or the decision is invalid.
  - Labels are not verified; check each key fingerprint or address out of band.     (only when a label is rendered)
```

Auditor line, exactly:

```
  - Auditor "<label>" (label not verified) - key fingerprint: <g1> <g2> <g3> <g4> <g5> <g6> <g7> <g8>
```

`<g1>..<g8>` are the 16 kid bytes as 32 lower-case hex digits in 8 groups of
4, single spaces: the full 128-bit kid, always. One line per auditor, mandate
order.

The text columns after `|` are the alternative of the same line. The
`principal:` line follows `sig_type`: the Ed25519 key in hex; for ADR-036 the
bech32 address `SIGNER` of 6.2 (the identity the wallet shows); for EIP-712
the 20-byte address, `0x` and lower-case hex (no EIP-55 checksum). The
`fast mode:` line is `not allowed` when key 16 is absent, and `<n>` is its
value otherwise. The `auditors:` line counts the auditors, followed by one
auditor line each. Without an asset rule's key 5 the text MUST say
`recipients: any`, and without the mandate's key 13 `kinds: any`. The notes
are fixed text; the fifth note is always present, the sixth exactly when at
least one label is rendered (today: when `auditors` is present). The
`state_salt` (key 18) is a secret and is never rendered; `mandate_hash`
covers it.

Label rule (human decision of 2026-10-09, not tied to private mode): every
label rendered next to a key or an address carries `(label not verified)`
and, on the same line, the full identifier (key hex, address) or the full
fingerprint. It covers auditors now and any future labelled agent, recipient
or principal, in every mode. Tool rule (normative for Edicta tools): the
verifier report (text and JSON), the principal CLI and gate logs that print a
label print the marker and the full fingerprint beside it. Threat note:
labels are untrusted text chosen by whoever built the mandate; the
out-of-band fingerprint check is the trust step. Vectors: `spec/vectors/policy/render.json` (cases show the
three principal lines, both fast-mode lines, both auditor lines with the
fingerprint lines and the label note, and two labels that differ in one
character).

## 8. Rule engine

### 8.1 Definitions

- `T_ref`: the reference time, the header time at `payload_ref.height`
  (core section 12.2): the anchor block's time `T_H` for an included
  reference (core K0), the time of block `h0` for a pending one (K-fast).
  It replaces `T_H` of earlier drafts everywhere; the state field `last_th`
  keeps its name and holds the `T_ref` of the last allow.
- Ledger: the state (section 9) plus the contents of its closed buckets.
- `seq`, `last_t`, `last_th`, `open`: fields of the state.
- Attribution time `T_eff = max(T_ref, last_t)` (`T_ref` when `seq = 0`).
- Window of `h` hours at time `t`: the buckets with index from
  `lo = k(t - 3600*h + 1)` (`lo = 0` when `t < 3600*h`) to `k(t)`. That is
  `h + 1` buckets, or `h` when `t mod 3600 = 3599`. A bucket partly inside the
  window counts fully: conservative and deterministic.
- `S(h, a, s)`: the sum of `sum(a, s)` over the buckets of the window at
  `T_eff`, open bucket included; `N(h)`: the sum of their `count`. Exact
  integers (at most 745 terms below `2^256`).
- Retention: the open bucket plus closed buckets with index
  `>= k(T_eff) - 767`, at most 767 of them. The longest window spans 745
  buckets, so retention covers it.

### 8.2 Admission, stage 4p (P1 to P8)

Inputs: the mandate, the extractor registry and the verified decision
(`agent_pubkey`, `action.type`, the action bytes that passed stage A,
`valid_until`, the reference form `payload_ref.anchor`). First failure wins,
in the order P1, P15, P2 to P8 (rule ids are labels and never reused).

| Rule | Check | Deny |
|---|---|---|
| P1 | `agent_pubkey` is in `agents` | `ErrAgentNotCovered` |
| P15 | the commitment's reference is included, or the mandate has `fast_mode_max_delay` (key 16) | `ErrFastModeNotAllowed` |
| P2 | an extractor exists for `action.type` | `ErrNoExtractor` |
| P3 | the extractor returns valid facts (X4) | `ErrFactsInvalid` |
| P4 | `valid_until <= not_after` | `ErrOutsideMandate` |
| P5 | the mandate has no `kinds`, or `facts.kind` is listed | `ErrKindNotAllowed` |
| P6 | `facts.asset` has an AssetRule and `facts.scale` equals its scale | `ErrAssetNotAllowed` |
| P7 | the rule has no `recipients`, or `facts.recipient` is present and listed | `ErrRecipientNotAllowed` |
| P8 | the rule has no `per_action_max`, or `amount <= per_action_max` | `ErrAmountAboveMax` |

Rule catalog v1 (human decision of 2026-10-07): per-action max (P8), rolling
sum max (P12), rolling count max (P13), `min_spacing` (P11), allowlists of
kind (P5), asset (P6) and recipient (P7), mandate validity `not_before` (P10)
and `not_after` (P4), and `max_decision_age` (P9). Every rule except P9 is a
pure function of the facts, `T_ref`, the counter state and fields of the
verified commitment; P9 is the one gate-clock rule and is deny-only. P4
compares `not_after` with the signed `valid_until` rather than with `T_ref`,
because it bounds when the action may still run; it implies `T_ref <
not_after` (core K1 and T2 give `T_ref <= issued_at + skew_s < valid_until`).
Format v1 adds the fast-mode consent P15: a pending reference (core section 11) is admitted only
under a mandate that states `fast_mode_max_delay`. The bound itself is
applied by the gate when it computes the anchor deadline (core 13.3:
`anchor_deadline - h0 <= fast_mode_max_delay`), not by a deny rule. After
the freeze, new rules need policy v2.

Threat note (P15). Fast mode weakens "anchored before the action" to
"availability evidence before the action, anchored by the deadline". The
principal, not the operator, decides whether its counter accepts that, and
for how many blocks. P15 is deny-only and reads only signed data (the
commitment's reference form and the mandate).

### 8.3 Reference age, stage 10p (P9)

`age = authorized_at - T_ref` (0 if negative), with `authorized_at` the gate
clock of core stage 10. If `age > max_decision_age` the deny is
`ErrDecisionAge`, and its verdict carries `gate_clock = 1`. Absent
`max_decision_age` means `MaxTTL(payload_ref.da)` (core 12.1) with the gate's
parameters at that time.

Reasoning. Without P9 a decision may be authorized up to the Fibre retention
(about 4 h) after its anchor, which lets an old anchor land spend in an old
window and makes short windows dishonest. P9 is deny-only and gate-attested:
the verifier cannot check the gate clock, so P9 can only refuse.

### 8.4 Evaluation, stage 10p (P10 to P14)

`Evaluate(mandate, ledger, facts, T_ref)`; first failure wins:

| Rule | Check | Deny |
|---|---|---|
| P10 | `T_ref >= not_before` | `ErrOutsideMandate` |
| P11 | `min_spacing` absent, or `seq = 0`, or `T_ref >= last_th + min_spacing` (saturating) | `ErrMinSpacing` |
| | Compute `T_eff`. If `seq >= 1` and `k(T_eff) > open.index`, roll over: the open bucket joins the closed set, closed buckets with `index < k(T_eff) - 767` are dropped, and the open bucket becomes empty at `k(T_eff)`. If `seq = 0` the open bucket is empty at `k(T_eff)`. | |
| P12 | for each `PeriodLimit(h, max)` of the asset's rule: `S(h, asset, scale) + amount <= max` (equality allowed) | `ErrPeriodLimit` |
| P13 | for each `CountLimit(h, n)`: `N(h) + 1 <= n` | `ErrCountLimit` |
| P14 | capacity, in this order: the open bucket's sum for `(asset, scale)` stays `<= 2^256 - 1` (reachable only for an asset without a period limit); its `count` stays `<= 2^63 - 1`; it holds at most 64 `(asset, scale)` pairs; `seq + 1 <= 2^63 - 1` | `ErrHistoryFull` |

On allow, `Apply(ledger, delta)` with `delta = (asset, scale, amount, T_ref)`:
roll over as above, add `amount` to the open bucket's sum for `(asset, scale)`
(a new pair is inserted in order), `count + 1`, `seq + 1`, `last_t = T_eff`,
`last_th = T_ref`. `Apply` checks no rule; it is the transition the verifier
replays.

Denies change nothing: a rollover found during a deny is not stored.
`ErrHistoryFull` is a capacity refusal, not a limit; it has its own code so
that operators can tell them apart.

### 8.5 Properties

- **Rolling bound.** For every allowed sequence of one counter and every
  `PeriodLimit(h, max)` of asset `a`: every interval `(u - 3600h, u]` on the
  attribution-time axis holds allowed amounts of `a` summing to at most
  `max`. Sketch: attribution times never decrease along allows. Let `x` be the
  last allow attributed inside the interval, at `t_x <= u`. Every earlier allow
  `y` attributed inside it has `t_x - 3600h < u - 3600h < t_y <= t_x`, so `y` is
  in a bucket of `x`'s window, and P12 at `x` bounded the total. The same holds
  for counts. With `min_spacing` set, allowed anchor times strictly increase,
  so `T_eff = T_ref` and the bound holds on the anchor time itself. Without it,
  an anchor older than an earlier allowed one is counted at the later time
  (clamping); it is never uncounted.
- **No boundary burst.** v1 has rolling windows only; calendar periods are
  not defined.
- **Lag.** An Authorization lags its anchor by at most `max_decision_age`.
- **What counts.** Limits count authorizations, not executions.

Vectors: `spec/vectors/policy/engine.json`.

## 9. State and hashes

### 9.1 Structures

```
Bucket    = { 1: format uint,                          ; 1
              2: index  uint,                          ; k(t) of its hour
              3: count  uint,                          ; >= 1
              4: sums   [+ Sum] }                      ; 1..64, strictly ascending by (asset bytewise, scale)
Sum       = { 1: asset tstr, 2: scale uint, 3: sum bstr }   ; as Facts; sum by the amount rule
ClosedSet = { 1: format uint,                          ; 1
              2: buckets [* ClosedRef] }               ; 0..767, strictly ascending by index
ClosedRef = { 1: index uint, 2: hash bstr .size 32 }   ; hash = bucket_hash
State     = { 1: format uint,                          ; 1
              2: seq uint,
              ? 3: last_t uint, ? 4: last_th uint,     ; present iff seq >= 1
              5: closed_root bstr .size 32,
              ? 6: open Bucket }                       ; present iff seq >= 1
bucket_hash = H(tag("edicta/policy/v1/bucket") || canon(Bucket))
closed_root = H(tag("edicta/policy/v1/closed") || canon(ClosedSet))
state_hash  = H(tag("edicta/policy/v1/state")  || canon(State))
```

`state_hash` covers every closed bucket through `closed_root` and the open
bucket inline: changing any sum, count or index anywhere changes it.

Blinded state hash (private mode only, `state_salt` = key 18 of the mandate):

```
state_hash_p(S) = state_hash(Genesis)                                                if S = Genesis
                = H( tag("edicta/policy/v1/state-blind") || state_salt || canon(S) )  otherwise
```

Where it applies, in private mode: verdict keys 14 and 20 (private form), the
registry cell head, the `successor_key` input (the value of key 20), the
chain rules of 10.3, and the verifier's recomputations with a key (13.2 step
6, walk L5) with the salt of the opened mandate. Walk L2 and the hash-form
fork rule compare bytes and need no salt. `bucket_hash` and `closed_root`
inside a State are unchanged. Public mode uses `state_hash` everywhere, as
before. Genesis keeps the public constant: its hash says only "first allow of
the counter", which the absence of keys 15 and 16 already says, and it keeps
the presence rule of 10.2 and the walk's genesis stop decidable without a
key. Threat note: unblinded, a public state hash would be a dictionary oracle
for amounts and limits (a state holds low-entropy sums and times); a gate that
blinded with another salt than its mandate's is caught by the verifier with a
key (`state_hash_p(prev_state) != key 20`, `gate_equivocation`).

### 9.2 Ledger validity (`ErrStateInvalid`)

A ledger is a State, the ClosedSet that hashes to its `closed_root`, and the
closed buckets the evaluation reads, each hashing to its ref. It is valid iff:
- `seq = 0`: the State equals genesis (9.4) exactly.
- `seq >= 1`: `last_th <= last_t`; `open.index = k(last_t)`; every ref index
  is `< open.index` and `>= open.index - 767` (when that is positive); each
  supplied bucket's `index` equals its ref's.

Only allowed actions create buckets, so every bucket has `count >= 1` and
the closed set lists only hours that had allows.

### 9.3 Archive cadence

A closed bucket is immutable and is archived once, when its hour closes (the
allow that rolls it over). The ClosedSet changes only at a rollover and is
archived once per rollover. A verdict carries the open bucket inline. Storage
grows with the number of allows times a few hundred bytes, never with history
size per allow.

### 9.4 Genesis

`Genesis = {1: 1, 2: 0, 5: closed_root({1: 1, 2: []})}`. Its bytes and hash are
vectored constants (`spec/vectors/policy/state.json`), and the empty ClosedSet
needs no archive read.

### 9.5 Private envelope (private mode)

A mandate with `auditors` (key 17) puts its counter in private mode: the
SignedMandate, every closed Bucket, every ClosedSet, the PrivatePart of every
verdict (10.1) and, through the core, the action bytes and salt of every
decision (core kind 17 form 2) are archived only encrypted to the
auditors (kind 15, section 12.1). Public stay the verdict's hashes, chain
links and outcome bit (10.2). The envelope is the core 9.1 blob layout, byte
for byte, with the policy tags:

```
DEK, aead_nonce, salt from a CSPRNG (one DEK per envelope, never reused)
ciphertext    = ChaCha20-Poly1305-Seal(DEK, aead_nonce, aad = tag("edicta/policy/v1/private"), salt || plaintext)
for each auditor i, in mandate order:
  enc_i, ctx_i  = SetupBaseS(pubkey_i, info = tag("edicta/policy/v1/private-dek"))
  wrapped_dek_i = ctx_i.Seal(aad = uint8(len(kid_i)) || kid_i, DEK)
envelope      = canon { 1: 1, 2: [ {1: kid_i, 2: enc_i, 3: wrapped_dek_i} ... ], 3: aead_nonce, 4: ciphertext }
```

HPKE suite, `enc` and wrap sizes as core 9.1. `kid_i` is the derived kid of
the auditor (6.1), 16 bytes, so the HPKE `aad` is `0x10 || kid`. `plaintext`
is the canonical SignedMandate (plaintext kind 1), Bucket (2), ClosedSet (3),
PrivatePart (4, 10.1), or `action_salt || action_bytes` (5, core 19.2). The salt keeps the
layout of core 9.1 identical, so one sealing function serves both with a tag
parameter; it is discarded after opening.

Reader rules: decode with core 9.2 (B0 to B7, with the section 3 cap of the
plaintext kind in place of `2^27`); unwrap as core 9.4, trying first the entry whose kid
equals the reader's own derived kid, then every entry (O4); an all-zero X25519
output is an unwrap failure; strip the 32-byte salt; then compute the
plaintext's hash under its own tag (`mandate_hash`, `bucket_hash`,
`closed_root`, `private_hash`; for plaintext kind 5 the core action hash
with the type of the decision record) and compare it with the hash the
reader expects before using the bytes: the record key, except for buckets
and ClosedSets in private mode, whose record key is blinded:

```
kind 15 key (plaintext kinds 2, 3, private mode) = H( tag("edicta/policy/v1/blind-key") || state_salt || bucket_hash )   ; resp. closed_root
```

A reader with a key decrypts, computes `bucket_hash` (or `closed_root`),
blinds it with the mandate's `state_salt` and compares it with the record
key; a lookup blinds the ref first. Reason: an unblinded `bucket_hash` as a
public archive path would be a dictionary oracle on hourly counts and sums. A mismatch, a decoding
failure or an AEAD failure with a key that the envelope lists is
`source_corrupt`; no entry that opens with the verifier's keys is
`policy_private`.

Threat notes:
- ChaCha20-Poly1305 is not key-committing; the hash compare is the defence
  (as core O7): a gate cannot give two auditors different plaintexts under
  one record, because the key is a hash it signed or the record key itself.
- Kids are public and derived from the key, so a kid identifies an auditor
  key across mandates (linkability, 9.6); labels never leave the mandate,
  which in private mode is itself encrypted.
- Auditors are encryption keys only (invariant 7 as amended); they never
  sign anything.
- Auditor key loss makes the records unreadable for everyone; a new mandate
  version with new auditors re-encrypts from then on.

Together, every public kind 15 key and every public hash in a private
verdict has a secret salt in its preimage:
the action hash (core 5.1), the state hashes (9.1), the bucket and
ClosedSet keys (above), and `private_hash` (the PrivatePart salt, 10.1).

### 9.6 Residual leakage in private mode (normative)

Private mode does not hide activity that is public by nature (human decision
of 2026-10-09). A reader without an auditor key can learn:

1. Executed transactions on public rails (amounts, recipients, times, hence
   the aggregate spend of allows); a notarized receipt links each to its
   `commitment_hash`, and a reveal on execution (core kind 18) publishes
   the salt of that executed action.
2. Existence and timing of published decisions (anchor heights, `T_ref`,
   record times), hence frequency.
3. The envelope of every decision: agent key, `gate_id`, nonce, `issued_at`,
   `valid_until`, `action.type` (the action's format), `payload_ref`,
   `mandate_ref`, payload size. `action_hash` is public but salted, so not
   testable.
4. The allow/deny bit of every verdict and the number of verdicts: allows per
   counter by walking the public links to genesis (so `seq` is derivable
   although not published); denies per mandate version and agent from kind 9
   records and markers (not chained, but countable), including the number
   of distinct deny reasons of one decision (one kind 9 record per reason;
   a retry refused for a reason already archived writes nothing, 12.1),
   but not the number of denied attempts.
5. Linkage of mandate versions of one counter (`counter_key` in
   `policy_successor` records).
6. Auditor kids (public in envelopes, linkable across mandates).
7. Lengths of envelopes and PrivateParts (may hint the deny row), and the
   timing of bucket and ClosedSet records (a rollover shows an allow in a new
   hour).
8. The first allow of a counter (the genesis hash, 9.1).
9. A removed auditor keeps the counter's `state_salt` and can test guesses
   against later state hashes (and read every record up to its removal); a
   fresh counter (new `mandate_id`) is the remedy.

Off-chain rails (the IBKR profile): the action bytes are never public, so
private mode hides everything except items 2 to 9. A decision refused at
stage 4m for naming another mandate than the one in force leaves no archive
record (core 8.8 M0, M2), so its action is not written in any form. The public `action_hash` of
a private verdict is safe only because it is salted (core 5.1). Not
addressed in v1 (BACKLOG, post-v1): timing and frequency hiding by batching
or padding; PrivatePart and envelope length padding.

## 10. PolicyVerdict

### 10.1 Schema

```
PolicyVerdict = {
  1: format uint,                    ; 1
  2: gate_id tstr,                   ; the gate's (core ID charset, 1..64)
  3: mandate_hash bstr .size 32,     ; the mandate version in force
  4: commitment_hash bstr .size 32,
  5: action_hash bstr .size 32,      ; c.action.hash
  6: agent_pubkey bstr .size 32,     ; c.agent_pubkey
  7: outcome uint,                   ; 1 allow, 2 deny
  ? 8: reason tstr,                  ; deny: bare sentinel name of section 8
  ? 9: extractor tstr,               ; extractor ID (X1)
  ? 10: facts Facts,
  ? 11: anchor_time uint,            ; T_ref (core section 12.2)
  ? 12: eval_time uint,              ; T_eff
  ? 13: prev_state State,            ; the state read, open bucket included
  ? 14: new_state_hash bstr .size 32,
  ? 15: prev_commitment_hash bstr .size 32,   ; the chain head read
  ? 16: prev_verdict_hash bstr .size 32,
  ? 17: decided_at uint,             ; gate clock, > 0, informational; required in public form, absent in private form
  ? 18: gate_clock uint,             ; 1: the deny rests on the gate clock (P9)
  ? 19: private_hash bstr .size 32,  ; private form: H(tag("edicta/policy/v1/private-part") || canon(PrivatePart))
  ? 20: prev_state_hash bstr .size 32  ; private form, allows: state_hash_p(prev_state) (9.1)
}
PrivatePart = { 1: format uint,                ; 1
                2: salt bstr .size 32,         ; fresh from a CSPRNG per verdict
                ? 8: reason tstr, ? 9: extractor tstr, ? 10: facts Facts,
                ? 11: anchor_time uint, ? 12: eval_time uint,
                ? 13: prev_state State,        ; column S of 10.2
                17: decided_at uint,           ; > 0
                ? 18: gate_clock uint }        ; 1, P9 only
private_hash    = H(tag("edicta/policy/v1/private-part") || canon(PrivatePart))
SignedPolicyVerdict = { 1: verdict PolicyVerdict, 2: signature bstr .size 64 }
verdict_hash    = H(tag("edicta/policy/v1/verdict") || canon(PolicyVerdict))
signed_message  = tag("edicta/policy/v1/verdict-sig") || verdict_hash   ; 61 bytes, gate key
prev_state_hash = state_hash(prev_state)       ; public form: derived from key 13, never a field
                                                ; private form: key 20 (blinded, 9.1)
```

Two forms. A verdict is in private form iff key 19 is present; a gate whose
mandate has `auditors` emits only private form, every other gate only public
form. The PrivatePart carries exactly the verdict keys removed from the
public part, under the same key numbers, with the presence of the
public-form row of 10.2 for its outcome and reason, plus the salt. The salt
exists because `private_hash` is public (key 19, and the kind 15 path) and the
PrivatePart is low-entropy (a reason from a list of fifteen, facts, times near
public anchor times): unsalted, it would be an oracle for deny reasons and
amounts (limit probing).

Logical verdict. With an auditor key the verifier opens the kind 15 `(4,
private_hash)` record (9.5) and merges: the public part without keys 19 and
20, plus the PrivatePart without keys 1 and 2, gives a public-form verdict on
which every public-mode step runs (13.2), with `state_hash_p` in place of
`state_hash`. `verdict_hash` and the signature are always over the
private-form bytes as signed. Cap of the PrivatePart: 16,384.

### 10.2 Presence (decoding rule, `ErrVerdictInvalid`)

Public form:

| Verdict | 8 | 9 | 10 | 11 | 12 | S | 14 | 15, 16 | 18 |
|---|---|---|---|---|---|---|---|---|---|
| Allow | - | R | R | R | R | R | R | R iff the state read is not genesis | - |
| Deny P1, P15, P2 | R | - | - | - | - | - | - | - | - |
| Deny P3 | R | R | - | - | - | - | - | - | - |
| Deny P4 to P8 | R | R | R | - | - | - | - | - | - |
| Deny P9 | R | R | R | R | - | - | - | - | R (`= 1`) |
| Deny P10 | R | R | R | R | - | R | - | - | - |
| Deny P11 to P14 | R | R | R | R | R | R | - | - | - |

`-` is absent. Column S is key 13 `prev_state`. Key 17 is required, keys 19
and 20 are absent. "The state read is not genesis" is `prev_state.seq >= 1`.

Private form (key 19 present), the public part:

| Verdict | Keys present |
|---|---|
| Allow | 1 to 7 (`outcome = 1`), 14 `new_state_hash` (blinded), 15 and 16 iff key 20 != `state_hash(Genesis)`, 19 `private_hash`, 20 `prev_state_hash` (blinded) |
| Deny (every row, P1 to P15 alike) | 1 to 7 (`outcome = 2`), 19 `private_hash` |

Keys 8 to 13, 17 and 18 are never present in private form, and a deny carries
no key 14, 15, 16 or 20: all private denies have the same public shape (no
reason, no stage, no amount, no state). A deny's state read (rows P10 to P14)
is in its PrivatePart. Any other key set is `ErrVerdictInvalid`; this decoding
rule needs no auditor key. "The state read is not genesis" is
`prev_state_hash != state_hash(Genesis)`; it agrees with `seq >= 1` because
strict decoding admits no state with `seq = 0` other than Genesis (9.2, 9.4)
and Genesis keeps the public hash under blinding (9.1).

PrivatePart presence, checked after opening against the public `outcome`: an
allow needs keys 9 to 13 and 17 and no 8 or 18; a deny needs 8 and then the
public-form row of its `reason`. Equivalently, the merged verdict passes the
public-form table. A failure is `ErrVerdictInvalid` for a decoder. For an
allow, `state_hash_p(prev_state) != key 20` is a gate-signed contradiction
(`gate_integrity` violated), checked before the presence rule.

Verifier reading of a presence failure. Bytes that do not decode or do not
hash to `private_hash` are a source problem (`source_corrupt`): any copy can
be altered. A PrivatePart that decodes and hashes to the gate-signed
`private_hash` but breaks the presence rule cannot come from an altered
copy, because the hash binds it to the gate's signature: the gate signed
contents it could not have produced honestly. That is a gate fault, never
`source_corrupt` (13.2 step 2, 13.4). Threat note: without this rule a gate
could hide the facts or the state of an allow behind a malformed PrivatePart
and leave only a source error that blames nobody.

Which form a verdict must use follows the mandate of `mandate_hash`: private
form iff the mandate has `auditors`. The decoder cannot know that; the
verifier checks it when it reads the mandate (13.2 step 2) and the gate
always emits the form of its mandate.

A decoder tells the rows apart by `outcome`, `reason` and the presence of key
11 (`ErrOutsideMandate` is P4 without it, P10 with it). `reason` is one of the
fourteen deny names of sections 8.2 to 8.4. `decided_at` is the gate clock at
the verdict: `authorized_at` of core stage 10 for stage 10p verdicts, `now`
of core stage 1 for stage 4p. No verifier rule reads it. The verdict contains
no tx hash and no rail reference (core invariant 6).

Private form size: the public part is at most the public form's size, so the
`SignedPolicyVerdict` cap stands.

### 10.3 Chain rules (normative)

For consecutive allows `n - 1` and `n` of one counter:
- `prev_commitment_hash(n) = commitment_hash(n-1)`, `prev_verdict_hash(n) = verdict_hash(n-1)`;
- `prev_state_hash(n) = new_state_hash(n-1)` (key 20 against key 14 in
  private form, bytewise, both blinded with the counter's one `state_salt`);
- `new_state_hash(n) = state_hash(Apply(ledger(n), delta(n)))` (`state_hash_p`
  in private mode), where `delta(n) = (facts.asset, facts.scale,
  facts.amount, anchor_time)`;
- `prev_state(n).seq = prev_state(n-1).seq + 1` (in private form `prev_state`
  is read from the PrivatePart).

**Fork.** Two allow verdicts signed by one gate, with the same `gate_id`, whose
mandates have the same `counter_key`, the same `prev_state.seq` and different
`commitment_hash`. In particular two allows with the same `prev_state_hash`
and different successors are a fork. One counter has exactly one allow per
`seq`, so an honest gate never signs a fork; a gate whose registry was lost
and recreated restarts at genesis and is reported as forking, which it is (it
re-spends headroom).

In private form, without the auditor key, `seq` and `counter_key` are not
visible (`counter_key` needs `principal` and `mandate_id`). The fork rule
then uses its hash form: two allow verdicts signed by one gate, with the same
`gate_id`, the same `mandate_hash` and the same `prev_state_hash` (key 20),
and different `commitment_hash`, are a fork. Forks across versions of one
counter need the key.

Vectors: `spec/vectors/policy/verify.json` (and the verdicts inside it).

## 11. Gate integration

### 11.1 Stages

The core order of core section 8.7, with two stages added. Without a mandate
both are skipped and nothing else changes. With a mandate, stage 4m checks
`mandate_ref` before 4p (core 8.8). Stage 4m also runs without a mandate:
it refuses a commitment that names one (M0).

| # | Stage | What | Sentinels |
|---|---|---|---|
| 1 to 4, 4m | D..C, E, L, A, mandate reference | core | core |
| 4p | Admission | P1, P15, P2 to P8 (8.2). On a deny, the stored-retry check below runs first; if it does not answer, the gate signs a deny verdict and then runs stage 4a, whose failure does not change the deny | 8.2, `ErrNonceUsed` |
| 4a | AR | unchanged; also runs after a 4p deny | core |
| 5 to 10 | N0, K or K-fast, K1, K2, P, T' | core; K-fast reads the mandate's `fast_mode_max_delay` for the deadline | core |
| 10p | Evaluation | P9 (8.3). Then take the policy lock, read the counter cell, `Evaluate` (8.4). A deny signs a deny verdict (with `prev_state` from the cell), releases the lock, writes nothing to the registry | 8.3, 8.4 |
| 11 | Z | the Authorization, and the allow verdict with the state read, `new_state_hash` and the chain links, both signed with the gate key under their own tags; in private mode the verdict is in private form (10.1: keys 8 to 13 and 17 move into the PrivatePart, keys 14 and 20 are blinded), and the PrivatePart bytes are kept with the entry | core |
| 12 | N | `ConsumeState`: the nonce entry (with the signed verdict, in private mode the PrivatePart bytes, and, when the allow closed an hour, the closed Bucket and the new ClosedSet bytes) and the cell compare-and-swap in one atomic, durable transaction; then release the lock | `ErrNonceUsed`, `ErrPolicyStateConflict` |
| 13 | R | the Authorization and the verdict; the archive writes of 12.2 (in private mode, kind 15 envelopes encrypted at this stage) | |

- Every deny wraps `policy.ErrDenied`. A deny's verdict is returned with it
  and archived with the rejection marker (12.3). Stage 1 to 4 failures beat
  the policy and sign nothing. In private mode stage 4p and 10p denies sign
  the private form (public keys 1 to 7 and 19 only) and keep the PrivatePart
  bytes for the deny's archive write.
- Operational failures sign nothing and are not marked: registry, signer,
  a cancelled lock, `ErrPolicyStateConflict` (the cell changed under the
  compare-and-swap; 503, retryable, nothing written).
- Retry rule (core 8.7) extended: the stored entry returns its Authorization
  and its verdict; a same-commitment retry never reaches 10p, so nothing is
  counted twice.
- Stored-retry check on a 4p deny. A retry of an authorized commitment can
  be denied at 4p when the mandate changed since (a later version dropped
  the agent, the asset or the recipient). Before signing that deny, the gate
  reads the nonce entry under (`agent_pubkey`, `nonce`) of the verified
  envelope:
  - The entry holds this `commitment_hash`: the request is a retry. The
    gate answers as the core retry rule does: the stored Authorization and
    the stored verdict, with `ErrNonceUsed`. It hands out the Authorization
    only after decoding it, verifying it under the gate key, and comparing
    its `commitment_hash` and `action_hash` with the presented ones in
    constant time; on a mismatch it answers `ErrActionMismatch` with no
    Authorization. No deny verdict is signed, no `policy_deny` record or
    rejection marker is written, and the result does not wrap
    `policy.ErrDenied`.
  - The entry names another commitment, or there is no entry: the deny is
    signed and archived as above. The 4p order comes before the advisory
    nonce check, so a deny here does not reveal anything about the other
    commitment.
  - Any registry error other than not-found: `ErrRegistryUnavailable`,
    nothing signed (fail-closed).

  Threat note. Without this check, a client that retries after its
  Authorization was lost in transit would get a signed deny for a
  commitment the gate already authorized, and the archive would hold an
  allow and a deny for one commitment. The check issues no new
  Authorization: it returns one already issued for this exact commitment
  and action, or refuses, so invariants 5 and 8 hold. Stages 1 to 4 have
  passed before it, as for the core advisory-nonce replay.
- Policy lock: one per gate, held from the cell read through stage 12, and
  it is ctx-aware. With a shared counter, concurrent requests are serialized.

### 11.2 Invariant 8 (core, as amended for v1)

Invariant 8 as amended by the human on 2026-10-09: the rules
are evaluated on the reference time `T_ref`; the mandate is signed under the
scheme its `sig_type` names; a commitment at a mandate gate carries a
`mandate_ref` equal to the hash of the mandate in force, or it is refused; a
fast-mode Authorization is issued only if the mandate consents, with a
deadline at or below the mandate's bound.

| Clause | Where |
|---|---|
| allows only if the verdict for exactly the committed action allows | 4p and 10p decide; Z signs only after both allow |
| facts from the registered extractor; no extractor or a parse failure is a deny | P2, P3, X4 |
| rules on `T_ref` | P10 to P13 use `T_ref` and `T_eff`; only P9 reads the gate clock |
| counter update atomic with the nonce mark | stage 12 |
| deny-only, fail-closed | every policy error refuses; nothing in the policy can skip a core stage |
| verdict under the gate's policy tag, no tx hash or rail reference | 10.1 |
| mandate signed by its principal under its `sig_type`, bound to this `gate_id`, version not lower than current | adoption (6.2, 6.3), and every compare-and-swap of stage 12 |
| `mandate_ref` equals the hash of the mandate in force | core stage 4m (M1, M2); without a mandate a commitment with `mandate_ref` is refused (M0) |
| a refusal for a `mandate_ref` other than the mandate in force (or present without a mandate) writes no decision record | core 8.8 (M0, M2) and core 8.7 (stage 4a row, AR5): refused at stage 4m before any record or marker |
| fast mode only with consent, deadline at or below the bound | P15; core 13.3 clamps the window to `fast_mode_max_delay` |

### 11.3 HTTP (additive to core 18)

- `POST /v1/authorize` (core section 18) 200 response: `{1: signed_authorization bstr, ? 5:
  policy_verdict bstr}`. Key 5 holds the canonical SignedPolicyVerdict and is
  present iff the gate has a mandate.
- Error body: new optional key `5: policy_verdict bstr` (1..16384). Present
  on every policy deny, and on a 409 `ErrNonceUsed` that carries `stored`
  when the stored entry holds a verdict. No other code carries it. At a
  private-mode gate key 5 holds the private-form verdict, never the
  PrivatePart, and the caller still gets the sentinel in the error body. HTTP
  answers are not archive data; protecting them is the caller's job.
- Mapping. Policy codes are prefixed with the package (`policy.`), as core
  18.3 prescribes for packages other than `commitment` and `gate`. They wrap
  no core sentinel and are matched after every core code of their status:

| Status | Codes, in match order | `retryable` |
|---|---|---|
| 403 | `policy.ErrAgentNotCovered`, `policy.ErrNoExtractor`, `policy.ErrOutsideMandate`, `policy.ErrKindNotAllowed`, `policy.ErrAssetNotAllowed`, `policy.ErrRecipientNotAllowed`, `policy.ErrAmountAboveMax`, `policy.ErrMinSpacing`, `policy.ErrPeriodLimit`, `policy.ErrCountLimit`, `policy.ErrHistoryFull`, `policy.ErrFastModeNotAllowed` | 0 |
| 410 | `policy.ErrDecisionAge` | 0 |
| 422 | `policy.ErrFactsInvalid` | 0 |
| 503 | `ErrPolicyStateConflict` (package `gate`) | 1 |

`ErrHistoryFull` shares 403 but has its own code: it is capacity, not a limit.
A client with a strict decoder that does not know key 5 fails on a mandate
gate's answers; that is the core rule for unknown keys, and a mandate is new
configuration. Vectors: `spec/vectors/policy/api.json`.

### 11.4 Registry (implementation rules, no wire format)

The cell under `counter_key` holds the mandate ID, version and hash, the
`scales` map (6.3, at most 1024 entries; the cell's encoder refuses a larger
map, as its decoder does), the chain head (`commitment_hash`, `verdict_hash` of the
last allow) and the ledger (state and retained closed buckets, at most 768
buckets) and, for a private counter, the `state_salt` of genesis (6.3).
Cells are never pruned.

The nonce entry of an allow holds, next to the SignedPolicyVerdict, the
canonical bytes of the Bucket closed by that allow and of the ClosedSet it
produced (both absent when the allow did not roll an hour over), the
`action_salt` of the decision (for the reveal on execution, core 19.7)
and, in private mode, the canonical PrivatePart bytes, in clear (the registry
is gate-local; the archive copies are encrypted at stage 13). They are
written in the same transaction as the cell, so they are exactly as durable
as the spend they describe: whatever the archive loses, the registry can
rewrite (12.2). Cost: at most 16,384 + 36,864 bytes, only on the
first allow of an hour. These bytes are archive data, not evidence: the
entry is gate-local and its encoding is not normative. The entry may be
pruned with the core nonce prune rules; the archive is the long-term copy,
and the rewrite must succeed before a prune (12.2). `ConsumeState` refuses, writing nothing, in this order: an existing
nonce entry (`ErrNonceUsed`), the core prune and clock watermark refusals,
then a cell that changed since it was read (`ErrPolicyStateConflict`). An
undecodable cell is `ErrRegistryUnavailable` (fail-closed). The private deny
dedup index (12.1) is gate-local and not evidence: it needs no transaction
with the cell, and an entry may be dropped once the decision's `valid_until`
passed (no later attempt reaches the policy stage); losing it costs at most
one extra record.

## 12. Archive records

Policy records are kinds of archive format 1 (core 19). Kind numbers are
scoped per archive format; kind 6 is not assigned (the core vector
`rec_kind_6` pins it as undefined). Every record is `{1: format = 1, 2: kind,
...}` under the rules of core 19.1; the nested policy structure travels as a
`bstr` and is strictly decoded with section 3, its sentinel as the cause.
Signatures are not checked at decoding; readers check them (section 13).

### 12.1 Kinds

| Kind | Name | Fields (key: name, type) | Logical key | Canonical path | Cap (bytes) | Identity (core AW2) | Precondition (core AW4) |
|---|---|---|---|---|---|---|---|
| 7 | `mandate` | 3: `signed_mandate` bstr 1..16384 | `mandate_hash` | `mandate/<hex>` | 16,448 | whole record | none |
| 8 | `policy_allow` | 3: `signed_verdict` bstr 1..16384, `outcome = 1` | `commitment_hash` (verdict key 4) | `policy-allow/<hex>` | 16,448 | whole record | the decision record and the mandate record of its `mandate_hash` (kind 7, or in private mode kind 15 `(1, mandate_hash)`) |
| 9 | `policy_deny` | 3: `signed_verdict` bstr 1..16384, `outcome = 2` | `(commitment_hash, reason)`; in private form `(commitment_hash, private_hash)` | `policy-deny/<hex>/<reason>`, `policy-deny/<hex>/private-<private_hash hex>` | 16,448 | the key (first write stays) | the decision record |
| 10 | `policy_bucket` | 3: `bucket` bstr (canonical Bucket) | `bucket_hash` | `policy-bucket/<hex>` | 16,448 | whole record | none |
| 11 | `policy_closed` | 3: `closed_set` bstr (canonical ClosedSet) | `closed_root` | `policy-closed/<hex>` | 36,928 | whole record | none |
| 12 | `policy_successor` | 3: `gate_id` tstr (ID, 1..64), 4: `counter_key` bstr 32, 5: `state_hash` bstr 32, 6: `commitment_hash` bstr 32 | `successor_key` (2.2) | `policy-successor/<hex>` | 256 | whole record | the `policy_allow` record of `commitment_hash`, whose verdict has this `gate_id` and `prev_state_hash = state_hash`, and whose mandate has this `counter_key` (otherwise `archive.ErrNotFound` when absent, `archive.ErrCorrupt` when it differs); with a private mandate the store cannot open it and skips the `counter_key` part, which readers with an auditor key check |

A reader recomputes the key from the record (hash of the nested bytes, or
the verdict's fields, or `successor_key` from fields 3 to 5) and reports a
mismatch as corrupt (core 19.3). For kind 9 the last segment is
`private-` followed by the verdict's `private_hash` in lower-case hex iff
the verdict has key 19, else the bare sentinel name; a public segment always
starts with `Err`, so the two never collide. Threat note (private segment):
a private deny shows no reason, so a key without the `private_hash` would
make every later deny of the same decision (a retry refused for another
reason, for example `ErrMinSpacing` and then `ErrPeriodLimit`) a conflict
whose verdict is dropped, and its kind 15 PrivatePart would be written with
nothing pointing to it. Keyed by `private_hash`, each private deny keeps its
record and the auditor's deny history keeps every distinct reason.
Dedup (gate-local, no wire format): the PrivatePart salt is fresh per verdict,
so a retry refused again for the same reason (a client retrying on
`ErrMinSpacing` until `valid_until`) would get a new `private_hash` and a new
record each time. The gate therefore keeps a local index keyed
`(commitment_hash, reason)`, set after the kind 9 write is acknowledged; a
private deny whose key is already in the index is signed and returned as
usual, but the gate writes no kind 9 and no kind 15 PrivatePart for it. It
still writes the `ErrDenied` marker (an idempotent no-op when present), so a
retry repairs a marker write that failed the first time. Threat note: without the index a private gate would store without
bound per decision and reveal the number of attempts, more than public mode,
where the same retries collapse onto one record per reason (first write
stays); with it, both modes publish one record per distinct reason. A lost
index (crash before it is set, a reset) only writes one more record, never a
wrong one. Vectors: `private.json` `private_deny.second_deny` (another
reason, a second record), `private_deny.same_reason_retry` (same reason, no
write). A `policy_allow` record holding a deny, or the
reverse, is corrupt (`ErrInvalidEnum`). A second `policy_successor` write with
another `commitment_hash` is `archive.ErrConflict`: an honest gate never
causes one, so the writer MUST log it at error level as a possible fork.

`successor_key` and not `state_hash` alone: every counter starts at the same
genesis state, so a key without the counter would collide across mandates
and gates sharing one archive.

Kind 15 `private_blob` (private mode) is defined in core section 19.2:
`{3: plaintext_kind (1 mandate, 2 bucket, 3 closed_set, 4 private_part, 5
action), 4: hash, 5: envelope}`, key `(plaintext_kind, hash)`, path
`private/<plaintext_kind>/<hex>`, cap 69,760, identity the key. In private
mode the gate writes kind 15 in place of kinds 7, 10 and 11 (for kinds 2 and
3 under the blinded key of 9.5), a kind 15 `(4, private_hash)` for **every**
verdict (allow and deny), written before kind 8 or 9, and, through the core,
a kind 15 `(5, action_hash)` before the kind 17 decision record. Kinds 8, 9
(private segment) and 12 are written as in public mode. A writer refuses a
clear kind 7, 10 or 11 for a private mandate (a bug, logged): privacy would
be lost for that record, verification would not. The `successor_key` uses
`prev_state_hash` (key 20, blinded) in private form.

### 12.2 Writers

- Gate start: the mandate record and the genesis ClosedSet. A failed write
  refuses the start.
- After an allow (stage 13), in this order: when an hour closed, the closed
  bucket and the new ClosedSet; then `policy_allow`; then `policy_successor`;
  then the Authorization record (core 10.7). Policy records first, so that a
  crash leaves no Authorization record without its verdict. A failed write
  does not change the answer; the gate repairs it (below).
- After a policy deny: `policy_deny` and the rejection marker (12.3); in
  private form, the kind 15 PrivatePart first (every archived private deny
  has one), and only when the `(commitment_hash, reason)` dedup index of
  12.1 does not hold the deny yet; the index is set after `policy_deny` is
  acknowledged. The marker is written on a dedup hit too (idempotent when
  present), so a retry repairs a failed marker write.
- Private mode (core 19.2): every clear record above is replaced by its
  kind 15 envelope (mandate and genesis ClosedSet at start; closed bucket and
  ClosedSet at a rollover), and the kind 15 PrivatePart of the verdict is
  written first. Order after an allow: private part, then (on a rollover)
  private bucket and private ClosedSet, then `policy_allow`,
  `policy_successor`, the Authorization record. Repair re-encrypts from the
  entry's clear bytes; the identity of kind 15 is its key, so a second
  envelope of the same plaintext is a no-op.
- Repair (start and sweep): for each registry entry of an allow, the writer
  rewrites the same chain as above from the entry alone, in this order: the
  closed Bucket and ClosedSet stored in the entry (when present),
  `policy_allow`, `policy_successor`, then the Authorization record. It
  stops the entry at the first write that fails, so an Authorization record
  never lands ahead of its policy records. The order across entries is not
  required (registry key order is fine): no archive precondition of an
  allow's chain depends on another allow's records. Cost: while a long
  repair runs, a reader may get `unchecked` (`state_history_unavailable`)
  for a verdict whose predecessor is not rewritten yet, never a wrong
  result. Every record is content-addressed or keyed
  by the verdict, so a rewrite of a record already present is a no-op.
  Because the entry is written in the same transaction as the spend, no
  ClosedSet or closed bucket a verdict names can be lost while its entry
  exists, including an older set replaced by a later rollover. A gate MUST
  NOT prune an allow's entry before the archive acknowledged every record
  of that chain. The cell's ledger is a second source for the retained
  buckets and the current set.
- Threat note: the archive is trusted for availability only. A record
  rewritten from the registry still hashes to its key, so a gate cannot use
  the repair to substitute content; a withheld record still gives
  `unchecked`, never `valid` or `invalid`.

### 12.3 Rejection markers

The marker verdict list of core 19.2 gains the fourteen policy deny names, bare:
`ErrAgentNotCovered`, `ErrFastModeNotAllowed`, `ErrNoExtractor`, `ErrFactsInvalid`,
`ErrOutsideMandate`, `ErrKindNotAllowed`, `ErrAssetNotAllowed`, `ErrRecipientNotAllowed`,
`ErrAmountAboveMax`, `ErrDecisionAge`, `ErrMinSpacing`, `ErrPeriodLimit`,
`ErrCountLimit`, `ErrHistoryFull`, and, in private mode only, `ErrDenied`: a
private-mode gate writes `ErrDenied` as the marker name of every policy deny
(the public marker must not reveal the reason), and a public-mode gate never
writes it. `ErrPolicyStateConflict` is operational and never a marker.

Vectors: `spec/vectors/policy/archive.json`.

## 13. Verifier

### 13.1 When the check runs

The named check `policy` (core 20.1) runs for a decision in record state
`authorized` when `RequirePolicy` is set, a `policy_allow` record exists for
it, its verified envelope has `mandate_ref` (the agent signed that a mandate
applies, core 8.8 M0 and 20.5), or its verified Authorization has `mode = 2`
(fast mode needs the principal's consent, core 20.5); it is then required
for `valid`. Without
an allow record it is then `unchecked` (`policy_verdict_unavailable`). `RequirePolicy` is the auditor's
statement that the gate had a mandate: without it and without `mandate_ref`
in the envelope, an archive that withholds the allow record silently skips
the check. Vector: `verify.json` `mandate_ref_without_verdict`. Every report also carries
`gate_integrity` (13.4). Inputs: the gate key on record for `gate_id` (the
key Authorizations verify under), `PrincipalKeys` (typed principal
identities: CLI `--principal ed25519:<hex>`, `--principal cosmos:<bech32>`
(compared with the address derived from the mandate's `principal` and
`principal_hrp`), `--principal eth:0x<hex>`), the extractor registry, `T_ref`
if header trust passed, the verified envelope (its `mandate_ref` and
reference form) and the verified Authorization (its `mode` and
`anchor_deadline`), optionally `AuditorKeys` (X25519 private keys, CLI
`--auditor-key <file>`, repeatable), and optionally `PolicyFull`, `MaxWalkSteps`
(the walk's step cap; 0 means the default of 10000, 13.3) and `Evidence`
(extra signed verdicts, for example those agents received).

### 13.2 Fast check (always)

Let `V` be the target verdict. Steps in order. The first **fail** or
unchecked result ends the steps, except the unverified-`T_ref` case of step 4,
after which the steps go on. A violation found in steps 1, 5 or 6 does not end
them. The full check and the fork search (13.3) run whenever step 1 passed,
and only the first violation found is reported.

1. **Allow record.** Absent: unchecked (`policy_verdict_unavailable`).
   Undecodable, key mismatch, or a gate signature that does not verify:
   unchecked (`source_corrupt`). If `V` names this commitment but another
   `action_hash`, `agent_pubkey` or `gate_id` than the verified decision, the
   gate contradicts itself: `gate_integrity` violated, evidence `[V]`. Then
   **mandate reference**: if the verified envelope carries `mandate_ref` and
   it differs from `V.mandate_hash`, **fail** (`mandate_ref_mismatch`): the
   gate signed an allow under a mandate the agent did not commit to (both
   inputs are signed). An absent `mandate_ref` is reported (`mandate_ref:
   absent`) and is not a fail: the gate's own rule (core M1) forbids it,
   and an allow without it shows a gate that skipped that rule, which the
   envelope alone cannot prove.
2. **Mandate** of `V.mandate_hash`: kind 7, else kind 15 `(1,
   mandate_hash)` opened with an auditor key (9.5). Neither present:
   unchecked (`policy_mandate_unavailable`). Only kind 15 and no key opens
   it: unchecked (`policy_private`), and the private-mode rule below applies.
   In private form, after the form check below, the PrivatePart of `V` is
   opened (kind 15 `(4, V.private_hash)`), hash-checked, checked against key
   20 and for presence (10.2), and merged (10.1): steps 3 to 6 run on the
   merged verdict. Absent: unchecked (`state_history_unavailable`); bytes
   that do not decode or do not hash to `private_hash`: unchecked
   (`source_corrupt`); a state that does not hash to key 20 under the
   mandate's `state_salt`: `gate_integrity` violated, evidence `[V]`. Bytes
   that hash to `private_hash` but break the presence rule (10.2):
   `gate_integrity` violated with reason
   `gate_signed_inconsistent_private_part`, evidence `[V]`, and steps 3 to 6
   still run on what the verifier derives on its own, and keys the presence
   rule forbids are ignored. Missing keys are replaced as follows: `facts`
   (and `extractor`) by its own extraction of the action bytes with the
   registered extractor (no extractor: unchecked `policy_no_extractor`);
   `anchor_time` by the verified `T_ref` (`T_ref` not verified: steps 5
   and 6 are unchecked `blocked`, naming `header_trust`; step 4 handles an
   unverified `T_ref` itself); `eval_time` by `max(anchor_time,
   prev_state.last_t)` (`anchor_time` when `prev_state.seq = 0`), the value
   step 6 requires. A missing `prev_state` has no derivation: steps 3 and 4
   still run (a fail there decides), and steps 5 and 6 are unchecked
   (`blocked`, naming `gate_integrity`). Vectors: `private.json`
   `private_part_allow_missing_facts`, `private_part_allow_missing_times`,
   `private_part_allow_missing_prev_state`. If those steps deny, `policy` fails with that rule
   and the decision is `invalid` (the gate allowed what correct data
   denies); otherwise `policy` keeps its outcome and only `gate_integrity`
   is violated.
   Undecodable, key mismatch or envelope failure: unchecked (`source_corrupt`).
   Scheme of `sig_type` not in this verifier build: unchecked
   (`principal_scheme_unsupported`). Bad principal signature: unchecked
   (`source_corrupt`). Principal not in `PrincipalKeys` (compared with its
   scheme): unchecked (`policy_principal_untrusted`). `mandate.gate_id !=
   V.gate_id`: **fail** (`mandate_gate_id`). `V` in the wrong form for the
   mandate (private form without `auditors`, public form with them, 10.2):
   `gate_integrity` violated, evidence `[V]`.
3. **Facts.** No extractor for `action.type`, or one with another ID than
   `V.extractor`: unchecked (`policy_no_extractor`). Extraction from the
   verified action bytes refuses, or gives other facts than `V.facts`:
   **fail** (`facts_mismatch`).
4. **Per-action rules** on verified data, in order: P1, P15, P4
   (`valid_until` from the verified envelope), P5, P6, P7, P8: any failure is
   **fail** with its sentinel name. P15 here reads the verified
   Authorization: `mode = 2` under a mandate without key 16 is **fail**
   (`ErrFastModeNotAllowed`); `mode = 2` with `anchor_deadline - h0 >
   fast_mode_max_delay` is **fail** (`fast_mode_delay`): the gate issued a
   deadline beyond the principal's bound (invariant 8 as amended). If `T_ref` is verified: `V.anchor_time != T_ref` is **fail**
   (`anchor_time_mismatch`), then P10 on `T_ref`. If `T_ref` is not verified,
   these two are unchecked (`blocked`, naming `header_trust`) and the steps go
   on.
5. **State read and closed buckets.** The ClosedSet of
   `V.prev_state.closed_root` (genesis: no read; in private mode looked up
   under its blinded key, 9.5), then every bucket with `index >= k(V.eval_time) - W`, where `W`
   is the largest `hours` among the asset's periods and the count limits (0
   if none). Absent: unchecked (`state_history_unavailable`). Bytes that do not
   hash to their key or fail decoding: unchecked (`source_corrupt`). A ledger
   that fails 9.2 is a gate-signed contradiction: `gate_integrity` violated,
   evidence `[V]`.
6. **Evaluation on the signed state.** `V.eval_time != max(V.anchor_time,
   prev_state.last_t)` is **fail** (`eval_time_mismatch`). `Evaluate(mandate,
   ledger, V.facts, V.anchor_time)` must allow; a deny is **fail** with its
   sentinel name: the gate's own signed state contradicts its allow. Then
   `state_hash(Apply(ledger, delta(V)))` (`state_hash_p` with the mandate's
   salt in private mode) must equal `V.new_state_hash`; if not,
   the transition is self-inconsistent: `gate_integrity` violated, evidence
   `[V]`.

A kind 15 record that is absent is `state_history_unavailable` (or
`policy_mandate_unavailable` for the mandate), as for its clear kind; one
that no configured key opens is `policy_private`.

**Private mode without an auditor key.** Step 1 runs in full: the allow
record, the gate signature, `gate_id`, `action_hash` and `agent_pubkey`
against the verified decision, and the `mandate_ref` equality (all public).
Steps 2 to 6 are `unchecked` (`policy_private`): the facts, `anchor_time`,
the rules, the fast-mode consent (P15 and the bound need the mandate) and the
state are private. The hash checks that still run: the public presence of the
private form (10.2), keys 15 and 16 iff key 20 is not the genesis hash, walk
L1 and L2, the hash-form fork rule, and genesis by key 20 (13.3). The core
`action` check of a private-form decision record is `unchecked`
(`policy_private`) as well (core 20.11), unless a reveal applies. The
result is `policy` `unchecked` (`policy_private`) unless step 1 failed. With a
key, every step runs on the merged verdict and the opened structures, and the
outcomes are exactly the public-mode ones; the report notes the mode and the
auditor kid as a fingerprint (13.5).

### 13.3 Full check (`PolicyFull`, CLI `--policy-full`)

Runs when step 1 passed and no violation was found yet. **Walk** from `n = V` back along
`prev_commitment_hash`, one step per hop, and stop at genesis (`n` has
`prev_state.seq = 0`), at the first finding (a violation or an unchecked
result of a hop), or when `MaxWalkSteps` steps are taken and `n` still has
`prev_state.seq >= 1`. A step is one hop: the read of `p` and the checks
L1 to L5 below. `MaxWalkSteps = 0` (unset) means the default of 10000;
CLI `--max-walk-steps N`, `N >= 1`.

Genesis is the start of the counter's history: a verdict with
`prev_state.seq = 0` read the state `Genesis` of 9.4 (strict decoding allows
no other state with `seq = 0`), and the counter of a mandate starts there
whatever its version (6.3). The retention horizon does not end the walk:
the archive keeps every allow record and ClosedSet (12), so the whole
history is readable, and a walk that stopped at the horizon would leave the
older part unread.

The cap bounds the verifier's work and memory: the walk holds every walked
verdict for the fork search, up to 16,384 bytes each, so about 160 MB at the
default. A counter with more than 10000 allows before `V` is not walked to
genesis by default; the auditor raises the cap, and pays its memory.

**Truncation.** A walk that ends at the cap, with no violation and no
unchecked result found, reports `gate_integrity` `unchecked` with reason
`policy_walk_truncated`, never `ok`, whether the cap is the default or set
explicitly. `ok` would read as "the gate's history is
clean" when its older part was never read. The truncation does not change
the `policy` check, the decision verdict or the exit code: the fast check
already proved this allow against the state the gate signed, and the walk
only judges the gate. The reason is on `gate_integrity` only (core 20.1.1).

Threat note: the cap is a verifier resource bound, not a trust boundary. A
gate that pads its counter with many allows cannot turn a fork older than
the cap into `ok`; it gets `unchecked` with the range that was read, and an
auditor with a higher cap, or the fork's other verdict as `Evidence`, still
finds it. Evidence verdicts are compared whatever the walk reached.

Per hop,
read the `policy_allow` record of `n.prev_commitment_hash` as `p` (absent:
`state_history_unavailable`; undecodable, key mismatch or bad signature:
`source_corrupt`), then `CheckLink(p, n)`, first failure wins:

| # | Check | On failure |
|---|---|---|
| L1 | `verdict_hash(p) = n.prev_verdict_hash` | violated `[p, n]` (unlinked) |
| L2 | `p.new_state_hash = prev_state_hash(n)` | violated `[p, n]` (unlinked; catches an understated `prev_state`) |
| L3 | `p.prev_state.seq + 1 = n.prev_state.seq` | violated `[p, n]` (seq gap) |
| L4 | the mandates of `p` and `n` (read like step 2; absent or corrupt as there) have the same `sig_type`, principal, `mandate_id` and `gate_id`, and `version(p) <= version(n)`, else violated `[p, n]`. Then the scale rule of 6.3, over every mandate reached: every asset of `mandate(p)` that a mandate of `n` or of any later walked verdict lists has the same scale there, else violated `[p, w]`, `w` the walked verdict nearest to `p` whose mandate lists that asset at another scale | violated `[p, n]` or `[p, w]` |
| L5 | `state_hash(Apply(ledger(p), delta(p))) = p.new_state_hash`, with the ClosedSet of `p.prev_state.closed_root` (absent or corrupt as in step 5) | violated `[p]` (self-inconsistent) |

**Private form without an auditor key.** L1 and L2 run on public fields
(`prev_state_hash` is key 20, compared bytewise with key 14 of `p`, no salt
needed); L3 (`seq` is private), L4 and L5 are not findings but are reported
`unchecked` (`policy_private`), and the walk goes on.
A hop whose verdicts change `mandate_hash` is reported, not judged (a version
bump cannot be told from a mandate change without the key). Genesis is
recognized by `prev_state_hash = state_hash(Genesis)`. A walk that reaches
genesis without a violation reports `gate_integrity` `unchecked`
(`policy_private`), never `ok`; the `walk` fields `from_seq`, `to_seq` and
`total` are absent and `steps` counts hops. With a key the walk is the
public-mode walk on the opened structures: each hop opens and merges the
PrivatePart of `p` and of `n`, L5 uses `state_hash_p`.

**Forks** (both modes). The held allow verdicts are: `V`; in the full mode
every walked verdict and every verdict a `policy_successor` record leads to
(for each walked `n`, the record under `successor_key(gate_id, counter_key,
prev_state_hash(n))`; if it names another commitment, read that allow); and
every `Evidence` verdict that decodes, is an allow, and verifies under the
gate key. A held verdict whose mandate cannot be read is ignored. Two held
verdicts that fork (10.3, the hash form for private verdicts without the key): violated, evidence both. The successor index is a
help only: a dishonest gate can leave it out, and an archive can lie in it,
so only signed verdicts are ever evidence.

The walk proves this: an understated open bucket in `prev_state(n)` cannot
hash to `new_state_hash(n-1)` unless `n - 1`'s transition is itself
inconsistent (L5). Either way a signed contradiction comes out.

### 13.4 Outcomes

| Finding | `policy` | `gate_integrity` |
|---|---|---|
| A per-action rule fails (including P15 and the fast-mode bound); facts differ from the re-extraction; the mandate is bound to another gate; `mandate_ref` differs from `V.mandate_hash` | fail | unchanged |
| A rule fails on the gate-signed `prev_state`; `eval_time` or `anchor_time` contradicts verified data | fail | unchanged |
| History missing: a ClosedSet, a needed bucket, or a verdict or mandate the walk needs | unchecked (`state_history_unavailable`) | `unchecked` with that reason if it happened in the walk |
| History bytes that do not hash to their key or do not decode | unchecked (`source_corrupt`) | same rule |
| Fork; unlinked consecutive verdicts; a self-inconsistent transition or ledger; a seq gap; a version decrease, a scale change or a `mandate_id`, principal or `gate_id` change inside one chain; a verdict that contradicts the verified decision | unchecked (`blocked`, naming `gate_integrity`) unless already fail or unchecked | `violated`, reason `gate_equivocation`, evidence: the signed verdicts (one for a self-inconsistent one) |
| Walk ended at the step cap (default or explicit), without findings | per the fast check | `unchecked`, reason `policy_walk_truncated` |
| Walk reached genesis without findings | per the fast check | `ok` |
| Private records and no auditor key opens them | unchecked (`policy_private`) unless step 1 failed | `unchecked` (`policy_private`) after a walk; `violated` on L1, L2 or a fork |
| A PrivatePart that does not decode or does not hash to `private_hash` | unchecked (`source_corrupt`) | unchanged |
| A PrivatePart that hashes to `private_hash` but whose presence does not fit the public outcome | per steps 3 to 6 on the verifier's own derivation (13.2 step 2): fail if they deny, else unchanged | `violated`, reason `gate_signed_inconsistent_private_part`, evidence `[V]` |
| The verifier lacks the mandate's principal scheme | unchecked (`principal_scheme_unsupported`) | unchanged |
| A verdict in the wrong form for its mandate; a decrypted state that does not hash to key 20 under the mandate's `state_salt` | unchecked (`blocked`, naming `gate_integrity`) unless already fail or unchecked | `violated`, reason `gate_equivocation`, evidence `[V]` |
| No walk and no violation | per the fast check | `not_checked` |

`gate_integrity` is `{status: ok | violated | not_checked | unchecked, reason,
evidence: [SignedPolicyVerdict bytes], walk}`; with `violated` the report also
lists each evidence `verdict_hash`. Without a policy check it is
`not_checked`. After a walk the status is one of three: `ok` (genesis
reached), `violated` or `unchecked`. `not_checked` means no walk ran and no
violation was found.

`walk` is present exactly when the walk ran, whatever the status:

| Field | Type | Meaning |
|---|---|---|
| `max_steps` | uint | The step cap in effect (10000 unless set). |
| `steps` | uint | Steps that passed every check: verdicts before `V` that the walk read and checked. |
| `to_seq` | uint | `V.prev_state.seq`. |
| `from_seq` | uint | `prev_state.seq` of the oldest verdict reached by a passed step (`to_seq` if none); `to_seq - from_seq = steps`. |
| `total` | uint | `to_seq + 1`: the allows of the counter up to and including `V`, as `V`'s signed state counts them. |
| `end` | enum | `genesis` (status `ok` unless evidence or a successor record shows a fork), `max_steps` (`policy_walk_truncated`), or `finding` (a violation or an unchecked hop ended it). |

`total` rests on the gate's signed `seq`, so it is the gate's claim, and
the walk checks it: L3 makes every step lower `seq` by exactly one, and
`ok` needs a `seq = 0` verdict that read genesis. A gate that signs a
smaller `seq` than its real history has started a second chain from
genesis; it gets `ok` on that chain alone, and any allow of the first chain
with the same `seq` is a fork once held (successor records, `Evidence`).

Precedence inside `policy`: fail; then `blocked` by a violation (a
`gate_signed_inconsistent_private_part` violation never blocks: the policy
was already judged on the verifier's own derivation); then the
first unchecked reason of the fast check; then that of the walk; else pass.
The agent may be honest when the gate equivocates, so equivocation never
makes the decision invalid; a proven fail stays fail, and `gate_integrity` is
still set and printed.

### 13.5 Verdict and exit code

Core 20.1: the verdict is `unchecked` whenever `gate_integrity` is
`violated` and no check fails, and the CLI exits with code 5 in that case.
Precedence of exit codes: 4, then 1, then 5, then 3, then 2, then 0. The text
output starts with the line `GATE INTEGRITY VIOLATED (<reason>)`
(`gate_equivocation` or `gate_signed_inconsistent_private_part`) whenever the
status is `violated`, including with exit 1.
After a walk the text output prints one line with the `walk` fields:
`gate integrity walk: last <steps + 1> of <total> verdicts checked (seq
<from_seq> to <to_seq>, <steps> of at most <max_steps> steps, ended at
<end>)`, and with `policy_walk_truncated` it advises raising
`--max-walk-steps` above `to_seq`.

The report's `policy` block: `mandate_hash`, `mandate_id`, `version`,
`principal` (with its scheme), `mode` (`public` or `private`, with
`auditor_kid` when opened, printed as the grouped 128-bit fingerprint of 7),
`mandate_ref` (`match` or `absent`), `seq` (of `prev_state`; absent in private
mode without a key), `anchor_time`, `eval_time`, `facts`, `extractor`,
`prev_state_hash`, `new_state_hash`, and `denials` (policy deny records of
this decision, informational; `ErrDecisionAge` flagged gate-attested;
reasons only for opened private denies, otherwise `private`). A verifier MAY
skip reading deny records. A label printed next to an auditor follows the
label rule of 7.

### 13.6 What it proves

- The principal's mandate, the gate's allow for exactly this action, the
  facts, the per-action rules, and that the allow is consistent with the
  exact state the gate signed.
- With the walk and evidence: that the gate's published chain has no
  internal contradiction back to genesis. `ok` means genesis was reached;
  a walk cut by the step cap, default or explicit, is `unchecked`
  (`policy_walk_truncated`) and states the range it read.

- With `mandate_ref`: that the agent itself committed to exactly the mandate
  the gate applied; with a fast-mode Authorization, that the principal
  consented and the deadline is within its bound.
- In private mode without an auditor key: only the allow, the `mandate_ref`
  equality, the hash links and forks; not the facts, not the reference time,
  not the fast-mode consent, not that the rules were respected.

Not proven: allows the gate kept outside every chain and every piece of
evidence (an Authorization of that kind is itself evidence when it surfaces);
the rule P9; execution.

## 14. Sentinels

Package `policy` unless noted. Deny sentinels wrap `ErrDenied`.

| Sentinel | Where | Meaning |
|---|---|---|
| `ErrDenied` | all denies | umbrella, never reported alone |
| `ErrAgentNotCovered` | P1 | agent not in the mandate |
| `ErrFastModeNotAllowed` | P15 | pending reference under a mandate without `fast_mode_max_delay` (verdict row like P1: key 8 only) |
| `ErrNoExtractor` | P2, X5 | no extractor for the action type |
| `ErrFactsInvalid` | P3, X4, section 4 | extractor refusal or invalid facts |
| `ErrOutsideMandate` | P4, P10 | outside `not_before` or `not_after` |
| `ErrKindNotAllowed` | P5 | facts kind not in `kinds` |
| `ErrAssetNotAllowed` | P6 | asset not listed, or another scale |
| `ErrRecipientNotAllowed` | P7 | recipient not listed or absent |
| `ErrAmountAboveMax` | P8 | above `per_action_max` |
| `ErrDecisionAge` | P9 | anchor older than `max_decision_age` by the gate clock |
| `ErrMinSpacing` | P11 | anchor too soon after the last allowed one |
| `ErrPeriodLimit` | P12 | rolling period sum |
| `ErrCountLimit` | P13 | rolling count |
| `ErrHistoryFull` | P14 | capacity |
| `ErrMandateInvalid` | 6 | mandate decoding or value rule (configuration, verifier `source_corrupt`) |
| `ErrAuditorKidMismatch` | 6.1 | an auditor's kid is not derived from its key; wraps `ErrMandateInvalid` |
| `ErrMandateSignature` | 6.2 | principal signature under the mandate's scheme (including high-s, `v` outside `{27, 28}`, a recovered address that differs, an ADR-036 signature over another text) |
| `ErrVerdictInvalid` | 10 | verdict or PrivatePart decoding, or presence rule |
| `ErrVerdictSignature` | 10.1 | gate signature on a verdict |
| `ErrStateInvalid` | 9 | Bucket, ClosedSet, State or ledger |
| `ErrDenied` (as a marker name) | 12.3 | private mode only: the marker of every policy deny |
| `ErrPolicyStateConflict` (package `gate`) | 11.4 | cell changed concurrently (operational) |
| `ErrPolicyViolation` (package `verifier`) | 13 | wraps every `policy` fail |

## 15. Vectors

Location `spec/vectors/policy/`. Every file has `"format":
"edicta-policy-vectors/v1"` and `"revision"` `policy-v1.0`. The
principal vectors are in `spec/vectors/principal/` (same format and
revision; ed25519.json, adr036.json, eip712.json).
A decision of the verify files carries `action_salt_hex` and its
`action_hash_hex` is the salted core hash. Auditor test
keys: `DeriveKeyPair(SHA-256("edicta/policy/v1 test auditor|" + name))`,
kid derived (6.1), labels `Alice` and `Bob`; test `state_salt` =
`SHA-256("edicta/policy/v1 test state salt|" + mandate label)`; PrivatePart
salt = `SHA-256("edicta/policy/v1 test private part salt|" + commitment_hash
hex)`.
The vector field `t_h` (in `engine.json` and `verify.json`) carries `T_ref`
(equal to `T_H` for an included reference); the name is kept so that one
concept has one name across the files. JSON as core
section 22: uints are decimal strings, byte strings and amounts lowercase
hex, text as JSON strings, optional fields absent when unset. Keys: `agent1`,
`agent2`, `gate1` of core `keys.json`; principals `p1`, `p2` with seed
`SHA-256("edicta/policy/v1 test principal|" + name)`. Commitment hashes in the
engine and verify files are stand-ins, `SHA-256("edicta/policy/v1 test
commitment|" + label)` (no envelope; the policy check takes the decision's
fields as verified by the core checks; draft.5 cases add the verified
`mandate_ref`, reference form, `h0`, `mode` and `anchor_deadline` where they
matter). The secp256k1 test principals use the seed `SHA-256("edicta/policy/v1
test principal secp|" + name)`; ECDSA signatures in vectors use RFC 6979
deterministic nonces. Auditor test keys and envelope randomness are fixed from
labels as in the core payload vectors (core 22, `payload_blob.json`
`derivation`).

| File | Contents |
|---|---|
| `facts.json` | `test_extractor`; `cases`: `input`, `cbor_hex`. `reject`: `cbor_hex`, `expect_error` = `ErrFactsInvalid`, `cause`. |
| `mandate.json` | `tags`, `keys`; `cases` (including a full mandate with `kinds`, `not_before` and every optional field, and a version 2 with the same counter key): `signer`, `input`, `mandate_cbor_hex`, `mandate_hash_hex`, `signed_message_hex`, `signature_hex`, `signed_mandate_hex`, `counter_key_hex`. `reject`: `signed_mandate_hex`, `expect_error` (`ErrMandateInvalid` or `ErrMandateSignature`), `cause`. `adoption` (6.3): optional `start` (the cell before the first step: `version`, `mandate_hash_hex`, `scales`; absent: no cell), `steps` of `signed_mandate_hex`, `mandate_hash_hex`, `expect` (`genesis`, `use`, `switch` or `refuse` with `error` = `gate.ErrInvalidConfig` and `cause` = `version`, `same_version_other_hash`, `scale` or `scales_full`), `version_after`, `scales_after` (the cell after the step; a refusal leaves it unchanged). Cases: a scale change of an unused asset; a scale change after an intermediate version dropped the asset; scales kept with an added asset, then a restart; a lower version; the same version with another hash; `adopt_scales_full` (a start cell of 1012 assets standing for earlier versions; a switch to exactly 1024; one more asset refused; a version with only known assets switched). Draft.5 adds: one full case per scheme (`sig_type` absent, 2, 3) with `counter_key_hex` by the typed formula; a mandate with `fast_mode_max_delay` and one with `auditors`; rejects `sig_type_1_present`, `sig_type_4`, `hrp_without_adr036`, `adr036_without_hrp`, `principal_32_for_adr036`, `principal_not_on_curve`, `principal_21_for_eip712`, `signature_64_for_eip712`, `fast_mode_max_delay_0`, `fast_mode_max_delay_1001`, `auditors_unsorted`, `auditors_duplicate_kid`, `auditor_low_order`, `auditors_17` (`ErrMandateInvalid`), and per scheme a bad signature (`ErrMandateSignature`). Draft.7: `m_private` with derived kids, labels and `state_salt`; rejects `auditors_empty_array`, `auditor_kid_mismatch` (rule `auditor_kid`), `kid_15_bytes`, `kid_17_bytes`, `auditor_pubkey_31`, `auditor_label_empty`, `auditor_label_65`, `auditor_label_quote`, `auditor_label_backslash`, `auditor_label_non_ascii`, `auditor_label_leading_space`, `auditor_label_trailing_space` (rule `auditor_label`), `auditors_duplicate_label` (rule `auditor_label_duplicate`), `state_salt_missing_with_auditors`, `state_salt_without_auditors`, `state_salt_31`, `sig_type_0`, `principal_hrp_17`, `hrp_with_eip712`; the draft.5 auditor rejects regenerated for the new Auditor schema; adoption case `state_salt_changed_on_successor` (steps of a private counter carry `state_salt_after_hex`). Every draft.4 case keeps its bytes. |
| `render.json` | `cases`: `mandate_ref` or `input`, `text`, and for `sig_type = 2` also `adr036_data` (the exact `D` of 6.2). Regenerated in draft.5 (every text changes). Cases cover the three `principal:` lines, both `fast mode:` lines and both `auditors:` lines, an ASCII escape case for the amino JSON (`<`, `>`, `&` in an asset or recipient). Draft.7: `render_m_private` with the auditor lines (unverified label and full fingerprint) and the label note; `render_m_private_two_auditors` (labels `Auditor 1` and `Auditor l`). |
| `state.json` | `genesis` (bytes, hash, empty ClosedSet bytes and root); `buckets`, `closed_sets`, `states` (input, bytes, hash); `coverage` (two states differing in one open sum, with different hashes); `reject` per structure. |
| `engine.json` | `scenarios`: `mandate`, optional `start` ledger (state, closed set and bucket bytes), `steps` (admitted `facts` and `t_h`, or a `repeat` form; `expect`: `allow` with `eval_time`, `new_state_hash_hex`, `new_state_cbor_hex`, `rolled_over`, `closed` count and, after a rollover, the closed bucket hash and ClosedSet bytes; or `deny` with the sentinel and, for `ErrHistoryFull`, `cause` = `sum`, `count`, `pairs` or `seq`), `final`. Scenarios: limit edges, bucket rounding, counts, min spacing, clamp, rollover, `not_before`, two assets, retention 767 over 800 hours, every `ErrHistoryFull` cause. |
| `verify.json` | `gate`, `extractors`; `records` (archive record bytes by canonical path); `cases`: `decision` (the fields the core checks verified), `t_h` (absent: header trust did not pass), `config` (`require_policy`, `policy_full`, `max_walk_steps` (null: the default), `principal_keys`, `extractors`, `evidence`), `archive` (paths present), optional `corrupt` (path to replacement bytes), `expect` (`policy` with `status` and `rule` or `reason`; `gate_integrity` with `status`, `reason`, `evidence` verdict hashes, and `walk` (13.4) when the walk ran; `verdict`; `exit`). One case per outcome row of 13.4: passes (genesis, closed bucket, hour rollover, chain continuity); a cap that reaches genesis exactly (`ok`) and caps of 1 and 2 steps on a chain of 4 (`unchecked`, `policy_walk_truncated`, verdict `valid`, exit 0); every unchecked reason; every per-action fail including kind and `not_before`; fails on the signed state; fork by evidence and by successor record; unlinked verdicts; self-inconsistent transition; understated open bucket (fast passes, walk exit 5); version decrease; scale change across a version boundary, consecutive and after an intermediate version dropped the asset (evidence the two verdicts whose mandates disagree); a walk across a version boundary that keeps every scale (no equivocation); seq gap; missing and corrupt history; fail with equivocation (exit 1). Draft.5 adds: `mandate_ref_match`, `mandate_ref_mismatch` (fail), `mandate_ref_absent` (pass, reported), `fast_mode_not_allowed` (fail), `fast_mode_delay_exceeded` (fail), `fast_mode_within_bound`, `principal_scheme_unsupported`, `principal_cosmos_pinned`, `principal_eth_pinned`, `principal_eth_not_cosmos` (the comparison is per scheme), `anchor_time_t_ref_pending`. Draft.7: the draft.5 cases regenerated for the salted action hash; `fast_mode_no_policy_record` (mode 2, no allow record, `require_policy` off: unchecked, `policy_verdict_unavailable`, exit 2). |
| `archive.json` | `kinds`, `reserved_kinds`, `marker_names`; `cases`: `kind`, `path`, `key_hex`, `record_cbor_hex` (each also in `verify.json`). `reject`: `record_cbor_hex`, `expect_error` = `archive.ErrCorrupt`, `cause`. Draft.5 adds kind 15 cases (one per `plaintext_kind`, `plaintext_kind` field, records in `private.json`), kind 15 rejects, and the marker name `ErrFastModeNotAllowed` (after `ErrAgentNotCovered`, 12.3 order). Draft.7: kind 15 cases regenerated (derived kids, blinded keys for kinds 2 and 3) plus `private_blob_action` (plaintext kind 5); `policy_deny_private` (path segment `private`); `marker_names` ends with `ErrDenied`, listed in `marker_names_private_only`; kind 15 rejects `private_kind_6` (replaces `private_kind_5`, now a defined kind), `private_envelope_65537` (plaintext kind 4), `private_over_cap` at 69,761 bytes (was 65,601, below the new cap); `reads`: `deny_private_under_reason_path`, `deny_public_under_private_path` (`archive.ErrCorrupt`) and a control. |
| `api.json` | the 11.3 mapping and example bodies (deny with key 5, authorize response with key 5, 409 with keys 4 and 5).; draft.5 adds `policy.ErrFastModeNotAllowed` and an authorize response on the alias path `/v1/authorize` (example field `endpoint`, an Authorization v1); draft.7 adds `authorize_deny_private` (a private-form deny verdict in key 5: keys 1 to 7 and 19, the sentinel only in the body); draft.8 removes the alias example (the only path is `/v1/authorize`). |
| `private.json` | Sections 9.1, 9.5, 9.6, 10 and the private-mode verifier rules (rewritten in draft.7). `tags` (with `state-blind`, `blind-key`, `auditor-kid`), `cap`, `action_cap`; `auditor_keys` (`ikm`, `sk`, `pk`, `kid_preimage_hex`, `kid_hex`, `fingerprint`, `label`), `derivation`; `envelopes` for plaintext kinds 1 to 5 (kinds 2 and 3 under blinded keys, with `plaintext_hash_hex` and `state_salt_hex`; kind 5 for core `v1_pending_fibre_mandate_ref`, with `action_type`, `action_salt_hex`, `action_hex`); `private_verdict`: an allow in private form, its `public_keys`, PrivatePart and `merged_verdict`, and `reject` (`ErrVerdictInvalid`): `verdict_mixed_forms`, `verdict_private_hash_only`, `verdict_state_hash_only`, `verdict_genesis_with_chain_keys`, `verdict_later_without_chain_keys`, `private_form_with_reason`, `private_form_with_facts`, `private_form_with_anchor_time`, `private_form_with_decided_at`, `private_form_with_gate_clock`, `private_deny_with_key_20`, `private_allow_without_14`, `public_form_without_decided_at`; `private_deny`: `private_deny_no_public_reason` (public keys exactly 1 to 7 and 19, kind 9 path `policy-deny/<hex>/private-<private_hash hex>`, marker `ErrDenied`) with `private_deny_with_key` (the reason from the opened PrivatePart) and `second_deny` (`private_deny_second_reason`: a second private deny of the same decision under its own path, with its kind 15 PrivatePart record) and `same_reason_retry` (`private_deny_same_reason_retry`: a retry denied again for the first reason, a fresh `private_hash`, `dedup_key` `(commitment_hash, reason)` and empty `archive_writes`); `blinding`: `state_hash_blind_vs_public`, `state_hash_blind_genesis`, `blind_key_bucket`, `blind_key_closed`, `private_part_salt`; envelope `reject`: `envelope_cap_exceeded`, `action_envelope_69633`, `tampered_ciphertext`, `wrong_tag_aad` (`source_corrupt`), `wrong_tag_dek_info` (`policy_private`). Verifier cases (records as `verify.json`): `private_with_key_pass`, `private_without_key` (`policy_private`, exit 2), `private_wrong_key`, `private_part_hash_differs` (`source_corrupt`), `private_walk_without_key` (`unchecked`, `policy_private`), `private_without_key_facts_mismatch` and `private_without_key_anchor_time_mismatch` (both `unchecked`, `policy_private`, exit 2 since draft.7), `private_with_key_facts_mismatch`, `private_with_key_anchor_time_mismatch` (fail), `private_state_not_key_20`, `state_salt_wrong`, `verdict_form_mismatch` (`gate_equivocation`), `private_part_row_mismatch`, `private_part_allow_missing_facts` (both `gate_signed_inconsistent_private_part`, policy pass, exit 5 since draft.8), `private_part_missing_facts_denies` (draft.8: the verifier's own facts deny; policy fail, exit 1), `private_fork_without_key`, `chain_continuity_without_salt`, `chain_continuity_tampered_without_salt` (violated without any key). |
| `spec/vectors/principal/adr036.json` | Section 6.2. Keys, `principal_hex`, `hrp`, `address`, `mandate_hash_hex`, `rendered_text` (`D`), `signdoc`, `digest_hex`, `signature_hex`. Rejects: `high_s`, `wrong_hrp`, `principal_32_bytes`, `not_on_curve`, `other_mandate_hash`, `text_differs_one_byte`, `last_line_not_hash`, `d_without_empty_line` (`D` = `Render` without its final LF, then `"\n" || "mandate hash: " || hex`), `d_trailing_lf` (`D` followed by one LF). Each reject carries the signature a wallet would produce over its own signdoc, so only the verifier's rebuild of `D` refuses it. Draft.7: `case_private` (the mandate with auditors and `state_salt`: the wallet-signed `D` carries the fingerprint lines and the label note), rejects `r_0`, `s_0`, `r_ge_n`. |
| `spec/vectors/principal/ed25519.json` | Section 6.2, `sig_type` absent: principal seed and key, `mandate_hash_hex`, `signed_message_hex` (`M`), `signature_hex`, `counter_key_hex` (untyped formula). Rejects: `s_not_reduced` (G2), `other_mandate_hash`, `low_order_principal` (G0, `ErrMandateInvalid`). |
| `spec/vectors/principal/eip712.json` | Section 6.2. Keys, `address`, `typed_data` (the `eth_signTypedData_v4` JSON), `domain_separator_hex`, `type_hash_hex`, `hash_struct_hex`, `digest_hex`, `signature_hex`. Rejects: `v_0`, `v_1`, `high_s`, `recovered_address_differs`, `wrong_domain_name`, `chain_id_present`, and since draft.7 `r_0`, `s_0`, `r_ge_n`. |

Profile vectors: `spec/vectors/profiles/bank-send/tia_transfer_facts.json`
(bank-send profile section 2.4).

Generation and checks: `spec/vectors/check/gen_policy.py` writes every file
above with the rules module `policy_v1.py`; `check_policy.py` (run by
`check_vectors.py`) regenerates and compares bytes, and independently
re-implements the encodings, hashes, signatures, strict decoding, rendering,
the engine and the verifier outcome rules from this document and checks
every expectation with them.
