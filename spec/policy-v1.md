# Edicta policy v1 (mandate, facts, rule engine, verdicts)

Status: revision `policy-v1-draft.2` (2026-10-08). Working draft, subject to
change. Built on the core spec `spec/decision-commitment-v0.md`, revision
`v0-draft.29`. Section numbers prefixed "core" refer to the core spec.

Keywords MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119. Items marked
`UNVERIFIED` are facts about Celestia or Fibre that a Celestia protocol
engineer must confirm. Everything else is normative for policy v1.

A gate operator attaches one principal-signed **mandate** to a gate. The gate
then authorizes only actions whose **facts**, extracted deterministically from
the exact action bytes, satisfy the mandate's rules. The rules are evaluated on
the anchor time `T_H`, over a hash-linked state of hourly buckets that is
updated atomically with the nonce mark. Every verdict is signed by the gate,
carries the state it was evaluated on, and chains to the previous one, so a
verifier can check an allow from archived data and detect a gate that forks or
rewrites its own history.

Policy is configured, not written: there is no per-agent code. The policy
never evaluates the agent, the truth of its inputs or the quality of its
decision; it bounds what may be authorized.

Nothing here changes a v0 byte: DecisionCommitment, the envelope, the
Authorization, the receipt, the record request, the publish request, every
`edicta/v0/*` tag and every existing vector are unchanged. A gate without a
mandate behaves exactly as core section 8.7 says.

## 0. Versioning

| Change | Rule |
|---|---|
| Editorial | No version change. |
| Any change to an encoding, a hash or signature preimage, a limit, the engine, or the outcome of a check, while in draft | Bump `policy-v1-draft.N`, regenerate the vectors under `spec/vectors/policy/`, record the change below. |
| Any such change after freeze | New family version: tags `edicta/policy/v2/*`, `format = 2` in every structure. A v1 reader rejects `format != 1`. |

| Revision | Change | Vectors |
|---|---|---|
| `policy-v1-draft.1` | First draft (task 028). | Initial set in `spec/vectors/policy/`; `spec/vectors/profiles/bank-send/tia_transfer_facts.json`. |
| `policy-v1-draft.2` | Asset scale is immutable per counter: the counter cell keeps the scale of every asset any adopted version listed, adoption refuses a change (6.3), and walk rule L4 checks the same rule across every mandate the walk reaches (13.3). Closed bucket and ClosedSet bytes are stored in the registry entry of the allow that closed the hour (11.1, 11.4, 12.2). No encoding, hash or signature preimage changed. | `mandate.json` gains `adoption`; `verify.json` gains three cases and their records. Both files now carry `policy-v1-draft.2`; every other file and every existing case and record is byte-identical. |

## 1. Threat model

| Mechanism | Defends against | Assumes |
|---|---|---|
| Principal Ed25519 signature over the mandate hash (section 6) | An operator or gate inventing or loosening the rules; a mandate of one gate configured at another (`gate_id` inside the signed bytes) | The principal's key is secret; the verifier pins the principal keys it trusts (`PrincipalKeys`). Key roles never overlap (core invariant 7) |
| `mandate_id` and monotonic `version` (section 6.3) | Rolling a mandate back to a looser version; resetting the counters by re-signing the same rules | The gate's registry keeps the counter cell (never pruned); the verifier's walk checks versions along the chain. A new `mandate_id` is a fresh counter by the principal's explicit choice |
| Immutable asset scale per counter (section 6.3, L4) | Fresh headroom from a rescaled asset: sums are kept per `(asset, scale)`, so a version that lists an asset at a new scale would count it from zero; an honest gate falsely reported as equivocating when a version rescales an asset the retained state does not hold | The gate refuses at adoption, from the scale map in the counter cell, not from the retained ledger (which forgets aged-out or never-used assets). The verifier applies the same rule to the mandates the walk reaches; a version adopted but never used is invisible to it, which only makes the gate stricter than what the verifier can see, never the reverse |
| Deterministic extractor, strict decoding (sections 4, 5) | One action byte string read as two different transfers by the gate and by the verifier; an action type the policy cannot read slipping through | Every reader uses the same extractor (same ID). No extractor, or bytes it cannot parse, is a deny. Extractors are code, reviewed per profile: a wrong extractor gives wrong facts everywhere at once, which shared vectors guard against |
| Rules on the anchor time `T_H` (section 8) | Gate clock manipulation moving spend between windows | `T_H` is the header time at `payload_ref.height`, checked by the gate (K0) and by the verifier (header trust). Only rule P9 reads the gate clock; it is deny-only and marked gate-attested |
| Anchor-age cap P9 (section 8.3) | An old anchor (up to the Fibre retention) used to land spend in an old window; stale decisions | The gate clock (core: within 30 s of true time). The verifier cannot check it, so it is deny-only |
| Conservative hourly buckets (section 8) | Allowing more than `max` in any rolling window | Exact integer arithmetic; buckets partly inside a window count fully. Cost: a window of `h` hours may count up to `h + 1` hours, so the gate may deny early |
| Counter update in the nonce transaction (section 11.4) | Two authorizations both counted against the same headroom; a crash leaving a counted spend without an Authorization or the reverse | The registry is atomic and durable (core stage 12) |
| Signed verdict with `prev_state` and `new_state_hash` (section 10) | A gate that authorizes over its own limits and denies it later; a gate that silently drops, understates or rewrites spends | The gate key is secret and pinned. The verifier's fast check proves consistency with the state the gate signed; the walk and external evidence prove the chain has no contradiction. Allows the gate keeps outside every chain and every piece of evidence are not detected (section 13.6) |
| Archive of closed buckets, sets, verdicts and successor index (section 12) | Losing the data a verifier needs | The archive is trusted for availability only: every record is bound to a hash or a signature. A withheld record gives `unchecked`, never `valid` or `invalid` |
| `ErrHistoryFull` (section 8.4) | Unbounded state | Capacity is independent of action frequency (768 buckets per counter); the bound that remains is per-bucket assets and integer widths |
| Nothing (open gap) | An operator who runs a gate without a mandate, or edits its own executor to skip the Authorization | Core section 16: enforcement is the integrator's. An auditor relying on a mandate sets `RequirePolicy` (section 13.1) |
| Nothing (out of scope) | Cross-asset or fiat totals; whether the facts' recipient is a good counterparty | Needs an oracle; v1 has per-asset limits only |

## 2. Notation and tag namespace

Notation as core section 2: `||` concatenation, `H(x) = SHA-256(x)`, hex lower
case, times are Unix seconds, `tag(t) = uint8(len(t)) || ASCII(t)`.
`k(t) = floor(t / 3600)` is the bucket index of time `t`. `canon(x)` is the
canonical encoding of section 3.

### 2.1 Namespace (normative for every Edicta tag family)

- Form `edicta/<family>/v<N>/<name>`, ASCII `[a-z0-9/-]`, lower case, at most
  64 bytes, applied as `tag(t)`. The DecisionCommitment core keeps its
  `edicta/v0/<name>` form. The family segment keeps policy tags apart from a
  future `edicta/v1/...` DecisionCommitment.
- A tag is never reused, for any purpose. A wire change gets a new `v<N>`.
- Hash tags and signature tags are distinct, and no two tags of any family
  are equal.
- No key signs under the tags of two roles. The principal signs only under
  `mandate-sig`. The gate key signs Authorizations, receipts and verdicts,
  each under its own tag.

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
| `TagCounter` | `edicta/policy/v1/counter` (24, `0x18`) | `counter_key = H(tag \|\| principal \|\| mandate_id)` (32 and 16 bytes) |
| `TagSuccessor` | `edicta/policy/v1/successor` (26, `0x1a`) | `successor_key = H(tag \|\| uint8(len(gate_id)) \|\| gate_id \|\| counter_key \|\| state_hash)` (archive key, section 12) |

Threat note (tags). Length prefixes equal to v0 tags (23, 24) are harmless:
the ASCII differs from the first byte after the prefix on (`edicta/p` versus
`edicta/v`). The two signed messages are 61 bytes and start with `0x1c`, which
no v0 signed message does (core: `0x0d`, `0x15`, `0x1b`, and the record and
publish requests `0x18`, `0x19` signed directly). A verdict signature can never
verify as an Authorization or receipt signature, and a principal signature is
over a different tag and a different hash.

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
| `Bucket`, `State` | 16,384 |
| `ClosedSet` | 36,864 (767 refs of at most 46 bytes plus the header: 35,289) |

Strict decoding, in this order; the first failure decides: (1) size cap;
(2) generic well-formedness as core section 6.2 with the limits above;
(3) schema, per map in encoded key order and depth first: unknown key, wrong
major type, length, charset; then missing required keys; (4) value rules of
the structure's section; (5) re-encoding gives the input bytes. Every failure
is the structure's sentinel (section 14): `ErrFactsInvalid`,
`ErrMandateInvalid`, `ErrVerdictInvalid` or `ErrStateInvalid` (Bucket,
ClosedSet, State and ledgers). Vectors also give the first failing rule as an
informational `cause` (a core section 12 name or a value-rule label).
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
  2: principal        bstr .size 32,
  3: gate_id          tstr,               ; 1..64, core ID charset
  4: agents           [+ bstr .size 32],  ; 1..64, strictly ascending bytewise
  5: not_before       uint,               ; >= 1; compared with T_H
  6: not_after        uint,               ; > not_before, <= 253402300799; compared with valid_until
  7: assets           [+ AssetRule],      ; 1..16, strictly ascending by asset
  ? 8: count_limits   [+ CountLimit],     ; 1..4, strictly ascending by hours
  9: mandate_id       bstr .size 16,
  10: version         uint,               ; >= 1
  ? 11: max_decision_age uint,            ; 1..86400 s; absent: MaxTTL(da)
  ? 12: min_spacing   uint,               ; 1..2678400 s
  ? 13: kinds         [+ tstr]            ; 1..8, Facts.kind grammar, strictly ascending; absent: any
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
SignedMandate = { 1: mandate Mandate, 2: signature bstr .size 64 }
```

Value rules (`ErrMandateInvalid`): `principal` and every agent key pass core
G0 (canonical point, not small order); `principal` is not in `agents` (key
roles, core invariant 7). `kinds` (P5) lists the kinds the agents may
perform; together with the asset (P6) and recipient (P7) allowlists it is
the allowlist part of the catalog. `not_after <= 253402300799` (9999-12-31T23:59:59Z, so
the rendered text is RFC 3339).

### 6.2 Hash and signature

```
mandate_hash   = H(tag("edicta/policy/v1/mandate") || canon(Mandate))
signed_message = tag("edicta/policy/v1/mandate-sig") || mandate_hash      ; 61 bytes
signature      = Ed25519(principal_priv, signed_message)
counter_key    = H(tag("edicta/policy/v1/counter") || principal || mandate_id)
```

Verification: strict decoding with the value rules (G0 on `principal` is
one of them), then `S < L` and the cofactorless equation (core G1, G2). A failure of the signature alone is
`ErrMandateSignature`. `mandate_hash` is never a field of the mandate.

### 6.3 Counter, versions and adoption

- **Counter.** A counter belongs to `(principal, mandate_id)` at one gate and
  is stored in the gate's registry under `counter_key`. All agents of a
  mandate share it.
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
- **Adoption at gate start.** Decode and verify the mandate; its `gate_id`
  MUST equal the gate's. The principal key MUST NOT equal the gate key, an
  executor key or an allowlisted agent key (`commitment.ErrKeyRole`). Every
  action type the gate allows MUST have an extractor (X6). Then read the cell
  under `counter_key`:

  | Stored cell | Action |
  |---|---|
  | absent | write genesis (section 9.4) with this mandate; `scales` from its AssetRules |
  | version above the configured one | refuse to start |
  | same version, different `mandate_hash` | refuse to start |
  | same version, same hash | use it |
  | version below the configured one | check every AssetRule against `scales`: an asset in the map with another scale refuses to start; otherwise switch the cell to this mandate and set `scales` to the union, in one compare-and-swap, keeping head and state |

  Any refusal is a configuration error (`gate.ErrInvalidConfig`). Every later
  state update (stage 12) compares the stored mandate hash too, so a lower
  version can never be adopted by a concurrent writer.

Vectors: `spec/vectors/policy/mandate.json` (encodings, hashes, signatures,
counter keys, rejects, and `adoption`: sequences of signed mandates applied to
one cell, with each step's action, refusal cause, version and `scales` after
it).

## 7. Rendered text (normative)

`Render(mandate)` is the text a wallet or CLI shows before the principal
signs. The signature covers the CBOR, not the text; two implementations MUST
render the same bytes.

Format: ASCII; LF line ends; no trailing spaces; one final LF; the line order
below; lists in mandate order; hex lower case; times RFC 3339 UTC with
seconds (`2026-10-07T00:00:00Z`). Amounts exact: the integer value in
decimal, with a `.` inserted so that exactly `scale` digits follow it (left
padded with zeros, at least one digit before the `.`); no `.` when `scale =
0`; no rounding, no separators. Example: `1500000` at scale 6 is `1.500000`;
`5` at scale 6 is `0.000005`.

```
Edicta mandate v1
principal: <hex32>
mandate_id: <hex16>
version: <n>
gate: <gate_id>
valid: anchor time from <not_before> ; decision valid_until up to <not_after>
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
  - Limits are measured on the anchor time of each decision (block time of its payload), not on execution time.
  - Limits use hourly buckets; a bucket partly inside a window counts fully, so a limit may cover up to one extra hour (a "per 1h" limit may span up to 2h): the gate may deny early, never allow extra.
  - Limits count authorizations, not executions.
  - Counters continue across versions of this mandate_id; a new mandate_id starts from zero.
```

The text columns after `|` are the alternative of the same line. Without an
asset rule's key 5 the text MUST say `recipients: any`, and without the
mandate's key 13 `kinds: any`. The notes are fixed text. Vectors:
`spec/vectors/policy/render.json`.

## 8. Rule engine

### 8.1 Definitions

- `T_H`: the header time at `payload_ref.height` (core K0).
- Ledger: the state (section 9) plus the contents of its closed buckets.
- `seq`, `last_t`, `last_th`, `open`: fields of the state.
- Attribution time `T_eff = max(T_H, last_t)` (`T_H` when `seq = 0`).
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
`valid_until`). First failure wins.

| Rule | Check | Deny |
|---|---|---|
| P1 | `agent_pubkey` is in `agents` | `ErrAgentNotCovered` |
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
pure function of the facts, `T_H`, the counter state and fields of the
verified commitment; P9 is the one gate-clock rule and is deny-only. P4
compares `not_after` with the signed `valid_until` rather than with `T_H`,
because it bounds when the action may still run; it implies `T_H <
not_after` (core K1 and T2 give `T_H <= issued_at + skew_s < valid_until`).
New rules are added on demand, each as a new draft with vectors and
rendering.

### 8.3 Anchor age, stage 10p (P9)

`age = authorized_at - T_H` (0 if negative), with `authorized_at` the gate
clock of core stage 10. If `age > max_decision_age` the deny is
`ErrDecisionAge`, and its verdict carries `gate_clock = 1`. Absent
`max_decision_age` means `MaxTTL(payload_ref.da)` (core 11.1) with the gate's
parameters at that time.

Reasoning. Without P9 a decision may be authorized up to the Fibre retention
(about 4 h) after its anchor, which lets an old anchor land spend in an old
window and makes short windows dishonest. P9 is deny-only and gate-attested:
the verifier cannot check the gate clock, so P9 can only refuse.

### 8.4 Evaluation, stage 10p (P10 to P14)

`Evaluate(mandate, ledger, facts, T_H)`; first failure wins:

| Rule | Check | Deny |
|---|---|---|
| P10 | `T_H >= not_before` | `ErrOutsideMandate` |
| P11 | `min_spacing` absent, or `seq = 0`, or `T_H >= last_th + min_spacing` (saturating) | `ErrMinSpacing` |
| | Compute `T_eff`. If `seq >= 1` and `k(T_eff) > open.index`, roll over: the open bucket joins the closed set, closed buckets with `index < k(T_eff) - 767` are dropped, and the open bucket becomes empty at `k(T_eff)`. If `seq = 0` the open bucket is empty at `k(T_eff)`. | |
| P12 | for each `PeriodLimit(h, max)` of the asset's rule: `S(h, asset, scale) + amount <= max` (equality allowed) | `ErrPeriodLimit` |
| P13 | for each `CountLimit(h, n)`: `N(h) + 1 <= n` | `ErrCountLimit` |
| P14 | capacity, in this order: the open bucket's sum for `(asset, scale)` stays `<= 2^256 - 1` (reachable only for an asset without a period limit); its `count` stays `<= 2^63 - 1`; it holds at most 64 `(asset, scale)` pairs; `seq + 1 <= 2^63 - 1` | `ErrHistoryFull` |

On allow, `Apply(ledger, delta)` with `delta = (asset, scale, amount, T_H)`:
roll over as above, add `amount` to the open bucket's sum for `(asset, scale)`
(a new pair is inserted in order), `count + 1`, `seq + 1`, `last_t = T_eff`,
`last_th = T_H`. `Apply` checks no rule; it is the transition the verifier
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
  so `T_eff = T_H` and the bound holds on the anchor time itself. Without it,
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
  ? 11: anchor_time uint,            ; T_H
  ? 12: eval_time uint,              ; T_eff
  ? 13: prev_state State,            ; the state read, open bucket included
  ? 14: new_state_hash bstr .size 32,
  ? 15: prev_commitment_hash bstr .size 32,   ; the chain head read
  ? 16: prev_verdict_hash bstr .size 32,
  17: decided_at uint,               ; gate clock, > 0, informational
  ? 18: gate_clock uint              ; 1: the deny rests on the gate clock (P9)
}
SignedPolicyVerdict = { 1: verdict PolicyVerdict, 2: signature bstr .size 64 }
verdict_hash    = H(tag("edicta/policy/v1/verdict") || canon(PolicyVerdict))
signed_message  = tag("edicta/policy/v1/verdict-sig") || verdict_hash   ; 61 bytes, gate key
prev_state_hash = state_hash(prev_state)                                 ; derived, never a field
```

### 10.2 Presence (decoding rule, `ErrVerdictInvalid`)

| Verdict | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15, 16 | 18 |
|---|---|---|---|---|---|---|---|---|---|
| Allow | - | R | R | R | R | R | R | R iff `prev_state.seq >= 1` | - |
| Deny P1, P2 | R | - | - | - | - | - | - | - | - |
| Deny P3 | R | R | - | - | - | - | - | - | - |
| Deny P4 to P8 | R | R | R | - | - | - | - | - | - |
| Deny P9 | R | R | R | R | - | - | - | - | R (`= 1`) |
| Deny P10 | R | R | R | R | - | R | - | - | - |
| Deny P11 to P14 | R | R | R | R | R | R | - | - | - |

`-` is absent. A decoder tells the rows apart by `outcome`, `reason` and the
presence of key 11 (`ErrOutsideMandate` is P4 without it, P10 with it).
`reason` is one of the thirteen deny names of sections 8.2 to 8.4. `decided_at`
is the gate clock at the verdict: `authorized_at` of core stage 10 for stage
10p verdicts, `now` of core stage 1 for stage 4p. No verifier rule reads it.
The verdict contains no tx hash and no rail reference (core invariant 6).

### 10.3 Chain rules (normative)

For consecutive allows `n - 1` and `n` of one counter:
- `prev_commitment_hash(n) = commitment_hash(n-1)`, `prev_verdict_hash(n) = verdict_hash(n-1)`;
- `prev_state_hash(n) = new_state_hash(n-1)`;
- `new_state_hash(n) = state_hash(Apply(ledger(n), delta(n)))`, where
  `delta(n) = (facts.asset, facts.scale, facts.amount, anchor_time)`;
- `prev_state(n).seq = prev_state(n-1).seq + 1`.

**Fork.** Two allow verdicts signed by one gate, with the same `gate_id`, whose
mandates have the same `counter_key`, the same `prev_state.seq` and different
`commitment_hash`. In particular two allows with the same `prev_state_hash`
and different successors are a fork. One counter has exactly one allow per
`seq`, so an honest gate never signs a fork; a gate whose registry was lost
and recreated restarts at genesis and is reported as forking, which it is (it
re-spends headroom).

Vectors: `spec/vectors/policy/verify.json` (and the verdicts inside it).

## 11. Gate integration

### 11.1 Stages

The core order of section 8.7 with two stages added. Without a mandate both
are skipped and nothing else changes.

| # | Stage | What | Sentinels |
|---|---|---|---|
| 1 to 4 | D..C, E, L, A | unchanged | core |
| 4p | Admission | P1 to P8 (8.2). A deny signs a deny verdict and then runs stage 4a, whose failure does not change the deny | 8.2 |
| 4a | AR | unchanged; also runs after a 4p deny | core |
| 5 to 10 | N0, K, K1, K2, P, T' | unchanged | core |
| 10p | Evaluation | P9 (8.3). Then take the policy lock, read the counter cell, `Evaluate` (8.4). A deny signs a deny verdict (with `prev_state` from the cell), releases the lock, writes nothing to the registry | 8.3, 8.4 |
| 11 | Z | the Authorization, and the allow verdict with `prev_state`, `new_state_hash` and the chain links, both signed with the gate key under their own tags | core |
| 12 | N | `ConsumeState`: the nonce entry (with the signed verdict and, when the allow closed an hour, the closed Bucket and the new ClosedSet bytes) and the cell compare-and-swap in one atomic, durable transaction; then release the lock | `ErrNonceUsed`, `ErrPolicyStateConflict` |
| 13 | R | the Authorization and the verdict | |

- Every deny wraps `policy.ErrDenied`. A deny's verdict is returned with it
  and archived with the rejection marker (12.3). Stage 1 to 4 failures beat
  the policy and sign nothing.
- Operational failures sign nothing and are not marked: registry, signer,
  a cancelled lock, `ErrPolicyStateConflict` (the cell changed under the
  compare-and-swap; 503, retryable, nothing written).
- Retry rule (core 8.7) extended: the stored entry returns its Authorization
  and its verdict; a same-commitment retry never reaches 10p, so nothing is
  counted twice.
- Policy lock: one per gate, held from the cell read through stage 12, and
  it is ctx-aware. With a shared counter, concurrent requests are serialized.

### 11.2 Invariant 8 (core)

| Clause | Where |
|---|---|
| allows only if the verdict for exactly the committed action allows | 4p and 10p decide; Z signs only after both allow |
| facts from the registered extractor; no extractor or a parse failure is a deny | P2, P3, X4 |
| rules on `T_H` | P10 to P13 use `T_H` and `T_eff`; only P9 reads the gate clock |
| counter update atomic with the nonce mark | stage 12 |
| deny-only, fail-closed | every policy error refuses; nothing in the policy can skip a core stage |
| verdict under the gate's policy tag, no tx hash or rail reference | 10.1 |
| mandate signed by its principal, bound to this `gate_id`, version not lower than current | adoption (6.3), and every compare-and-swap of stage 12 |

### 11.3 HTTP (additive to core 18)

- `POST /v0/authorize` 200 response: `{1: signed_authorization bstr, ? 5:
  policy_verdict bstr}`. Key 5 holds the canonical SignedPolicyVerdict and is
  present iff the gate has a mandate.
- Error body: new optional key `5: policy_verdict bstr` (1..16384). Present
  on every policy deny, and on a 409 `ErrNonceUsed` that carries `stored`
  when the stored entry holds a verdict. No other code carries it.
- Mapping. Policy codes are prefixed with the package (`policy.`), as core
  18.3 prescribes for packages other than `commitment` and `gate`. They wrap
  no core sentinel and are matched after every core code of their status:

| Status | Codes, in match order | `retryable` |
|---|---|---|
| 403 | `policy.ErrAgentNotCovered`, `policy.ErrNoExtractor`, `policy.ErrOutsideMandate`, `policy.ErrKindNotAllowed`, `policy.ErrAssetNotAllowed`, `policy.ErrRecipientNotAllowed`, `policy.ErrAmountAboveMax`, `policy.ErrMinSpacing`, `policy.ErrPeriodLimit`, `policy.ErrCountLimit`, `policy.ErrHistoryFull` | 0 |
| 410 | `policy.ErrDecisionAge` | 0 |
| 422 | `policy.ErrFactsInvalid` | 0 |
| 503 | `ErrPolicyStateConflict` (package `gate`) | 1 |

`ErrHistoryFull` shares 403 but has its own code: it is capacity, not a limit.
A client with a strict decoder that does not know key 5 fails on a mandate
gate's answers; that is the core rule for unknown keys, and a mandate is new
configuration. Vectors: `spec/vectors/policy/api.json`.

### 11.4 Registry (implementation rules, no wire format)

The cell under `counter_key` holds the mandate ID, version and hash, the
`scales` map (6.3), the chain head (`commitment_hash`, `verdict_hash` of the
last allow) and the ledger (state and retained closed buckets, at most 768
buckets). Cells are never pruned.

The nonce entry of an allow holds, next to the SignedPolicyVerdict, the
canonical bytes of the Bucket closed by that allow and of the ClosedSet it
produced (both absent when the allow did not roll an hour over). They are
written in the same transaction as the cell, so they are exactly as durable
as the spend they describe: whatever the archive loses, the registry can
rewrite in chain order. Cost: at most 16,384 + 36,864 bytes, only on the
first allow of an hour. These bytes are archive data, not evidence: the
entry is gate-local and its encoding is not normative. The entry may be
pruned with the core nonce prune rules; the archive is the long-term copy,
and the rewrite must succeed before a prune (12.2). `ConsumeState` refuses, writing nothing, in this order: an existing
nonce entry (`ErrNonceUsed`), the core prune and clock watermark refusals,
then a cell that changed since it was read (`ErrPolicyStateConflict`). An
undecodable cell is `ErrRegistryUnavailable` (fail-closed).

## 12. Archive records

Policy records extend archive format 0 (core 19) without changing any
existing record. Kind 6 is reserved and never assigned (the core vector
`rec_kind_6` pins it as undefined). Every record is `{1: format = 0, 2: kind,
...}` under the rules of core 19.1; the nested policy structure travels as a
`bstr` and is strictly decoded with section 3, its sentinel as the cause.
Signatures are not checked at decoding; readers check them (section 13).

### 12.1 Kinds

| Kind | Name | Fields (key: name, type) | Logical key | Canonical path | Cap (bytes) | Identity (core AW2) | Precondition (core AW4) |
|---|---|---|---|---|---|---|---|
| 7 | `mandate` | 3: `signed_mandate` bstr 1..16384 | `mandate_hash` | `mandate/<hex>` | 16,448 | whole record | none |
| 8 | `policy_allow` | 3: `signed_verdict` bstr 1..16384, `outcome = 1` | `commitment_hash` (verdict key 4) | `policy-allow/<hex>` | 16,448 | whole record | the decision record and the mandate record of its `mandate_hash` |
| 9 | `policy_deny` | 3: `signed_verdict` bstr 1..16384, `outcome = 2` | `(commitment_hash, reason)` | `policy-deny/<hex>/<reason>` | 16,448 | the key (first write stays) | the decision record |
| 10 | `policy_bucket` | 3: `bucket` bstr (canonical Bucket) | `bucket_hash` | `policy-bucket/<hex>` | 16,448 | whole record | none |
| 11 | `policy_closed` | 3: `closed_set` bstr (canonical ClosedSet) | `closed_root` | `policy-closed/<hex>` | 36,928 | whole record | none |
| 12 | `policy_successor` | 3: `gate_id` tstr (ID, 1..64), 4: `counter_key` bstr 32, 5: `state_hash` bstr 32, 6: `commitment_hash` bstr 32 | `successor_key` (2.2) | `policy-successor/<hex>` | 256 | whole record | the `policy_allow` record of `commitment_hash`, whose verdict has this `gate_id` and `prev_state_hash = state_hash`, and whose mandate has this `counter_key` (otherwise `archive.ErrNotFound` when absent, `archive.ErrCorrupt` when it differs) |

A reader recomputes the key from the record (hash of the nested bytes, or
the verdict's fields, or `successor_key` from fields 3 to 5) and reports a
mismatch as corrupt (core 19.3). A `policy_allow` record holding a deny, or the
reverse, is corrupt (`ErrInvalidEnum`). A second `policy_successor` write with
another `commitment_hash` is `archive.ErrConflict`: an honest gate never
causes one, so the writer MUST log it at error level as a possible fork.

`successor_key` and not `state_hash` alone: every counter starts at the same
genesis state, so a key without the counter would collide across mandates
and gates sharing one archive.

### 12.2 Writers

- Gate start: the mandate record and the genesis ClosedSet. A failed write
  refuses the start.
- After an allow (stage 13), in this order: when an hour closed, the closed
  bucket and the new ClosedSet; then `policy_allow`; then `policy_successor`;
  then the Authorization record (core 10.7). Policy records first, so that a
  crash leaves no Authorization record without its verdict. A failed write
  does not change the answer; the gate repairs it (below).
- After a policy deny: `policy_deny` and the rejection marker (12.3).
- Repair (start and sweep): for each registry entry of an allow, in chain
  order (ascending `prev_state.seq` per counter), the writer rewrites the
  same chain as above from the entry alone: the closed Bucket and ClosedSet
  stored in the entry (when present), `policy_allow`, `policy_successor`,
  then the Authorization record. Every record is content-addressed or keyed
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

The marker verdict list of core 19.2 gains the thirteen policy deny names, bare:
`ErrAgentNotCovered`, `ErrNoExtractor`, `ErrFactsInvalid`,
`ErrOutsideMandate`, `ErrKindNotAllowed`, `ErrAssetNotAllowed`, `ErrRecipientNotAllowed`,
`ErrAmountAboveMax`, `ErrDecisionAge`, `ErrMinSpacing`, `ErrPeriodLimit`,
`ErrCountLimit`, `ErrHistoryFull`. `ErrPolicyStateConflict` is operational and
never a marker.

Vectors: `spec/vectors/policy/archive.json`.

## 13. Verifier

### 13.1 When the check runs

The named check `policy` (core 20.1) runs for a decision in record state
`authorized` when `RequirePolicy` is set or a `policy_allow` record exists for
it; it is then required for `valid`. `RequirePolicy` is the auditor's
statement that the gate had a mandate: without it, an archive that withholds
the allow record silently skips the check. Every report also carries
`gate_integrity` (13.4). Inputs: the gate key on record for `gate_id` (the
key Authorizations verify under), `PrincipalKeys`, the extractor registry,
`T_H` if header trust passed, and optionally `PolicyFull`, `PolicyDepth` and
`Evidence` (extra signed verdicts, for example those agents received).

### 13.2 Fast check (always)

Let `V` be the target verdict. Steps in order. The first **fail** or
unchecked result ends the steps, except the unverified-`T_H` case of step 4,
after which the steps go on. A violation found in steps 1, 5 or 6 does not end
them. The full check and the fork search (13.3) run whenever step 1 passed,
and only the first violation found is reported.

1. **Allow record.** Absent: unchecked (`policy_verdict_unavailable`).
   Undecodable, key mismatch, or a gate signature that does not verify:
   unchecked (`source_corrupt`). If `V` names this commitment but another
   `action_hash`, `agent_pubkey` or `gate_id` than the verified decision, the
   gate contradicts itself: `gate_integrity` violated, evidence `[V]`.
2. **Mandate** of `V.mandate_hash`. Absent: unchecked
   (`policy_mandate_unavailable`). Undecodable, key mismatch or bad principal
   signature: unchecked (`source_corrupt`). Principal not in `PrincipalKeys`:
   unchecked (`policy_principal_untrusted`). `mandate.gate_id != V.gate_id`:
   **fail** (`mandate_gate_id`).
3. **Facts.** No extractor for `action.type`, or one with another ID than
   `V.extractor`: unchecked (`policy_no_extractor`). Extraction from the
   verified action bytes refuses, or gives other facts than `V.facts`:
   **fail** (`facts_mismatch`).
4. **Per-action rules** on verified data, in order: P1, P4 (`valid_until`
   from the verified envelope), P5, P6, P7, P8: any failure is **fail** with its
   sentinel name. If `T_H` is verified: `V.anchor_time != T_H` is **fail**
   (`anchor_time_mismatch`), then P10 on `T_H`. If `T_H` is not verified,
   these two are unchecked (`blocked`, naming `header_trust`) and the steps go
   on.
5. **Closed buckets.** The ClosedSet of `V.prev_state.closed_root` (genesis:
   no read), then every bucket with `index >= k(V.eval_time) - W`, where `W`
   is the largest `hours` among the asset's periods and the count limits (0
   if none). Absent: unchecked (`state_history_unavailable`). Bytes that do not
   hash to their key or fail decoding: unchecked (`source_corrupt`). A ledger
   that fails 9.2 is a gate-signed contradiction: `gate_integrity` violated,
   evidence `[V]`.
6. **Evaluation on the signed state.** `V.eval_time != max(V.anchor_time,
   prev_state.last_t)` is **fail** (`eval_time_mismatch`). `Evaluate(mandate,
   ledger, V.facts, V.anchor_time)` must allow; a deny is **fail** with its
   sentinel name: the gate's own signed state contradicts its allow. Then
   `state_hash(Apply(ledger, delta(V)))` must equal `V.new_state_hash`; if not,
   the transition is self-inconsistent: `gate_integrity` violated, evidence
   `[V]`.

### 13.3 Full check (`PolicyFull`, CLI `--policy-full`)

Runs when step 1 passed and no violation was found yet. **Walk** from `n = V` back along
`prev_commitment_hash` and stop at genesis (`prev_state.seq = 0`), after
`PolicyDepth` hops, or when `prev_state.last_t` is older than
`V.eval_time - 32 days` (the retention horizon; the default depth). Per hop,
read the `policy_allow` record of `n.prev_commitment_hash` as `p` (absent:
`state_history_unavailable`; undecodable, key mismatch or bad signature:
`source_corrupt`), then `CheckLink(p, n)`, first failure wins:

| # | Check | On failure |
|---|---|---|
| L1 | `verdict_hash(p) = n.prev_verdict_hash` | violated `[p, n]` (unlinked) |
| L2 | `p.new_state_hash = prev_state_hash(n)` | violated `[p, n]` (unlinked; catches an understated `prev_state`) |
| L3 | `p.prev_state.seq + 1 = n.prev_state.seq` | violated `[p, n]` (seq gap) |
| L4 | the mandates of `p` and `n` (read like step 2; absent or corrupt as there) have the same principal, `mandate_id` and `gate_id`, and `version(p) <= version(n)`, else violated `[p, n]`. Then the scale rule of 6.3, over every mandate reached: every asset of `mandate(p)` that a mandate of `n` or of any later walked verdict lists has the same scale there, else violated `[p, w]`, `w` the walked verdict nearest to `p` whose mandate lists that asset at another scale | violated `[p, n]` or `[p, w]` |
| L5 | `state_hash(Apply(ledger(p), delta(p))) = p.new_state_hash`, with the ClosedSet of `p.prev_state.closed_root` (absent or corrupt as in step 5) | violated `[p]` (self-inconsistent) |

**Forks** (both modes). The held allow verdicts are: `V`; in the full mode
every walked verdict and every verdict a `policy_successor` record leads to
(for each walked `n`, the record under `successor_key(gate_id, counter_key,
prev_state_hash(n))`; if it names another commitment, read that allow); and
every `Evidence` verdict that decodes, is an allow, and verifies under the
gate key. A held verdict whose mandate cannot be read is ignored. Two held
verdicts that fork (10.3): violated, evidence both. The successor index is a
help only: a dishonest gate can leave it out, and an archive can lie in it,
so only signed verdicts are ever evidence.

The walk proves this: an understated open bucket in `prev_state(n)` cannot
hash to `new_state_hash(n-1)` unless `n - 1`'s transition is itself
inconsistent (L5). Either way a signed contradiction comes out.

### 13.4 Outcomes

| Finding | `policy` | `gate_integrity` |
|---|---|---|
| A per-action rule fails; facts differ from the re-extraction; the mandate is bound to another gate | fail | unchanged |
| A rule fails on the gate-signed `prev_state`; `eval_time` or `anchor_time` contradicts verified data | fail | unchanged |
| History missing: a ClosedSet, a needed bucket, or a verdict or mandate the walk needs | unchecked (`state_history_unavailable`) | `unchecked` with that reason if it happened in the walk |
| History bytes that do not hash to their key or do not decode | unchecked (`source_corrupt`) | same rule |
| Fork; unlinked consecutive verdicts; a self-inconsistent transition or ledger; a seq gap; a version decrease, a scale change or a `mandate_id`, principal or `gate_id` change inside one chain; a verdict that contradicts the verified decision | unchecked (`blocked`, naming `gate_integrity`) unless already fail or unchecked | `violated`, reason `gate_equivocation`, evidence: the signed verdicts (one for a self-inconsistent one) |
| Walk completed without findings | per the fast check | `ok` |
| No walk and no violation | per the fast check | `not_checked` |

`gate_integrity` is `{status: ok | violated | not_checked | unchecked, reason,
evidence: [SignedPolicyVerdict bytes]}`; with `violated` the report also lists
each evidence `verdict_hash`. Without a policy check it is `not_checked`.

Precedence inside `policy`: fail; then `blocked` by a violation; then the
first unchecked reason of the fast check; then that of the walk; else pass.
The agent may be honest when the gate equivocates, so equivocation never
makes the decision invalid; a proven fail stays fail, and `gate_integrity` is
still set and printed.

### 13.5 Verdict and exit code

Core 20.1 as amended in `v0-draft.29`: the verdict is `unchecked` whenever
`gate_integrity` is `violated` and no check fails, and the CLI exits with
code 5 in that case. Precedence of exit codes: 4, then 1, then 5, then 3,
then 2, then 0. The text output starts with the line `GATE INTEGRITY VIOLATED
(gate_equivocation)` whenever the status is `violated`, including with exit 1.

The report's `policy` block: `mandate_hash`, `mandate_id`, `version`,
`principal`, `seq` (of `prev_state`), `anchor_time`, `eval_time`, `facts`,
`extractor`, `prev_state_hash`, `new_state_hash`, and `denials` (policy deny
records of this decision, informational; `ErrDecisionAge` flagged
gate-attested). A verifier MAY skip reading deny records.

### 13.6 What it proves

- The principal's mandate, the gate's allow for exactly this action, the
  facts, the per-action rules, and that the allow is consistent with the
  exact state the gate signed.
- With the walk and evidence: that the gate's published chain has no
  internal contradiction back to the depth reached.

Not proven: allows the gate kept outside every chain and every piece of
evidence (an Authorization of that kind is itself evidence when it surfaces);
the rule P9; execution.

## 14. Sentinels

Package `policy` unless noted. Deny sentinels wrap `ErrDenied`.

| Sentinel | Where | Meaning |
|---|---|---|
| `ErrDenied` | all denies | umbrella, never reported alone |
| `ErrAgentNotCovered` | P1 | agent not in the mandate |
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
| `ErrMandateSignature` | 6.2 | principal signature |
| `ErrVerdictInvalid` | 10 | verdict decoding or presence rule |
| `ErrVerdictSignature` | 10.1 | gate signature on a verdict |
| `ErrStateInvalid` | 9 | Bucket, ClosedSet, State or ledger |
| `ErrPolicyStateConflict` (package `gate`) | 11.4 | cell changed concurrently (operational) |
| `ErrPolicyViolation` (package `verifier`) | 13 | wraps every `policy` fail |

## 15. Vectors

Location `spec/vectors/policy/`. Every file has `"format":
"edicta-policy-vectors/v1"` and `"revision"` set to the revision that last
changed its bytes: `policy-v1-draft.2` for `mandate.json` and `verify.json`,
`policy-v1-draft.1` for the others. JSON as core
section 13: uints are decimal strings, byte strings and amounts lowercase
hex, text as JSON strings, optional fields absent when unset. Keys: `agent1`,
`agent2`, `gate1` of core `keys.json`; principals `p1`, `p2` with seed
`SHA-256("edicta/policy/v1 test principal|" + name)`. Commitment hashes in the
engine and verify files are stand-ins, `SHA-256("edicta/policy/v1 test
commitment|" + label)` (no envelope; the policy check takes the decision's
fields as verified by the core checks).

| File | Contents |
|---|---|
| `facts.json` | `test_extractor`; `cases`: `input`, `cbor_hex`. `reject`: `cbor_hex`, `expect_error` = `ErrFactsInvalid`, `cause`. |
| `mandate.json` | `tags`, `keys`; `cases` (including a full mandate with `kinds`, `not_before` and every optional field, and a version 2 with the same counter key): `signer`, `input`, `mandate_cbor_hex`, `mandate_hash_hex`, `signed_message_hex`, `signature_hex`, `signed_mandate_hex`, `counter_key_hex`. `reject`: `signed_mandate_hex`, `expect_error` (`ErrMandateInvalid` or `ErrMandateSignature`), `cause`. `adoption` (6.3, from an absent cell): `steps` of `signed_mandate_hex`, `mandate_hash_hex`, `expect` (`genesis`, `use`, `switch` or `refuse` with `error` = `gate.ErrInvalidConfig` and `cause` = `version`, `same_version_other_hash` or `scale`), `version_after`, `scales_after` (the cell after the step; a refusal leaves it unchanged). Cases: a scale change of an unused asset; a scale change after an intermediate version dropped the asset; scales kept with an added asset, then a restart; a lower version; the same version with another hash. |
| `render.json` | `cases`: `mandate_ref` or `input`, `text`. |
| `state.json` | `genesis` (bytes, hash, empty ClosedSet bytes and root); `buckets`, `closed_sets`, `states` (input, bytes, hash); `coverage` (two states differing in one open sum, with different hashes); `reject` per structure. |
| `engine.json` | `scenarios`: `mandate`, optional `start` ledger (state, closed set and bucket bytes), `steps` (admitted `facts` and `t_h`, or a `repeat` form; `expect`: `allow` with `eval_time`, `new_state_hash_hex`, `new_state_cbor_hex`, `rolled_over`, `closed` count and, after a rollover, the closed bucket hash and ClosedSet bytes; or `deny` with the sentinel and, for `ErrHistoryFull`, `cause` = `sum`, `count`, `pairs` or `seq`), `final`. Scenarios: limit edges, bucket rounding, counts, min spacing, clamp, rollover, `not_before`, two assets, retention 767 over 800 hours, every `ErrHistoryFull` cause. |
| `verify.json` | `gate`, `extractors`; `records` (archive record bytes by canonical path); `cases`: `decision` (the fields the core checks verified), `t_h` (absent: header trust did not pass), `config` (`require_policy`, `policy_full`, `policy_depth`, `principal_keys`, `extractors`, `evidence`), `archive` (paths present), optional `corrupt` (path to replacement bytes), `expect` (`policy` with `status` and `rule` or `reason`; `gate_integrity` with `status`, `reason`, `evidence` verdict hashes; `verdict`; `exit`). One case per outcome row of 13.4: passes (genesis, closed bucket, hour rollover, chain continuity, depth); every unchecked reason; every per-action fail including kind and `not_before`; fails on the signed state; fork by evidence and by successor record; unlinked verdicts; self-inconsistent transition; understated open bucket (fast passes, walk exit 5); version decrease; scale change across a version boundary, consecutive and after an intermediate version dropped the asset (evidence the two verdicts whose mandates disagree); a walk across a version boundary that keeps every scale (no equivocation); seq gap; missing and corrupt history; fail with equivocation (exit 1). |
| `archive.json` | `kinds`, `reserved_kinds`, `marker_names`; `cases`: `kind`, `path`, `key_hex`, `record_cbor_hex` (each also in `verify.json`). `reject`: `record_cbor_hex`, `expect_error` = `archive.ErrCorrupt`, `cause`. |
| `api.json` | the 11.3 mapping and example bodies (deny with key 5, authorize response with key 5, 409 with keys 4 and 5). |

Profile vectors: `spec/vectors/profiles/bank-send/tia_transfer_facts.json`
(bank-send profile section 2.4).

Generation and checks: `spec/vectors/check/gen_policy.py` writes every file
above with the rules module `policy_v1.py`; `check_policy.py` (run by
`check_vectors.py`) regenerates and compares bytes, and independently
re-implements the encodings, hashes, signatures, strict decoding, rendering,
the engine and the verifier outcome rules from this document and checks
every expectation with them.
