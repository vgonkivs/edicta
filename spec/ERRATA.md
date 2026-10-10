# Errata to the frozen v1 specifications

Scope: `spec/decision-commitment-v1.md` (revision `v1.0`), `spec/policy-v1.md`
(revision `policy-v1.0`) and their vectors. The frozen texts are the source of
truth. An erratum changes only a conformance expectation, or wording that
contradicts other frozen text. It never changes wire bytes, hashes, domain
tags or invariants: such a change needs a new format version and the human's
decision.

Versioning (core section 0, amended 2026-10-10). The wire format is frozen
for good. After the freeze the spec has one revision counter, `v1.0.1`,
`v1.0.2`, ..., and each revision has one typed changelog entry in core
section 0: `erratum`, `security` or `clarification`. This file holds the
detailed record of the `erratum` and `clarification` entries (ids E1, E2,
... across both types); a `security` entry is recorded in the core changelog
and the section it changes. Every revision gets the annotated tag
`spec-v1.0.N`, whose message lists the entry ids and, when vectors changed,
the new hashes of `spec/vectors/MANIFEST.sha256`. The revision labels in the
spec texts (`v1.0`, `policy-v1.0`) and the `revision` field of the frozen
vector files stay unchanged, because no byte string that a v1.0
implementation produces or accepts changes meaning.

Software releases are a separate, semantic-version sequence (`v1.0.0`,
`v1.0.1`, ...); their release notes state the spec revision they implement.
The two sequences may share a commit and need not share a number:
`spec-v1.0.1` (E1) and the software tag `v1.0.1` are both on `0ac2689`,
while the software tags `v1.0.2` and `v1.0.3` are code-only releases of spec
revision `v1.0.1`. No freeze tag ever moves.

An erratum or clarification never changes a check outcome. A stricter
outcome is a `security` revision (only to close a path to a false `valid` or
`invalid`, with the human's approval); a relaxation needs a minor revision
`v1.1` (core section 0).

Threat note: a frozen vector that contradicts the frozen text pushes
implementations to invent a rule that no text defines. Here that rule would
be a policy-only record reader, and two readers of one archive would then
disagree on the cause of a corrupt record. The fix is always to the vector.

## E1. Record causes in `policy/archive.json` follow the general record reader

- Type: erratum. Spec revision `v1.0.1`, tag `spec-v1.0.1`.
- Date: 2026-10-10.
- Author: protocol-engineer (task 040), approved by the human.
- File: `spec/vectors/policy/archive.json`, array `reject`. Record bytes,
  ids, `expect_error` and every other case are unchanged; only `cause` and
  `description` of the two cases below change.

| Case | Old `cause` | New `cause` |
|---|---|---|
| `kind_13` | `ErrInvalidEnum` | `ErrWrongType` |
| `private_over_cap` | `ErrTooLarge` | `ErrTrailingData` |

Rationale. Policy 12 puts policy records "under the rules of core 19.1", so
there is one strict reader for every format 1 record, and the first failure
in its order decides. The policy vectors had taken their causes from a
policy-only reader that ran its own header checks.

- `kind_13` is `{1: 1, 2: 13, 3: <signed mandate bstr>}`. Core 19.1 assigns
  kind 13 (anchor intent) in the `kind` row and in strict decoding step 3, so
  step 3 passes. Step 5 then checks the kind 13 schema of core 19.2, where key
  3 `da` is a uint. The record has a bstr there, so the cause is
  `ErrWrongType`. The core vector `v1/archive.json` accepts kind 13 records
  (`intent_fibre`, `intent_blob`) through the same reader, so `ErrInvalidEnum`
  here also contradicted another frozen vector. Kinds 3, 6 and 16 stay the
  unassigned-kind cases (`kind_6_reserved` here, `kind_3_unassigned`,
  `kind_6_reserved`, `kind_16_reserved` in `v1/archive.json`).
- `private_over_cap` is 69,761 bytes whose map head counts four entries
  while a fifth (key 5) follows. Core 19.1 checks only `MaxRecordSize` before
  parsing (step 1). Generic well-formedness (step 2) runs next and finds bytes
  after the four-entry map (`ErrTrailingData`). The per-kind cap (step 4,
  69,760 for kind 15) is never reached. The old expectation came from a reader
  that checked the kind 15 cap before parsing, which no text allows. The case
  no longer exercises the kind 15 cap; a well-formed over-cap kind 15 record
  is a candidate for a later vector revision. Adding that record is outside
  an erratum.

Sweep (whole class). Every vector record of format 1 was decoded with the
general reader: `v1/archive.json`, `archive/records.json`,
`policy/archive.json` (cases and rejects), and the record pools of
`policy/verify.json` and `policy/private.json`. Every expectation that names
a kind, or another enum value, as invalid (`ErrInvalidEnum`) was compared with
the frozen tables (core 19.1 kind row and step 7, core 19.2, policy 6 and 12).
The two cases above were the only disagreements. No suite expects an assigned
kind to be refused as unassigned, or an unassigned kind (3, 6, 16) to be
accepted. No record appears in two suites with different expectations.

Prevention. `spec/vectors/check/records.py` is the general reader. It reads the
assigned and unassigned kinds from the frozen core text, runs core 19.1
steps 1 to 3 once, and then the kind's schema: core kinds through
`archive.py`, policy kinds 7 to 12 through `policy_v1.py`. `gen_policy.py`
computes the reject causes with it. `check_records.py` (run by
`check_vectors.py`) decodes every listed record of all suites with this one
reader. It fails when a record's outcome differs from its expectation, when
one record carries different expectations in two suites, or when a decoder or
vector kind table differs from core 19.1. `check_policy.py` independently
checks every reject that is not of a policy kind 7 to 12 against the core
rules module `archive.py`. Each check fails on the old `kind_13` expectation.

Manifest after E1 (`spec/vectors/MANIFEST.sha256`, changed line):

```
35a024bbfed92ce6e2dedec387ceb27c1d260e3b2df22fe3b5393e97857e9847  spec/vectors/policy/archive.json
```

## E2. "Anchored" means inclusion proven; the anchor tx result is not part of the claim

- Type: clarification. Spec revision `v1.0.2`, tag `spec-v1.0.2` (the human
  creates it).
- Date: 2026-10-10.
- Author: protocol-engineer (task 045), human decisions of 2026-10-10
  (task 045 `questions.md`: round 1 answer 1, round 2 answer A, and the
  complete `da = 1` definition). Supersedes the first E2 text (commit
  `2afafcd`, never tagged), which called the code `node-attested` under the
  report's assumptions.
- Files: `spec/decision-commitment-v1.md` sections 0, 1, 10.4 (facts), new
  10.6.3, 10.6.1 (report table, settlement paragraph), 10.7, 12.2, 13.1,
  19.8, 20.6, 20.9, 20.10, 23. No vector file changes; no vector carries the
  printed report lines.

| Place | Before | After |
|---|---|---|
| Definition | "anchored" undefined; 20.9 put it under `Proven:` | 10.6.3: inclusion proven against the trusted header at `H`. `da = 2`: the blob's commitment proof against the data root. `da = 1`: complete `PFF_NS` namespace proof against `data_hash`, txs parsed from the proven shares, the PFF selected by its commitment; CV2; certificate CV3 to CV7 offline against the archived `historical_info`, promise header on the trusted chain |
| 20.9, `Proven:` line | "anchored on L1 no later than T_H" (first E2: "... (anchor tx included; anchor tx result code node-attested)") | "anchored on L1 no later than T_H (anchor inclusion proven)" |
| 20.9, result code | first E2: `Assumptions: anchor tx result: node-attested` | `da = 1` only, informational, not an assumption: `anchor tx result: code 0, node-reported, not part of the claim`; JSON `anchor_tx_result` |
| 10.6.1 report | `settlement: node-attested` | unchanged, plus `anchor_tx_result` (both modes, `da = 1`) |
| Section 1 | first E2: row "Nothing in `v1.0` (open gap)" | row "Anchored means inclusion proven": `tx_code` is the only node-attested field of the evidence and is not part of the claim |
| 10.7 | block results and header `height + 1`: SHOULD, for a planned proven settlement | MAY; no proven settlement level is planned |
| `UNVERIFIED` | non-zero PFF code; unsettled shard retention; keeper height window at the pin | VERIFIED by code at the pin (task 045 `fibre-shards-research.md`); new items: failed-PFB shares count as published (`da = 2`), no out-of-tree shard pruning |

Scope check: no check outcome changes. CV8 keeps requiring the archived
`tx_code = 0`, and the evidence record still admits only 0 (section 19.2):
dropping that requirement would turn an `unchecked` into a pass, a
relaxation, which section 0 allows only in a minor revision. Every other rule
named in 10.6.3 is an existing rule (NA2 to NA5, CV2 to CV8, section 10.5,
section 10.6.2). The x/fibre height window is implied by inclusion under the
honest-majority assumption (ProcessProposal executes every PFF message); no
check is added for it, because the parameter's value at `H` is not archived
and has no upper bound. Wire bytes, hashes, tags, records, reasons and
vectors are unchanged.

Rationale. The human defined the claim: a fast-mode or strict decision is
"anchored" when inclusion is proven; the result code says whether the
escrow (`da = 1`) or the fee payer (`da = 2`) paid, not whether the payload
was published. Research at the pin (task 045) shows that validators fix
shard retention at upload and prune on wall-clock time only, whatever the
PFF's result, and that a PFF can be included with a non-zero code only
through an ante failure, after its message (escrow, expiry, replay, height
window) passed in ProcessProposal. For `da = 2` the shares are in the square
whatever the PFB's result, and the absence proof (AB6) already reads no
code. The first E2 text reported a node-attested code as an assumption of
the verdict; it is not one.

Sweep (whole class). Every statement that calls the anchor, its settlement
or its result code proven or assumed was read: sections 1, 10.4 (NA6, NA7,
the lookup threat note), 10.6.1 (CV8, `settlement`), 10.7, 11.1, 12.2, 13.1,
19.2 (`tx_code`), 19.8, 20.1, 20.6, 20.9, 20.10, 23. The gate's NA6 and NA7
and K-fast F6 and B5 keep requiring code 0 for the gate's own lookup; that
is the gate's check, unchanged. Outside the spec, not changed here (owners:
programmer, docs): `verifier/pending.go` and the `da = 1` report (replace
the assumption line of the first E2 with the informational
`anchor_tx_result` line, in both modes), and `guide/verifier.md` (the copy
of the 20.9 block).

Prevention. The informational line and the JSON value are fixed strings that
the verifier's report test can compare. No vector change; the manifest is
unchanged.

Addendum (same revision, human answers R3 of 2026-10-10, task 045
`questions.md`). Clarifications only, no check outcome changes, no vector
changes:
- 10.6.3, next to the definition: "v1.0 verifiers additionally require
  `tx_code == 0` (CV8); this requirement is removed in v1.1."
- 10.6.3, promise height: the included-reference window is stated as an
  assumption that follows from inclusion, with the pinned call path
  (`ProcessProposalHandler` `if isPFF` branch -> `executeTxMsgs` ->
  `msgServer.PayForFibre` -> `validatePaymentPromiseStatefulInternal`); the
  window parameter is not archived. Pending references rest on the gate's
  K-fast rule (13.3 window cap, F5 (2)), covered by `v1/anchor.json`
  `window_chain_min`, `window_chain_zero` and the gate's fast-mode tests.
- New section 23.2, re-pin checklist; item PC1 re-verifies that
  ProcessProposal still enforces the window.
