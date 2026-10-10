# Errata to the frozen v1 specifications

Scope: `spec/decision-commitment-v1.md` (revision `v1.0`), `spec/policy-v1.md`
(revision `policy-v1.0`) and their vectors. The frozen texts are the source of
truth. An erratum changes only a conformance expectation, or wording that
contradicts other frozen text. It never changes wire bytes, hashes, domain
tags or invariants: such a change needs a new format version and the human's
decision.

Versioning: an erratum keeps the revision labels (`v1.0`, `policy-v1.0`), in
the spec texts and in the `revision` field of the vector files, because no
byte string that a v1.0 implementation produces or accepts changes meaning.
The fix commit carries the annotated patch tag `v1.0.N` (E1 = `v1.0.1`), whose message lists
the erratum ids and the new hashes of `spec/vectors/MANIFEST.sha256`.
`v1.0.0` never moves. Patch tags `v1.0.N` are shared with code-only fixes
that change no wire byte; such tags carry no erratum and are not listed here
(`v1.0.2`: code-only).

Threat note: a frozen vector that contradicts the frozen text pushes
implementations to invent a rule that no text defines. Here that rule would
be a policy-only record reader, and two readers of one archive would then
disagree on the cause of a corrupt record. The fix is always to the vector.

## E1. Record causes in `policy/archive.json` follow the general record reader

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
