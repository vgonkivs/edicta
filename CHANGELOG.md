# Changelog

## v1.1 (spec revision v1.1)

An additive minor revision. No byte of a frozen v1.0 object, archive record,
domain tag or test vector changed; the vector manifest still pins them. Gate
checks, signed objects and invariants are unchanged.

What is new:

- Presence trust up to `H`: for a fast-mode decision whose archived anchor
  evidence verifies at `H` inside the window, a trusted header reaching `H`
  is enough for `anchor` to pass. Verdicts that rest on absence still need
  the deadline.
- Archive kind 19, archived execution results: the gate moves its execution
  result captures into the archive, keyed by `(chain_id, rail_ref)`, and
  `--check-execution` proves the result from them after nodes have pruned the
  block. New verifier flag `--result-archive` (repeatable) for extra copies.
- API codes: `recorder.ErrAnchorRejected` (502, not retryable) and
  `recorder.ErrClockSkew` (503, retryable).
- Wording: `anchor_unpaid` now says that a valid verdict requires a paid
  anchor and that an unpaid anchor is an operator funding failure.

A paid anchor (`tx_code == 0`) stays required for `valid`.
The removal announced for v1.1 was withdrawn. An included anchor with another
code stays `unchecked` (`anchor_unpaid`) and is never `invalid`.

What a v1.0.N reader does with v1.1 artifacts:

- It refuses a kind 19 record (invalid enum) and does not use it; the
  execution check falls back to the nodes.
- It reports `anchor_pending` where a v1.1 verifier says `pass` (trusted
  header between `H` and the deadline). Never a wrong `valid` or `invalid`.
- The two new API codes decode as `edictaapi.ErrInternal`.

Operators, act on this:

- An archive must answer a missing key as absent (404 or a missing file).
  The execution check now reads an `exec/` key even for decisions that have
  none, so a store that answers 403 for missing keys stops every
  `--check-execution` run with exit 4. Fix the store before upgrading
  verifiers (see `docs/verifier.md`).
- With `[capture]` enabled the gate writes kind 19 records into the archive
  and drops the capture after reading the record back. A conflicting record
  under the same key keeps the capture and makes `/v1/health` report
  degraded (see `docs/operator.md`).
- Clients that retried on 425 for a rejected anchor must not retry on 502.
