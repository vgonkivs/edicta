# Changelog

## v1.3.0 (2026-10-24, spec revision v1.2.1)

No v1 wire byte, archive record, domain tag, core test vector or gate check
changed.

- Celestia mainnet releases: the Celestia modules build against
  celestia-node v0.34.3, celestia-app v10.4.0 and celestia-core v0.42.3
  (with cosmos-sdk v0.52.12) instead of the testnet tags. celestia-app
  v10.4.0 is the commit the Fibre commitment vectors were generated at, and
  they reproduce byte for byte; the Fibre build check pins the new set. The
  new releases only refuse more on the read paths Edicta uses, and the
  share proof verifier keeps its own row checks. Spec revision v1.2.1
  (clarification E4) records the new pins. The dev network runs the
  release images, pinned by digest.
- Eden escrow profile drafts 10 and 11:
  - The signer broadcasts a deposit directly to the chain's Eden RPC by
    default. The payment server's relay is an explicit fallback
    (`broadcaster = "houston-relay"`); `relay_url` alone is refused. A
    relay deprecation marker is logged once.
  - One payer key per agent per chain: `[[chain.payer]]` entries
    (`agent_pubkey`, `key_file`, `address`) replace `payer_key_file` and
    `payer_address`, which are refused by name at start, as are a served
    agent without a payer on a chain and a key or address shared by two
    agents or chains.
  - Client relay handoff: after the paid retry is refused twice in a
    recognised way, the client hands the stored signed deposit once to its
    payment server's relay and retries with the same Payment-Signature.
    Nothing is signed again; the relay's answer is never evidence. Go:
    `POST /v1/paid-retry` on `edicta agent serve` (`--payment-server`,
    `--pickup-delay`); TypeScript: `paidRetryWithHandoff`.
  - `edicta agent serve` and `edicta commit --state-dir` hold an exclusive
    lock on the state directory; a second process is refused (busy,
    retryable).
  - Recorded Eden mainnet payments are profile inputs, with a vector file
    derived from them.
  - The example signer configuration bounds the refund delay at one week
    (`max_refund_delay_s = 604800`), since payment server quotes carry about
    604500 s.
- Operator guidance: the payer key is a hot key; keep each payer wallet to
  a small working float and top it up.

## v1.2.0 (2026-10-23, spec revision v1.1)

A code layout and command line release. No wire byte, archive record, domain
tag, test vector, API code or gate check changed.

- Layout by component: the core under `engine/`, the HTTP wire formats under
  `api/`, the rails and the Celestia adapter under `plugins/`, the gate, the
  signer and the command line under `services/`, the demos under `examples/`,
  shared helpers under `internal/`, the `edicta.toml` schema in `config/` and
  the user guides in `docs/`. Package names are unchanged; import paths moved
  without compatibility shims. `docs/code-locations.md` maps every old path
  and binary to the new one.
- Modules: the root module `github.com/vgonkivs/edicta`, and the nested
  modules `plugins/celestia` (the former `celestia` and `fibre` modules),
  `services/gate`, `services/signer`, `services/cli` and `examples`.
- One `edicta` binary: `edicta gate serve` replaces `edictad`, `edicta
  verify|replay|absence --no-config` replaces `edicta-verify`, `edicta dev
  init` replaces `edicta-devinit` (builds with the `edictadev` tag), and
  `edicta signer serve` and `edicta principal` run the signer and the
  principal tool. Flags, defaults and exit codes of every command are those
  of the binary it replaces; usage and error messages name the new command,
  `edicta verify -h` lists `--no-config`, and the help no longer lists test
  flags of linked dependencies. Build output goes to `bin/`.
- Light standalones: `edicta-signer` (in `services/signer`) and
  `edicta-principal` (in the root module) link no Celestia node or chain
  code, so the processes that hold the payer key and the principal key stay
  small; a guard test keeps them so.
- The demo is an example binary: `edicta-demo` (`make demo`) replaces
  `edicta demo`; `edicta-live` moved to `examples/tia-transfer`.
- `make release-check` builds, vets and checks every module, the guard
  tests, the command line pin, the vector manifest, the documentation links
  and repository hygiene, without running the full test suite.

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
