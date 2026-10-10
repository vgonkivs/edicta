# Edicta user guide

These guides describe Edicta wire version 1: the frozen specification
revision `v1.0` (release tag `v1.0.0`) and its erratum E1 (tag `v1.0.1`,
which changed two expectations in a vector file and no wire bytes). The
earlier v0 drafts are superseded and unsupported.

| Guide | For | Covers |
|---|---|---|
| [quickstart.md](quickstart.md) | everyone | The v1 flow, the one-command demo, strict and fast mode |
| [operator.md](operator.md) | gate operators | `edictad`: gate, archive, mandate, fast mode, Recorder, startup refusals |
| [principal.md](principal.md) | principals | Mandates: Ed25519, Keplr (ADR-036), MetaMask (EIP-712), auditors, versions |
| [profiles.md](profiles.md) | integrators | Executor side: Authorization check, salt, fast-mode policy, public execution |
| [private-mode.md](private-mode.md) | principals, auditors | What a private mandate hides and what it does not |
| [verifier.md](verifier.md) | auditors | `verify`, `replay`, `absence`: checks, reasons, verdicts, trust inputs |
| [mocha-checklist.md](mocha-checklist.md) | gate operators | Manual live run of fast mode on Mocha; not yet run |

Other documents:
- [../README.md](../README.md): what Edicta is and is not.
- [../celestia/README.md](../celestia/README.md): the manual `edicta-live` run and the full `edictad` reference.
- [../celestia/demo/README.md](../celestia/demo/README.md): the one-command demo.
- [../examples/dca-agent/README.md](../examples/dca-agent/README.md): an off-chain profile (IBKR order).

Source of truth. When a guide and the specification disagree, the
specification wins: `spec/decision-commitment-v1.md` (core),
`spec/policy-v1.md` (mandates), `spec/ERRATA.md`, and the profiles in
`spec/profiles/`. Guides cite them as "file, section N".

Every guide ends with what Edicta verifies in that part and what it does not.
Edicta never judges the agent: not its logic, not the truth of its inputs,
not the quality of its decisions. It proves what was decided, on what
context, before the action, and that exactly that action was authorized.
