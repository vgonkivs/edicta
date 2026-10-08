# `edicta demo`

One command, one Enter, about 3 to 5 minutes on the Mocha testnet. The demo
runs the whole Edicta flow with a real agent decision, a real gate, a real
transfer on chain and an independent verifier, then tries to cheat four ways, grouped in three layers below.
Testnet TIA only; keep the amounts small.

## What it proves

1. **The gate prevents.** An executor cannot get an Authorization for other
   bytes than the agent committed. A different amount is refused
   (`ErrActionMismatch`), and a decision cannot be used twice
   (`ErrNonceUsed`, no new Authorization; the executor refuses it as seen).
   The mandate also holds: an amount above the per-action maximum is refused
   (`policy.ErrAmountAboveMax`), with a signed deny verdict in the archive.
2. **Sources cannot frame an honest agent.** The demo flips one byte in a copy
   of the archive. The verifier does not accuse anyone: the result is
   INCONCLUSIVE with `source_corrupt`. Bad bytes prove the copy is bad, not
   that the agent did something wrong.
3. **Bypass is detected.** A deliberately broken executor skips its checks and
   sends `amount + 1` under a genuine Authorization. The verifier says
   INVALID: the transaction does not match the action the agent committed.
   The gate authorized only the committed bytes; enforcing them is the
   executor's job, and the verifier proves when that was skipped.

Edicta does not judge the agent's price source or strategy. It proves what was
decided, on what context, before the action, and that exactly that action ran.

## The seven steps

| Step | What happens | On chain |
|---|---|---|
| 1 Environment | Checks the network, clock and endpoints, then starts the gate in-process on a loopback port. The agent, executor and verifier talk to it over its real HTTP API. | nothing |
| Funding | Moves the needed utia from your funder account to two demo accounts (Recorder and executor). Asks for one Enter first. | up to 2 bank sends |
| 2 Mandate | Prints the mandate the gate enforces, as rendered text: bank sends of utia to the demo recipient only, at most 2x `--amount` per action and 3x `--amount` per rolling 24h, valid for 24 hours. A fresh principal key signed it for this run; the key stays in the run directory and is never printed. | nothing |
| 3 Decision | The agent reads a TIA/USD price and builds the decision: payload, plus a bank-send action of `--amount` utia. | nothing |
| 4 Publish | The Recorder publishes the encrypted payload as a blob and the agent signs the commitment. | `MsgPayForBlobs` (the anchor) |
| 5 Authorize and execute | The gate checks the invariants and signs an Authorization. The executor checks it and sends exactly the authorized bytes, with the commitment hash as memo. The gate records a receipt. | `MsgSend` |
| 6 Verify | The verifier re-checks everything from the archive and public RPCs, with the trust root below, and the policy: `--principal-key <this run's principal> --require-policy --policy-full` (the decision must satisfy the mandate, and the gate's verdict chain is walked to genesis, shown as the `gate_integrity` line). Must end VALID, and VALID now lists `policy: pass` among its assumptions. | nothing |
| 7 Cheating attempts | Layer 1 and 2 attempts run first and move no funds. Layer 1 now includes the over-limit commitment, which the policy refuses (a blob for the refused decision is published). The rogue executor (layer 3) runs last with a second decision. | the rogue run: one blob and one `MsgSend` |

## Build and run

From the repository root:

```
make demo
```

or, step by step:

```
make build                 # or: go -C celestia build -o bin/edicta ./cmd/edicta
celestia/bin/edicta demo
```

Flags go after `demo`, or through `make demo ARGS="..."`.

The demo needs a terminal. It refuses to start without one, before any key is
created. Nothing is broadcast until you press Enter at the start prompt, and no
flag skips that Enter.

State lives in `~/.edicta-demo` (change with `--home`). Only one demo runs at a
time per home.

### Funding

The demo uses three distinct chain accounts: a **funder** (yours), and a
**Recorder** and **executor** that it creates. The funder pays the other two.

Default flow, with one account:

1. Run `edicta demo`. On first run it generates the funder key and prints its
   address and the faucet link.
2. It reads balances and computes what is missing. Leftovers from earlier runs
   are kept and counted, so a rerun often sends nothing.
3. If the funder is short, it prints `Fund it, then press Enter to start.`
   Send TIA to the printed address from the faucet. The demo shows
   `waiting for funds...` and polls. If nothing arrives within `--fund-timeout`
   (default 5m) you choose: Enter keeps waiting, `q` quits.
4. If the funder already has enough, it asks `Press Enter to move N utia and
   start.` If there is nothing to move: `Press Enter to start.`

Use your own funded account instead of the generated one, from a Cosmos SDK
file keyring:

```
celestia/bin/edicta demo \
  --funder-keyring-dir <keyring dir> --funder-key <key name> \
  --funder-passphrase-file <file> \
  --address <celestia1... address>
```

- `--funder-passphrase-file` must have mode 0600. Without it the passphrase is
  asked on the terminal without echo. It is never taken from a flag.
- `--address` is optional. If given, it must equal the key's address, or the
  demo stops before sending anything.
- The funder, Recorder and executor must be three different accounts.

### Funding caps

Funding is bounded by a send limit that is checked in the demo, not by any node:

| Limit | Value |
|---|---|
| Per send (`MaxAmount`) | 200,000 utia |
| Lifetime total per funder (`MaxTotalAmount`) | 2,000,000 utia, remembered in the state file |
| Fee per send (`MaxFee`) | 20,000 utia |

To raise the lifetime total, pass `--max-total-funding <utia>`. The demo prints
the new cap and asks you to confirm; `--yes` skips only that confirmation (it is
refused without `--max-total-funding`, and it never skips the start Enter).

The funding node (`grpc-mocha.pops.one`) is trusted to report committed state
honestly. A node that lied could cause an extra send of at most the per-send
limit, and never more than the lifetime total in any case. If a send ends in an
unclear state, the demo offers an explicit typed "abandon" confirmation; nothing
else, including `--yes`, abandons it.

## Spending policy

The demo's edictad takes a `[policy] mandate_file` (a canonical SignedMandate signed by
the principal for the demo gate id). The demo generates a principal key per run, writes
the mandate to the run directory (mode 0600) and prints its rendered text before the
agent decides. Limits: per action 2x `--amount` (so the rogue executor's `amount + 1`
is still allowed), 3x `--amount` per rolling 24h, recipients pinned to the funder
address, `max_decision_age` at its default, 24 hours of validity.

The attempt `policy-denies-over-limit` commits `2x amount + 1`. The gate answers
`policy.ErrAmountAboveMax` with a signed deny verdict and issues no Authorization, so
there is nothing to execute. The verify steps pass `--principal-key HEX --require-policy
--policy-full`; offline, the same flags confirm the decision and the denial. See the
policy section of `celestia/README.md`.

## Trust root (demo mode only)

The verifier walks block headers backward from a header it already trusts. That
header cannot come from the same RPC that supplies the data, or one hostile RPC
could invent a whole consistent chain.

In the demo, after the transfer is included, header **T** (two blocks above the
transaction) is read from the Celenium explorer API, and its hash is printed with
a link so you can check it in a browser:

```
[trust root] header 4817249 = AB12... from Celenium; check https://mocha.celenium.io/block/4817249
```

- `--trusted-header HEIGHT:HASH` replaces Celenium with a hash from any source
  you choose. It must be at or above the needed height, or the demo asks you for
  another one; it is never silently replaced.
- If Celenium is unavailable, the demo does **not** fall back to a data RPC. It
  asks you to paste `HEIGHT:HASH`. If you quit instead, the verdict is
  INCONCLUSIVE (`no_trusted_header`).
- The run is refused if the Celenium host is the same as a configured RPC host.

A VALID verdict prints its assumptions: that Celenium and the data RPCs do not
collude, that the header cross-check is off, and that inclusion and the
execution result are proven. This is demo mode only. Production should take the
trust root from its own node or, later, from validator signature verification,
and should enable `--cross-check` with an independent operator.

## Verdicts and exit codes

The verifier is tri-state, and every line that is not a pass shows its reason.

| Verdict | Meaning |
|---|---|
| VALID | everything was proven from verified data |
| INVALID | a violation was proven (for example the executed transaction differs from the committed action) |
| INCONCLUSIVE | a source was missing, corrupt or lagging; no claim either way |

A hostile source can cause at most INCONCLUSIVE, never VALID or INVALID.

`edicta verify` exits 0 VALID, 1 INVALID, 2 INCONCLUSIVE, 3 NOT AUTHORIZED,
4 usage or I/O error. `edicta demo` exits:

| Code | Meaning |
|---|---|
| 0 | the verify step VALID and every attempt ended as expected |
| 1 | something proven wrong or unexpected |
| 2 | inconclusive or stopped: INCONCLUSIVE after retries, funding or network failure, funding cap, you quit |
| 3 | the verify step NOT AUTHORIZED |
| 4 | bad flags or configuration, no terminal, home locked by another demo |
| 130 | interrupted (Ctrl-C) |

## Run directory and offline verification

Each run writes `~/.edicta-demo/runs/<UTC timestamp>/` and keeps it:

| File | Contents |
|---|---|
| `evidence.json` | summary: hashes, heights, verdict, attempts, funding sends |
| `trust-root.json` | the header, hash, source and link used |
| `archive/` | the real archive: decision, Authorization, payload |
| `tampered-archive/` | the copy with one flipped byte (tampered-archive attempt) |
| `receipt.cbor`, `rogue-receipt.cbor` | the gate-signed receipts |
| `verify-*.json` | the verifier's full report for each verify run |
| `mandate.cbor` | the signed mandate the gate loaded (mode 0600) |
| `*.ed25519` (including `principal.ed25519`), `recipient.x25519`, `*.token`, `registry.db`, `*.toml` | per-run keys, tokens, gate registry and configs (testnet only, mode 0600) |

Chain keys and the funder state live under `~/.edicta-demo/chain/`.

To re-verify later without the demo's gate, point `edicta verify` at the kept
archive. The exact command with all flags is in `verify-step5.json` and printed
at the end of the run:

```
celestia/bin/edicta verify <commitment hash> --gate-key <gate public key hex> \
  --archive ~/.edicta-demo/runs/<timestamp>/archive \
  --headers-rpc https://rpc-mocha.pops.one \
  --checkpoint <HEIGHT>:<HASH> \
  --receipt ~/.edicta-demo/runs/<timestamp>/receipt.cbor \
  --tx-rpc https://rpc-1.testnet.celestia.nodes.guru --check-execution
```

Use the same `--checkpoint` as the run (see `trust-root.json`). Headers pruned by
the RPC give INCONCLUSIVE, never VALID.

## Troubleshooting

- **Rate limits or timeouts from a public RPC.** The verifier retries timing
  problems (the next block not yet visible, a transaction not yet indexed) up to
  three times. If it still ends INCONCLUSIVE with a reason such as
  `tx_source_unavailable`, wait a minute and rerun, or override endpoints with
  `--headers-rpc` and `--tx-rpc` (they must be different hosts, and the
  transaction source must serve `/tx?prove=true` and `/block_results`).
- **Celenium unavailable or lagging.** The demo retries for up to 60 s, then
  asks you to paste a trusted header as `HEIGHT:HASH` from a source you trust
  (any block explorer page, at or above the height it names). Quitting there
  gives INCONCLUSIVE `no_trusted_header` and skips the attempts that need it.
  Alternatives: `--trust-root-api` and `--trust-root-page` for another
  explorer, or `--trusted-header`.
- **Clock window.** The decision has a short validity window. If your clock
  differs from chain time by more than the allowed skew, the demo refuses before
  the Enter (`ErrClockSkew`); a smaller skew is only a warning. Fix the system
  clock. If the gate later reports a time refusal, check the clock first.
- **Waiting for funds.** The faucet can be slow or limited. Rerunning is safe:
  an earlier pending funding send is settled first, and nothing is sent twice.
- **A second demo says the home is locked.** Another run is using the same
  `--home`; wait for it or use a different home.
