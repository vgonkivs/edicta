# Code locations

Release `v1.2.0` regrouped the repository by component and replaced the
separate command binaries with one `edicta` binary. No wire byte, domain tag,
test vector or gate check changed. Text written for earlier releases,
including the frozen specification, names the paths and binaries of that
time; this page maps them to where they are now. It is not normative.

The layout itself is described in [../ARCHITECTURE.md](../ARCHITECTURE.md),
section "Code layout".

## Modules

| Before | Now |
|---|---|
| `github.com/vgonkivs/edicta` (root) | unchanged; it no longer contains the rails' examples or the signer, and it gained `config` and `internal/` |
| `github.com/vgonkivs/edicta/celestia` | `github.com/vgonkivs/edicta/plugins/celestia` for the Celestia plugin; its commands and services moved to the modules below |
| `github.com/vgonkivs/edicta/fibre` | merged into `github.com/vgonkivs/edicta/plugins/celestia` |
| (none) | `github.com/vgonkivs/edicta/services/gate`, `github.com/vgonkivs/edicta/services/signer`, `github.com/vgonkivs/edicta/services/cli`, `github.com/vgonkivs/edicta/examples` |

Package names did not change, only their import paths.

## Packages

Root module:

| Before | Now |
|---|---|
| `commitment` | `engine/commitment` |
| `principalsig` | `engine/principalsig` |
| `policy` | `engine/policy` |
| `policy/privatebox` | `engine/policy/privatebox` |
| `gate` | `engine/gate` |
| `gate/registry` | `engine/gate/registry` |
| `gate/registry/memreg` | `engine/gate/registry/memreg` |
| `gate/registry/boltreg` | `engine/gate/registry/boltreg` |
| `gate/registry/regtest` | `engine/gate/registry/regtest` |
| `gate/gatetest` | `engine/gate/gatetest` |
| `gate/dacommit/blobv1` | `engine/dacommit/blobv1` |
| `dacommit/sharev1` | `engine/dacommit/sharev1` |
| `retention` | `engine/retention` |
| `retention/memstore` | `engine/retention/memstore` |
| `test/retentionstore` | `engine/retention/retentionstore` |
| `archive` | `engine/archive` |
| `archive/fsarchive` | `engine/archive/fsarchive` |
| `archive/httparchive` | `engine/archive/httparchive` |
| `verifier` | `engine/verifier` |
| `edictaapi` | `api/edictaapi` |
| `examples/tia-transfer/bankaction` | `plugins/banksend/bankaction` |
| `examples/tia-transfer/bankmsg` | `plugins/banksend/bankmsg` |
| `examples/tia-transfer/transfer` | `plugins/banksend/transfer` |
| `edenescrow` | `plugins/edenescrow` |
| `edenexec` | `plugins/edenescrow/edenexec` |
| `edenexec/edenrpc` | `plugins/edenescrow/edenrpc` |
| `examples/dca-agent/ibkr` | `plugins/ibkr` |
| `examples/dca-agent/ibkrorder` | `plugins/ibkr/ibkrorder` |
| `test/brokerfake` | `plugins/ibkr/brokerfake` |
| `signer` | `services/signer` (own module) |
| `signer/eden` | `services/signer/eden` |
| `signer/signertest` | `services/signer/signertest` |
| `cmd/edicta-principal` | `cmd/edicta-principal` (unchanged); its body is `internal/principalcli` |
| `guide/*.md` | `docs/*.md` |

The example agents keep their paths and now belong to the `examples`
module: `examples/tia-transfer/agent`, `examples/tia-transfer/pricefeed`,
`examples/tia-transfer/pricetrigger` and `examples/dca-agent/dca`.

New packages: `engine/dasource` (the DA read interfaces and their refusal
reasons), `engine/recorder` (the Recorder interface and its refusal reasons),
`api/signerapi` (the signer's wire format),
`plugins/celestia/chain/anchor` (Celestia anchor reading, formerly part of
`gatechain`), `internal/cborx`, `internal/evm`, `internal/evm/rlp`,
`internal/flock` and `internal/testkit`.

Former `celestia` module:

| Before | Now |
|---|---|
| `celestia/config` | `config` (root module) |
| `celestia/keyfile` | `internal/keyfile` (root module) |
| `celestia/secret` | `internal/secret` (root module) |
| `celestia/policyext/tiatransfer` | `plugins/banksend/tiatransfer` (root module) |
| `celestia/node` | `plugins/celestia/node` |
| `celestia/heightcheck` | `plugins/celestia/node/heightcheck` |
| `celestia/gatechain` | `plugins/celestia/chain/gatechain` and `plugins/celestia/chain/anchor` |
| `celestia/inclusion` | `plugins/celestia/chain/inclusion` |
| `celestia/cometrpc` | `plugins/celestia/chain/cometrpc` |
| `celestia/anchorverify` | `plugins/celestia/proof/anchorverify` |
| `celestia/absence` | `plugins/celestia/proof/absence` |
| `celestia/fibrecert` | `plugins/celestia/proof/fibrecert` |
| `celestia/fibreproof` | `plugins/celestia/proof/fibreproof` |
| `celestia/headertrust` | `plugins/celestia/proof/headertrust` |
| `celestia/recorder` | `plugins/celestia/recorder` |
| `celestia/railtx` | `plugins/celestia/banksend/railtx` |
| `celestia/railverify` | `plugins/celestia/banksend/railverify` |
| `celestia/execcapture` | `plugins/celestia/banksend/execcapture` |
| `celestia/nodefake` | `plugins/celestia/celestiatest/nodefake` |
| `celestia/test/fibrefix` | `plugins/celestia/celestiatest/fibrefix` |
| `celestia/test/fibreworld` | `plugins/celestia/celestiatest/fibreworld` |
| `celestia/test/cometfake` | `plugins/celestia/celestiatest/cometfake` |
| `celestia/edictad` | `services/gate/edictad` |
| `celestia/edictad/wire` | `services/gate/edictad/wire` |
| `celestia/signerd` | `services/signer/signerd` |
| `celestia/verifycli` | `services/cli/verifycli` |
| `celestia/doctor` | `services/cli/doctor` |
| `celestia/initcmd` | `services/cli/initcmd` |
| `celestia/commitcmd` | `services/cli/commitcmd` |
| `celestia/clearerr` | `services/cli/internal/clearerr` |
| `celestia/demo` | `examples/tia-transfer/demo` |
| `celestia/cmd/edicta` | `services/cli/cmd/edicta`, with the command bodies in `services/cli/clicmd` and the routing in `services/cli/edictacli` |
| `celestia/cmd/edictad` | `services/gate/gatecmd` (run as `edicta gate serve`) |
| `celestia/cmd/edicta-signer` | `services/signer/cmd/edicta-signer`, with the body in `services/signer/signercmd` |
| `celestia/cmd/edicta-verify` | `services/cli/verifycli`, run as `edicta verify --no-config` |
| `celestia/cmd/edicta-devinit` | `services/cli/devinitcmd` (run as `edicta dev init`) |
| `celestia/cmd/edicta-live` | `examples/tia-transfer/cmd/edicta-live` |
| `celestia/README.md` | `services/gate/README.md` (the gate reference) and `examples/tia-transfer/README.md` (the manual run) |

Former `fibre` module:

| Before | Now |
|---|---|
| `fibre/fibrecommit` | `plugins/celestia/fibrecommit` |
| `fibre/fibrecommit/internal/genpins` | `plugins/celestia/fibrecommit/internal/genpins` |

## Files the specification cites

| Before | Now |
|---|---|
| `gate/fast_test.go` | `engine/gate/fast_test.go` |
| `gate/fast_edge_test.go` | `engine/gate/fast_edge_test.go` |
| `verifier/pending.go` | `engine/verifier/pending.go` |
| `guide/verifier.md` | `docs/verifier.md` |
| `celestia/railverify/testdata/tx_prove_1442606.json` | `plugins/celestia/banksend/railverify/testdata/tx_prove_1442606.json` |
| `celestia/railverify/testdata/header_1442606.json` | `plugins/celestia/banksend/railverify/testdata/header_1442606.json` |
| `examples/tia-transfer` (bank-send profile) | the rail in `plugins/banksend`, the agent and demo in `examples/tia-transfer` |
| `examples/dca-agent` (IBKR profile) | the rail in `plugins/ibkr`, the agent in `examples/dca-agent` |

The `source` field of `spec/vectors/verifier/execution_outcomes.json` keeps
the old path: the vector file is frozen.

## Binaries and commands

| Before | Now |
|---|---|
| `edictad -config FILE [-print-config]` | `edicta gate serve -config FILE [-print-config]` |
| `edicta-signer -config FILE [-check-config]` | unchanged, and also `edicta signer serve -config FILE [-check-config]` |
| `edicta-verify verify\|replay\|absence ...` | `edicta verify\|replay\|absence --no-config ...` (without `--no-config` the command also reads `edicta.toml`) |
| `edicta-devinit --home DIR` | `edicta dev init --home DIR`, in builds with the `edictadev` tag |
| `edicta-principal COMMAND ...` | unchanged, and also `edicta principal COMMAND ...` |
| `edicta demo [fast-mode\|fast-live] ...` | `edicta-demo [fast-mode\|fast-live] ...`, or `make demo ARGS="..."` |
| `edicta-live ...` | unchanged, built from `examples/tia-transfer/cmd/edicta-live` |
| `edicta init\|doctor\|commit\|agent serve` | unchanged |
| `celestia/bin/` (build output) | `bin/` |
| `go -C celestia run ./cmd/edictad -config FILE` | `go -C services/cli run ./cmd/edicta gate serve -config FILE` |
| `go -C celestia run ./cmd/edicta-live ...` | `go -C examples run ./tia-transfer/cmd/edicta-live ...` |
| `go -C celestia run ./cmd/edicta-verify ...` | `go -C services/cli run ./cmd/edicta verify --no-config ...` |

Messages that named a binary now name the command that prints them:

| Before | Now |
|---|---|
| `edictad: ...` (an error that stops the command) | `edicta gate serve: ...`; the daemon's own log lines keep `edictad:` |
| `edicta-signer: ...` | `edicta signer serve: ...` under `edicta`, unchanged in the standalone binary |
| `edicta-principal: ...` and its usage | `edicta principal ...` under `edicta`, unchanged in the standalone binary |
| `edicta-devinit: ...` | `edicta dev init: ...` |
| `edicta: ...` in the demo | `edicta-demo: ...` |
| `gatechain: invalid config`, `gatechain: bridge probe inconclusive` | `anchor: invalid config`, `anchor: bridge probe inconclusive` |

Clients of the HTTP APIs are not affected: they match error codes, which did
not change.
