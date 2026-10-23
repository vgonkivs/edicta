<!-- SPDX-License-Identifier: Apache-2.0 -->
# Local dev stack (docker compose)

DEV ONLY. Every key is generated into the `dev-home` volume at first start and
is worthless outside it. The chains are distinct on purpose: Celestia
`edicta-dev-1`, Eden EVM chain id `31337`. Never fund these keys on a public
network and never copy them to one. Nothing here talks to a public network at
run time; the first `up` pulls images and builds two small ones from source.

```
make dev-up       # build, start, wait until healthy (about 40 s warm)
make dev-smoke    # host-side checks of the running stack
make dev-down     # stop and delete every volume
```

or `cd deploy/dev && docker compose --profile dev up -d --build --wait`.

## What starts

| Service | Image | Role |
|---|---|---|
| `genesis-init` | `edicta-dev-tools` (built from `Dockerfile`, tag `edictadev`) | one shot (`edicta dev init`): DEV keys, dev mandate, `edictad.toml`, `edicta.toml`, Eden genesis, JWT secret. Never overwrites. |
| `celestia-init` | celestia-app | one shot: devnet genesis funding the Recorder and a demo funder |
| `celestia` | celestia-app v10.4.0 | one validator, app version 10, about 2.5 s blocks |
| `celestia-bridge` | celestia-node v0.34.3 | bridge node on a private network; `edictad` reads blobs and proofs through it |
| `edictad` | `edicta-dev-tools` | gate and Recorder (`edicta gate serve`), celestia_blob, fast mode (`da = 2`), published on `127.0.0.1:18480` |
| `eden-da` | built from ev-node v1.1.4 source (`Dockerfile.local-da`) | in-memory local DA, ev-node only |
| `eden-reth` | ev-reth v0.4.1 | EVM, chain id 31337, Prague and Osaka from genesis, RPC on `127.0.0.1:18545` |
| `eden-node` | ev-node-evm v1.1.4 | single sequencer, 100 ms blocks (`EDEN_BLOCK_TIME` in `.env`) |

Ports are in `.env`.

## Placeholders

- NativeEscrow is not in the Eden genesis yet. `edicta dev init` takes
  `--escrow-address` and `--escrow-code-file` (runtime code, hex) and puts the
  code in the alloc; until then the slot is absent and `genesis-init` prints
  `PLACEHOLDER`.
- The gate allows the Celestia bank-send action type, the only one this build
  has a policy extractor for. The Eden escrow action replaces it with its own
  extractor. `edicta.toml` names a placeholder USDC address for the same
  reason.
- Not started yet: the signer, the mock x402 resource, the demo agent and the
  verifier one-shot.

## Facts worth knowing

- `edicta.toml` cannot switch fast mode on; `edictad` reads the legacy
  `edictad.toml` that `genesis-init` writes next to it.
- Dev keys are random per volume, not derived from a fixed seed. `down -v`
  makes new ones.
- Eden is ephemeral: its state lives in the volumes `eden-reth-data` and
  `eden-node-data` and the DA is in memory, so restart all three Eden services
  together or run `make dev-down`.
- The upstream `ghcr.io/evstack/ev-node-local-da` image has no `blob.Submit`
  and does not work with ev-node v1.1.4; that is why `eden-da` is built from
  source, pinned by commit.
- Celestia images pinned by digest: celestia-app, celestia-node, ev-reth and
  ev-node-evm in `compose.yaml`; the two locally built images pin their base
  images by digest and the ev-node source by commit.
- On a port clash edit `.env`.
