# Mocha checklist: fast mode with the edictad Recorder

**Manual, not yet run.** Nobody has run this checklist yet, so fast mode has
not run live. It is run by a human, on Mocha (`mocha-5`). It publishes blobs
and spends test TIA. Nothing here runs in CI. Background:
[operator.md](operator.md), sections "Gate in fast mode" and "Recorder in
fast mode"; [verifier.md](verifier.md) for `verify` and `absence`.

What it shows, per data availability mode:
1. The Recorder returns a pending reference before the anchor is in a block
   (for `fibre`: the availability certificate exists before inclusion).
2. The anchor tx (PayForFibre or PayForBlob) is a separate tx, sent once, from
   the Recorder's own account.
3. The gate authorizes in fast mode on the archived intent.
4. The Recorder writes the evidence at the anchor height H (H > h0).
5. A forced stale sequence gives a sticky `ErrIntentStale` and no second
   signature.
6. A killed anchor is absent at the deadline, and the gate raises
   `anchor_missing`.

Steps marked **UNVERIFIED** use commands or node options nobody has run
yet. Write down what actually happened.

## 0. Prerequisites

- Your own Mocha consensus node: celestia-app 10.x, `tx_index = "kv"`, gRPC
  on `:9090`, and CometBFT RPC on `:26657` for the `celestia-appd` commands.
  Both `gate.fast.own_node` and `recorder.own_node` (fibre) attest that this
  node is yours. A public endpoint does not count.
- A bridge node for reads (any Mocha bridge you trust).
- `celestia-appd` at the version of your node, plus `jq`.
- Build from the repo root:
  ```
  go -C celestia build -o /tmp/edictad ./cmd/edictad
  go -C celestia build -o /tmp/edicta-live ./cmd/edicta-live
  go -C celestia build -o /tmp/edicta-verify ./cmd/edicta-verify
  ```
- The gate seed, agent, executor and principal keys from the normal demo
  setup. These are Ed25519 keys. The Recorder account below is a secp256k1
  Cosmos key, so it can never be one of them. Keep it out of every other
  tool anyway.

## 1. The Recorder's dedicated account

The account of `recorder.key_name` must sign nothing but this Recorder's
anchor txs. A tx from anywhere else moves its sequence. A signed and archived
anchor tx is never signed again, so that blob's pending reference goes stale.

```
celestia-appd keys add edicta-recorder-fast --keyring-backend file \
  --keyring-dir /var/lib/edictad/keyring
celestia-appd keys show edicta-recorder-fast -a --keyring-backend file \
  --keyring-dir /var/lib/edictad/keyring          # -> celestia1... (ADDR)
```

- Do not import this key into the executor, `edicta-live` or any wallet.
- Do not point a strict-mode Recorder (another edictad) at it.
- Put its passphrase in `recorder.passphrase_file` (mode 0600).

Expected: `celestia-appd query auth account $ADDR` returns "not found" until
the account is funded, then sequence 0.

## 2. Test TIA

- Faucet: the Mocha faucet listed on
  https://docs.celestia.org/operate/networks/mocha-testnet (web faucet or the
  Discord `#mocha-faucet` channel, `$request <ADDR>`). Ask for at least
  10 TIA.
- `celestia_blob`: fees only. One PayForBlob of a small blob costs a few
  thousand utia at the 0.004 utia/gas minimum, so 1 TIA covers hundreds of
  runs.
- `fibre`: the escrow pays per upload `650000 + 45000 * ceil(upload_bytes /
  262144)` utia, plus the tx fee from the balance. To learn the minimum
  headroom, start edictad once with `fast_escrow_headroom_utia = 0`. The
  refusal names it:
  `recorder.fast_escrow_headroom_utia must be at least <N> utia ...`.
  A smaller `recorder.max_blob_bytes` lowers N. Deposit at least
  `N (headroom) + escrow_margin_utia + 5 * cost` so that a few runs fit.
  **UNVERIFIED** flags:
  ```
  celestia-appd tx fibre deposit-to-escrow <amount>utia --from edicta-recorder-fast \
    --keyring-backend file --keyring-dir /var/lib/edictad/keyring \
    --node http://<own node>:26657 --chain-id mocha-5 --fees 2000utia
  celestia-appd query fibre --help        # find the escrow query; note the balance
  ```
  Note the escrow balance and the account sequence (`SEQ0`) before step 4.

## 3. Configuration

Start from `celestia/cmd/edictad/edictad.example.toml` and the demo's gate
setup, with a mandate that sets `fast_mode_max_delay`. Add:

```toml
[network.consensus_grpc]
addr = "<own node>:9090"

[recorder]
enabled = true
namespace = "<58 hex>"
keyring_dir = "/var/lib/edictad/keyring"
keyring_backend = "file"
key_name = "edicta-recorder-fast"
passphrase_file = "/etc/edictad/keyring.pass"
max_blob_bytes = 65536
fast = true
fast_dedicated_account = true
# celestia_blob only:
fast_timeout_blocks = 100
# fibre only (with own_node = true):
fast_upload_addr = "<own node>:9090"        # exactly network.consensus_grpc.addr
fast_escrow_headroom_utia = <N or more>

[gate.fast]
enabled = true
own_node = true
pending_namespaces = ["<the same 58 hex>"]
```

Expected refusals: try each change once and keep the error line.
- `fast_dedicated_account` removed: `recorder.fast_dedicated_account must be true`.
- `[gate.fast]` removed: `recorder.fast needs gate.fast.enabled`.
- Namespace not in `pending_namespaces`: `recorder.fast needs recorder.namespace in gate.fast.pending_namespaces`.
- fibre, another `fast_upload_addr`: `must be network.consensus_grpc.addr`.
- celestia_blob, `fast_timeout_blocks = 13`: `must exceed gate.fast.max_h0_age_blocks + gate.fast.min_fast_slack_blocks`.

Start:
```
/tmp/edictad -config /etc/edictad/edictad.toml 2>&1 | tee edictad.log
```
Expected lines: `edictad: fast mode on ...` and
`edictad: recorder fast mode on; this account must sign nothing else account=<hex of ADDR> da=<mode> ...`.
Check that no line contains the passphrase or the mnemonic. Only the address
may appear: `grep -c "<passphrase>" edictad.log` must print 0.

## 4. Happy path (run once per da mode)

1. Publish through the agent:
   ```
   /tmp/edicta-live --fast --mandate-hash <64-hex hash of the mandate in force> --inclusion self --archive-url <edictad archive URL> \
     --grpc-addr <own node>:9090 [--bridge-addr <bridge> for celestia_blob] ...
   ```
   Note the wall-clock time `T_pub` when the pending reference is printed:
   anchor pending, height h0.
2. Look in the archive right away:
   `find <archive.dir> -newer edictad.log -type f | sort` shows the payload
   record, then the anchor intent, before any evidence.
   Expected: no evidence file yet.
3. Certificate before inclusion (fibre): the intent's tx carries
   MsgPayForFibre with the validator signatures. Compute its hash as the
   SHA-256 of the intent tx. Run `celestia-appd query tx <HASH> --node
   http://<own node>:26657` immediately after step 1.
   Expected: "not found" for a moment, then found at height H > h0. The block
   time of H is later than `T_pub`.
4. Separate anchor tx: on https://mocha.celenium.io/address/<ADDR> the account
   shows exactly one new tx per decision (MsgPayForFibre or MsgPayForBlobs),
   and its sequence is `SEQ0 + 1`. No deposit and no other tx exists:
   `AutoFund` is off and the uploader never broadcasts.
5. Fast Authorization: the agent's authorize returns 200. The archived
   Authorization has mode fast and `anchor_deadline` = min(h0 +
   fast_window_blocks, the tx timeout (blob) or the promise window (fibre),
   h0 + the mandate's delay).
6. Evidence at H: within a few polls of H, the archive gains the evidence
   record. Its height is H, not h0. No `recorder:` warning other than "anchor
   evidence not written yet" appears.
7. `/tmp/edicta-verify verify <ref>` (flags as in [verifier.md](verifier.md)) reports the decision
   as published, with the anchor at H inside its window.
8. fibre: after the promise timeout, the escrow balance went down by exactly
   one upload cost per decision.

## 5. Forced stale sequence (sticky error, no re-sign)

This deliberately breaks the dedicated-account rule, so use a throwaway blob.

1. Hold the anchor on your node only: set `[mempool] broadcast = false` in
   the own node's `config.toml` and restart the node. **UNVERIFIED** with the
   CAT mempool: check in step 3 that a public node does not know the tx.
2. Publish a new blob (step 4.1). Note the intent's sequence `S`. You can
   read it with `celestia-appd tx decode` on the intent tx, or it is
   `SEQ0 + k`.
3. Check on a public node (`--node https://rpc-mocha.pops.one`) that the
   intent's hash is not found.
4. Send a 1 utia self-send from the Recorder account at sequence `S` through
   that public node:
   ```
   celestia-appd tx bank send edicta-recorder-fast $ADDR 1utia --sequence S \
     --keyring-backend file --keyring-dir /var/lib/edictad/keyring \
     --node https://rpc-mocha.pops.one --chain-id mocha-5 --fees 2000utia
   ```
   Expected: it lands. The account sequence is now `S + 1`.
5. Set `broadcast = true` again and restart your node.
6. Within about 30 poll intervals the Recorder sends the archived bytes again
   and the node refuses them. Expected log:
   `recorder: the anchor tx of a pending reference was refused when sent again ... ErrIntentStale`.
   It is logged once, and nothing more happens for that blob.
7. No re-sign: the account sequence stays at `S + 1`, the explorer shows no
   new MsgPayForFibre or MsgPayForBlobs, and the archive holds exactly one
   intent for this blob.
8. Publishing the same blob again answers 409 `recorder.ErrIntentStale`. The
   API caches a successful answer per blob for twice (skew + 300 s), so within
   that window you get the cached pending reference instead. Wait it out.
9. A new blob publishes normally at sequence `S + 1`. The Recorder learned
   the sequence from the refusal.
10. After the deadline this blob is absent: see section 6, steps 4 to 6.

## 6. Kill the anchor and see absence

1. Hold anchors on your node only, as in section 5 step 1.
2. Publish a new blob and authorize a decision on it (the gate sends the
   intent again, but only to your node, which does not relay it). Then stop
   edictad and keep it down until step 3 is over. Its confirmation loop and
   the gate send the intent again, and once relaying is back on that would
   land the anchor before the deadline.
3. Wait past the deadline: celestia_blob, h0 + `fast_timeout_blocks`; fibre,
   h0 + the promise height window (`celestia-appd query fibre params`). That
   is about 2.85 s per block. Then set `broadcast = true` and restart the
   node. The tx can no longer be included: its timeout height or its promise
   has passed.
4. Restart edictad. Expected: `recorder: the anchor of a pending reference did
   not land in its window`. Publishing that blob gives 409
   `recorder.ErrAnchorExpired` (after the API cache window).
5. On the first sweep after the restart (`archive.sweep_interval_s`), at
   least 10 blocks past the Authorization's deadline, the gate logs
   `edictad: anchor_missing: no anchor evidence after the deadline of a
   fast-mode Authorization`. It is at-least-once: it repeats after a restart.
6. `/tmp/edicta-verify absence <ref>` (with `--archive`, `--gate-key` and
   `--absence-source`, see [verifier.md](verifier.md)) writes the absence
   proof, and `verify` reports `anchor_absent`, attributed to ADDR, the
   intent's signer.
7. fibre: the unsettled promise may still be charged by a timeout settlement.
   The escrow balance after the promise timeout shows whether it was. The
   headroom is what keeps later uploads funded in that case.

## 7. Restart while pending

1. With broadcast on, publish, then `kill -9` edictad before H.
2. Restart. Expected: no new signature (the account sequence moves by one per
   blob only). The evidence is written at H, from the archived intent.
3. Publish a new blob right after the restart. If the old intent is still in
   a mempool, the new one may collide on its sequence. That costs at most one
   stale blob (section 5 behaviour), never a second anchor for one blob.

## Results

| Step | mode | expected | observed | notes |
|---|---|---|---|---|
| 3 refusals | both | five errors as listed | | |
| 4.3 cert before inclusion | fibre | found at H > h0, block time > T_pub | | |
| 4.4 one tx per decision | both | sequence +1 | | |
| 4.6 evidence at H | both | evidence height H | | |
| 5 stale | both | sticky ErrIntentStale, no re-sign | | |
| 6 absence | both | ErrAnchorExpired, anchor_missing, anchor_absent | | |
| 7 restart | both | evidence at H, no re-sign | | |
