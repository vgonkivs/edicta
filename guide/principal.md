# Principal guide: mandates

A mandate is the principal's signed limit on what a gate may authorize for a
set of agents: assets, per-action and per-period maximums, recipients, action
kinds, a validity window and, optionally, consent to fast mode. The gate
denies anything outside it; it can never allow what the core checks refuse.
Spec: `spec/policy-v1.md`, sections 6 (mandate), 7 (rendered text) and 9
(private mode).

The tool is `edicta-principal` in the root module:

```sh
go build -o edicta-principal ./cmd/edicta-principal
```

```
edicta-principal render     --mandate FILE [--book FILE] [--accept-new-key]
edicta-principal typed-data --mandate FILE
edicta-principal signdoc    --mandate FILE
edicta-principal private    --mandate FILE --auditor LABEL:PUBKEY... [--new-id] [--out FILE]
edicta-principal sign       --mandate FILE --scheme ed25519|cosmos|eth (--key FILE | --signature SIG)
                            [--replaces FILE] [--book FILE] [--accept-new-key] [--out FILE]
edicta-principal verify     --signed FILE
edicta-principal publish    --signed FILE --archive DIR
```

A mandate file holds canonical CBOR, binary or as hex text. Without `--out`,
`private` and `sign` print hex; with `--out` they write binary CBOR, which is
what `edictad` reads.

## 1. Write the mandate

No command builds a mandate from scratch yet. Build the `policy.Mandate`
value in Go and encode it (the demo does the same in
`celestia/demo/policy.go`):

```go
m := &policy.Mandate{
    Format:    1,
    Principal: principalPub,          // see "Signature schemes" below
    GateID:    "my-gate-1",           // must equal the gate's gate.gate_id
    Agents:    [][]byte{agentPub},    // Ed25519 agent keys, ascending
    NotBefore: uint64(now.Unix()),
    NotAfter:  uint64(now.Add(30 * 24 * time.Hour).Unix()),
    Kinds:     []string{"transfer"},
    Assets: []policy.AssetRule{{
        Asset:        "cosmos:<chain-id>/utia",
        Scale:        6,
        PerActionMax: policy.AmountFromUint64(2_000_000),
        Periods:      []policy.PeriodLimit{{Hours: 24, Max: policy.AmountFromUint64(10_000_000)}},
        Recipients:   []string{"cosmos:<chain-id>:celestia1..."},
    }},
    MandateID: id,                    // 16 bytes from crypto/rand
    Version:   1,
    // FastModeMaxDelay: 20,          // blocks; leave out to forbid fast mode
}
b, err := policy.EncodeMandate(m)     // write hex.EncodeToString(b) to mandate.hex
```

Read what you are about to sign:

```sh
edicta-principal render --mandate mandate.hex
```

The text is normative (`spec/policy-v1.md`, section 7): limits are measured
on each decision's reference time (block time at its payload reference
height), hourly buckets may make a limit cover one extra hour (the gate may
deny early, never allow extra), and limits count authorizations, not
executions.

## 2. Signature schemes

| Scheme | `sig_type` | `principal` field | Sign with |
|---|---|---|---|
| Ed25519 | absent | 32-byte public key | `--key FILE` (32-byte seed, hex) |
| Cosmos ADR-036 | 2 (`policy.SigTypeADR036`), plus `PrincipalHRP` such as `"celestia"` | 33-byte compressed secp256k1 public key | Keplr, or `--key FILE` (secp256k1 scalar, hex) |
| EIP-712 | 3 (`policy.SigTypeEIP712`) | 20-byte Ethereum address | MetaMask, or `--key FILE` |

The principal key must not be a gate, executor or agent key; the gate
refuses to start otherwise.

**Keplr and MetaMask flows are implemented and vector-tested, but have not
been tested live with real wallets.** The specification marks as unverified
that Keplr `signArbitrary` accepts and displays a multi-line text of several
KB and produces exactly the expected sign document, and that MetaMask
`eth_signTypedData_v4` accepts a domain without `chainId`
(`spec/policy-v1.md`, section 6.2). A wallet signature that does not verify
is refused by `sign`, so nothing wrong is written; you would only find out
that the wallet path does not work.

### Ed25519

```sh
edicta-principal sign --mandate mandate.hex --scheme ed25519 --key principal.key --out mandate.cbor
```

### Keplr (Cosmos ADR-036)

The wallet signs the text `D`: the rendered mandate, an empty line and
`mandate hash: <hex>`. Keplr shows `D`, so you read the rules in the wallet.

1. Print the sign document and extract `D` from it:
   ```sh
   edicta-principal signdoc --mandate mandate.hex
   edicta-principal signdoc --mandate mandate.hex | jq -r '.msgs[0].value.data' | base64 --decode > D.txt
   ```
   The `signer` field is your `celestia1...` address; it must be the Keplr
   account whose public key is the mandate's `principal`.
2. In a browser page with Keplr, sign `D` as arbitrary data for that
   address: `window.keplr.signArbitrary(<chain id>, <celestia1... address>, <contents of D.txt>)`.
   Keplr returns the signature in base64.
3. Attach it:
   ```sh
   edicta-principal sign --mandate mandate.hex --scheme cosmos --signature <base64> --out mandate.cbor
   ```

### MetaMask (EIP-712)

MetaMask shows only `mandateHash`, `mandateId`, `version` and `gateId`, not
the rules. Your consent rests on the `render` output being what was hashed,
so render it with a tool you trust before signing.

1. Print the typed data:
   ```sh
   edicta-principal typed-data --mandate mandate.hex
   ```
2. In a browser page with MetaMask, request `eth_signTypedData_v4` with your
   address and that JSON. MetaMask returns a 65-byte hex signature.
3. Attach it:
   ```sh
   edicta-principal sign --mandate mandate.hex --scheme eth --signature 0x<hex> --out mandate.cbor
   ```

## 3. Verify and hand over

```sh
edicta-principal verify --signed mandate.cbor
```

It prints `valid`, the mandate hash and the principal line. Give:
- `mandate.cbor` to the gate operator (`[policy] mandate_file`);
- the mandate hash to every agent: each commitment must carry it as
  `mandate_ref`, or the gate refuses it;
- your principal identity to auditors, who pin it with
  `--principal ed25519:<hex>`, `--principal cosmos:<celestia1...>` or
  `--principal eth:0x<hex>`.

`edictad` writes the mandate record to its archive at start. To put a public
mandate into another archive: `edicta-principal publish --signed mandate.cbor
--archive DIR`. A private mandate is refused there, because it may enter an
archive only encrypted to its auditors, which `edictad` does.

## 4. Fast-mode consent

`FastModeMaxDelay` (1..1000 blocks) is your consent to fast mode: the gate
may authorize before the payload's anchor lands on L1, and the anchor must
land within that many blocks of the reference height or the decision is
provably invalid. Leave it out and the gate refuses fast-mode decisions
under this mandate. A gate in fast mode refuses at start a mandate whose
value is below its `min_fast_slack_blocks + 1` (cause
`fast_delay_below_slack`); with the default slack of 3 that means at least 4.

## 5. Auditors and private mode

A private mandate encrypts the mandate itself, the policy state and the
decision content to its auditors' X25519 keys. What that hides and what it
does not: [private-mode.md](private-mode.md).

Each auditor makes an X25519 key pair; no Edicta command does this yet. With
OpenSSL 3:

```sh
openssl genpkey -algorithm X25519 -out auditor.pem
openssl pkey -in auditor.pem -outform DER | tail -c 32 | xxd -p -c 32 > auditor.key   # private, chmod 600
openssl pkey -in auditor.pem -pubout -outform DER | tail -c 32 | xxd -p -c 32         # public, give to the principal
```

`auditor.key` is what the auditor passes to the verifier with
`--auditor-key`.

Make the mandate private:

```sh
edicta-principal private --mandate mandate.hex \
  --auditor "audit-firm:<64 hex public key>" --auditor "risk-desk:<64 hex>" \
  --out private.cbor
```

It sets the auditors (the key id is derived from the key, never typed), draws
a fresh 32-byte `state_salt` and, with `--new-id` or an all-zero
`mandate_id`, a fresh `mandate_id`, all from the system's CSPRNG. The output
file is mode 0600: the state salt blinds the private counter's hashes.

**Fingerprints.** Every tool prints an auditor as

```
Auditor "audit-firm" (label not verified) - key fingerprint: 16ad b7a9 605d 9bd8 e4b9 d296 8dd7 188e
```

The label is untrusted text. Before you sign, compare each full fingerprint
with the auditor over a channel you trust (in person, a call). The wallet
(Keplr) and `render` show the same line.

**Address book.** `--book FILE` (JSON, label to public key) remembers each
label's key. `render` and `sign` print a note for a new label and refuse a
known label that now maps to another key, with a warning, unless you pass
`--accept-new-key`. `sign` adds new labels to the book after it succeeds.

## 6. New versions and the counter reset

Counters (spent amounts per period, decision counts) belong to
`(scheme, principal, mandate_id)` at one gate.

- A new **version** of the same `mandate_id` continues the counters. The
  gate refuses a lower version, the same version with other content, and a
  version that gives an existing asset another scale.
- A new **mandate_id** starts every counter at zero.
- Switching between public and private mode needs a new `mandate_id`, so it
  also starts at zero.

**Warning: a counter reset forgets what was already spent in the current
periods.** A mandate of 10 TIA per 24 hours, replaced at noon by one with a
new `mandate_id`, allows another 10 TIA that afternoon. `sign` warns:

```
WARNING: the counters of this mandate start at zero; amounts already spent in the current periods are not carried over
```

Pass the version you replace with `--replaces old.cbor` so `sign` can tell
you whether the counters continue; without it, it warns every time.

To replace a mandate at a running gate: sign the higher version, put it in
`mandate_file`, restart `edictad`, and give agents the new hash. In-flight
decisions under the old hash are refused (`ErrMandateMismatch`) and the agent
re-signs under the new one.

## What is verified, what is not

Verified by the gate and by any verifier: your signature under the scheme
the mandate names, the binding to one `gate_id`, the version order, the
per-action rules on facts re-extracted from the exact action bytes, the
period limits on the state the gate signed, and, with `mandate_ref`, that the
agent committed to exactly your mandate.

Not verified: that the rendered text you read matches what a wallet that
shows only a hash (MetaMask, Ed25519 tooling) signed, beyond your trust in
the tool that rendered it; that an auditor label belongs to the person you
think (check the fingerprint); totals across assets or in fiat (limits are
per asset); and allows the gate kept outside every chain and every piece of
evidence.
