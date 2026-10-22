# Private mode

A mandate with auditors is private: the mandate, the policy state and the
decision content go to the shared archive only encrypted to the auditors'
X25519 keys. Anyone can still check that the records hang together; only an
auditor can read them. Spec: `spec/policy-v1.md`, sections 9.5 (envelope) and
9.6 (residual leakage, normative); `spec/decision-commitment-v1.md`, section
20.11 (decision record and reveal).

How to make a mandate private: [principal.md](principal.md), section 5.

## What is hidden

Encrypted to the auditors (archive record kind 15):
- the signed mandate itself: its limits, allowlists, recipients and the
  auditor list with labels;
- the policy state: every closed hourly bucket and closed set (sums, counts,
  open buckets);
- the private part of every verdict: the facts (kind, asset, amount,
  recipient) and the deny reasons;
- the action bytes and the action salt of every decision (the decision
  record stores no action in clear).

The payload is always encrypted to the recipients the agent chooses; under a
private mandate, seal it to the auditors.

Public hashes that would otherwise be dictionary oracles all carry a secret
salt: the action hash (the action salt), the state hashes and the archive
keys of buckets and closed sets (the mandate's `state_salt`), and the verdict's
`private_hash`.

## What is not hidden

From `spec/policy-v1.md`, section 9.6. A reader without an auditor key can
learn:

1. Executed transactions on public rails: amounts, recipients, times, hence
   the total spend. A receipt links each to its decision, and a reveal (below)
   publishes that executed action's salt.
2. That decisions exist and when (anchor heights, reference times), hence
   their frequency.
3. The commitment envelope of every decision: agent key, `gate_id`, nonce,
   `issued_at`, `valid_until`, the action type, the payload reference,
   `mandate_ref`, payload size. The action hash is public but salted, so it
   cannot be tested against guesses.
4. Allow or deny for every verdict, and how many: allows per counter by
   walking the public links, denies per mandate version and agent, and the
   number of distinct deny reasons of one decision (not the number of denied
   attempts).
5. Which mandate versions belong to one counter.
6. Auditor key ids, linkable across mandates.
7. Lengths of envelopes and private parts, and the timing of bucket records
   (a rollover shows an allow in a new hour).
8. The first allow of a counter.
9. A removed auditor keeps the counter's `state_salt`: it can still test
   guesses against later state hashes and read everything up to its removal.
   Start a new `mandate_id` to cut it off.

On an off-chain rail (the IBKR profile) the action bytes are never public, so
only items 2 to 9 apply. Timing and length padding are not part of v1.

## Reveal on execution (public rails)

On a public rail the executed transaction is public anyway, but without its
salt nobody can tie it to the salted `action_hash`, so a verifier without a
key reports `action` and `execution` as `unchecked` (`policy_private`).

The operator can list such action types in `gate.reveal_on_execution`. Once
a receipt names the transaction, the gate archives a reveal record with the
salt; a verifier rebuilds the action bytes from the transaction
(`ActionFromTx`) and accepts them only if they hash to the agent-signed
`action_hash` with that salt. Only types whose profile is
`public_execution = true` are allowed (bank-send yes, IBKR no), and only
executed decisions with a receipt are revealed: denied or never executed
decisions stay hidden. See [profiles.md](profiles.md).

## Verifying a private decision

With an auditor key:

```sh
celestia/bin/edicta verify <commitment hash> --gate-key <hex> --archive <dir> \
  --headers-rpc <RPC> --checkpoint <HEIGHT>:<HASH> \
  --principal cosmos:<celestia1...> --require-policy --policy-full \
  --auditor-key auditor.key
```

`--auditor-key` takes a file with the X25519 private key in hex, mode 0600;
repeat it for several auditors. The report names the fingerprint of the key
that opened the mandate.

Without a key the verifier still checks: the agent signature, the payload
and anchor, the gate's Authorization, that an allow verdict exists for this
decision, that `mandate_ref` equals the verdict's mandate hash, and the hash
links and forks of the verdict chain. It cannot check the facts, the
reference time, fast-mode consent, or that the rules were respected; those
checks are `unchecked` with `policy_private`.

A private record that hashes correctly but contradicts its own gate-signed
verdict is the gate's fault: `gate_integrity` violated with
`gate_signed_inconsistent_private_part` (exit 5).

## Operator notes

- `edictad` writes the encrypted records itself, including the mandate at
  start. It refuses to write a mandate, bucket or closed set in clear under a
  private mandate. `edicta-principal publish` refuses a private mandate.
- A counter cannot switch between public and private mode; the principal
  starts a new `mandate_id`, which resets the counters to zero.
- Losing every auditor key makes the private records unreadable for
  everyone. A new mandate version with new auditors encrypts from then on.

## What is verified, what is not

Verified for everyone: the same integrity as a public mandate, minus the
content: signatures, anchors, the allow bit, the `mandate_ref` match, and the
consistency of the verdict chain. Verified for an auditor: everything a
public mandate allows a verifier to check.

Not hidden: the items listed above. Not guaranteed: that the agent sealed its
payload to the auditors (the gate never decrypts), and that an auditor key
belongs to the person its label names (the principal checks the fingerprint).
