<!-- SPDX-License-Identifier: Apache-2.0 -->

# @edicta/houston

Replaces the "sign + send" step of an escrow-upto payment flow. The agent
process holds no wallet key: it talks to a local `edicta agent serve`, which
commits the decision, gets the gate Authorization, has the signer sign and
send the deposit, waits until it executed and releases the Payment-Signature.

Node 20.3+, no runtime dependencies.

```ts
import { edictaPay, PayQueue } from "@edicta/houston";

const r = await edictaPay({
  agentServeUrl: "http://127.0.0.1:8500",   // loopback; token only for a remote service
  paymentRequiredHeader: res402.headers.get("payment-required")!,
  build: await buildRes.json(),             // the /deposit/build answer, unchanged
  resource: "https://inference.example/v1/chat/completions",
  model: { id: "my-model", version: "1" },  // committed and published as given
  policy: { id: "my-agent-policy", version: "1" },
  context: { request_hash: "..." },         // optional: your own decision context
});
// r.paymentSignature goes into the retry exactly where the starter put its own signature.
```

## Where it plugs into the flow

1. `POST /v1/chat/completions` returns 402 with the `payment-required` header.
2. `POST /deposit/build` with `from` = your agent's own payer address on that
   chain (the signer pins one payer key per agent per chain; ask its operator).
   Wrap steps 2 and 3 in `PayQueues.for(payer).run(...)` so two builds for one payer never overlap.
3. `edictaPay(...)` replaces "sign the unsigned tx", "POST /deposit/send" and the
   wait for confirmation: the signer sends the signed deposit itself, directly
   to Eden by default, and the call returns only after the deposit is
   executed. The signer's `broadcaster = "houston-relay"` is an optional
   fallback for a server that must see the deposit through `/deposit/send`
   (deprecated by the server). `signedTx` is returned for callers who want to
   relay it themselves.
4. Retry the original request with `Payment-Signature`, built from
   `r.paymentSignature` by the starter's existing encoder.

The decision committed is the decoded deposit transaction, not the server's
description of it; a quote that does not match the transaction is refused.

## Paid retry and relay handoff

A payment server may not pick up a deposit the signer sent directly to Eden.
Give `edictaPay` the paid retry and the handoff settings and it makes the
retry itself; or call `paidRetryWithHandoff(result, retry, handoff)` with the
result of an earlier `edictaPay`.

```ts
const r = await edictaPay({
  ...options,
  paidRetry: (paymentSignature) => fetch(resourceUrl, retryInit(paymentSignature)), // your existing encoder
  handoff: { paymentServerUrl: "https://pay.example" },   // the base you called /deposit/build on
});
// r.paidRetry.response is the last answer, unread.
// r.paidRetry.needsOperator: still refused after the handoff; do not pay a new quote under this decision.
```

What it does, and nothing else:

- It retries with the same Payment-Signature. Only two refusals are acted on:
  a 402 whose `payment-required` quote names this deposit's `paymentId`
  (RR1), and a 403 whose body contains `neither the escrow buyer` (RR2). A
  success, any other status, a quote for another `paymentId`, or an answer
  over 16384 bytes is returned as it is.
- After a recognised refusal it waits `pickupDelayMs` (default 10 s, at most
  120 s) and retries once. Refused in a recognised way again, it checks that
  keccak256 of the stored signed deposit equals `railRef`, records the
  handoff in the store, and posts exactly those bytes, with the `paymentId`
  of their calldata, to `{paymentServerUrl}/deposit/send`. It never signs,
  rebuilds or pays anything: the deposit already executed. The relay's
  answer is never evidence; a relay error is reported in `relayFault` and
  not retried.
- It waits `pickupDelayMs` once more and makes one last retry.
- At most one handoff per commitment hash, across restarts. The default store
  is `FileHandoffStore` in `$EDICTA_HOME/handoff` (else `~/.edicta/handoff`):
  one file per commitment hash, created exclusively and synced before the
  bytes are sent. Pass your own `store` (any `{ claim(commitmentHash):
  Promise<boolean> }` that is atomic and durable; `true` only for the first
  claim) when the agent runs in more than one process or on more than one
  host.

`edicta agent serve --state-dir DIR --payment-server https://... [--pickup-delay 10s]`
offers the same rules to clients in other languages: `POST /v1/paid-retry`
with `commitment_hash`, `payment_signature`, `status`, `payment_required` and
`body` (base64) of each paid retry's answer returns `next` (`none`, `retry`
after `retry_after_ms`, or `operator`) and makes the one handoff itself.

## Resume: never start over

`edicta agent serve` must run with `--state-dir` for resume by hash. Without it
use the `resume` option with the material from the failed call (`error.resume`).

**Never start over with a fresh 402 while a commitment hash is pending: resume
it.** A new quote and build pay a second time. When an error carries
`commitmentHash` or `resume`, call `edictaPay` again with `resumeHash` (or
`resume`) and the original `paymentRequiredHeader`, until it succeeds or the
quote has expired. This also holds for `EdictaProtocolError` on a 200 and for a
transport error after a timeout.

A signer credential shared between agents cannot follow a pending deposit: the
signer answers `signer.ErrSharedCredential` (an `EdictaRefusedError`, never
retryable). Do not start over and do not commit again; give the agent its own
signer credential and resume the pending hash, or ask the operator.

## Errors

All errors extend `EdictaError` (`code`, `status`, `retryable`, `commitmentHash`,
`railRef`, `resume`, `authorization`). The service's `code` decides the class,
not the HTTP status: gate and policy refusals arrive with 400, 403 or 409 and
are `EdictaRefusedError`.

| Class | Meaning | Action |
|---|---|---|
| `EdictaInputError` | malformed call (checked locally or at the service) | fix the call |
| `EdictaAccessError` | bad token, Host or Origin | fix configuration |
| `EdictaRefusedError` | gate, signer or a local check refused (policy deny, nonce used, quote or Authorization expired, ...) | do not retry unchanged |
| `EdictaUnavailableError` | retryable: busy, 5xx or proxy errors, `settlement_pending` | retry; resume when a hash or `resume` is set |
| `EdictaTransportError` | no answer (connection, timeout, abort); the run may exist | retry the same inputs only if no hash exists yet |
| `EdictaProtocolError` | the answer did not have the documented shape | treat as a refusal, keep the hash and resume |

`wait` (sent only when you set it; the service default applies otherwise) bounds
the settlement wait. The HTTP call is cut off `marginMs` later (default 6 min,
at most 1 h); keep it above the service's publish and authorize time. The token
is sent only as a bearer header, redirects are refused (a custom `fetch` must do
the same), and no error or log line contains it.

## Test

`npm install && npm test` (builds with `tsc`, runs `node --test` against a local fake service and the live fixtures).
