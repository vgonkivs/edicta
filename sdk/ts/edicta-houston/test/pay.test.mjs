// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import http from "node:http";
import { test } from "node:test";

import {
  EdictaAccessError,
  EdictaInputError,
  EdictaProtocolError,
  EdictaRefusedError,
  EdictaTransportError,
  EdictaUnavailableError,
  PayQueue,
  PayQueues,
  edictaPay,
  parseDurationMs,
} from "../dist/src/index.js";

const live = new URL("../../../../spec/vectors/profiles/eden-escrow/live/", import.meta.url);
const fixture = (n) => readFileSync(new URL(n, live), "utf8");
const build = JSON.parse(fixture("houston-deposit-build.json"));
const header = Buffer.from(fixture("houston-payment-required.json")).toString("base64");
const HASH = "ab".repeat(32);
const TOKEN = "s3cret-token-value";

function okBody(over = {}) {
  return {
    commitment_hash: HASH,
    settled: true,
    payment_signature: "0x" + "11".repeat(65),
    rail_ref: "0x" + "22".repeat(32),
    signed_tx: "AAEC",
    payer: "0x" + "33".repeat(20),
    authorization: "QUJD",
    ...over,
  };
}

// handler(req, bodyJson) returns [status, body] or a function taking res.
async function fake(handler) {
  const seen = [];
  const srv = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString();
      let json;
      try { json = JSON.parse(raw); } catch { json = undefined; }
      seen.push({ method: req.method, url: req.url, headers: req.headers, json });
      const out = handler(req, json, res);
      if (out === undefined) return;
      const [status, body] = out;
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(typeof body === "string" ? body : JSON.stringify(body));
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${srv.address().port}`;
  return { url, seen, close: () => new Promise((r) => { srv.closeAllConnections(); srv.close(r); }) };
}

const base = (url, over = {}) => ({
  agentServeUrl: url,
  paymentRequiredHeader: header,
  build,
  resource: "https://inference.bot.fun/v1/chat/completions",
  policy: { id: "houston-pay", version: "1" },
  model: { id: "agent" },
  ...over,
});

test("happy path sends the documented request and returns the checked result", async () => {
  const f = await fake(() => [200, okBody()]);
  try {
    const r = await edictaPay(base(f.url, { token: TOKEN, validFor: "10m" }));
    assert.equal(r.paymentSignature, "0x" + "11".repeat(65));
    assert.equal(r.commitmentHash, HASH);
    assert.equal(r.payer, "0x" + "33".repeat(20));
    const [req] = f.seen;
    assert.equal(req.method, "POST");
    assert.equal(req.url, "/v1/commit");
    assert.equal(req.headers.authorization, `Bearer ${TOKEN}`);
    assert.match(req.headers["content-type"], /^application\/json/);
    const b = req.json;
    assert.equal(b.sign && b.broadcast && b.record && b.payment_signature, true);
    assert.equal("wait" in b, false);
    assert.equal("context" in b, false);
    assert.equal(b.valid_for, "10m");
    assert.equal(b.eden.payment_required, header);
    assert.deepEqual(b.eden.build, build);
    assert.equal(b.eden.resource, "https://inference.bot.fun/v1/chat/completions");
    assert.deepEqual(b.policy, { id: "houston-pay", version: "1" });
  } finally {
    await f.close();
  }
});

test("build may be passed as JSON text", async () => {
  const f = await fake(() => [200, okBody()]);
  try {
    await edictaPay(base(f.url, { build: fixture("houston-deposit-build.json") }));
    assert.deepEqual(f.seen[0].json.eden.build, build);
  } finally {
    await f.close();
  }
});

test("resume sends only the hash and the header, and checks the answer names that hash", async () => {
  const f = await fake(() => [200, okBody()]);
  try {
    await edictaPay({ agentServeUrl: f.url, paymentRequiredHeader: header, resumeHash: HASH });
    const b = f.seen[0].json;
    assert.equal(b.resume_hash, HASH);
    assert.deepEqual(Object.keys(b.eden), ["payment_required"]);
    assert.equal(b.model, undefined);
    await assert.rejects(
      edictaPay({ agentServeUrl: f.url, paymentRequiredHeader: header, resumeHash: "cd".repeat(32) }),
      EdictaProtocolError,
    );
  } finally {
    await f.close();
  }
});

test("service error codes map to typed errors and keep the resume material", async () => {
  const cases = [
    [400, { code: "usage", message: "bad" }, EdictaInputError],
    [400, { code: "eden_input", message: "bad" }, EdictaInputError],
    [403, { code: "host_refused", message: "no" }, EdictaAccessError],
    [401, { code: "unauthorized", message: "no" }, EdictaAccessError],
    [422, { code: "quote_expired", message: "late", commitment_hash: HASH }, EdictaRefusedError],
    [422, { code: "authorization_expired", message: "late", commitment_hash: HASH }, EdictaRefusedError],
    [422, { code: "signer_response_invalid", message: "x" }, EdictaRefusedError],
    [422, { code: "payment_proof_unavailable", message: "x" }, EdictaRefusedError],
    [409, { code: "ErrNonceUsed", message: "gate" }, EdictaRefusedError],
    [403, { code: "policy.ErrAmountAboveMax", message: "mandate" }, EdictaRefusedError],
    [403, { code: "policy.ErrMandateMismatch", message: "mandate" }, EdictaRefusedError],
    [403, { code: "ErrSignatureInvalid", message: "sig" }, EdictaRefusedError],
    [400, { code: "ErrMalformed", message: "envelope" }, EdictaRefusedError],
    [401, { code: "ErrSignatureInvalid", message: "sig" }, EdictaRefusedError],
    [500, { code: "internal", message: "x" }, EdictaUnavailableError],
    [429, { code: "busy", message: "x", retryable: true }, EdictaUnavailableError],
    [503, { code: "settlement_pending", message: "x", retryable: true, commitment_hash: HASH, rail_ref: "0xabc" }, EdictaUnavailableError],
    [503, { code: "state_unavailable", message: "x", retryable: true, commitment_hash: HASH }, EdictaUnavailableError],
  ];
  for (const [status, body, cls] of cases) {
    const f = await fake(() => [status, body]);
    try {
      await assert.rejects(edictaPay(base(f.url)), (e) => {
        assert.ok(e instanceof cls, `${body.code} -> ${e.name}`);
        assert.equal(e.code, body.code);
        assert.equal(e.status, status);
        assert.equal(e.commitmentHash, body.commitment_hash);
        assert.equal(e.retryable, cls === EdictaUnavailableError);
        return true;
      });
    } finally {
      await f.close();
    }
  }
});

// Every code `agent serve` emits (commitcmd), with the status it uses.
test("every code agent serve emits maps to the documented class", async () => {
  const rows = [
    ["usage", 400, EdictaInputError],
    ["eden_input", 400, EdictaInputError],
    ["method_not_allowed", 405, EdictaInputError],
    ["media_type", 415, EdictaInputError],
    ["forbidden", 403, EdictaAccessError],
    ["host_refused", 403, EdictaAccessError],
    ["origin_refused", 403, EdictaAccessError],
    ["unauthorized", 401, EdictaAccessError],
    ["busy", 429, EdictaUnavailableError],
    ["source_unavailable", 503, EdictaUnavailableError],
    ["state_unavailable", 503, EdictaUnavailableError],
    ["settlement_pending", 503, EdictaUnavailableError],
    ["build_failed", 422, EdictaRefusedError],
    ["publication_refused", 422, EdictaRefusedError],
    ["recorder_fast_mode", 422, EdictaRefusedError],
    ["quote_expired", 422, EdictaRefusedError],
    ["quote_outlives_authorization", 422, EdictaRefusedError],
    ["authorization_expired", 422, EdictaRefusedError],
    ["signer_response_invalid", 422, EdictaRefusedError],
    ["payment_proof_unavailable", 422, EdictaRefusedError],
    ["deposit_reverted", 422, EdictaRefusedError],
    ["deposit_not_executed", 422, EdictaRefusedError],
    ["settlement_wrong", 422, EdictaRefusedError],
    ["signer.unparsable", 422, EdictaRefusedError],
    ["signer.ErrNotAuthorized", 422, EdictaRefusedError],
    ["signer.ErrSharedCredential", 422, EdictaRefusedError],
  ];
  for (const [code, status, cls] of rows) {
    const body = { code, message: "m", retryable: cls === EdictaUnavailableError, commitment_hash: HASH };
    const f = await fake(() => [status, body]);
    try {
      await assert.rejects(edictaPay(base(f.url)), (e) => e instanceof cls && e.code === code && e.commitmentHash === HASH, code);
    } finally {
      await f.close();
    }
  }
});

test("a shared signer credential is a refusal that keeps the hash and is never retryable", async () => {
  const f = await fake(() => [422, { code: "signer.ErrSharedCredential", message: "shared; do not commit again", commitment_hash: HASH }]);
  try {
    await assert.rejects(edictaPay(base(f.url)), (e) => e instanceof EdictaRefusedError && !e.retryable && e.commitmentHash === HASH);
  } finally {
    await f.close();
  }
});

test("success fields the service adds are exposed; signed bytes may be missing after a resume", async () => {
  const f = await fake(() => [200, okBody({ recorded: true, receipt: "UkNQ", warning: "payer not cross-checked\u0001", rail_ref: undefined, signed_tx: undefined, payer: undefined })]);
  try {
    const r = await edictaPay(base(f.url));
    assert.equal(r.recorded, true);
    assert.equal(r.receipt, "UkNQ");
    assert.match(r.warning, /^payer not cross-checked/);
    assert.equal(r.railRef, undefined);
    assert.equal(r.signedTx, undefined);
  } finally {
    await f.close();
  }
});

test("a failure that carries the signed deposit exposes it", async () => {
  const f = await fake(() => [503, { code: "state_unavailable", message: "x", retryable: true, commitment_hash: HASH, signed_tx: "AAEC" }]);
  try {
    await assert.rejects(edictaPay(base(f.url)), (e) => e.signedTx === "AAEC");
  } finally {
    await f.close();
  }
});

test("a pending settlement keeps the rail ref", async () => {
  const f = await fake(() => [503, { code: "settlement_pending", message: "x", retryable: true, commitment_hash: HASH, rail_ref: "0xabc" }]);
  try {
    await assert.rejects(edictaPay(base(f.url)), (e) => e.railRef === "0xabc" && e.retryable);
  } finally {
    await f.close();
  }
});

test("a malformed commitment hash in an error body is dropped", async () => {
  const f = await fake(() => [422, { code: "x", message: "m", commitment_hash: "nope" }]);
  try {
    await assert.rejects(edictaPay(base(f.url)), (e) => e instanceof EdictaRefusedError && e.commitmentHash === undefined);
  } finally {
    await f.close();
  }
});

test("a non-JSON error body and unusable successes are classified, not trusted", async () => {
  let f;
  for (const status of [502, 503, 504]) {
    f = await fake(() => [status, "<html>bad gateway</html>"]);
    try {
      await assert.rejects(edictaPay(base(f.url)), (e) => e instanceof EdictaUnavailableError && e.retryable);
    } finally {
      await f.close();
    }
  }
  f = await fake(() => [418, "teapot"]);
  try {
    await assert.rejects(edictaPay(base(f.url)), EdictaRefusedError);
  } finally {
    await f.close();
  }
  const broken = [
    "not json",
    {},
    okBody({ settled: false }),
    okBody({ settled: undefined }),
    okBody({ payment_signature: "" }),
    okBody({ payment_signature: "has space" }),
    okBody({ payment_signature: undefined }),
    okBody({ commitment_hash: "short" }),
    okBody({ payer: "0x12" }),
    okBody({ rail_ref: "" }),
    okBody({ signed_tx: "" }),
    okBody({ authorization: undefined }),
    okBody({ receipt: 5 }),
  ];
  for (const body of broken) {
    f = await fake(() => [200, body]);
    try {
      await assert.rejects(edictaPay(base(f.url)), EdictaProtocolError, JSON.stringify(body));
    } finally {
      await f.close();
    }
  }
});

test("redirects are refused so the token is never re-sent elsewhere", async () => {
  const f = await fake((req, j, res) => {
    res.writeHead(307, { Location: "http://127.0.0.1:1/v1/commit" });
    res.end();
  });
  try {
    await assert.rejects(edictaPay(base(f.url, { token: TOKEN })), EdictaTransportError);
  } finally {
    await f.close();
  }
});

test("a dead service and an overdue answer are transport errors; neither leaks the token", async () => {
  await assert.rejects(
    edictaPay(base("http://127.0.0.1:1", { token: TOKEN })),
    (e) => e instanceof EdictaTransportError && e.retryable && !String(e.message).includes(TOKEN),
  );
  const f = await fake(() => undefined);
  try {
    await assert.rejects(
      edictaPay(base(f.url, { token: TOKEN, wait: "50ms", marginMs: 50 })),
      (e) => e instanceof EdictaTransportError && /timed out/.test(e.message) && !JSON.stringify(e).includes(TOKEN),
    );
    const ac = new AbortController();
    const p = edictaPay(base(f.url, { signal: ac.signal }));
    setTimeout(() => ac.abort(), 20);
    await assert.rejects(p, (e) => e instanceof EdictaTransportError && /aborted/.test(e.message));
  } finally {
    await f.close();
  }
});

test("input is checked before any request is made", async () => {
  const f = await fake(() => [200, okBody()]);
  try {
    const bad = [
      { agentServeUrl: "ftp://127.0.0.1" },
      { agentServeUrl: "not a url" },
      { agentServeUrl: "http://user:pw@127.0.0.1:1" },
      { agentServeUrl: "http://127.0.0.1:1/?x=1" },
      { agentServeUrl: "http://example.com:8500" },
      { agentServeUrl: "http://example.com:8500", allowRemote: true, token: TOKEN },
      { agentServeUrl: "https://example.com:8500", allowRemote: true },
      { token: "has space" },
      { token: "" },
      { paymentRequiredHeader: "" },
      { paymentRequiredHeader: "not base64!!" },
      { paymentRequiredHeader: "A".repeat(70000) },
      { build: undefined },
      { build: "{" },
      { build: [] },
      { build: { txData: {}, paymentId: build.paymentId } },
      { build: { txData: { ...build.txData, to: "0x12" }, paymentId: build.paymentId } },
      { build: { txData: build.txData, paymentId: "0x12" } },
      { resource: undefined },
      { resource: "http://inference.bot.fun/x" },
      { policy: undefined },
      { policy: { id: "" } },
      { model: { id: "m", version: 3 } },
      { wait: "forever" },
      { wait: "2h" },
      { wait: "0s" },
      { validFor: "-5m" },
      { validFor: "soon" },
      { marginMs: -1 },
      { marginMs: 1e12 },
      { marginMs: "5" },
      { model: undefined },
      { context: [] },
      { context: { eden_escrow: {} } },
      { context: { n: 1n } },
      { context: { big: "x".repeat(70000) } },
      { build: { ...build, n: 1n } },
      { resume: { envelope: "AA==", action: "AA==", salt: "not b64!" } },
      { resume: { envelope: "AA==", action: "AA==", salt: "AA==" }, resumeHash: HASH },
      { resume: { envelope: "AA==", action: "AA==", salt: "AA==" } },
      { resumeHash: "XYZ" },
      { resumeHash: HASH },
    ];
    for (const o of bad) {
      const opts = base(f.url, o);
      await assert.rejects(edictaPay(opts), (e) => e instanceof EdictaInputError && e.code === "client_input", Object.keys(o).join(","));
    }
    assert.equal(f.seen.length, 0);
  } finally {
    await f.close();
  }
});

test("the remote form needs https, a token and is sent with the bearer", async () => {
  // Only the checks run here; the https endpoint does not exist, so the call ends as a transport error.
  await assert.rejects(
    edictaPay(base("https://127.0.0.2:1", { token: TOKEN, allowRemote: true })),
    EdictaTransportError,
  );
});

test("context, wait and resume material are sent as given; failures expose resume material", async () => {
  const mat = { envelope: "AQID", action: "BAUG", salt: "BwgJ" };
  let f = await fake(() => [200, okBody()]);
  try {
    await edictaPay(base(f.url, { context: { request_hash: "abc" }, wait: "2m" }));
    assert.deepEqual(f.seen[0].json.context, { request_hash: "abc" });
    assert.equal(f.seen[0].json.wait, "2m");
    await edictaPay({ agentServeUrl: f.url, paymentRequiredHeader: header, resume: mat });
    assert.deepEqual(f.seen[1].json.resume, mat);
    assert.equal(f.seen[1].json.resume_hash, undefined);
  } finally {
    await f.close();
  }
  f = await fake(() => [503, { code: "settlement_pending", message: "m\u0007x", retryable: true, commitment_hash: HASH, rail_ref: "0xabc", ...mat, authorization: "QUJD" }]);
  try {
    await assert.rejects(edictaPay(base(f.url)), (e) => {
      assert.deepEqual(e.resume, mat);
      assert.equal(e.authorization, "QUJD");
      assert.ok(!/[\u0000-\u001f]/.test(e.message));
      return e.commitmentHash === HASH;
    });
  } finally {
    await f.close();
  }
});

test("a chunked answer above the size bound is cut off", async () => {
  const f = await fake((req, j, res) => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.write("x".repeat(5 * 1024 * 1024));
    res.end();
  });
  try {
    await assert.rejects(edictaPay(base(f.url)), EdictaProtocolError);
  } finally {
    await f.close();
  }
});

test("PayQueues keys by payer, case-insensitively", () => {
  const qs = new PayQueues();
  assert.equal(qs.for("0xAB"), qs.for("0xab"));
  assert.notEqual(qs.for("0xab"), qs.for("0xcd"));
});

test("parseDurationMs", () => {
  assert.equal(parseDurationMs("5m"), 300000);
  assert.equal(parseDurationMs("1h30m"), 5400000);
  assert.equal(parseDurationMs("1.5s"), 1500);
  assert.equal(parseDurationMs("250ms"), 250);
  assert.equal(parseDurationMs(""), undefined);
  assert.equal(parseDurationMs("5"), undefined);
  assert.equal(parseDurationMs("-5m"), undefined);
});

test("PayQueue runs tasks one at a time and survives a failing task", async () => {
  const q = new PayQueue();
  const order = [];
  let active = 0;
  const task = (n, fail) => async () => {
    active++;
    assert.equal(active, 1);
    order.push(`start${n}`);
    await new Promise((r) => setTimeout(r, 10));
    order.push(`end${n}`);
    active--;
    if (fail) throw new Error("boom");
    return n;
  };
  const res = await Promise.allSettled([q.run(task(1, true)), q.run(task(2)), q.run(task(3))]);
  assert.deepEqual(res.map((r) => r.status), ["rejected", "fulfilled", "fulfilled"]);
  assert.deepEqual(order, ["start1", "end1", "start2", "end2", "start3", "end3"]);
});
