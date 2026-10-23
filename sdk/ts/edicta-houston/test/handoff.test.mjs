// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  EdictaInputError,
  EdictaRefusedError,
  FileHandoffStore,
  asksForPayment,
  decodePaymentRequired,
  depositPaymentId,
  edictaPay,
  keccak256,
  paidRetryWithHandoff,
  recognisedRefusal,
} from "../dist/src/index.js";

const vectors = new URL("../../../../spec/vectors/profiles/eden-escrow/", import.meta.url);
const vec = (n) => JSON.parse(readFileSync(new URL(n, vectors), "utf8"));
const x402 = vec("x402.json");
const signedVec = vec("signed.json");
const hex = (b) => Buffer.from(b).toString("hex");
const unhex = (s) => new Uint8Array(Buffer.from(s, "hex"));
const enc = (s) => new TextEncoder().encode(s);

const BUYER = "signer is neither the escrow buyer nor an authorized device key";
const buildPid = x402.build.profile_fields.payment_id_hex;
const liveR = readFileSync(new URL("live/houston-payment-required.json", vectors));

test("keccak256 matches the empty-input hash and every signed vector's rail_ref", () => {
  assert.equal(hex(keccak256(new Uint8Array(0))), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
  assert.equal(hex(keccak256(new Uint8Array(136))).length, 64, "a full block");
  for (const c of signedVec.cases) assert.equal(hex(keccak256(unhex(c.signed_hex))), c.rail_ref, c.id);
  for (const c of signedVec.exact_tx) assert.equal(hex(keccak256(unhex(c.signed_hex))), c.rail_ref, c.id);
});

test("the paymentId comes from the transaction's own calldata", () => {
  assert.equal(depositPaymentId(unhex(x402.build.tx_hex)), buildPid, "the unsigned build transaction");
  for (const c of signedVec.cases) assert.match(depositPaymentId(unhex(c.signed_hex)) ?? "", /^[0-9a-f]{64}$/, c.id);
  assert.equal(depositPaymentId(unhex("01" + x402.build.tx_hex.slice(2))), undefined, "not type 2");
  assert.equal(depositPaymentId(unhex(x402.build.tx_hex.slice(0, 40))), undefined, "truncated");
});

test("PAYMENT-REQUIRED header decoding follows the vectors", () => {
  for (const c of x402.requirements.header.accept) assert.equal(hex(decodePaymentRequired(c.value) ?? []), c.r_hex, c.id);
  for (const c of x402.requirements.header.reject) assert.equal(decodePaymentRequired(c.value), undefined, c.id);
});

test("a quote asks again for the payment only under the document rules and with the paymentId", () => {
  assert.equal(asksForPayment(liveR, buildPid), true, "the recorded quote");
  const other = "11".repeat(32);
  for (const c of x402.requirements.accept) {
    assert.equal(asksForPayment(unhex(c.r_hex), buildPid), true, c.id);
    assert.equal(asksForPayment(unhex(c.r_hex), other), false, `${c.id}: another paymentId is a new quote`);
  }
  for (const c of x402.requirements.reject) {
    if (["S4a", "S4c", "S4d"].includes(c.expect)) assert.equal(asksForPayment(unhex(c.r_hex), buildPid), false, c.id);
    if (["S4e", "S4f"].includes(c.expect)) assert.equal(asksForPayment(unhex(c.r_hex), buildPid), true, `${c.id}: only the document and the paymentId are read`);
  }
  const entry = (pid) => `{"scheme":"escrow-upto","extra":{"paymentId":"0x${pid}"}}`;
  const doc = (...e) => enc(`{"x402Version":2,"accepts":[${e.join(",")}]}`);
  assert.equal(asksForPayment(doc(entry(buildPid), entry(buildPid)), buildPid), false, "two entries for the payment");
  assert.equal(asksForPayment(doc(entry(other), entry(buildPid.toUpperCase())), buildPid), true, "one entry for the payment, hex of either case");
  assert.equal(asksForPayment(enc(`{"x402Version":2,"x402Version":2,"accepts":[${entry(buildPid)}]}`), buildPid), false, "a repeated member");
  assert.equal(asksForPayment(enc(`{"x402Version":2,"accepts":[${entry(buildPid)}],"n":"\\ud800"}`), buildPid), false, "a lone surrogate");
  assert.equal(asksForPayment(enc(`﻿{"x402Version":2,"accepts":[${entry(buildPid)}]}`), buildPid), false, "a byte order mark");
});

test("only RR1 and RR2 are recognised", () => {
  const header = Buffer.from(liveR).toString("base64");
  const otherR = Buffer.from(Buffer.from(liveR).toString("latin1").replaceAll(buildPid, "1".repeat(64)), "latin1").toString("base64");
  const big = enc("x".repeat(16384) + BUYER);
  assert.equal(recognisedRefusal(402, header, new Uint8Array(0), buildPid), "RR1");
  assert.equal(recognisedRefusal(403, null, enc(`{"error":"${BUYER}"}`), buildPid), "RR2");
  assert.equal(recognisedRefusal(402, otherR, new Uint8Array(0), buildPid), undefined, "a new quote");
  assert.equal(recognisedRefusal(402, null, enc(BUYER), buildPid), undefined, "a 402 without the header");
  assert.equal(recognisedRefusal(402, header.replaceAll("+", "-") + "-", new Uint8Array(0), buildPid), undefined, "URL-safe base64");
  assert.equal(recognisedRefusal(402, header, big, buildPid), undefined, "an answer over 16384 bytes");
  assert.equal(recognisedRefusal(403, null, big, buildPid), undefined, "an answer over 16384 bytes");
  assert.equal(recognisedRefusal(403, null, enc("forbidden"), buildPid), undefined, "another 403");
  assert.equal(recognisedRefusal(403, null, enc(BUYER.toUpperCase()), buildPid), undefined, "the text in other case");
  for (const status of [200, 201, 204, 302, 307, 400, 401, 404, 409, 422, 429, 500, 502, 503]) {
    assert.equal(recognisedRefusal(status, header, enc(BUYER), buildPid), undefined, String(status));
  }
});

// A decision whose signed deposit is the first signed vector.
const sv = signedVec.cases[0];
const svPid = depositPaymentId(unhex(sv.signed_hex));
const svAction = Buffer.from(unhex(vec("action.json").cases.find((c) => c.id === sv.action_ref).cbor_hex)).toString("base64");
// The vector key's personal_sign over svPid (v = 27 + y_parity), as the signer releases it.
const svProof = "0x06ca9a1c1571faefad19ada013c4e64815e56913f23a1dabd32f4525395975cc46d97c6eb47610bfff455f9a232a57850e49413d55e4dc07fc7757fe1e1fc5481c";
const decision = (over = {}) => ({
  commitmentHash: "ab".repeat(32),
  paymentSignature: svProof,
  signedTx: Buffer.from(unhex(sv.signed_hex)).toString("base64"),
  railRef: sv.rail_ref,
  raw: { action: svAction, deposit: { payment_id_hex: svPid, escrow: "0x65d77c98e73dfbea91ecb72b27c9753e186a94c8" }, payer: sv.payer },
  ...over,
});
const quoteFor = (pid) =>
  Buffer.from(`{"x402Version":2,"accepts":[{"scheme":"escrow-upto","extra":{"paymentId":"0x${pid}"}}]}`).toString("base64");
const rr1 = () => new Response("payment required", { status: 402, headers: { "payment-required": quoteFor(svPid) } });
const rr2 = () => new Response(`{"error":"${BUYER}"}`, { status: 403 });
const ok = () => new Response(`{"choices":[]}`, { status: 200 });

function world(answers, relay = () => new Response(`{"txHash":"0x${sv.rail_ref}","deprecation":true}`, { status: 200 })) {
  const w = { sigs: [], relayCalls: [], sleeps: [], dir: mkdtempSync(join(tmpdir(), "edicta-handoff-")) };
  w.retry = async (sig) => {
    w.sigs.push(sig);
    const a = answers.shift();
    assert.ok(a, "no more paid retries were expected");
    return a();
  };
  w.opts = (over = {}) => ({
    paymentServerUrl: "https://pay.example/api/",
    store: new FileHandoffStore(join(w.dir, "marks")),
    sleep: async (ms) => { w.sleeps.push(ms); },
    fetch: async (url, init) => {
      w.relayCalls.push({ url: String(url), init, body: JSON.parse(init.body) });
      return relay();
    },
    ...over,
  });
  return w;
}

test("no handoff without two recognised refusals", async () => {
  for (const answers of [[ok], [rr2, ok], [rr1, () => new Response("busy", { status: 503 })], [() => new Response(BUYER, { status: 401 })]]) {
    const w = world([...answers]);
    const out = await paidRetryWithHandoff(decision(), w.retry, w.opts());
    assert.equal(out.handoff, "none");
    assert.equal(w.relayCalls.length, 0);
    assert.equal(w.sigs.length, answers.length);
    assert.equal(out.needsOperator, false);
  }
});

test("two recognised refusals PickupDelay apart lead to one handoff of exactly the stored bytes", async () => {
  const w = world([rr2, rr1, ok]);
  const out = await paidRetryWithHandoff(decision(), w.retry, w.opts({ pickupDelayMs: 15_000 }));
  assert.equal(out.handoff, "sent");
  assert.equal(out.relayFault, undefined);
  assert.equal(out.relayDeprecated, true);
  assert.deepEqual(out.refusals, ["RR2", "RR1"]);
  assert.equal(out.response.status, 200);
  assert.equal(out.needsOperator, false);
  assert.deepEqual(w.sleeps, [15_000, 15_000], "the wait before the second retry and after the handoff");
  assert.deepEqual(w.sigs, Array(3).fill(decision().paymentSignature), "the same Payment-Signature every time");
  assert.equal(w.relayCalls.length, 1);
  const [call] = w.relayCalls;
  assert.equal(call.url, "https://pay.example/api/deposit/send", "only the configured payment server");
  assert.equal(call.init.redirect, "error");
  assert.deepEqual(call.body, { signedTx: "0x" + sv.signed_hex, paymentId: "0x" + svPid });
});

test("a refusal after the handoff goes to the operator", async () => {
  const w = world([rr1, rr1, rr2]);
  const out = await paidRetryWithHandoff(decision(), w.retry, w.opts());
  assert.equal(out.handoff, "sent");
  assert.equal(out.needsOperator, true);
  assert.deepEqual(w.sleeps, [10_000, 10_000], "the default pickup delay");
});

test("the once mark survives a restart", async () => {
  const w = world([rr2, rr2, rr2, rr2, rr2]);
  const first = await paidRetryWithHandoff(decision(), w.retry, w.opts());
  assert.equal(first.handoff, "sent");
  // A new process: a new store object on the same directory.
  const again = await paidRetryWithHandoff(decision(), w.retry, w.opts());
  assert.equal(again.handoff, "already_used");
  assert.equal(again.needsOperator, true);
  assert.equal(w.relayCalls.length, 1, "never a second handoff");
});

test("a relay fault is not retried and moves nothing", async () => {
  const w = world([rr2, rr2, rr2, rr2], () => new Response(`{"error":"failed to broadcast transaction"}`, { status: 400 }));
  const out = await paidRetryWithHandoff(decision(), w.retry, w.opts());
  assert.equal(out.handoff, "relay_fault");
  assert.match(out.relayFault, /status 400/);
  assert.equal(w.sigs.length, 3, "the last retry is still made");
  const named = world([rr2, rr2, ok], () => new Response(`{"result":{"hash":"0x${"1".repeat(64)}"}}`, { status: 200 }));
  const other = await paidRetryWithHandoff(decision(), named.retry, named.opts());
  assert.equal(other.handoff, "relay_fault", "the relay names another transaction");
});

test("bytes that do not hash to the rail_ref are never posted and spend no mark", async () => {
  const w = world([rr2, rr2]);
  const d = decision({ railRef: "00".repeat(32) });
  await assert.rejects(paidRetryWithHandoff(d, w.retry, w.opts()), (e) => e instanceof EdictaRefusedError && e.code === "handoff_hash_mismatch");
  assert.equal(w.relayCalls.length, 0);
  assert.equal(existsSync(join(w.dir, "marks", `${d.commitmentHash}.handoff`)), false);

  const tampered = unhex(sv.signed_hex);
  tampered[tampered.length - 1] ^= 1;
  const w2 = world([rr2, rr2]);
  await assert.rejects(
    paidRetryWithHandoff(decision({ signedTx: Buffer.from(tampered).toString("base64") }), w2.retry, w2.opts()),
    (e) => e instanceof EdictaRefusedError && e.code === "handoff_hash_mismatch",
  );
  assert.equal(w2.relayCalls.length, 0);
});

test("the payment server URL, the delays and the decision are checked first", async () => {
  const w = world([]);
  for (const [over, why] of [
    [{ paymentServerUrl: "http://pay.example" }, "plain http"],
    [{ paymentServerUrl: "https://pay.example/?x=1" }, "a query"],
    [{ paymentServerUrl: "https://user:pw@pay.example" }, "credentials"],
    [{ pickupDelayMs: 120_001 }, "pickup above 120 s"],
    [{ pickupDelayMs: 0 }, "zero pickup"],
    [{ serverTimeoutMs: 60_001 }, "server timeout above 60 s"],
  ]) {
    await assert.rejects(paidRetryWithHandoff(decision(), w.retry, w.opts(over)), EdictaInputError, why);
  }
  await assert.rejects(
    paidRetryWithHandoff(decision({ raw: { deposit: { payment_id_hex: "22".repeat(32) } } }), w.retry, w.opts()),
    EdictaRefusedError,
    "the service's deposit names another paymentId",
  );
  assert.equal(w.sigs.length, 0, "no paid retry was made");
});

test("without signed bytes the paid retry still runs, and only a due handoff is refused", async () => {
  const fine = world([ok]);
  const out = await paidRetryWithHandoff(decision({ signedTx: undefined, railRef: undefined }), fine.retry, fine.opts());
  assert.equal(out.handoff, "none");
  assert.equal(out.response.status, 200);

  const w = world([rr1, rr2]);
  await assert.rejects(
    paidRetryWithHandoff(decision({ signedTx: undefined, railRef: undefined }), w.retry, w.opts()),
    (e) => e instanceof EdictaRefusedError && e.code === "handoff_unavailable",
  );
  assert.equal(w.sigs.length, 2, "the quote is read with the committed paymentId");
  assert.equal(w.relayCalls.length, 0);
});

test("FileHandoffStore claims once per hash", async () => {
  const dir = join(mkdtempSync(join(tmpdir(), "edicta-store-")), "m");
  const s = new FileHandoffStore(dir);
  assert.equal(await s.claim("cd".repeat(32)), true);
  assert.equal(await s.claim("cd".repeat(32)), false);
  assert.equal(await new FileHandoffStore(dir).claim("cd".repeat(32)), false);
  assert.equal(await s.claim("ef".repeat(32)), true);
  await assert.rejects(s.claim("../x"), EdictaInputError);
});

test("edictaPay makes the paid retry with the handoff when asked", async () => {
  const hash = "ab".repeat(32);
  const srv = http.createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        commitment_hash: hash, settled: true, payment_signature: svProof, authorization: "QUJD",
        rail_ref: sv.rail_ref, signed_tx: decision().signedTx, action: svAction, deposit: { payment_id_hex: svPid },
      }));
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  try {
    const url = `http://127.0.0.1:${srv.address().port}`;
    const header = Buffer.from(liveR).toString("base64");
    const w = world([rr2, rr1, ok]);
    const r = await edictaPay({ agentServeUrl: url, paymentRequiredHeader: header, resumeHash: hash, paidRetry: w.retry, handoff: w.opts() });
    assert.equal(r.paidRetry.handoff, "sent");
    assert.equal(r.paidRetry.response.status, 200);
    assert.equal(w.relayCalls.length, 1);
    assert.deepEqual(w.sigs, Array(3).fill(r.paymentSignature));

    await assert.rejects(
      edictaPay({ agentServeUrl: url, paymentRequiredHeader: header, resumeHash: hash, paidRetry: w.retry }),
      EdictaInputError,
      "paidRetry needs the handoff options",
    );
  } finally {
    srv.closeAllConnections();
    await new Promise((r) => srv.close(r));
  }
});

test("edictaPay keeps its result when the paid retry or the handoff fails", async () => {
  const hash = "ab".repeat(32);
  let answer = {};
  const srv = http.createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        commitment_hash: hash, settled: true, payment_signature: svProof, authorization: "QUJD",
        action: svAction, deposit: { payment_id_hex: svPid }, ...answer,
      }));
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  try {
    const url = `http://127.0.0.1:${srv.address().port}`;
    const header = Buffer.from(liveR).toString("base64");
    const pay = (w) => edictaPay({ agentServeUrl: url, paymentRequiredHeader: header, resumeHash: hash, paidRetry: w.retry, handoff: w.opts() });

    // The service did not know the signed bytes: the paid retry still runs.
    const fine = world([ok]);
    const r1 = await pay(fine);
    assert.equal(r1.paidRetry.handoff, "none");
    assert.equal(r1.paidRetryError, undefined);
    assert.equal(fine.sigs.length, 1);

    // Refused twice, and no signed bytes to hand over.
    const refused = world([rr2, rr2]);
    const r2 = await pay(refused);
    assert.equal(r2.paymentSignature, svProof, "the result is kept");
    assert.equal(r2.commitmentHash, hash);
    assert.equal(r2.paidRetry, undefined);
    assert.ok(r2.paidRetryError instanceof EdictaRefusedError);
    assert.equal(r2.paidRetryError.code, "handoff_unavailable");

    // Signed bytes that are not this decision's.
    answer = { signed_tx: decision().signedTx, rail_ref: "00".repeat(32) };
    const r3 = await pay(world([rr2, rr2]));
    assert.equal(r3.signedTx, decision().signedTx);
    assert.equal(r3.paidRetryError.code, "handoff_hash_mismatch");

    // The paid call itself fails in transport.
    const broken = world([() => { throw new TypeError("fetch failed"); }]);
    const r4 = await pay(broken);
    assert.equal(r4.paymentSignature, svProof);
    assert.match(r4.paidRetryError.message, /fetch failed/);
  } finally {
    srv.closeAllConnections();
    await new Promise((r) => srv.close(r));
  }
});
