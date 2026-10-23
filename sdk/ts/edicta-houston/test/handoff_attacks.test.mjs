// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { EdictaRefusedError, FileHandoffStore, depositPaymentId, paidRetryWithHandoff } from "../dist/src/index.js";

const vectors = new URL("../../../../spec/vectors/profiles/eden-escrow/", import.meta.url);
const signedVec = JSON.parse(readFileSync(new URL("signed.json", vectors), "utf8"));
const unhex = (s) => new Uint8Array(Buffer.from(s, "hex"));
const b64 = (hexStr) => Buffer.from(unhex(hexStr)).toString("base64");

const BUYER = "signer is neither the escrow buyer nor an authorized device key";
const sv = signedVec.cases[0];
const other = signedVec.cases.find((c) => depositPaymentId(unhex(c.signed_hex)) !== depositPaymentId(unhex(sv.signed_hex)));
const svPid = depositPaymentId(unhex(sv.signed_hex));
const EVIL = "https://evil.example/deposit/send";

const actionVec = JSON.parse(readFileSync(new URL("action.json", vectors), "utf8"));
const actionOf = (c) => b64(actionVec.cases.find((a) => a.id === c.action_ref).cbor_hex);
// The vector key's personal_sign over svPid (v = 27 + y_parity), as the signer releases it.
const svProof = "0x06ca9a1c1571faefad19ada013c4e64815e56913f23a1dabd32f4525395975cc46d97c6eb47610bfff455f9a232a57850e49413d55e4dc07fc7757fe1e1fc5481c";
const decision = (over = {}) => ({
  commitmentHash: "ab".repeat(32),
  paymentSignature: svProof,
  signedTx: b64(sv.signed_hex),
  railRef: sv.rail_ref,
  raw: { action: actionOf(sv), deposit: { payment_id_hex: svPid } },
  ...over,
});
const quoteFor = (...pids) =>
  Buffer.from(
    `{"x402Version":2,"accepts":[${pids.map((p) => `{"scheme":"escrow-upto","extra":{"paymentId":"0x${p}"}}`).join(",")}]}`,
  ).toString("base64");
const rr1 = () => new Response("payment required", { status: 402, headers: { "payment-required": quoteFor(svPid) } });
const rr2 = () => new Response(`{"error":"${BUYER}"}`, { status: 403 });

function world(answers, relay = () => new Response(`{"txHash":"0x${sv.rail_ref}"}`, { status: 200 })) {
  const w = { events: [], relayCalls: [], dir: mkdtempSync(join(tmpdir(), "edicta-handoff-attack-")) };
  w.marks = join(w.dir, "marks");
  w.retry = async (sig) => {
    w.events.push("retry");
    const a = answers.shift();
    assert.ok(a, "no more paid retries were expected");
    return a();
  };
  w.opts = (over = {}) => ({
    paymentServerUrl: "https://pay.example/api",
    store: new FileHandoffStore(w.marks),
    sleep: async (ms) => { w.events.push(`sleep ${ms}`); },
    fetch: async (url, init) => {
      w.events.push("relay");
      w.relayCalls.push({ url: String(url), init, marked: existsSync(w.marks) && readdirSync(w.marks).length > 0 });
      return relay();
    },
    ...over,
  });
  w.markCount = () => (existsSync(w.marks) ? readdirSync(w.marks).length : 0);
  return w;
}

const ambiguous = {
  "500 with the buyer text": () => new Response(BUYER, { status: 500 }),
  "502 with the quote": () => new Response("", { status: 502, headers: { "payment-required": quoteFor(svPid) } }),
  "402 for another paymentId": () => new Response("", { status: 402, headers: { "payment-required": quoteFor("22".repeat(32)) } }),
  "402 naming this paymentId twice": () => new Response("", { status: 402, headers: { "payment-required": quoteFor(svPid, svPid) } }),
  "402 without the header": () => new Response(BUYER, { status: 402 }),
  "403 with another text": () => new Response(`{"error":"forbidden"}`, { status: 403 }),
  "403 with the text in a header only": () => new Response("", { status: 403, headers: { "x-error": BUYER } }),
  "401 with the buyer text": () => new Response(BUYER, { status: 401 }),
  "429 with the quote": () => new Response("", { status: 429, headers: { "payment-required": quoteFor(svPid) } }),
  "302 to another server": () => new Response("", { status: 302, headers: { location: EVIL } }),
  "200": () => new Response("{}", { status: 200 }),
};

test("an ambiguous answer, first or second, never triggers the handoff", async () => {
  for (const [name, a] of Object.entries(ambiguous)) {
    for (const answers of [[a], [rr2, a], [rr1, a]]) {
      const w = world([...answers]);
      const out = await paidRetryWithHandoff(decision(), w.retry, w.opts());
      assert.equal(out.handoff, "none", name);
      assert.equal(out.needsOperator, false, name);
      assert.equal(w.relayCalls.length, 0, name);
      assert.equal(w.markCount(), 0, `${name}: no mark is spent`);
      assert.equal(w.events.filter((e) => e === "retry").length, answers.length, name);
    }
  }
});

// The refusal is read through res.clone(); cancelling one branch of a cloned
// body settles only once the other branch is cancelled too, so a reader that
// waited for it would stall on an answer over the cap.
test(
  "an answer over 16384 bytes is not a refusal and does not stall the client",
  async () => {
    const big = {
      "403 with the text": () => new Response("x".repeat(16384) + BUYER, { status: 403 }),
      "402 with the quote": () =>
        new Response("x".repeat(16385), { status: 402, headers: { "payment-required": quoteFor(svPid) } }),
    };
    for (const [name, a] of Object.entries(big)) {
      for (const answers of [[a], [rr2, a]]) {
        const w = world([...answers]);
        let timer;
        const stalled = new Promise((resolve) => { timer = setTimeout(() => resolve("stalled"), 2000); });
        const out = await Promise.race([paidRetryWithHandoff(decision(), w.retry, w.opts()), stalled]);
        clearTimeout(timer);
        assert.notEqual(out, "stalled", name);
        assert.equal(out.handoff, "none", name);
        assert.equal(w.relayCalls.length, 0, name);
      }
    }
  },
);

// A body that sends part of a refusal and then never ends.
const dribble = (status, text, headers = {}) => () =>
  new Response(
    new ReadableStream({
      start(c) {
        c.enqueue(new TextEncoder().encode(text));
      },
    }),
    { status, headers },
  );

test("a paid retry's answer that never ends is not a refusal and does not stall the client", async () => {
  const slow = {
    "403 with the text": dribble(403, `{"error":"${BUYER}`),
    "402 with the quote": dribble(402, "payment required", { "payment-required": quoteFor(svPid) }),
  };
  for (const [name, a] of Object.entries(slow)) {
    for (const answers of [[a], [rr2, a]]) {
      const w = world([...answers]);
      const started = Date.now();
      const out = await paidRetryWithHandoff(decision(), w.retry, w.opts({ serverTimeoutMs: 200 }));
      assert.ok(Date.now() - started < 2000, `${name}: answered promptly`);
      assert.equal(out.handoff, "none", name);
      assert.equal(w.relayCalls.length, 0, name);
      assert.equal(w.markCount(), 0, name);
    }
  }
});

test("a relay answer that never ends is a relay fault and the last retry is still made", async () => {
  const w = world([rr2, rr2, rr2], dribble(200, `{"txHash":"0x${sv.rail_ref}"`));
  const started = Date.now();
  const out = await paidRetryWithHandoff(decision(), w.retry, w.opts({ serverTimeoutMs: 200 }));
  assert.ok(Date.now() - started < 2000, "answered promptly");
  assert.equal(out.handoff, "relay_fault");
  assert.match(out.relayFault, /not read in time/);
  assert.equal(out.needsOperator, true);
  assert.equal(w.relayCalls.length, 1);
});

test("a timeout or transport error of a paid retry never triggers the handoff", async () => {
  const timeout = () => Promise.reject(new DOMException("The operation was aborted due to timeout", "TimeoutError"));
  const reset = () => Promise.reject(new TypeError("fetch failed"));
  for (const answers of [[timeout], [rr2, timeout], [rr1, reset]]) {
    const w = world([...answers]);
    await assert.rejects(paidRetryWithHandoff(decision(), w.retry, w.opts()));
    assert.equal(w.relayCalls.length, 0);
    assert.equal(w.markCount(), 0);
  }
});

test("the second paid retry is made only after the pickup delay", async () => {
  const w = world([rr2, rr1, rr2]);
  const out = await paidRetryWithHandoff(decision(), w.retry, w.opts({ pickupDelayMs: 20_000 }));
  assert.equal(out.handoff, "sent");
  assert.deepEqual(w.events, ["retry", "sleep 20000", "retry", "relay", "sleep 20000", "retry"]);

  const aborted = world([rr2, rr2]);
  const stop = async () => { throw new Error("aborted"); };
  await assert.rejects(paidRetryWithHandoff(decision(), aborted.retry, aborted.opts({ sleep: stop })), /aborted/);
  assert.deepEqual(aborted.events, ["retry"], "a wait cut short makes no second retry and no handoff");
  assert.equal(aborted.markCount(), 0);
});

test("the once mark is durable before the bytes leave", async () => {
  const w = world([rr2, rr2, rr2]);
  await paidRetryWithHandoff(decision(), w.retry, w.opts());
  assert.equal(w.relayCalls.length, 1);
  assert.equal(w.relayCalls[0].marked, true);

  const failing = world([rr2, rr2]);
  const broken = { claim: async () => { throw new Error("disk full"); } };
  await assert.rejects(paidRetryWithHandoff(decision(), failing.retry, failing.opts({ store: broken })), /disk full/);
  assert.equal(failing.relayCalls.length, 0, "no mark, no handoff");
});

test("the caller's signal stops the flow before the mark but never cuts the relay call", async () => {
  const early = new AbortController();
  early.abort();
  const w = world([rr2]);
  await assert.rejects(paidRetryWithHandoff(decision(), w.retry, w.opts({ signal: early.signal })));
  assert.deepEqual(w.events, [], "no paid retry once aborted");

  const late = new AbortController();
  const w2 = world([rr2, rr2, rr2]);
  let cut;
  const opts = w2.opts({
    signal: late.signal,
    fetch: async (url, init) => {
      late.abort();
      await new Promise((r) => setTimeout(r, 20));
      cut = init.signal.aborted;
      w2.relayCalls.push({ url: String(url) });
      return new Response(`{"txHash":"0x${sv.rail_ref}"}`, { status: 200 });
    },
  });
  const out = await paidRetryWithHandoff(decision(), w2.retry, opts);
  assert.equal(cut, false, "the relay call ran on its own timeout");
  assert.equal(out.handoff, "sent", "what happened is still returned");
  assert.equal(out.needsOperator, true);
  assert.equal(w2.relayCalls.length, 1);
  assert.equal(w2.markCount(), 1);
  assert.equal(w2.events.filter((e) => e === "retry").length, 2, "no paid retry after the abort");
});

test("the relay URL is the configured payment server, never one from an answer", async () => {
  const lure = () =>
    new Response(JSON.stringify({ error: BUYER, relay: EVIL, paymentServerUrl: "https://evil.example" }), {
      status: 403,
      headers: { location: EVIL, link: `<${EVIL}>; rel="relay"` },
    });
  const w = world([lure, lure, lure], () => new Response("", { status: 307, headers: { location: EVIL } }));
  const out = await paidRetryWithHandoff(decision(), w.retry, w.opts());
  assert.equal(w.relayCalls.length, 1);
  assert.equal(w.relayCalls[0].url, "https://pay.example/api/deposit/send");
  assert.equal(w.relayCalls[0].init.redirect, "error");
  assert.equal(out.handoff, "relay_fault", "a redirect answer is a relay fault, not followed");
  assert.equal(out.needsOperator, true);
});

test("bytes of another decision are never posted", async () => {
  assert.ok(other, "a signed vector with another paymentId");
  const cases = [
    ["another decision's bytes under this rail_ref", { signedTx: b64(other.signed_hex), raw: undefined }, "handoff_hash_mismatch", 2],
    ["another decision's bytes, the service names this paymentId", { signedTx: b64(other.signed_hex) }, "handoff_unavailable", 0],
    ["another decision's bytes with their own rail_ref", { signedTx: b64(other.signed_hex), railRef: other.rail_ref }, "handoff_unavailable", 0],
    ["this decision's bytes under another rail_ref", { railRef: other.rail_ref }, "handoff_hash_mismatch", 2],
    ["a rail_ref in upper case with 0x of another decision", { railRef: "0x" + other.rail_ref.toUpperCase() }, "handoff_hash_mismatch", 2],
  ];
  for (const [name, over, code, retries] of cases) {
    const w = world([rr2, rr2]);
    await assert.rejects(
      paidRetryWithHandoff(decision(over), w.retry, w.opts()),
      (e) => e instanceof EdictaRefusedError && e.code === code,
      name,
    );
    assert.equal(w.relayCalls.length, 0, name);
    assert.equal(w.markCount(), 0, name);
    assert.equal(w.events.filter((e) => e === "retry").length, retries, name);
  }
});

// The committed transaction of sv signed by another key (sha256 of "edicta ts
// handoff test: another payer"), made with the Go signer code.
const SIGNED_BY_OTHER =
  "02f901338202ca07808208fb83030d409465d77c98e73dfbea91ecb72b27c9753e186a94c8873972f538a8081db8c4b707d860e7b0fe0c168a34ec93cfca6752955af23bbe002de0d16d399f35ff910b160f35000000000000000000000000c5aaa301b580d31e64b3bf546846586d934416dc000000000000000000000000ec7557ea26e646020b3c6c90f8af6fbf73460f45000000000000000000000000000000000000000000000000000000006ad87b94000000000000000000000000000000000000000000000000000000006ae1b4e800000000000000000000000000000000000000000000000008c9da13856cd000c001a014cc1ec05a132bb7470a17aec1ea30f28be5562703f54d8b78a1533275f1def1a02d00a2fefc6a768625da0edd69aae34262dfd32e56d852bc2a480de7d1f3dada";
// That key's personal_sign over svPid, and the vector key's over paymentId 0.
const PROOF_BY_OTHER =
  "0x6d08f19d561c897c48dab3e8740eadb7d43eb474a2ebd6c15407a0c498c745ee0bbd434a7ad61ae16769565735729277d04b32d48747de832dac1d83c3f326a21b";
const PROOF_OTHER_PID =
  "0xe7cf3dfb92d71dc67ccc212c2cc3de383ed668fd9ac2aa72726d944f9bd284ec48ef638ecc9e709f96130e3389221003446e393953f6a9091ae6c3c2a84433e91b";
const keccakHex = async (h) => Buffer.from((await import("../dist/src/index.js")).keccak256(unhex(h))).toString("hex");

// sv with s replaced by n - s and the parity flipped: the same signer, a
// malleated signature.
const N = BigInt("0x" + signedVec.secp256k1_n_hex);
const highS = (() => {
  const s = sv.s_hex;
  const hs = (N - BigInt("0x" + s)).toString(16).padStart(64, "0");
  const tail = `80a0${sv.r_hex}a0${s}`;
  assert.ok(sv.signed_hex.endsWith(tail) && sv.y_parity === "0");
  return sv.signed_hex.slice(0, -tail.length) + `01a0${sv.r_hex}a0${hs}`;
})();

test("bytes or a Payment-Signature not tied to the decision are never posted", async () => {
  const cases = [
    ["the committed tx signed by another key", { signedTx: b64(SIGNED_BY_OTHER), railRef: await keccakHex(SIGNED_BY_OTHER) }],
    ["the committed tx signed by another key, with that key's Payment-Signature",
      { signedTx: b64(SIGNED_BY_OTHER), railRef: await keccakHex(SIGNED_BY_OTHER), paymentSignature: PROOF_BY_OTHER, raw: { action: actionOf(sv), payer: sv.payer } }],
    ["a Payment-Signature of another payer", { paymentSignature: PROOF_BY_OTHER }],
    ["a Payment-Signature over another paymentId", { paymentSignature: PROOF_OTHER_PID }],
    ["a Payment-Signature that is not hex", { paymentSignature: "0x" + "zz".repeat(65) }],
    ["a Payment-Signature of 64 bytes", { paymentSignature: svProof.slice(0, -2) }],
    ["a high-s signature of the payer", { signedTx: b64(highS), railRef: await keccakHex(highS) }],
    ["no committed action", { raw: { deposit: { payment_id_hex: svPid } } }],
    ["the service names another payer", { raw: { action: actionOf(sv), payer: "0x" + "11".repeat(20) } }],
    ["the service names another escrow", { raw: { action: actionOf(sv), deposit: { payment_id_hex: svPid, escrow: "0x" + "22".repeat(20) } } }],
  ];
  for (const [name, over] of cases) {
    const w = world([rr2, rr2]);
    await assert.rejects(
      paidRetryWithHandoff(decision(over), w.retry, w.opts()),
      (e) => e instanceof EdictaRefusedError && e.code === "handoff_unbound",
      name,
    );
    assert.equal(w.relayCalls.length, 0, name);
    assert.equal(w.markCount(), 0, name);
    assert.equal(w.events.filter((e) => e === "retry").length, 2, name);
  }

  const w = world([rr2, rr2, rr2]);
  const ok = await paidRetryWithHandoff(decision({ paymentSignature: svProof.slice(0, -2) + "01" }), w.retry, w.opts());
  assert.equal(ok.handoff, "sent", "a Payment-Signature with v as y_parity is the same proof");
});

test("the committed action of another decision is refused before any paid retry", async () => {
  assert.ok(other, "a signed vector with another paymentId");
  const w = world([]);
  await assert.rejects(
    paidRetryWithHandoff(decision({ raw: { action: actionOf(other), deposit: { payment_id_hex: svPid } } }), w.retry, w.opts()),
    (e) => e instanceof EdictaRefusedError && e.code === "handoff_unavailable",
  );
  await assert.rejects(
    paidRetryWithHandoff(decision({ raw: { action: actionOf(other) } }), w.retry, w.opts()),
    (e) => e instanceof EdictaRefusedError && e.code === "handoff_unavailable",
    "the signed bytes name another paymentId than the committed action",
  );
  await assert.rejects(paidRetryWithHandoff(decision({ raw: { action: "AAEC" } }), w.retry, w.opts()), /not an Eden escrow deposit/);
  assert.equal(w.events.length, 0);
});

test("two concurrent handoffs for one decision post once", async () => {
  const dir = mkdtempSync(join(tmpdir(), "edicta-handoff-race-"));
  const relayCalls = [];
  const run = () =>
    paidRetryWithHandoff(decision(), async () => rr2(), {
      paymentServerUrl: "https://pay.example",
      store: new FileHandoffStore(dir),
      sleep: async () => {},
      fetch: async (url) => {
        relayCalls.push(String(url));
        return new Response("{}", { status: 200 });
      },
    });
  const outs = await Promise.all(Array.from({ length: 8 }, run));
  assert.equal(outs.filter((o) => o.handoff === "sent").length, 1);
  assert.equal(outs.filter((o) => o.handoff === "already_used").length, 7);
  assert.equal(relayCalls.length, 1);
});

test("FileHandoffStore: concurrent claims in one process, one wins", async () => {
  const s = new FileHandoffStore(join(mkdtempSync(join(tmpdir(), "edicta-claim-")), "m"));
  const got = await Promise.all(Array.from({ length: 32 }, () => s.claim("cd".repeat(32))));
  assert.equal(got.filter(Boolean).length, 1);
});

test("FileHandoffStore: concurrent claims from separate processes, one wins", async () => {
  const dir = join(mkdtempSync(join(tmpdir(), "edicta-claim-proc-")), "m");
  const mod = new URL("../dist/src/index.js", import.meta.url).href;
  const script = `const { FileHandoffStore } = await import(${JSON.stringify(mod)});
process.stdout.write(String(await new FileHandoffStore(${JSON.stringify(dir)}).claim("ef".repeat(32))));`;
  const one = () =>
    new Promise((resolve, reject) => {
      const p = spawn(process.execPath, ["--input-type=module", "-e", script], { stdio: ["ignore", "pipe", "inherit"] });
      let out = "";
      p.stdout.on("data", (b) => { out += b; });
      p.on("error", reject);
      p.on("close", (code) => (code === 0 ? resolve(out) : reject(new Error(`child exited ${code}`))));
    });
  const outs = await Promise.all(Array.from({ length: 8 }, one));
  assert.equal(outs.filter((o) => o === "true").length, 1, outs.join(","));
  assert.equal(outs.filter((o) => o === "false").length, 7);
  assert.equal(await new FileHandoffStore(dir).claim("ef".repeat(32)), false, "the mark outlives every process");
});
