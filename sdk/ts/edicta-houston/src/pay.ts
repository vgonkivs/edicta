// SPDX-License-Identifier: Apache-2.0

import {
  EdictaError,
  EdictaInputError,
  EdictaProtocolError,
  EdictaTransportError,
  classifyFailure,
} from "./errors.js";
import type { ResumeMaterial } from "./errors.js";

export interface Named {
  id: string;
  version?: string;
  /** Policy text; a model has none. */
  text?: string;
}

export interface PayOptions {
  /** Base URL of `edicta agent serve`, e.g. http://127.0.0.1:8500. Loopback unless allowRemote. */
  agentServeUrl: string;
  /** Bearer token of the service. Needed only for a service started with the remote flag. Never logged. */
  token?: string;
  allowRemote?: boolean;
  /** The `payment-required` header of the 402, as received (base64). */
  paymentRequiredHeader: string;
  /** The /deposit/build answer, parsed or as the JSON text. Required unless resumeHash is set. */
  build?: unknown;
  /** The https URL the client calls. Required unless resumeHash is set. */
  resource?: string;
  /** Required for a new run: it is committed and published as given. */
  model?: Named;
  /** Your own decision context (a JSON object); the service adds the quote under the reserved key eden_escrow. */
  context?: Record<string, unknown>;
  policy?: Named;
  /** Go duration (e.g. "10m") the decision stays valid. The service default applies when absent. */
  validFor?: string;
  /** Go duration the service waits for the deposit to execute (default "5m", at most "1h"). */
  wait?: string;
  /** Continue a run whose earlier call failed with a commitmentHash. Build, resource, model and policy are then not sent. */
  resumeHash?: string;
  /**
   * Alternative to resumeHash: the resume material of a failed call
   * (error.resume). Needs no state directory at the service; resumeHash does.
   */
  resume?: ResumeMaterial;
  /**
   * Extra time on top of `wait` before the HTTP call is cut off, in ms (default
   * 360000, at most 3600000). It must exceed the service's publish and
   * authorize time (authorize alone can take 2 minutes per attempt); a shorter
   * cut-off loses the answer that carries the resume material.
   */
  marginMs?: number;
  signal?: AbortSignal;
  /** Replaces globalThis.fetch (tests, proxies). It must refuse redirects itself: the bearer token would follow them. */
  fetch?: typeof fetch;
}

export interface PayResult {
  /** Value for the retry's Payment-Signature step (the starter encodes it as before). */
  paymentSignature: string;
  commitmentHash: string;
  /** Hash of the signed deposit transaction; absent when the service did not know the signed bytes. */
  railRef: string | undefined;
  /** Signed deposit transaction, base64. The signer has already sent it. */
  signedTx: string | undefined;
  payer: string | undefined;
  /** Base64 gate Authorization, kept for audit. */
  authorization: string;
  /** The gate recorded the execution (receipt notarized). */
  recorded: boolean;
  /** Base64 receipt, when recorded. */
  receipt: string | undefined;
  /** Set when the service could not cross-check something, e.g. the payer. Show it to the operator. */
  warning: string | undefined;
  /** The service's full answer. */
  raw: Record<string, unknown>;
}

const MAX_HEADER = 64 * 1024;
const MAX_BUILD = 256 * 1024;
const MAX_RESPONSE = 4 * 1024 * 1024;
const MAX_WAIT_MS = 3600_000;
const DEFAULT_WAIT_MS = 300_000;
// The service spends its publish and authorize budget (authorize alone: 2 min
// per attempt) before the settlement wait starts; cutting off earlier loses
// the settlement_pending answer that carries the resume material.
const DEFAULT_MARGIN_MS = 360_000;
const MAX_MARGIN_MS = 3600_000;
const MAX_CONTEXT = 64 * 1024;

const UNITS_MS: Record<string, number> = { ns: 1e-6, us: 1e-3, "µs": 1e-3, ms: 1, s: 1000, m: 60_000, h: 3_600_000 };
const DURATION = /^(?:\d+(?:\.\d+)?(?:ns|us|µs|ms|s|m|h))+$/;

/** Parses a Go duration string; returns milliseconds or undefined when it is not one. */
export function parseDurationMs(s: string): number | undefined {
  if (!DURATION.test(s)) return undefined;
  let total = 0;
  for (const m of s.matchAll(/(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)/g)) {
    total += Number(m[1]) * (UNITS_MS[m[2] as string] as number);
  }
  return total;
}

function bad(msg: string): EdictaInputError {
  return new EdictaInputError("input", msg, { code: "client_input" });
}

function checkUrl(raw: string, allowRemote: boolean, hasToken: boolean): URL {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw bad("agentServeUrl is not a URL");
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") throw bad("agentServeUrl must be http or https");
  if (u.username || u.password) throw bad("agentServeUrl must not carry credentials");
  if (u.search || u.hash) throw bad("agentServeUrl must not carry a query or fragment");
  const host = u.hostname.replace(/^\[|\]$/g, "");
  const loopback = host === "localhost" || /^127(?:\.\d{1,3}){3}$/.test(host) || host === "::1";
  if (!loopback) {
    if (!allowRemote) throw bad("agentServeUrl is not loopback (set allowRemote for a remote service)");
    if (!hasToken) throw bad("a remote service needs a token");
    if (u.protocol !== "https:") throw bad("a remote service must be reached over https");
  }
  return u;
}

function checkName(n: Named | undefined, what: string): Record<string, string> | undefined {
  if (n === undefined) return undefined;
  if (typeof n !== "object" || n === null || typeof n.id !== "string" || n.id === "") throw bad(`${what}.id is required`);
  const out: Record<string, string> = { id: n.id };
  if (n.version !== undefined) {
    if (typeof n.version !== "string") throw bad(`${what}.version must be a string`);
    out.version = n.version;
  }
  if (n.text !== undefined) {
    if (typeof n.text !== "string") throw bad(`${what}.text must be a string`);
    out.text = n.text;
  }
  return out;
}

function checkBuild(build: unknown): unknown {
  let v = build;
  if (typeof build === "string") {
    if (build.length > MAX_BUILD) throw bad("build is too large");
    try {
      v = JSON.parse(build);
    } catch {
      throw bad("build is not valid JSON");
    }
  }
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw bad("build must be the /deposit/build JSON object");
  const o = v as Record<string, unknown>;
  const tx = o.txData;
  if (typeof tx !== "object" || tx === null) throw bad("build.txData is missing");
  const t = tx as Record<string, unknown>;
  if (typeof t.to !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(t.to)) throw bad("build.txData.to is not an address");
  if (typeof t.data !== "string" || !/^0x(?:[0-9a-fA-F]{2})+$/.test(t.data)) throw bad("build.txData.data is not hex");
  if (typeof o.paymentId !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(o.paymentId)) throw bad("build.paymentId is not 32 bytes of hex");
  let size: number;
  try {
    size = JSON.stringify(v).length;
  } catch {
    throw bad("build is not JSON-serialisable");
  }
  if (size > MAX_BUILD) throw bad("build is too large");
  return v;
}

/** Checks the header is base64 and its decoded body is a JSON object; the service re-checks everything. */
function checkHeader(h: unknown): string {
  if (typeof h !== "string" || h === "") throw bad("paymentRequiredHeader is required");
  if (h.length > MAX_HEADER) throw bad("paymentRequiredHeader is too large");
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(h)) throw bad("paymentRequiredHeader is not base64");
  return h;
}

function isHex64(s: unknown): s is string {
  return typeof s === "string" && /^[0-9a-f]{64}$/.test(s);
}

/**
 * Replaces the "sign and send" step of the starter flow. Give it the 402's
 * `payment-required` header and the /deposit/build answer; it asks the local
 * `edicta agent serve` to commit the decision, get the gate Authorization,
 * have the signer sign and send the deposit, wait until it executed and
 * release the Payment-Signature. The agent never holds the wallet key.
 */
export async function edictaPay(opts: PayOptions): Promise<PayResult> {
  if (typeof opts !== "object" || opts === null) throw bad("options are required");
  if (opts.token !== undefined && (typeof opts.token !== "string" || opts.token === "" || /[^\x21-\x7e]/.test(opts.token))) {
    throw bad("token must be a non-empty printable string");
  }
  const base = checkUrl(opts.agentServeUrl, opts.allowRemote === true, opts.token !== undefined);
  const header = checkHeader(opts.paymentRequiredHeader);
  const resume = opts.resumeHash;
  if (resume !== undefined && !isHex64(resume)) throw bad("resumeHash must be 64 lowercase hex characters");
  const material = opts.resume === undefined ? undefined : checkResume(opts.resume);
  if (resume !== undefined && material !== undefined) throw bad("give resumeHash or resume, not both");
  const resuming = resume !== undefined || material !== undefined;

  const waitMs = opts.wait === undefined ? DEFAULT_WAIT_MS : parseDurationMs(opts.wait);
  if (waitMs === undefined || waitMs <= 0 || waitMs > MAX_WAIT_MS) throw bad("wait must be a Go duration up to 1h");
  const margin = opts.marginMs ?? DEFAULT_MARGIN_MS;
  if (typeof margin !== "number" || !Number.isFinite(margin) || margin < 0 || margin > MAX_MARGIN_MS) {
    throw bad("marginMs must be a number from 0 to 3600000");
  }
  if (opts.validFor !== undefined && (parseDurationMs(opts.validFor) ?? 0) <= 0) throw bad("validFor must be a positive Go duration");

  const eden: Record<string, unknown> = { payment_required: header };
  const body: Record<string, unknown> = {
    sign: true,
    broadcast: true,
    record: true,
    payment_signature: true,
  };
  if (opts.wait !== undefined) body.wait = opts.wait;
  if (resuming) {
    if (
      opts.build !== undefined || opts.resource !== undefined || opts.model !== undefined ||
      opts.policy !== undefined || opts.validFor !== undefined || opts.context !== undefined
    ) {
      throw bad("a resume replaces build, resource, model, policy, context and validFor");
    }
    if (resume !== undefined) body.resume_hash = resume;
    else body.resume = material;
  } else {
    if (opts.build === undefined) throw bad("build is required");
    eden.build = checkBuild(opts.build);
    if (typeof opts.resource !== "string" || !/^https:\/\/[^\s]+$/.test(opts.resource)) throw bad("resource must be an https URL");
    eden.resource = opts.resource;
    const model = checkName(opts.model, "model");
    if (model === undefined) throw bad("model is required");
    body.model = model;
    if (opts.context !== undefined) body.context = checkContext(opts.context);
    const policy = checkName(opts.policy, "policy");
    if (policy === undefined) throw bad("policy is required");
    body.policy = policy;
    if (opts.validFor !== undefined) body.valid_for = opts.validFor;
  }
  body.eden = eden;

  const headers: Record<string, string> = { "Content-Type": "application/json", Accept: "application/json" };
  if (opts.token !== undefined) headers.Authorization = `Bearer ${opts.token}`;

  let payload: string;
  try {
    payload = JSON.stringify(body);
  } catch {
    throw bad("the request is not JSON-serialisable");
  }
  const timeout = AbortSignal.timeout(Math.ceil(waitMs + margin));
  const signal = opts.signal ? AbortSignal.any([opts.signal, timeout]) : timeout;
  const doFetch = opts.fetch ?? globalThis.fetch;
  const url = new URL("v1/commit", base.href.endsWith("/") ? base.href : base.href + "/");

  let res: Response;
  let text: string;
  try {
    res = await doFetch(url, { method: "POST", headers, body: payload, signal, redirect: "error", cache: "no-store" });
    text = await readBounded(res);
  } catch (e) {
    if (e instanceof EdictaError) throw e;
    const why = timeout.aborted ? "timed out" : opts.signal?.aborted ? "aborted" : "failed";
    throw new EdictaTransportError(
      "transport",
      `call to the agent service ${why}`,
      { code: "transport", retryable: true, commitmentHash: resume, resume: material },
      { cause: e },
    );
  }

  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    if (!res.ok) throw classifyFailure(res.status, undefined);
    throw new EdictaProtocolError("protocol", "answer is not JSON", { code: "bad_response", status: res.status });
  }
  if (!res.ok) throw classifyFailure(res.status, json);
  return checkResult(json, resume, res.status);
}

async function readBounded(res: Response): Promise<string> {
  const tooBig = () => new EdictaProtocolError("protocol", "answer too large", { code: "bad_response", status: res.status });
  if (Number(res.headers.get("content-length") ?? 0) > MAX_RESPONSE) throw tooBig();
  if (res.body === null) return "";
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let n = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    n += value.byteLength;
    if (n > MAX_RESPONSE) {
      await reader.cancel().catch(() => undefined);
      throw tooBig();
    }
    chunks.push(value);
  }
  const all = new Uint8Array(n);
  let off = 0;
  for (const c of chunks) {
    all.set(c, off);
    off += c.byteLength;
  }
  return new TextDecoder().decode(all);
}

function checkResume(r: ResumeMaterial): ResumeMaterial {
  const ok = (v: unknown) => typeof v === "string" && v.length > 0 && v.length <= 1 << 20 && /^[A-Za-z0-9+/]+={0,2}$/.test(v);
  if (typeof r !== "object" || r === null || !ok(r.envelope) || !ok(r.action) || !ok(r.salt)) {
    throw bad("resume needs base64 envelope, action and salt");
  }
  return { envelope: r.envelope, action: r.action, salt: r.salt };
}

function checkContext(c: unknown): unknown {
  if (typeof c !== "object" || c === null || Array.isArray(c)) throw bad("context must be a JSON object");
  if (Object.keys(c).some((k) => k.toLowerCase() === "eden_escrow")) throw bad("context key eden_escrow is reserved");
  let s: string;
  try {
    s = JSON.stringify(c);
  } catch {
    throw bad("context is not JSON-serialisable");
  }
  if (s.length > MAX_CONTEXT) throw bad("context is too large");
  return JSON.parse(s);
}

function checkResult(json: unknown, resume: string | undefined, status: number): PayResult {
  const fail = (why: string) => new EdictaProtocolError("protocol", `answer ${why}`, { code: "bad_response", status });
  if (typeof json !== "object" || json === null || Array.isArray(json)) throw fail("is not an object");
  const o = json as Record<string, unknown>;
  const hash = o.commitment_hash;
  if (!isHex64(hash)) throw fail("has no commitment_hash");
  const d = { code: "bad_response", status, commitmentHash: hash };
  const f = (why: string) => new EdictaProtocolError("protocol", `answer ${why}`, d);
  if (resume !== undefined && hash !== resume) throw f("names a different commitment than the one resumed");
  if (o.settled !== true) throw f("does not report the deposit settled");
  const sig = o.payment_signature;
  if (typeof sig !== "string" || sig === "" || sig.length > 1024 || /[^\x21-\x7e]/.test(sig)) throw f("has no usable payment_signature");
  // The service leaves these out when it cannot know the signed transaction
  // (a resume after the signer lost track); a wrong value is still refused.
  const railRef = o.rail_ref;
  if (railRef !== undefined && (typeof railRef !== "string" || railRef === "" || railRef.length > 200)) throw f("has a bad rail_ref");
  const signedTx = o.signed_tx;
  if (signedTx !== undefined && (typeof signedTx !== "string" || signedTx === "")) throw f("has a bad signed_tx");
  const payer = o.payer;
  if (payer !== undefined && (typeof payer !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(payer))) throw f("has a bad payer address");
  const authorization = o.authorization;
  if (typeof authorization !== "string" || authorization === "") throw f("has no authorization");
  const receipt = o.receipt;
  if (receipt !== undefined && typeof receipt !== "string") throw f("has a bad receipt");
  const warning =
    typeof o.warning === "string" ? o.warning.replace(/[\u0000-\u001f\u007f-\u009f]/g, " ").slice(0, 1000) : undefined;
  return {
    paymentSignature: sig,
    commitmentHash: hash,
    railRef,
    signedTx,
    payer,
    authorization,
    recorded: o.recorded === true,
    receipt,
    warning,
    raw: o,
  };
}

/**
 * Runs tasks one at a time. The payment server picks the pending nonce when it
 * builds the deposit, so two builds for one payer in flight collide: wrap the
 * whole build-then-pay step in run().
 */
export class PayQueue {
  #tail: Promise<unknown> = Promise.resolve();

  run<T>(task: () => Promise<T>): Promise<T> {
    const next = this.#tail.then(task, task);
    this.#tail = next.catch(() => undefined);
    return next;
  }
}

/** One PayQueue per payer address (case-insensitive); processes sharing a payer are not covered. */
export class PayQueues {
  readonly #queues = new Map<string, PayQueue>();

  for(payer: string): PayQueue {
    const key = payer.toLowerCase();
    let q = this.#queues.get(key);
    if (q === undefined) {
      q = new PayQueue();
      this.#queues.set(key, q);
    }
    return q;
  }
}
