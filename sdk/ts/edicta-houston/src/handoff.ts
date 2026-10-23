// SPDX-License-Identifier: Apache-2.0

import { closeSync, constants, fsyncSync, mkdirSync, openSync, writeSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import { EdictaInputError, EdictaRefusedError } from "./errors.js";
import { keccak256 } from "./keccak.js";
import { asksForPayment, decodePaymentRequired } from "./quote.js";

export const DEFAULT_PICKUP_DELAY_MS = 10_000;
export const MAX_PICKUP_DELAY_MS = 120_000;
const DEFAULT_SERVER_TIMEOUT_MS = 10_000;
const MAX_SERVER_TIMEOUT_MS = 60_000;
/** A paid retry's answer longer than this is never a recognised refusal; so is a longer relay answer. */
export const MAX_RETRY_ANSWER = 16384;

const BUYER_REFUSAL = "neither the escrow buyer";
const DEPOSIT_SELECTOR = "b707d860";

/** A recognised refusal of a paid retry: RR1 (402 asking again for this paymentId) or RR2 (403 buyer check). */
export type Refusal = "RR1" | "RR2";

/**
 * The durable once-per-decision mark of the relay handoff. claim must be
 * atomic and durable before it resolves: it resolves true when this call
 * recorded the mark, false when one already exists (from this or an
 * earlier process). The signed bytes are sent only after a true.
 */
export interface HandoffStore {
  claim(commitmentHash: string): Promise<boolean>;
}

/**
 * The default HandoffStore: one file per commitment hash in a directory only
 * its owner can read (created with mode 0700), made with an exclusive create
 * and synced with its directory before claim resolves.
 */
export class FileHandoffStore implements HandoffStore {
  readonly dir: string;

  constructor(dir: string) {
    if (typeof dir !== "string" || dir === "") throw new EdictaInputError("input", "handoff store directory is required", { code: "client_input" });
    this.dir = dir;
  }

  async claim(commitmentHash: string): Promise<boolean> {
    if (!/^[0-9a-f]{64}$/.test(commitmentHash)) throw new EdictaInputError("input", "bad commitment hash", { code: "client_input" });
    mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    let fd: number;
    try {
      fd = openSync(join(this.dir, `${commitmentHash}.handoff`), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "EEXIST") return false;
      throw e;
    }
    try {
      writeSync(fd, `${new Date().toISOString()}\n`);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    const d = openSync(this.dir, constants.O_RDONLY);
    try {
      fsyncSync(d);
    } finally {
      closeSync(d);
    }
    return true;
  }
}

/** $EDICTA_HOME/handoff, or ~/.edicta/handoff. */
export function defaultHandoffDir(): string {
  const home = process.env.EDICTA_HOME;
  return join(home !== undefined && home !== "" ? home : join(homedir(), ".edicta"), "handoff");
}

export interface HandoffOptions {
  /**
   * The payment server's base URL, the one the client called /deposit/build
   * on (https). The handoff posts to {paymentServerUrl}/deposit/send and to
   * nothing else; no URL is ever taken from a server answer.
   */
  paymentServerUrl: string;
  /** Wait between the two refused paid retries, and between the handoff and the last retry (default 10000, at most 120000). */
  pickupDelayMs?: number;
  /** Bound of the relay call (default 10000, at most 60000). */
  serverTimeoutMs?: number;
  /** The once mark; default new FileHandoffStore(defaultHandoffDir()). */
  store?: HandoffStore;
  /** Replaces globalThis.fetch for the relay call. It must refuse redirects. */
  fetch?: typeof fetch;
  /** Replaces the timer between paid retries (tests). */
  sleep?: (ms: number) => Promise<void>;
  signal?: AbortSignal;
}

/** The decision the paid retry pays for, as edictaPay returned it. */
export interface HandoffDecision {
  commitmentHash: string;
  paymentSignature: string;
  /** The signed deposit, base64, as the signer stored it. */
  signedTx: string | undefined;
  /** keccak256 of the signed deposit, 64 hex digits. */
  railRef: string | undefined;
  /** The service's answer; its deposit.payment_id_hex, when present, must name the same paymentId. */
  raw?: Record<string, unknown>;
}

/** Makes the paid call again with the given Payment-Signature and returns the server's answer unread. */
export type PaidRetryFn = (paymentSignature: string) => Promise<Response>;

export interface PaidRetryOutcome {
  /** The last paid retry's answer, unread. */
  response: Response;
  /** The recognised refusals, in order. */
  refusals: Refusal[];
  /**
   * none: no handoff (no second recognised refusal); sent: the stored bytes
   * went to the relay; relay_fault: the relay call failed and is not
   * repeated; already_used: an earlier handoff for this decision exists.
   */
  handoff: "none" | "sent" | "relay_fault" | "already_used";
  /** The relay's failure, if any. Its answer is never evidence of anything. */
  relayFault: string | undefined;
  /** The relay's answer carried the server's deprecation marker. */
  relayDeprecated: boolean;
  /** The last answer is still a recognised refusal: the operator decides; never pay a new quote under this decision. */
  needsOperator: boolean;
}

function bad(msg: string): EdictaInputError {
  return new EdictaInputError("input", msg, { code: "client_input" });
}

function hex(b: Uint8Array): string {
  return Buffer.from(b).toString("hex");
}

function checkMs(v: number | undefined, def: number, max: number, what: string): number {
  if (v === undefined) return def;
  if (typeof v !== "number" || !Number.isFinite(v) || v <= 0 || v > max) throw bad(`${what} must be a number in (0, ${max}]`);
  return v;
}

function relayEndpoint(raw: string): URL {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw bad("paymentServerUrl is not a URL");
  }
  if (u.protocol !== "https:") throw bad("paymentServerUrl must be https: the signed deposit would travel in clear");
  if (u.username || u.password || u.search || u.hash) throw bad("paymentServerUrl must be https://host[/path] only");
  return new URL(u.pathname.replace(/\/+$/, "") + "/deposit/send", u.origin);
}

interface RlpItem {
  list: boolean;
  start: number;
  end: number;
}

function rlpItem(b: Uint8Array, off: number): RlpItem {
  const p = b[off];
  if (p === undefined) throw new Error("truncated");
  const long = (base: number) => {
    const n = p - base;
    let len = 0;
    for (let i = 1; i <= n; i++) {
      const x = b[off + i];
      if (x === undefined) throw new Error("truncated");
      len = len * 256 + x;
    }
    return { start: off + 1 + n, len };
  };
  let start: number;
  let len: number;
  let list = false;
  if (p < 0x80) {
    start = off;
    len = 1;
  } else if (p <= 0xb7) {
    start = off + 1;
    len = p - 0x80;
  } else if (p < 0xc0) {
    ({ start, len } = long(0xb7));
  } else if (p <= 0xf7) {
    list = true;
    start = off + 1;
    len = p - 0xc0;
  } else {
    list = true;
    ({ start, len } = long(0xf7));
  }
  if (start + len > b.length) throw new Error("truncated");
  return { list, start, end: start + len };
}

/** w0, the paymentId in the calldata of a type-2 deposit transaction (signed or not), as 64 hex digits. */
export function depositPaymentId(tx: Uint8Array): string | undefined {
  try {
    if (tx[0] !== 0x02) return undefined;
    const top = rlpItem(tx, 1);
    if (!top.list || top.end !== tx.length) return undefined;
    let off = top.start;
    for (let i = 0; i < 7; i++) off = rlpItem(tx, off).end;
    const data = rlpItem(tx, off);
    if (data.list || data.end - data.start < 36) return undefined;
    const d = tx.subarray(data.start, data.end);
    if (hex(d.subarray(0, 4)) !== DEPOSIT_SELECTOR) return undefined;
    return hex(d.subarray(4, 36));
  } catch {
    return undefined;
  }
}

/** Reads at most limit + 1 bytes of a body; the stream is cancelled after. */
async function readCapped(body: ReadableStream<Uint8Array> | null, limit: number): Promise<Uint8Array> {
  if (body === null) return new Uint8Array(0);
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let n = 0;
  try {
    while (n <= limit) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      n += value.byteLength;
    }
  } finally {
    await reader.cancel().catch(() => undefined);
  }
  const all = new Uint8Array(n);
  let o = 0;
  for (const c of chunks) {
    all.set(c, o);
    o += c.byteLength;
  }
  return all;
}

/**
 * Classifies a paid retry's answer, given its status, PAYMENT-REQUIRED
 * header and body. RR1: a 402 whose header decodes and whose quote names
 * paymentIdHex in exactly one escrow-upto entry. RR2: a 403 whose body
 * contains the ASCII text "neither the escrow buyer". Anything else,
 * including a body over 16384 bytes, is undefined.
 */
export function recognisedRefusal(
  status: number,
  paymentRequired: string | null | undefined,
  body: Uint8Array,
  paymentIdHex: string,
): Refusal | undefined {
  if (body.length > MAX_RETRY_ANSWER) return undefined;
  if (status === 402) {
    if (typeof paymentRequired !== "string" || paymentRequired === "") return undefined;
    const r = decodePaymentRequired(paymentRequired);
    return r !== undefined && asksForPayment(r, paymentIdHex) ? "RR1" : undefined;
  }
  if (status === 403 && Buffer.from(body).includes(BUYER_REFUSAL, 0, "latin1")) return "RR2";
  return undefined;
}

async function classify(res: Response, paymentIdHex: string): Promise<Refusal | undefined> {
  if (res.status !== 402 && res.status !== 403) return undefined;
  const body = await readCapped(res.clone().body, MAX_RETRY_ANSWER);
  // Headers.get trims the value, as the HTTP library the profile assumes does.
  return recognisedRefusal(res.status, res.headers.get("payment-required"), body, paymentIdHex);
}

function relayHashes(answer: Uint8Array): { fault?: string; deprecated: boolean; hashes: string[] } {
  if (answer.length === 0 || Buffer.from(answer).toString("latin1").trim() === "") return { deprecated: false, hashes: [] };
  let top: unknown;
  try {
    top = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(answer));
  } catch {
    return { fault: "the answer is not JSON", deprecated: false, hashes: [] };
  }
  if (typeof top !== "object" || top === null || Array.isArray(top)) return { fault: "the answer is not a JSON object", deprecated: false, hashes: [] };
  const o = top as Record<string, unknown>;
  const deprecated = o.deprecation === true;
  if (o.error !== undefined && o.error !== null) return { fault: "the answer carries an error", deprecated, hashes: [] };
  const hashes: string[] = [];
  for (const obj of [o, o.result, o.tx, o.transaction]) {
    if (typeof obj !== "object" || obj === null) continue;
    for (const k of ["txHash", "hash", "transactionHash"]) {
      const h = (obj as Record<string, unknown>)[k];
      if (h !== undefined) hashes.push(typeof h === "string" ? h : "");
    }
  }
  return { deprecated, hashes };
}

const sleepTimer = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/**
 * Makes the paid retry with the decision's Payment-Signature and, when the
 * server refuses it twice in a recognised way at least pickupDelayMs apart,
 * hands the stored signed deposit once to the configured payment server's
 * /deposit/send, then retries once more after pickupDelayMs. It signs
 * nothing and pays nothing new: the bytes are the ones the signer signed
 * and the chain already executed, checked to hash to railRef before they
 * are posted. The once mark is claimed in the store before the post; the
 * relay's answer is never evidence.
 */
export async function paidRetryWithHandoff(d: HandoffDecision, retry: PaidRetryFn, opts: HandoffOptions): Promise<PaidRetryOutcome> {
  if (typeof retry !== "function") throw bad("retry must be a function");
  if (typeof opts !== "object" || opts === null) throw bad("handoff options are required");
  const endpoint = relayEndpoint(opts.paymentServerUrl);
  const pickup = checkMs(opts.pickupDelayMs, DEFAULT_PICKUP_DELAY_MS, MAX_PICKUP_DELAY_MS, "pickupDelayMs");
  const timeoutMs = checkMs(opts.serverTimeoutMs, DEFAULT_SERVER_TIMEOUT_MS, MAX_SERVER_TIMEOUT_MS, "serverTimeoutMs");
  if (!/^[0-9a-f]{64}$/.test(d.commitmentHash)) throw bad("commitmentHash must be 64 lowercase hex characters");
  if (typeof d.paymentSignature !== "string" || d.paymentSignature === "") throw bad("the Payment-Signature is required");
  if (typeof d.signedTx !== "string" || typeof d.railRef !== "string") {
    throw new EdictaRefusedError("refused", "no signed deposit is known for this decision: no handoff is possible", {
      code: "handoff_unavailable",
      commitmentHash: d.commitmentHash,
    });
  }
  const signed = new Uint8Array(Buffer.from(d.signedTx, "base64"));
  const paymentId = depositPaymentId(signed);
  if (paymentId === undefined) {
    throw new EdictaRefusedError("refused", "the signed deposit carries no escrow paymentId", { code: "handoff_unavailable", commitmentHash: d.commitmentHash });
  }
  const dep = d.raw?.deposit as Record<string, unknown> | undefined;
  if (dep !== undefined && dep.payment_id_hex !== paymentId) {
    throw new EdictaRefusedError("refused", "the signed deposit is not for the decision's paymentId", { code: "handoff_unavailable", commitmentHash: d.commitmentHash });
  }
  const sleep = opts.sleep ?? sleepTimer;
  const out: PaidRetryOutcome = {
    response: undefined as unknown as Response,
    refusals: [],
    handoff: "none",
    relayFault: undefined,
    relayDeprecated: false,
    needsOperator: false,
  };
  const attempt = async (): Promise<Refusal | undefined> => {
    out.response = await retry(d.paymentSignature);
    const r = await classify(out.response, paymentId);
    if (r !== undefined) out.refusals.push(r);
    return r;
  };

  if ((await attempt()) === undefined) return out;
  await sleep(pickup);
  if ((await attempt()) === undefined) return out;

  if (hex(keccak256(signed)) !== d.railRef.toLowerCase().replace(/^0x/, "")) {
    throw new EdictaRefusedError("refused", "the stored signed deposit does not hash to its rail_ref: nothing is sent", {
      code: "handoff_hash_mismatch",
      commitmentHash: d.commitmentHash,
      railRef: d.railRef,
    });
  }
  const railRef = hex(keccak256(signed));
  const store = opts.store ?? new FileHandoffStore(defaultHandoffDir());
  if (!(await store.claim(d.commitmentHash))) {
    out.handoff = "already_used";
    out.needsOperator = true;
    return out;
  }

  out.handoff = "sent";
  try {
    const timeout = AbortSignal.timeout(timeoutMs);
    const res = await (opts.fetch ?? globalThis.fetch)(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ signedTx: "0x" + hex(signed), paymentId: "0x" + paymentId }),
      redirect: "error",
      cache: "no-store",
      signal: opts.signal ? AbortSignal.any([opts.signal, timeout]) : timeout,
    });
    const answer = await readCapped(res.body, MAX_RETRY_ANSWER);
    const read = relayHashes(answer.length > MAX_RETRY_ANSWER ? new Uint8Array(0) : answer);
    out.relayDeprecated = read.deprecated || res.headers.get("deprecation") !== null;
    if (answer.length > MAX_RETRY_ANSWER) out.relayFault = "answer above 16384 bytes";
    else if (!res.ok) out.relayFault = `status ${res.status}`;
    else if (read.fault !== undefined) out.relayFault = read.fault;
    else if (read.hashes.some((h) => h.toLowerCase() !== "0x" + railRef)) out.relayFault = "the relay names another transaction";
  } catch (e) {
    out.relayFault = e instanceof Error ? e.message : "relay call failed";
  }
  if (out.relayFault !== undefined) out.handoff = "relay_fault";

  await sleep(pickup);
  out.needsOperator = (await attempt()) !== undefined;
  return out;
}
