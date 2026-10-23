// SPDX-License-Identifier: Apache-2.0

import { closeSync, constants, fsyncSync, mkdirSync, openSync, writeSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import { EdictaInputError, EdictaRefusedError } from "./errors.js";
import { keccak256 } from "./keccak.js";
import { asksForPayment, decodePaymentRequired } from "./quote.js";
import { SECP256K1_N, personalDigest32, recoverAddress } from "./secp256k1.js";

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
  /** Bound of the relay call and of reading each paid retry's answer (default 10000, at most 60000). */
  serverTimeoutMs?: number;
  /** The once mark; default new FileHandoffStore(defaultHandoffDir()). */
  store?: HandoffStore;
  /** Replaces globalThis.fetch for the relay call. It must refuse redirects. */
  fetch?: typeof fetch;
  /** Replaces the timer between paid retries (tests). */
  sleep?: (ms: number) => Promise<void>;
  /**
   * Stops the flow before a paid retry or before the once mark is claimed.
   * It never cuts the relay call: once the mark is claimed, the one call it
   * allows runs to serverTimeoutMs.
   */
  signal?: AbortSignal;
}

/**
 * The decision the paid retry pays for: pass edictaPay's result as it is.
 * The handoff ties the signed bytes to it: they must be the committed
 * transaction (raw.action) with one signature, and the Payment-Signature
 * must come from the key that signed them.
 */
export interface HandoffDecision {
  commitmentHash: string;
  paymentSignature: string;
  /** The signed deposit, base64, as the signer stored it. */
  signedTx: string | undefined;
  /** keccak256 of the signed deposit, 64 hex digits. */
  railRef: string | undefined;
  /**
   * The service's answer. Its action (base64) is the committed action, which
   * the handoff needs; its deposit.payment_id_hex and deposit.escrow, and its
   * payer, must agree with it when present.
   */
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
  /** Where the item's encoding starts. */
  off: number;
  /** Where its payload starts and ends. */
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
  return { list, off, start, end: start + len };
}

/** The items of a type-2 transaction's list, or undefined when tx is not one list after the type byte. */
function txItems(tx: Uint8Array): { top: RlpItem; items: RlpItem[] } | undefined {
  try {
    if (tx[0] !== 0x02) return undefined;
    const top = rlpItem(tx, 1);
    if (!top.list || top.end !== tx.length) return undefined;
    const items: RlpItem[] = [];
    for (let off = top.start; off < top.end; ) {
      const it = rlpItem(tx, off);
      if (it.end > top.end) return undefined;
      items.push(it);
      off = it.end;
    }
    return { top, items };
  } catch {
    return undefined;
  }
}

/**
 * The unsigned transaction (key 2) of a committed action, a deterministic
 * CBOR map; the service checked the rest of it when it committed it.
 */
function actionTx(action: Uint8Array): Uint8Array | undefined {
  let off = 0;
  const head = (): { major: number; arg: number } | undefined => {
    const b = action[off++];
    if (b === undefined) return undefined;
    const major = b >> 5;
    const ai = b & 31;
    if (ai < 24) return { major, arg: ai };
    const n = ai === 24 ? 1 : ai === 25 ? 2 : ai === 26 ? 4 : 0;
    if (n === 0) return undefined;
    let arg = 0;
    for (let i = 0; i < n; i++) {
      const x = action[off++];
      if (x === undefined) return undefined;
      arg = arg * 256 + x;
    }
    return { major, arg };
  };
  const map = head();
  if (map === undefined || map.major !== 5) return undefined;
  let tx: Uint8Array | undefined;
  for (let i = 0; i < map.arg; i++) {
    const k = head();
    const v = head();
    if (k === undefined || k.major !== 0 || v === undefined) return undefined;
    if (v.major === 2 || v.major === 3) {
      if (off + v.arg > action.length) return undefined;
      if (k.arg === 2) {
        if (v.major !== 2 || tx !== undefined) return undefined;
        tx = action.subarray(off, off + v.arg);
      }
      off += v.arg;
    } else if (v.major !== 0) {
      return undefined;
    }
  }
  return off === action.length ? tx : undefined;
}

/** The committed deposit transaction, as far as the handoff reads it. */
interface Committed {
  unsigned: Uint8Array;
  paymentId: string;
  /** The escrow, 40 hex digits. */
  to: string;
}

function committedDeposit(raw: Record<string, unknown> | undefined): Committed | undefined {
  const a = raw?.action;
  if (a === undefined) return undefined;
  if (typeof a !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(a)) throw bad("raw.action is not base64");
  const unsigned = actionTx(new Uint8Array(Buffer.from(a, "base64")));
  const parts = unsigned && txItems(unsigned);
  const paymentId = unsigned && depositPaymentId(unsigned);
  const to = parts?.items[5];
  if (unsigned === undefined || parts?.items.length !== 9 || paymentId === undefined || to === undefined || to.list || to.end - to.start !== 20) {
    throw bad("raw.action is not an Eden escrow deposit");
  }
  return { unsigned, paymentId, to: hex(unsigned.subarray(to.start, to.end)) };
}

/** A canonical RLP integer of at most 32 bytes, or undefined. */
function rlpUint(b: Uint8Array, it: RlpItem): bigint | undefined {
  const v = b.subarray(it.start, it.end);
  if (it.list || v.length > 32 || (v.length > 0 && v[0] === 0)) return undefined;
  if (v.length === 1 && (v[0] as number) < 0x80 && it.off !== it.start) return undefined;
  return v.length === 0 ? 0n : BigInt("0x" + hex(v));
}

/**
 * Ties the signed bytes and the Payment-Signature to the decision: the bytes
 * are the committed transaction with one low-s signature appended, the
 * Payment-Signature over the committed paymentId recovers to the same
 * signer, and the service's view (deposit escrow, payer) agrees.
 */
function bindToDecision(d: HandoffDecision, signed: Uint8Array, c: Committed | undefined): void {
  const fail = (why: string) =>
    new EdictaRefusedError("refused", `${why}: nothing is sent`, { code: "handoff_unbound", commitmentHash: d.commitmentHash });
  if (c === undefined) throw fail("the committed action (raw.action) is not known, so the signed deposit cannot be tied to the decision");
  const sp = txItems(signed);
  const up = txItems(c.unsigned);
  if (sp === undefined || up === undefined || sp.items.length !== 12) throw fail("the signed deposit is not a signed type 2 transaction");
  const want = c.unsigned.subarray(up.top.start, up.top.end);
  const got = signed.subarray(sp.top.start, sp.top.start + want.length);
  if (!Buffer.from(got).equals(Buffer.from(want)) || sp.items[9]?.off !== sp.top.start + want.length) {
    throw fail("the signed deposit is not the committed transaction");
  }
  const [yi, ri, si] = sp.items.slice(9) as [RlpItem, RlpItem, RlpItem];
  const yb = yi.end - yi.off === 1 ? signed[yi.off] : undefined;
  const y = yb === 0x80 ? 0 : yb === 0x01 ? 1 : undefined;
  const r = rlpUint(signed, ri);
  const s = rlpUint(signed, si);
  if (y === undefined || r === undefined || s === undefined || s > SECP256K1_N / 2n) throw fail("the signed deposit's signature is not canonical");
  const signer = recoverAddress(keccak256(c.unsigned), r, s, y);
  if (signer === undefined) throw fail("the signed deposit's signature recovers no key");
  const payer = "0x" + hex(signer);

  const raw = d.raw ?? {};
  if (raw.payer !== undefined && (typeof raw.payer !== "string" || raw.payer.toLowerCase() !== payer)) {
    throw fail("the service names another payer than the signer of the deposit");
  }
  const dep = raw.deposit as Record<string, unknown> | undefined;
  if (dep?.escrow !== undefined && (typeof dep.escrow !== "string" || dep.escrow.toLowerCase() !== "0x" + c.to)) {
    throw fail("the service names another escrow than the committed transaction");
  }

  const ps = d.paymentSignature;
  if (!/^0x[0-9a-fA-F]{130}$/.test(ps)) throw fail("the Payment-Signature is not 65 bytes of hex");
  const sig = new Uint8Array(Buffer.from(ps.slice(2), "hex"));
  const v = sig[64] as number;
  const proofSigner = recoverAddress(
    personalDigest32(new Uint8Array(Buffer.from(c.paymentId, "hex"))),
    BigInt("0x" + hex(sig.subarray(0, 32))),
    BigInt("0x" + hex(sig.subarray(32, 64))),
    v >= 27 ? v - 27 : v,
  );
  if (proofSigner === undefined || "0x" + hex(proofSigner) !== payer) throw fail("the Payment-Signature is not the deposit payer's");
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

interface CappedBody {
  bytes: Uint8Array;
  /** The body did not end, or could not be read, within the time given. */
  unread: boolean;
}

/**
 * Reads at most limit + 1 bytes of a body within ms. The reader is cancelled
 * after without waiting for it: cancelling one branch of a cloned body settles
 * only once the other branch is cancelled too, which the caller may never do.
 */
async function readCapped(body: ReadableStream<Uint8Array> | null, limit: number, ms: number): Promise<CappedBody> {
  if (body === null) return { bytes: new Uint8Array(0), unread: false };
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let n = 0;
  let unread = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<"timeout">((resolve) => {
    timer = setTimeout(() => resolve("timeout"), ms);
  });
  try {
    while (n <= limit) {
      const step = await Promise.race([reader.read(), deadline]);
      if (step === "timeout") {
        unread = true;
        break;
      }
      if (step.done) break;
      chunks.push(step.value);
      n += step.value.byteLength;
    }
  } catch {
    unread = true;
  } finally {
    clearTimeout(timer);
    reader.cancel().catch(() => undefined);
  }
  const all = new Uint8Array(n);
  let o = 0;
  for (const c of chunks) {
    all.set(c, o);
    o += c.byteLength;
  }
  return { bytes: all, unread };
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

// The caller gets the answer unread, so the refusal is read from a clone. An
// answer that does not end in time is not a recognised refusal.
async function classify(res: Response, paymentIdHex: string | undefined, ms: number): Promise<Refusal | undefined> {
  if (res.status !== 403 && (res.status !== 402 || paymentIdHex === undefined)) return undefined;
  const body = await readCapped(res.clone().body, MAX_RETRY_ANSWER, ms);
  if (body.unread) return undefined;
  // Headers.get trims the value, as the HTTP library the profile assumes does.
  return recognisedRefusal(res.status, res.headers.get("payment-required"), body.bytes, paymentIdHex ?? "");
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
 * and the chain already executed, checked before they are posted to hash to
 * railRef, to be the committed transaction, and to be signed by the key
 * that made the Payment-Signature. The once mark is claimed in the store
 * before the post; the relay's answer is never evidence.
 */
export async function paidRetryWithHandoff(d: HandoffDecision, retry: PaidRetryFn, opts: HandoffOptions): Promise<PaidRetryOutcome> {
  if (typeof retry !== "function") throw bad("retry must be a function");
  if (typeof opts !== "object" || opts === null) throw bad("handoff options are required");
  const endpoint = relayEndpoint(opts.paymentServerUrl);
  const pickup = checkMs(opts.pickupDelayMs, DEFAULT_PICKUP_DELAY_MS, MAX_PICKUP_DELAY_MS, "pickupDelayMs");
  const timeoutMs = checkMs(opts.serverTimeoutMs, DEFAULT_SERVER_TIMEOUT_MS, MAX_SERVER_TIMEOUT_MS, "serverTimeoutMs");
  if (!/^[0-9a-f]{64}$/.test(d.commitmentHash)) throw bad("commitmentHash must be 64 lowercase hex characters");
  if (typeof d.paymentSignature !== "string" || d.paymentSignature === "") throw bad("the Payment-Signature is required");
  if (d.signedTx !== undefined && typeof d.signedTx !== "string") throw bad("signedTx must be base64");
  if (d.railRef !== undefined && typeof d.railRef !== "string") throw bad("railRef must be a string");
  const unavailable = (why: string) =>
    new EdictaRefusedError("refused", why, { code: "handoff_unavailable", commitmentHash: d.commitmentHash });

  // What the decision says about its paymentId must agree before any paid
  // retry; what only the handoff needs is checked when it is due, so the
  // paid retry itself always runs.
  const committed = committedDeposit(d.raw);
  const dep = d.raw?.deposit as Record<string, unknown> | undefined;
  let paymentId = committed?.paymentId;
  if (dep?.payment_id_hex !== undefined) {
    if (paymentId !== undefined && dep.payment_id_hex !== paymentId) throw unavailable("the service's deposit names another paymentId than the committed action");
    if (typeof dep.payment_id_hex === "string" && /^[0-9a-f]{64}$/.test(dep.payment_id_hex)) paymentId ??= dep.payment_id_hex;
  }
  const signed = d.signedTx === undefined ? undefined : new Uint8Array(Buffer.from(d.signedTx, "base64"));
  if (signed !== undefined) {
    const sp = depositPaymentId(signed);
    if (sp === undefined) throw unavailable("the signed deposit carries no escrow paymentId");
    if (paymentId !== undefined && sp !== paymentId) throw unavailable("the signed deposit is not for the decision's paymentId");
    paymentId ??= sp;
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
    opts.signal?.throwIfAborted();
    out.response = await retry(d.paymentSignature);
    const r = await classify(out.response, paymentId, timeoutMs);
    if (r !== undefined) out.refusals.push(r);
    return r;
  };

  if ((await attempt()) === undefined) return out;
  await sleep(pickup);
  if ((await attempt()) === undefined) return out;

  if (signed === undefined || d.railRef === undefined) throw unavailable("no signed deposit is known for this decision: no handoff is possible");
  if (hex(keccak256(signed)) !== d.railRef.toLowerCase().replace(/^0x/, "")) {
    throw new EdictaRefusedError("refused", "the stored signed deposit does not hash to its rail_ref: nothing is sent", {
      code: "handoff_hash_mismatch",
      commitmentHash: d.commitmentHash,
      railRef: d.railRef,
    });
  }
  bindToDecision(d, signed, committed);
  const railRef = hex(keccak256(signed));
  const store = opts.store ?? new FileHandoffStore(defaultHandoffDir());
  opts.signal?.throwIfAborted();
  if (!(await store.claim(d.commitmentHash))) {
    out.handoff = "already_used";
    out.needsOperator = true;
    return out;
  }

  out.handoff = "sent";
  try {
    // The mark is spent: only the timeout may cut the one call it allows.
    const timeout = AbortSignal.timeout(timeoutMs);
    const res = await (opts.fetch ?? globalThis.fetch)(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ signedTx: "0x" + hex(signed), paymentId: "0x" + (committed as Committed).paymentId }),
      redirect: "error",
      cache: "no-store",
      signal: timeout,
    });
    const { bytes: answer, unread } = await readCapped(res.body, MAX_RETRY_ANSWER, timeoutMs);
    const read = relayHashes(unread || answer.length > MAX_RETRY_ANSWER ? new Uint8Array(0) : answer);
    out.relayDeprecated = read.deprecated || res.headers.get("deprecation") !== null;
    if (unread) out.relayFault = "the answer was not read in time";
    else if (answer.length > MAX_RETRY_ANSWER) out.relayFault = "answer above 16384 bytes";
    else if (!res.ok) out.relayFault = `status ${res.status}`;
    else if (read.fault !== undefined) out.relayFault = read.fault;
    else if (read.hashes.some((h) => h.toLowerCase() !== "0x" + railRef)) out.relayFault = "the relay names another transaction";
  } catch (e) {
    out.relayFault = e instanceof Error ? e.message : "relay call failed";
  }
  if (out.relayFault !== undefined) out.handoff = "relay_fault";

  // After the handoff an abort still returns what happened: the last answer
  // was a recognised refusal, so the operator decides.
  if (!opts.signal?.aborted) await sleep(pickup);
  out.needsOperator = opts.signal?.aborted === true || (await attempt()) !== undefined;
  return out;
}
