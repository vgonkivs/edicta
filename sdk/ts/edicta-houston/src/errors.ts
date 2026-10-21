// SPDX-License-Identifier: Apache-2.0

export type ErrorKind = "input" | "access" | "refused" | "unavailable" | "transport" | "protocol";

/** What a failure after the commitment returns, base64. Pass it back as the resume option. */
export interface ResumeMaterial {
  envelope: string;
  action: string;
  salt: string;
}

export interface ErrorDetail {
  code: string;
  status?: number;
  retryable?: boolean;
  commitmentHash?: string;
  railRef?: string;
  resume?: ResumeMaterial;
  authorization?: string;
  signedTx?: string;
}

/**
 * Base of every error edictaPay throws. When commitmentHash or resume is set
 * the decision already exists: call edictaPay again with resumeHash (or
 * resume) instead of starting a new payment; a fresh 402 can pay twice.
 */
export class EdictaError extends Error {
  readonly kind: ErrorKind;
  readonly code: string;
  readonly status: number | undefined;
  readonly retryable: boolean;
  readonly commitmentHash: string | undefined;
  readonly railRef: string | undefined;
  /** Set once the commitment is signed; lets a call continue without publishing again. */
  readonly resume: ResumeMaterial | undefined;
  /** A gate Authorization that was issued but not used (the nonce is spent); keep it. */
  readonly authorization: string | undefined;
  /** The signed deposit, when the service could not store it: keep it, it may already be on its way to the chain. */
  readonly signedTx: string | undefined;

  constructor(kind: ErrorKind, message: string, d: ErrorDetail, options?: { cause?: unknown }) {
    super(message, options);
    this.name = new.target.name;
    this.kind = kind;
    this.code = d.code;
    this.status = d.status;
    this.retryable = d.retryable ?? false;
    this.commitmentHash = d.commitmentHash;
    this.railRef = d.railRef;
    this.resume = d.resume;
    this.authorization = d.authorization;
    this.signedTx = d.signedTx;
  }
}

/** The call was malformed (checked locally, or exit 64 at the service). Never retry unchanged. */
export class EdictaInputError extends EdictaError {}
/** The service refused the caller: bearer token, Host or Origin. */
export class EdictaAccessError extends EdictaError {}
/** The gate, the signer or a local pre-check refused, policy denials included. Retrying the same call will not help. */
export class EdictaRefusedError extends EdictaError {}
/** Retryable (exit 6 / HTTP 429, 5xx), including settlement_pending. Resume when a hash or resume material is set. */
export class EdictaUnavailableError extends EdictaError {}
/** No usable HTTP answer: connection failure, timeout or abort. The run may already exist at the service. */
export class EdictaTransportError extends EdictaError {}
/** The answer did not have the documented shape; nothing unchecked is handed on to a payment server. */
export class EdictaProtocolError extends EdictaError {}

const INPUT = new Set(["usage", "eden_input", "media_type", "method_not_allowed", "client_input"]);
const ACCESS = new Set(["unauthorized", "forbidden", "host_refused", "origin_refused"]);
const UNAVAILABLE = new Set(["busy", "source_unavailable", "state_unavailable", "settlement_pending", "internal"]);

function b64(v: unknown): string | undefined {
  return typeof v === "string" && v.length > 0 && v.length <= 1 << 20 && /^[A-Za-z0-9+/]+={0,2}$/.test(v) ? v : undefined;
}

/**
 * Maps an agent-serve error body (HTTP status plus the code field) to a typed
 * error. The code decides first: the gate's own refusals travel with 400, 403
 * and 409 statuses and must not be read as input or access problems. Status is
 * used only when the body has no usable code.
 */
export function classifyFailure(status: number, body: unknown): EdictaError {
  const b = (typeof body === "object" && body !== null ? body : {}) as Record<string, unknown>;
  const hasCode = typeof b.code === "string" && /^[A-Za-z0-9_.]{1,80}$/.test(b.code);
  const code = hasCode ? (b.code as string) : "unknown";
  const text =
    typeof b.message === "string" ? b.message.replace(/[\u0000-\u001f\u007f-\u009f]/g, " ").slice(0, 1000) : `HTTP ${status}`;
  const hash =
    typeof b.commitment_hash === "string" && /^[0-9a-f]{64}$/.test(b.commitment_hash) ? b.commitment_hash : undefined;
  const railRef = typeof b.rail_ref === "string" && b.rail_ref.length <= 200 ? b.rail_ref : undefined;
  const envelope = b64(b.envelope);
  const action = b64(b.action);
  const salt = b64(b.salt);
  const d: ErrorDetail = {
    code,
    status,
    retryable: b.retryable === true,
    commitmentHash: hash,
    railRef,
    resume: envelope && action && salt ? { envelope, action, salt } : undefined,
    authorization: b64(b.authorization),
    signedTx: b64(b.signed_tx),
  };
  const msg = `${code}: ${text}`;
  const unavailable = () => new EdictaUnavailableError("unavailable", msg, { ...d, retryable: true });
  if (hasCode) {
    if (ACCESS.has(code)) return new EdictaAccessError("access", msg, d);
    if (INPUT.has(code)) return new EdictaInputError("input", msg, d);
    if (UNAVAILABLE.has(code) || d.retryable) return unavailable();
    return new EdictaRefusedError("refused", msg, d);
  }
  if (status === 401 || status === 403) return new EdictaAccessError("access", msg, d);
  if (status === 400 || status === 405 || status === 415) return new EdictaInputError("input", msg, d);
  if (status === 429 || status >= 500) return unavailable();
  return new EdictaRefusedError("refused", msg, d);
}
