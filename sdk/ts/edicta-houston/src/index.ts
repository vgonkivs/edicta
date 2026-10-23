// SPDX-License-Identifier: Apache-2.0

export { edictaPay, PayQueue, PayQueues, parseDurationMs } from "./pay.js";
export type { PayOptions, PayResult, Named } from "./pay.js";
export {
  paidRetryWithHandoff,
  recognisedRefusal,
  depositPaymentId,
  FileHandoffStore,
  defaultHandoffDir,
  DEFAULT_PICKUP_DELAY_MS,
  MAX_PICKUP_DELAY_MS,
  MAX_RETRY_ANSWER,
} from "./handoff.js";
export type { HandoffStore, HandoffOptions, HandoffDecision, PaidRetryFn, PaidRetryOutcome, Refusal } from "./handoff.js";
export { decodePaymentRequired, asksForPayment } from "./quote.js";
export { keccak256 } from "./keccak.js";
export {
  EdictaError,
  EdictaInputError,
  EdictaAccessError,
  EdictaRefusedError,
  EdictaUnavailableError,
  EdictaTransportError,
  EdictaProtocolError,
  classifyFailure,
} from "./errors.js";
export type { ErrorKind, ErrorDetail, ResumeMaterial } from "./errors.js";
