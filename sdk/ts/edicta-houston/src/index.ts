// SPDX-License-Identifier: Apache-2.0

export { edictaPay, PayQueue, PayQueues, parseDurationMs } from "./pay.js";
export type { PayOptions, PayResult, Named } from "./pay.js";
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
