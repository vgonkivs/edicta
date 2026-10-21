// SPDX-License-Identifier: Apache-2.0

package signer

import "errors"

// Refusals of the signer. A refused request leaves nothing stored and
// counts nothing. The names are the codes of the HTTP API with the prefix
// "signer.".
var (
	// ErrNotAuthorized: the request lacks a valid agent envelope from a
	// pinned key, or a valid Authorization of the pinned gate for exactly
	// these action bytes and salt. A gate signature alone never suffices.
	ErrNotAuthorized = errors.New("signer: not authorized")
	// ErrPinMismatch: the action is outside the operator's pins (chain,
	// facilitator, refund delay, fee and gas caps, payer, nonce).
	ErrPinMismatch = errors.New("signer: action outside the signer's pins")
	// ErrEscrowCode: the escrow's runtime code is not the table's, or could
	// not be read. The check fails closed.
	ErrEscrowCode = errors.New("signer: escrow code is not the table's")
	// ErrExpired: the Authorization expires too soon, or the deposit would
	// take effect after it.
	ErrExpired = errors.New("signer: expired")
	// ErrDigestConflict: this decision already holds another digest.
	ErrDigestConflict = errors.New("signer: another transaction is reserved for this decision")
	// ErrRiskLimit: the operator's per-action or per-hour cap would be
	// passed.
	ErrRiskLimit = errors.New("signer: operator risk limit reached")
	// ErrFastModeRefused: the Authorization is fast mode and the operator
	// refuses fast mode.
	ErrFastModeRefused = errors.New("signer: fast mode refused")
	// ErrUnavailable: a dependency (the chain RPC, the store, the wallet,
	// the gate) did not answer. Retryable; never a reason to sign other
	// bytes.
	ErrUnavailable = errors.New("signer: dependency unavailable")
)
