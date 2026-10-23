// SPDX-License-Identifier: Apache-2.0

// Package signerapi is the HTTP wire format of edicta-signer: the routes,
// the request and answer messages with their CBOR schemas (JSON is derived
// from the same schemas by the core API's transport rules), the decision
// states and the codes of the signer's refusals. Both the signer and its
// clients use it, so a client links no part of the signer.
package signerapi

import (
	"errors"

	"github.com/vgonkivs/edicta/api/edictaapi"
	"github.com/vgonkivs/edicta/engine/commitment"
)

// Routes of the signer API.
const (
	RouteSign   = "/v1/sign"
	RouteHealth = "/v1/health"
	// RouteRequeue is the operator's route back from state wrong.
	RouteRequeue = "/v1/admin/requeue"
	// RoutePaymentSignature releases the payment proof of a decision the
	// rail executed.
	RoutePaymentSignature = "/v1/payment-signature"
	// RouteStatusPrefix is followed by a commitment hash in 64 lower-case
	// hex digits: GET shows the caller's own decision.
	RouteStatusPrefix = "/v1/status/"
)

// MaxRequirementsSize bounds the payment requirements of a request.
const MaxRequirementsSize = 16384

// SignLimit bounds a sign request in CBOR: the envelope, the action, the
// salt, the Authorization and the payment requirements with their wrapper
// heads.
const SignLimit = commitment.MaxSignedSize + commitment.MaxActionSize + commitment.ActionSaltSize +
	commitment.MaxAuthorizationSize + MaxRequirementsSize + 48

// PaymentLimit bounds a payment-signature request in CBOR: a sign request,
// the commitment hash and the field.
const PaymentLimit = SignLimit + 32 + maxFieldName + 16

const maxFieldName = 32

// State is where one decision stands at the signer.
type State string

const (
	// StateReserved: the digest is reserved and counted, nothing is signed
	// yet. A repeat of the request signs it.
	StateReserved State = "reserved"
	// StateSigned: the signed bytes are stored and may be on their way; the
	// rail has not been seen to include them.
	StateSigned State = "signed"
	// StateExecuted and StateReverted: the rail included the transaction at
	// the confirmation depth with that outcome; the record request is due.
	StateExecuted State = "executed"
	StateReverted State = "reverted"
	// StateRecorded: the gate returned its receipt for the rail_ref.
	StateRecorded State = "recorded"
	// StateNotExecuted: no source served the transaction by the deadline.
	// Nothing is recorded and nothing else is ever signed for the decision.
	StateNotExecuted State = "not_executed"
	// StateWrong: the rail answered with something the signed bytes cannot
	// explain, or the gate refused the record for good. The operator looks.
	StateWrong State = "wrong"
)

// Refusals a client acts on. The signer returns these very values.
var (
	// ErrUnknownDecision: the store holds nothing for this commitment hash.
	ErrUnknownDecision = errors.New("signer: unknown decision")
	// ErrNotExecuted: no payment proof before the rail executed the
	// decision's transaction on the word of enough operators. Retryable.
	ErrNotExecuted = errors.New("signer: not executed")
)

// Codes of the signer's own refusals in an error answer. The other codes an
// answer may carry are those of the core API and of the served profiles.
const (
	CodeUnavailable      = "signer.ErrUnavailable"
	CodeExpired          = "signer.ErrExpired"
	CodeNotAuthorized    = "signer.ErrNotAuthorized"
	CodePinMismatch      = "signer.ErrPinMismatch"
	CodeEscrowCode       = "signer.ErrEscrowCode"
	CodeFastModeRefused  = "signer.ErrFastModeRefused"
	CodeDigestConflict   = "signer.ErrDigestConflict"
	CodeNotRequeueable   = "signer.ErrNotRequeueable"
	CodeUnknownDecision  = "signer.ErrUnknownDecision"
	CodeSharedCredential = "signer.ErrSharedCredential"
	CodeRiskLimit        = "signer.ErrRiskLimit"
	CodeNotExecuted      = "signer.ErrNotExecuted"
	CodeRequirements     = "signer.ErrRequirements"
	CodeInternal         = "signer.ErrInternal"
)

// Request is one signing request: the agent's signed envelope, the action
// bytes and salt it committed, and the gate's SignedAuthorization, with the
// payment requirements the action binds when the profile has them.
type Request struct {
	Envelope      []byte
	Action        []byte
	Salt          []byte
	Authorization []byte
	// Requirements are optional; a profile may require them.
	Requirements []byte
}

// Output is what the signer hands back: the signed rail request, ready to
// send, and its rail_ref.
type Output struct {
	CommitmentHash commitment.Hash
	Signed         []byte
	RailRef        string
	// Repeat is set when the decision was signed before and the stored
	// bytes are returned; nothing was counted again.
	Repeat bool
}

// PaymentProofRequest asks for the payment proof of one decision: the
// commitment hash it names, the field the proof covers, and the decision's
// own signing request (envelope, action, salt, Authorization, and optionally
// the payment requirements again).
type PaymentProofRequest struct {
	CommitmentHash commitment.Hash
	Field          string
	Request
}

// PaymentProof is a released payment proof.
type PaymentProof struct {
	CommitmentHash commitment.Hash
	// Message is what the proof covers; Signature is the proof as the
	// profile formats it.
	Message   [32]byte
	Signature []byte
	// Repeat is set when the stored proof is returned.
	Repeat bool
}

// Status is what the signer tells an agent about its own decision.
type Status struct {
	State State
	// Sent: the first send was allowed to start.
	Sent    bool
	RailRef string
	Signed  []byte
	Outcome string
	Detail  string
	// PaymentProofAllowed: the settlement is strong enough for a payment
	// proof.
	PaymentProofAllowed bool
	Receipt             []byte
}

func fieldNameChar(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}

var (
	// SignRequestSchema is the request of POST /v1/sign.
	SignRequestSchema = edictaapi.NewSchema(
		edictaapi.Field{Key: 1, Name: "envelope", Kind: edictaapi.KindBytes, Min: 1, Max: commitment.MaxSignedSize, Required: true},
		edictaapi.Field{Key: 2, Name: "action", Kind: edictaapi.KindBytes, Min: 1, Max: commitment.MaxActionSize, Required: true},
		edictaapi.Field{Key: 3, Name: "action_salt", Kind: edictaapi.KindBytes, Min: commitment.ActionSaltSize, Max: commitment.ActionSaltSize, Required: true},
		edictaapi.Field{Key: 4, Name: "signed_authorization", Kind: edictaapi.KindBytes, Min: 1, Max: commitment.MaxAuthorizationSize, Required: true},
		edictaapi.Field{Key: 5, Name: "payment_required", Kind: edictaapi.KindBytes, Min: 1, Max: MaxRequirementsSize},
	)
	// PaymentRequestSchema is the request of POST /v1/payment-signature.
	PaymentRequestSchema = edictaapi.NewSchema(
		edictaapi.Field{Key: 1, Name: "commitment_hash", Kind: edictaapi.KindBytes, Min: 32, Max: 32, Required: true},
		edictaapi.Field{Key: 2, Name: "field", Kind: edictaapi.KindText, Min: 1, Max: maxFieldName, Charset: fieldNameChar, Required: true},
		edictaapi.Field{Key: 3, Name: "envelope", Kind: edictaapi.KindBytes, Min: 1, Max: commitment.MaxSignedSize, Required: true},
		edictaapi.Field{Key: 4, Name: "action", Kind: edictaapi.KindBytes, Min: 1, Max: commitment.MaxActionSize, Required: true},
		edictaapi.Field{Key: 5, Name: "action_salt", Kind: edictaapi.KindBytes, Min: commitment.ActionSaltSize, Max: commitment.ActionSaltSize, Required: true},
		edictaapi.Field{Key: 6, Name: "signed_authorization", Kind: edictaapi.KindBytes, Min: 1, Max: commitment.MaxAuthorizationSize, Required: true},
		edictaapi.Field{Key: 7, Name: "payment_required", Kind: edictaapi.KindBytes, Min: 1, Max: MaxRequirementsSize},
	)
	// PaymentResponseSchema is the 200 answer of POST /v1/payment-signature.
	PaymentResponseSchema = edictaapi.NewSchema(
		edictaapi.Field{Key: 1, Name: "signature", Kind: edictaapi.KindText, Min: 1, Max: 256, Required: true},
		edictaapi.Field{Key: 2, Name: "message", Kind: edictaapi.KindBytes, Min: 32, Max: 32, Required: true},
		edictaapi.Field{Key: 3, Name: "repeat", Kind: edictaapi.KindUint, Required: true},
	)
	// StatusResponseSchema is the 200 answer of GET /v1/status/{hash}.
	StatusResponseSchema = edictaapi.NewSchema(
		edictaapi.Field{Key: 1, Name: "state", Kind: edictaapi.KindText, Min: 1, Max: 32, Required: true},
		edictaapi.Field{Key: 2, Name: "commitment_hash", Kind: edictaapi.KindBytes, Min: 32, Max: 32, Required: true},
		edictaapi.Field{Key: 3, Name: "sent", Kind: edictaapi.KindUint, Required: true},
		edictaapi.Field{Key: 4, Name: "rail_ref", Kind: edictaapi.KindText, Max: 128},
		edictaapi.Field{Key: 5, Name: "signed_tx", Kind: edictaapi.KindBytes},
		edictaapi.Field{Key: 6, Name: "outcome", Kind: edictaapi.KindText, Max: 64},
		edictaapi.Field{Key: 7, Name: "detail", Kind: edictaapi.KindText, Max: 1024},
		edictaapi.Field{Key: 8, Name: "payment_proof_allowed", Kind: edictaapi.KindUint, Required: true},
		edictaapi.Field{Key: 9, Name: "receipt", Kind: edictaapi.KindBytes},
	)
	// SignResponseSchema is the 200 answer of POST /v1/sign.
	SignResponseSchema = edictaapi.NewSchema(
		edictaapi.Field{Key: 1, Name: "signed_tx", Kind: edictaapi.KindBytes, Min: 1, Required: true},
		edictaapi.Field{Key: 2, Name: "rail_ref", Kind: edictaapi.KindText, Min: 1, Max: 128, Required: true},
		edictaapi.Field{Key: 3, Name: "commitment_hash", Kind: edictaapi.KindBytes, Min: 32, Max: 32, Required: true},
		edictaapi.Field{Key: 4, Name: "repeat", Kind: edictaapi.KindUint, Required: true},
	)
	// RequeueRequestSchema and RequeueResponseSchema are POST
	// /v1/admin/requeue.
	RequeueRequestSchema = edictaapi.NewSchema(
		edictaapi.Field{Key: 1, Name: "commitment_hash", Kind: edictaapi.KindBytes, Min: 32, Max: 32, Required: true},
	)
	RequeueResponseSchema = edictaapi.NewSchema(
		edictaapi.Field{Key: 1, Name: "state", Kind: edictaapi.KindText, Min: 1, Max: 32, Required: true},
	)
	// HealthSchema is the 200 answer of GET /v1/health.
	HealthSchema = edictaapi.NewSchema(
		edictaapi.Field{Key: 1, Name: "status", Kind: edictaapi.KindText, Min: 1, Max: 64, Required: true},
	)
)
