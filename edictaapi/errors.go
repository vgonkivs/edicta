// Package edictaapi is the HTTP+CBOR transport of Edicta (spec sections 17
// and 18): the handler served by edictad, the Go client, the publish request
// message, the per-agent publish quotas and the error table.
package edictaapi

import (
	"context"
	"errors"
	"fmt"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/policy"
)

// Sentinels of this package. The names are the codes of section 18.3 with the
// prefix "edictaapi.".
var (
	ErrPublishStale     = errors.New("edictaapi: publish request outside the time window")
	ErrTokenInvalid     = errors.New("edictaapi: bearer token missing or invalid")
	ErrPublishSignature = errors.New("edictaapi: publish request signature invalid")
	ErrRouteNotFound    = errors.New("edictaapi: route not found")
	ErrPublishDisabled  = errors.New("edictaapi: publishing is disabled on this server")
	ErrMethodNotAllowed = errors.New("edictaapi: method not allowed")
	ErrQuotaExceeded    = errors.New("edictaapi: quota exceeded")
	ErrMediaType        = errors.New("edictaapi: content type must be application/cbor")
	ErrDeadline         = fmt.Errorf("edictaapi: deadline exceeded: %w", context.DeadlineExceeded)
	ErrInternal         = errors.New("edictaapi: internal error")
)

// ErrorRule maps an error returned by an operation to a wire code and status.
// Code is the sentinel name as section 12 writes it, with its package prefix
// outside the commitment and gate packages (for example
// "recorder.ErrOutcomeUnknown").
type ErrorRule struct {
	Code      string
	Err       error
	Status    int
	Retryable bool
}

func retryableStatus(status int) bool {
	switch status {
	case 425, 429, 503, 504:
		return true
	}
	return false
}

func rule(status int, code string, err error) ErrorRule {
	return ErrorRule{Code: code, Err: err, Status: status, Retryable: retryableStatus(status)}
}

const codeInternal = "edictaapi.ErrInternal"

// table is the normative mapping of section 18.3, in match order.
var table = []ErrorRule{
	rule(410, "ErrAnchorTooOld", gate.ErrAnchorTooOld),
	rule(410, "ErrExpired", commitment.ErrExpired),
	rule(410, "edictaapi.ErrPublishStale", ErrPublishStale),
	rule(410, "policy.ErrDecisionAge", policy.ErrDecisionAge),
	rule(410, "ErrH0TooOld", gate.ErrH0TooOld),
	rule(410, "ErrAnchorWindowClosed", gate.ErrAnchorWindowClosed),

	rule(400, "ErrMalformed", commitment.ErrMalformed),
	rule(400, "ErrTrailingData", commitment.ErrTrailingData),
	rule(400, "ErrFloat", commitment.ErrFloat),
	rule(400, "ErrSimpleValue", commitment.ErrSimpleValue),
	rule(400, "ErrTag", commitment.ErrTag),
	rule(400, "ErrIndefiniteLength", commitment.ErrIndefiniteLength),
	rule(400, "ErrNonMinimalInt", commitment.ErrNonMinimalInt),
	rule(400, "ErrNestingTooDeep", commitment.ErrNestingTooDeep),
	rule(400, "ErrUnsortedMap", commitment.ErrUnsortedMap),
	rule(400, "ErrDuplicateKey", commitment.ErrDuplicateKey),
	rule(400, "ErrKeyType", commitment.ErrKeyType),
	rule(400, "ErrInvalidString", commitment.ErrInvalidString),
	rule(400, "ErrUnknownKey", commitment.ErrUnknownKey),
	rule(400, "ErrWrongType", commitment.ErrWrongType),
	rule(400, "ErrMissingField", commitment.ErrMissingField),
	rule(400, "ErrFieldSize", commitment.ErrFieldSize),
	rule(400, "ErrNonCanonical", commitment.ErrNonCanonical),
	rule(400, "ErrUnsupportedVersion", commitment.ErrUnsupportedVersion),
	rule(400, "ErrIntRange", commitment.ErrIntRange),
	rule(400, "ErrInvalidEnum", commitment.ErrInvalidEnum),
	rule(400, "ErrZeroValue", commitment.ErrZeroValue),
	rule(400, "ErrPayloadTooLarge", commitment.ErrPayloadTooLarge),
	rule(400, "ErrInvalidNamespace", commitment.ErrInvalidNamespace),
	rule(400, "ErrTimeOrder", commitment.ErrTimeOrder),
	rule(400, "ErrActionSize", commitment.ErrActionSize),

	rule(401, "edictaapi.ErrTokenInvalid", ErrTokenInvalid),
	rule(401, "edictaapi.ErrPublishSignature", ErrPublishSignature),

	rule(403, "ErrInvalidPublicKey", commitment.ErrInvalidPublicKey),
	rule(403, "ErrSignatureInvalid", commitment.ErrSignatureInvalid),
	rule(403, "ErrScopeMismatch", commitment.ErrScopeMismatch),
	rule(403, "ErrActionTypeNotAllowed", commitment.ErrActionTypeNotAllowed),
	rule(403, "ErrDANotAllowed", gate.ErrDANotAllowed),
	rule(403, "ErrAgentKeyIsGateKey", gate.ErrAgentKeyIsGateKey),
	rule(403, "ErrAgentNotAllowed", gate.ErrAgentNotAllowed),
	rule(403, "ErrAgentKeyMismatch", gate.ErrAgentKeyMismatch),
	rule(403, "ErrExecutorNotAllowed", gate.ErrExecutorNotAllowed),
	rule(403, "ErrKeyRole", commitment.ErrKeyRole),
	rule(403, "policy.ErrAgentNotCovered", policy.ErrAgentNotCovered),
	rule(403, "policy.ErrFastModeNotAllowed", policy.ErrFastModeNotAllowed),
	rule(403, "policy.ErrNoExtractor", policy.ErrNoExtractor),
	rule(403, "policy.ErrOutsideMandate", policy.ErrOutsideMandate),
	rule(403, "policy.ErrKindNotAllowed", policy.ErrKindNotAllowed),
	rule(403, "policy.ErrAssetNotAllowed", policy.ErrAssetNotAllowed),
	rule(403, "policy.ErrRecipientNotAllowed", policy.ErrRecipientNotAllowed),
	rule(403, "policy.ErrAmountAboveMax", policy.ErrAmountAboveMax),
	rule(403, "policy.ErrMinSpacing", policy.ErrMinSpacing),
	rule(403, "policy.ErrPeriodLimit", policy.ErrPeriodLimit),
	rule(403, "policy.ErrCountLimit", policy.ErrCountLimit),
	rule(403, "policy.ErrHistoryFull", policy.ErrHistoryFull),
	rule(403, "ErrAnchorPending", gate.ErrAnchorPending),
	rule(403, "ErrNamespaceNotAllowed", gate.ErrNamespaceNotAllowed),
	rule(403, "ErrMandateRefMissing", gate.ErrMandateRefMissing),
	rule(403, "ErrMandateMismatch", gate.ErrMandateMismatch),

	rule(404, "edictaapi.ErrRouteNotFound", ErrRouteNotFound),
	rule(404, "edictaapi.ErrPublishDisabled", ErrPublishDisabled),
	rule(405, "edictaapi.ErrMethodNotAllowed", ErrMethodNotAllowed),

	rule(409, "ErrNonceUsed", gate.ErrNonceUsed),
	rule(409, "ErrReceiptExists", gate.ErrReceiptExists),
	rule(409, "ErrBeforeRegistryEpoch", gate.ErrBeforeRegistryEpoch),

	rule(413, "ErrTooLarge", commitment.ErrTooLarge),
	rule(413, "ErrPayloadAboveCap", gate.ErrPayloadAboveCap),
	rule(415, "edictaapi.ErrMediaType", ErrMediaType),

	rule(422, "ErrActionMismatch", commitment.ErrActionMismatch),
	rule(422, "ErrPayloadSizeMismatch", commitment.ErrPayloadSizeMismatch),
	rule(422, "ErrPayloadHashMismatch", commitment.ErrPayloadHashMismatch),
	rule(422, "ErrDACommitmentMismatch", gate.ErrDACommitmentMismatch),
	rule(422, "ErrArchiveRecomputeUnsupported", gate.ErrArchiveRecomputeUnsupported),
	rule(422, "ErrIssuedBeforeAnchor", commitment.ErrIssuedBeforeAnchor),
	rule(422, "ErrTTLTooLong", commitment.ErrTTLTooLong),
	rule(422, "ErrNotAuthorized", gate.ErrNotAuthorized),
	rule(422, "policy.ErrFactsInvalid", policy.ErrFactsInvalid),
	rule(422, "ErrAnchorIntentInvalid", gate.ErrAnchorIntentInvalid),
	rule(422, "ErrCertInvalid", gate.ErrCertInvalid),

	rule(425, "ErrNotYetValid", commitment.ErrNotYetValid),
	rule(425, "ErrAnchorNotFound", gate.ErrAnchorNotFound),

	rule(429, "edictaapi.ErrQuotaExceeded", ErrQuotaExceeded),

	rule(503, "ErrPayloadUnavailable", gate.ErrPayloadUnavailable),
	rule(503, "ErrRetentionUnavailable", gate.ErrRetentionUnavailable),
	rule(503, "ErrChainUnavailable", gate.ErrChainUnavailable),
	rule(503, "ErrAllowlistUnavailable", gate.ErrAllowlistUnavailable),
	rule(503, "ErrRegistryUnavailable", gate.ErrRegistryUnavailable),
	rule(503, "ErrClockRegression", gate.ErrClockRegression),
	rule(503, "ErrClosed", gate.ErrClosed),
	rule(503, "ErrArchiveUnavailable", gate.ErrArchiveUnavailable),
	rule(503, "ErrPolicyStateConflict", gate.ErrPolicyStateConflict),
	rule(503, "ErrAnchorIntentUnavailable", gate.ErrAnchorIntentUnavailable),
	rule(503, "ErrAnchorIntentRejected", gate.ErrAnchorIntentRejected),

	rule(504, "edictaapi.ErrDeadline", ErrDeadline),
	rule(500, codeInternal, ErrInternal),
}

// builtinSentinel returns the root sentinel of a built-in code.
func builtinSentinel(code string) (error, bool) {
	for i := range table {
		if table[i].Code == code {
			return table[i].Err, true
		}
	}
	return nil, false
}

// classify returns the first rule err matches: the built-in table in order,
// with extra just before the deadline rule. A bare context deadline counts as
// ErrDeadline only when ownDeadline says the handler's own deadline fired: a
// deadline inside an operation's error belongs to that operation's rule. The
// bool is false when nothing matches (the caller reports ErrInternal).
func classify(err error, extra []ErrorRule, ownDeadline bool) (ErrorRule, bool) {
	extras := func() (ErrorRule, bool) {
		for _, r := range extra {
			if r.Err != nil && errors.Is(err, r.Err) {
				return r, true
			}
		}
		return ErrorRule{}, false
	}
	for _, r := range table {
		if r.Err == ErrDeadline {
			if x, ok := extras(); ok {
				return x, true
			}
			if errors.Is(err, ErrDeadline) || (ownDeadline && errors.Is(err, context.DeadlineExceeded)) {
				return r, true
			}
			continue
		}
		if errors.Is(err, r.Err) {
			return r, true
		}
	}
	return ErrorRule{}, false
}

// Error is an error answered by the server (section 18.3). Is and Unwrap map
// the code back to its root sentinel, so errors.Is(err, gate.ErrNonceUsed)
// works across the API. A code this module does not define (for example
// "recorder.ErrOutcomeUnknown") is reported as ErrInternal by Is and Unwrap;
// Code, Status and Retryable still carry the server's answer.
type Error struct {
	Status    int
	Code      string
	Message   string
	Retryable bool
	// Stored is the stored result of a 409 (key 4), nil otherwise.
	Stored []byte
	// PolicyVerdict is the signed verdict of a policy deny or of a stored
	// 409 (key 5), nil otherwise.
	PolicyVerdict []byte
}

func (e *Error) sentinel() error {
	if s, ok := builtinSentinel(e.Code); ok {
		return s
	}
	return ErrInternal
}

func (e *Error) Error() string {
	return fmt.Sprintf("edictaapi: %s (status %d): %s", e.Code, e.Status, e.Message)
}

// Unwrap returns the root sentinel of the code.
func (e *Error) Unwrap() error { return e.sentinel() }

// Is reports whether target is the root sentinel of the code, or another
// *Error with the same code.
func (e *Error) Is(target error) bool {
	if t, ok := target.(*Error); ok {
		return t.Code == e.Code
	}
	return errors.Is(e.sentinel(), target)
}
