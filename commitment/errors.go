package commitment

import "errors"

// Decoding.
var (
	ErrTooLarge         = errors.New("commitment: too large")
	ErrMalformed        = errors.New("commitment: malformed CBOR")
	ErrTrailingData     = errors.New("commitment: trailing data")
	ErrFloat            = errors.New("commitment: float not allowed")
	ErrSimpleValue      = errors.New("commitment: simple value not allowed")
	ErrTag              = errors.New("commitment: CBOR tag not allowed")
	ErrIndefiniteLength = errors.New("commitment: indefinite length not allowed")
	ErrNonMinimalInt    = errors.New("commitment: non-minimal integer head")
	ErrNestingTooDeep   = errors.New("commitment: nesting too deep")
	ErrUnsortedMap      = errors.New("commitment: map keys not ascending")
	ErrDuplicateKey     = errors.New("commitment: duplicate map key")
	ErrKeyType          = errors.New("commitment: map key is not a uint")
	ErrInvalidString    = errors.New("commitment: invalid string")
	ErrUnknownKey       = errors.New("commitment: unknown key")
	ErrWrongType        = errors.New("commitment: wrong CBOR type")
	ErrMissingField     = errors.New("commitment: missing required field")
	ErrFieldSize        = errors.New("commitment: field size out of range")
	ErrNonCanonical     = errors.New("commitment: re-encoding differs from input")
)

// Static validation.
var (
	ErrUnsupportedVersion = errors.New("commitment: unsupported version")
	ErrIntRange           = errors.New("commitment: integer above 2^63-1")
	ErrInvalidEnum        = errors.New("commitment: invalid enum value")
	ErrZeroValue          = errors.New("commitment: zero value not allowed")
	ErrPayloadTooLarge    = errors.New("commitment: payload_size above limit")
	ErrInvalidNamespace   = errors.New("commitment: invalid blob namespace")
	ErrTimeOrder          = errors.New("commitment: valid_until not after issued_at")
	ErrTTLTooLong         = errors.New("commitment: ttl above maximum")
	ErrInvalidParams      = errors.New("commitment: invalid params")
)

// Stages G, T, C, A, P.
var (
	ErrInvalidPublicKey     = errors.New("commitment: invalid agent public key")
	ErrSignatureInvalid     = errors.New("commitment: signature invalid")
	ErrNotYetValid          = errors.New("commitment: not yet valid")
	ErrExpired              = errors.New("commitment: expired")
	ErrScopeMismatch        = errors.New("commitment: scope mismatch")
	ErrActionTypeNotAllowed = errors.New("commitment: action type not allowed at this gate")
	ErrActionSize           = errors.New("commitment: action bytes size out of range")
	ErrActionMismatch       = errors.New("commitment: action mismatch")
	ErrPayloadSizeMismatch  = errors.New("commitment: payload size mismatch")
	ErrPayloadHashMismatch  = errors.New("commitment: payload hash mismatch")
)

// Anchor time.
var ErrIssuedBeforeAnchor = errors.New("commitment: issued_at before the anchor block")
