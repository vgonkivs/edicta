package gatefix

import (
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
)

// Sentinel maps a spec sentinel name to the Go error.
func Sentinel(name string) (error, bool) {
	m := map[string]error{
		"ErrTooLarge":                    commitment.ErrTooLarge,
		"ErrMalformed":                   commitment.ErrMalformed,
		"ErrTrailingData":                commitment.ErrTrailingData,
		"ErrFloat":                       commitment.ErrFloat,
		"ErrSimpleValue":                 commitment.ErrSimpleValue,
		"ErrTag":                         commitment.ErrTag,
		"ErrIndefiniteLength":            commitment.ErrIndefiniteLength,
		"ErrNonMinimalInt":               commitment.ErrNonMinimalInt,
		"ErrNestingTooDeep":              commitment.ErrNestingTooDeep,
		"ErrUnsortedMap":                 commitment.ErrUnsortedMap,
		"ErrDuplicateKey":                commitment.ErrDuplicateKey,
		"ErrKeyType":                     commitment.ErrKeyType,
		"ErrInvalidString":               commitment.ErrInvalidString,
		"ErrUnknownKey":                  commitment.ErrUnknownKey,
		"ErrWrongType":                   commitment.ErrWrongType,
		"ErrMissingField":                commitment.ErrMissingField,
		"ErrFieldSize":                   commitment.ErrFieldSize,
		"ErrNonCanonical":                commitment.ErrNonCanonical,
		"ErrUnsupportedVersion":          commitment.ErrUnsupportedVersion,
		"ErrIntRange":                    commitment.ErrIntRange,
		"ErrInvalidEnum":                 commitment.ErrInvalidEnum,
		"ErrZeroValue":                   commitment.ErrZeroValue,
		"ErrPayloadTooLarge":             commitment.ErrPayloadTooLarge,
		"ErrInvalidNamespace":            commitment.ErrInvalidNamespace,
		"ErrTimeOrder":                   commitment.ErrTimeOrder,
		"ErrTTLTooLong":                  commitment.ErrTTLTooLong,
		"ErrInvalidParams":               commitment.ErrInvalidParams,
		"ErrInvalidPublicKey":            commitment.ErrInvalidPublicKey,
		"ErrSignatureInvalid":            commitment.ErrSignatureInvalid,
		"ErrNotYetValid":                 commitment.ErrNotYetValid,
		"ErrExpired":                     commitment.ErrExpired,
		"ErrActionTypeNotAllowed":        commitment.ErrActionTypeNotAllowed,
		"ErrActionSize":                  commitment.ErrActionSize,
		"ErrScopeMismatch":               commitment.ErrScopeMismatch,
		"ErrActionMismatch":              commitment.ErrActionMismatch,
		"ErrPayloadSizeMismatch":         commitment.ErrPayloadSizeMismatch,
		"ErrPayloadHashMismatch":         commitment.ErrPayloadHashMismatch,
		"ErrIssuedBeforeAnchor":          commitment.ErrIssuedBeforeAnchor,
		"ErrAgentNotAllowed":             gate.ErrAgentNotAllowed,
		"ErrAgentKeyMismatch":            gate.ErrAgentKeyMismatch,
		"ErrAgentKeyIsGateKey":           gate.ErrAgentKeyIsGateKey,
		"ErrNonceUsed":                   gate.ErrNonceUsed,
		"ErrBeforeRegistryEpoch":         gate.ErrBeforeRegistryEpoch,
		"ErrAnchorNotFound":              gate.ErrAnchorNotFound,
		"ErrRetentionUnavailable":        gate.ErrRetentionUnavailable,
		"ErrAnchorTooOld":                gate.ErrAnchorTooOld,
		"ErrDACommitmentMismatch":        gate.ErrDACommitmentMismatch,
		"ErrArchiveRecomputeUnsupported": gate.ErrArchiveRecomputeUnsupported,
		"ErrPayloadUnavailable":          gate.ErrPayloadUnavailable,
	}
	e, ok := m[name]
	return e, ok
}
