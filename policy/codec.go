package policy

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"github.com/vgonkivs/edicta/commitment"
)

// Tags of the policy v1 family.
const (
	TagMandate    = "edicta/policy/v1/mandate"
	TagMandateSig = "edicta/policy/v1/mandate-sig"
	TagVerdict    = "edicta/policy/v1/verdict"
	TagVerdictSig = "edicta/policy/v1/verdict-sig"
	TagBucket     = "edicta/policy/v1/bucket"
	TagClosed     = "edicta/policy/v1/closed"
	TagState      = "edicta/policy/v1/state"
	TagCounter    = "edicta/policy/v1/counter"
	TagSuccessor  = "edicta/policy/v1/successor"
)

const (
	maxInt         = uint64(1)<<63 - 1
	maxFactsSize   = 512
	maxSignedSize  = 16384
	maxStateSize   = 16384
	maxClosedSize  = 36864
	maxCounterSize = 16 << 20
)

var (
	encMode  cbor.EncMode
	decMode  cbor.DecMode
	codecErr error
)

func init() {
	var err error
	encMode, err = cbor.EncOptions{
		Sort:          cbor.SortCoreDeterministic,
		ShortestFloat: cbor.ShortestFloat16,
		NilContainers: cbor.NilContainerAsEmpty,
		IndefLength:   cbor.IndefLengthForbidden,
	}.EncMode()
	if err != nil {
		codecErr = fmt.Errorf("policy: encoder: %w", err)
		return
	}
	decMode, err = cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
		MaxNestedLevels:   6,
		MaxArrayElements:  1024,
		MaxMapPairs:       1024,
		UTF8:              cbor.UTF8RejectInvalid,
	}.DecMode()
	if err != nil {
		codecErr = fmt.Errorf("policy: decoder: %w", err)
	}
}

func marshal(v any) ([]byte, error) {
	if codecErr != nil {
		return nil, codecErr
	}
	return encMode.Marshal(v)
}

// decodeStrict unmarshals b into v and requires that v re-encodes to b, which
// rejects non-shortest heads, unsorted keys, nulls and empty optionals.
func decodeStrict(b []byte, limit int, v any, sentinel error) error {
	if codecErr != nil {
		return codecErr
	}
	if len(b) > limit {
		return fmt.Errorf("%w: %d bytes above the cap %d", sentinel, len(b), limit)
	}
	if err := decMode.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%w: %v", sentinel, err)
	}
	return nil
}

func requireCanonical(in []byte, enc func() ([]byte, error), sentinel error) error {
	out, err := enc()
	if err != nil {
		return fmt.Errorf("%w: %v", sentinel, err)
	}
	if !bytes.Equal(in, out) {
		return fmt.Errorf("%w: %w", sentinel, commitment.ErrNonCanonical)
	}
	return nil
}

func tagged(tag string, parts ...[]byte) []byte {
	out := append([]byte{byte(len(tag))}, tag...)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func hashTagged(tag string, canon []byte) commitment.Hash {
	return sha256.Sum256(tagged(tag, canon))
}

func signingMessage(tag string, h commitment.Hash) []byte { return tagged(tag, h[:]) }

func isPrintable(s string, lo, hi int) bool {
	if len(s) < lo || len(s) > hi {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func checkHash(b []byte, what string) error {
	if len(b) != 32 {
		return fmt.Errorf("%s has %d bytes: %w", what, len(b), commitment.ErrFieldSize)
	}
	return nil
}

func checkUint(v uint64, what string) error {
	if v > maxInt {
		return fmt.Errorf("%s: %w", what, commitment.ErrIntRange)
	}
	return nil
}

var errNil = errors.New("policy: nil argument")
