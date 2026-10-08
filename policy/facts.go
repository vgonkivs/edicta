package policy

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/vgonkivs/edicta/commitment"
)

// Facts is what the policy sees of an action.
type Facts struct {
	Kind      string `cbor:"1,keyasint"`
	Asset     string `cbor:"2,keyasint"`
	Amount    []byte `cbor:"3,keyasint"`
	Scale     uint64 `cbor:"4,keyasint"`
	Recipient string `cbor:"5,keyasint,omitempty"`
}

func validKind(s string) bool {
	if len(s) < 1 || len(s) > 32 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func checkAmount(b []byte) error {
	if len(b) < 1 || len(b) > 32 {
		return fmt.Errorf("amount of %d bytes: %w", len(b), commitment.ErrFieldSize)
	}
	if len(b) > 1 && b[0] == 0 {
		return errors.New("amount is not minimal")
	}
	return nil
}

func amountBig(b []byte) *big.Int { return new(big.Int).SetBytes(b) }

// AmountFromUint64 returns the minimal big-endian form of v.
func AmountFromUint64(v uint64) []byte {
	if v == 0 {
		return []byte{0}
	}
	return big.NewInt(0).SetUint64(v).Bytes()
}

// CompareAmount compares two minimal amounts as integers.
func CompareAmount(a, b []byte) int {
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return bytes.Compare(a, b)
}

// Validate checks the value rules of the facts.
func (f Facts) Validate() error {
	switch {
	case !validKind(f.Kind):
		return errors.New("kind outside its grammar")
	case !isPrintable(f.Asset, 1, 128):
		return errors.New("asset outside its charset")
	case f.Scale > 255:
		return fmt.Errorf("scale %d above 255", f.Scale)
	case f.Recipient != "" && !isPrintable(f.Recipient, 1, 128):
		return errors.New("recipient outside its charset")
	}
	return checkAmount(f.Amount)
}

// EncodeFacts returns the canonical encoding of validated facts.
func EncodeFacts(f *Facts) ([]byte, error) {
	if f == nil {
		return nil, errNil
	}
	if err := f.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFactsInvalid, err)
	}
	return marshal(f)
}

// DecodeFacts strictly decodes canonical facts.
func DecodeFacts(b []byte) (Facts, error) {
	var f Facts
	if err := decodeStrict(b, maxFactsSize, &f, ErrFactsInvalid); err != nil {
		return Facts{}, err
	}
	if err := f.Validate(); err != nil {
		return Facts{}, fmt.Errorf("%w: %w", ErrFactsInvalid, err)
	}
	if err := requireCanonical(b, func() ([]byte, error) { return marshal(&f) }, ErrFactsInvalid); err != nil {
		return Facts{}, err
	}
	return f, nil
}
