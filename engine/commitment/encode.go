package commitment

import (
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

var encMode, encModeErr = func() (cbor.EncMode, error) {
	o := cbor.CoreDetEncOptions()
	o.IndefLength = cbor.IndefLengthForbidden
	o.NilContainers = cbor.NilContainerAsEmpty
	return o.EncMode()
}()

var errNilCommitment = errors.New("commitment: nil commitment")

// Encode returns the canonical CBOR of c. A nil and an empty byte slice
// encode identically; the decoder rejects empty values, so the wire
// form stays unique. It does not validate values;
// that is the job of the decoder and ValidateStatic.
func Encode(c *Commitment) ([]byte, error) {
	if c == nil {
		return nil, errNilCommitment
	}
	if encModeErr != nil {
		return nil, encModeErr
	}
	b, err := encMode.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("commitment: encode: %w", err)
	}
	return b, nil
}

func EncodeSigned(s *SignedCommitment) ([]byte, error) {
	if s == nil {
		return nil, errNilCommitment
	}
	if encModeErr != nil {
		return nil, encModeErr
	}
	b, err := encMode.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("commitment: encode envelope: %w", err)
	}
	return b, nil
}
