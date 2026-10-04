// Package payload defines the plaintext a decision is committed to: model,
// policy, free-form context and the exact action and constraints.
package payload

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"github.com/vgonkivs/edicta/commitment"
)

const (
	Version = 0

	// MediaTypeDCAv0 is the context type of the dollar-cost-averaging agent.
	MediaTypeDCAv0 = "application/vnd.edicta.dca.v0+cbor"

	maxMediaType = 64
	maxID        = 128
	maxVersion   = 64
	digestSize   = 32
)

var (
	ErrMalformed = errors.New("payload: malformed")
	ErrVersion   = errors.New("payload: unsupported version")
	ErrTooLarge  = errors.New("payload: too large")
)

// Data is opaque bytes with a required media type.
type Data struct {
	MediaType string `cbor:"1,keyasint"`
	Bytes     []byte `cbor:"2,keyasint"`
}

type Model struct {
	ID      string  `cbor:"1,keyasint"`
	Version *string `cbor:"2,keyasint,omitempty"`
	Digest  []byte  `cbor:"3,keyasint,omitempty"`
}

type Policy struct {
	ID      string  `cbor:"1,keyasint"`
	Version *string `cbor:"2,keyasint,omitempty"`
	Digest  []byte  `cbor:"3,keyasint,omitempty"`
	Text    []byte  `cbor:"4,keyasint,omitempty"`
}

type Payload struct {
	Version     uint64                 `cbor:"1,keyasint"`
	Model       Model                  `cbor:"2,keyasint"`
	Policy      Policy                 `cbor:"3,keyasint"`
	Context     Data                   `cbor:"4,keyasint"`
	Action      commitment.Action      `cbor:"5,keyasint"`
	Constraints commitment.Constraints `cbor:"6,keyasint"`
	Metadata    *Data                  `cbor:"7,keyasint,omitempty"`
}

var encMode, encModeErr = func() (cbor.EncMode, error) {
	o := cbor.CoreDetEncOptions()
	o.IndefLength = cbor.IndefLengthForbidden
	o.NilContainers = cbor.NilContainerAsEmpty
	return o.EncMode()
}()

var decMode, decModeErr = cbor.DecOptions{
	DupMapKey:         cbor.DupMapKeyEnforcedAPF,
	IndefLength:       cbor.IndefLengthForbidden,
	TagsMd:            cbor.TagsForbidden,
	UTF8:              cbor.UTF8RejectInvalid,
	ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
	MaxNestedLevels:   4,
	MaxArrayElements:  16,
	MaxMapPairs:       16,
}.DecMode()

// Encode returns the canonical CBOR of p after checking every rule Decode
// applies, so Decode(Encode(p)) always succeeds.
func Encode(p *Payload) ([]byte, error) {
	if p == nil {
		return nil, fmt.Errorf("%w: nil payload", ErrMalformed)
	}
	if err := validate(p); err != nil {
		return nil, err
	}
	if p.Version != Version {
		return nil, fmt.Errorf("%w: %d", ErrVersion, p.Version)
	}
	if encModeErr != nil {
		return nil, fmt.Errorf("payload: encoder: %w", encModeErr)
	}
	b, err := encMode.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("%w: encode: %v", ErrMalformed, err)
	}
	return b, nil
}

// Decode accepts exactly the canonical encodings of a valid Payload.
func Decode(b []byte) (*Payload, error) {
	if len(b) > commitment.MaxPayloadSize {
		return nil, fmt.Errorf("%w: %d bytes", ErrTooLarge, len(b))
	}
	if decModeErr != nil || encModeErr != nil {
		return nil, fmt.Errorf("payload: codec: %w", errors.Join(decModeErr, encModeErr))
	}
	var p Payload
	if err := decMode.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if err := validate(&p); err != nil {
		return nil, err
	}
	again, err := encMode.Marshal(&p)
	if err != nil || !bytes.Equal(again, b) {
		return nil, fmt.Errorf("%w: not the canonical encoding", ErrMalformed)
	}
	if p.Version != Version {
		return nil, fmt.Errorf("%w: %d", ErrVersion, p.Version)
	}
	return &p, nil
}

func validate(p *Payload) error {
	if err := checkLabel("model.id", p.Model.ID, maxID); err != nil {
		return err
	}
	if err := checkOptLabel("model.version", p.Model.Version); err != nil {
		return err
	}
	if err := checkDigest("model.digest", p.Model.Digest); err != nil {
		return err
	}
	if err := checkLabel("policy.id", p.Policy.ID, maxID); err != nil {
		return err
	}
	if err := checkOptLabel("policy.version", p.Policy.Version); err != nil {
		return err
	}
	if err := checkDigest("policy.digest", p.Policy.Digest); err != nil {
		return err
	}
	if p.Policy.Text != nil && len(p.Policy.Text) == 0 {
		return fmt.Errorf("%w: policy.text is empty", ErrMalformed)
	}
	if !validMediaType(p.Context.MediaType) {
		return fmt.Errorf("%w: context media type", ErrMalformed)
	}
	if p.Metadata != nil {
		if !validMediaType(p.Metadata.MediaType) {
			return fmt.Errorf("%w: metadata media type", ErrMalformed)
		}
		if len(p.Metadata.Bytes) == 0 {
			return fmt.Errorf("%w: metadata is empty", ErrMalformed)
		}
	}
	return checkActionConstraints(p.Action, p.Constraints)
}

func checkLabel(name, s string, max int) error {
	if len(s) < 1 || len(s) > max {
		return fmt.Errorf("%w: %s length %d", ErrMalformed, name, len(s))
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return fmt.Errorf("%w: %s is not printable ASCII", ErrMalformed, name)
		}
	}
	return nil
}

func checkOptLabel(name string, s *string) error {
	if s == nil {
		return nil
	}
	return checkLabel(name, *s, maxVersion)
}

func checkDigest(name string, d []byte) error {
	if d != nil && len(d) != digestSize {
		return fmt.Errorf("%w: %s length %d", ErrMalformed, name, len(d))
	}
	return nil
}

// validMediaType accepts lower-case "name/name" with RFC 6838 restricted-name
// characters, 1..64 bytes, no parameters.
func validMediaType(s string) bool {
	if len(s) < 3 || len(s) > maxMediaType {
		return false
	}
	slash := -1
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '/':
			if slash >= 0 {
				return false
			}
			slash = i
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case i == 0 || i == slash+1:
			return false
		default:
			switch c {
			case '!', '#', '$', '&', '^', '_', '.', '+', '-':
			default:
				return false
			}
		}
	}
	return slash > 0 && slash < len(s)-1
}

// checkActionConstraints applies the commitment's own decoder to the action
// and constraints by wrapping them in a throwaway commitment.
func checkActionConstraints(a commitment.Action, c commitment.Constraints) error {
	probe := &commitment.Commitment{
		AgentID:     "a",
		AgentPubKey: make([]byte, 32),
		Nonce:       make([]byte, 16),
		Scope:       commitment.Scope{GateID: "g", Rail: commitment.RailIBKR, Account: "a"},
		Action:      a,
		Constraints: c,
		PayloadRef: commitment.PayloadRef{
			DA:         commitment.DACelestiaBlob,
			Namespace:  make([]byte, 29),
			Commitment: make([]byte, 32),
			Signer:     make([]byte, 20),
		},
		CiphertextHash: make([]byte, 32),
		PlaintextHash:  make([]byte, 32),
	}
	raw, err := commitment.Encode(probe)
	if err == nil {
		_, err = commitment.Decode(raw)
	}
	if err != nil {
		return fmt.Errorf("%w: action or constraints: %v", ErrMalformed, err)
	}
	return nil
}
