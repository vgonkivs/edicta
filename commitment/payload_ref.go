package commitment

import (
	"bytes"
	"fmt"
)

// EncodePayloadRef returns the canonical CBOR of ref, the bytes a commitment
// carries under its payload_ref key. It refuses a reference that Decode would
// refuse.
func EncodePayloadRef(ref PayloadRef) ([]byte, error) {
	if encModeErr != nil {
		return nil, encModeErr
	}
	if err := checkPayloadRef(ref); err != nil {
		return nil, err
	}
	b, err := encMode.Marshal(ref)
	if err != nil {
		return nil, fmt.Errorf("commitment: encode payload_ref: %w", err)
	}
	return b, nil
}

func checkPayloadRef(ref PayloadRef) error {
	if ref.DA != DAFibre && ref.DA != DACelestiaBlob {
		return fmt.Errorf("%w: da %d", ErrInvalidEnum, ref.DA)
	}
	if len(ref.Namespace) != 29 {
		return fmt.Errorf("%w: payload_ref.namespace length %d", ErrFieldSize, len(ref.Namespace))
	}
	if len(ref.Commitment) != 32 {
		return fmt.Errorf("%w: payload_ref.commitment length %d", ErrFieldSize, len(ref.Commitment))
	}
	if ref.Height == 0 {
		return fmt.Errorf("%w: height", ErrZeroValue)
	}
	if ref.Height > maxUint63 {
		return fmt.Errorf("%w: height", ErrIntRange)
	}
	switch {
	// The standalone reference is the frozen v0 form of the publish answer;
	// a pending reference has no encoding here.
	case ref.Anchor != 0 || ref.anchorZero:
		return fmt.Errorf("%w: payload_ref.anchor", ErrUnknownKey)
	case ref.DA == DAFibre && ref.Signer != nil:
		return fmt.Errorf("%w: payload_ref.signer on da 1", ErrUnknownKey)
	case ref.DA == DACelestiaBlob && len(ref.Signer) != 20:
		return fmt.Errorf("%w: payload_ref.signer length %d", ErrFieldSize, len(ref.Signer))
	}
	return nil
}

// DecodePayloadRef parses and strictly validates the bytes EncodePayloadRef
// produces. It returns the zero value with an error, and the result does not
// alias b.
func DecodePayloadRef(b []byte) (PayloadRef, error) {
	if len(b) > MaxCommitmentSize {
		return PayloadRef{}, fmt.Errorf("%w: payload_ref of %d bytes", ErrTooLarge, len(b))
	}
	root, err := scanTop(b, 3)
	if err != nil {
		return PayloadRef{}, err
	}
	if root.major != majMap {
		return PayloadRef{}, fmt.Errorf("%w: payload_ref is not a map", ErrWrongType)
	}
	if err := checkMap(root, payloadRefSchema, "payload_ref"); err != nil {
		return PayloadRef{}, err
	}
	m := byKey(root)
	ref := PayloadRef{
		DA: DA(m[1].u), Namespace: bytes.Clone(m[2].b), Commitment: bytes.Clone(m[3].b),
		Height: m[4].u, Signer: optBytes(m[5]),
	}
	enc, err := EncodePayloadRef(ref)
	if err != nil {
		return PayloadRef{}, err
	}
	if !bytes.Equal(enc, b) {
		return PayloadRef{}, fmt.Errorf("%w: payload_ref", ErrNonCanonical)
	}
	return ref, nil
}
