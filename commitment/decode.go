package commitment

import (
	"bytes"
	"fmt"
)

// Decode parses and strictly validates bare commitment bytes of either
// version: key 1 selects the schema.
func Decode(b []byte) (*Commitment, error) {
	return decode(b, true)
}

func decode(b []byte, v1 bool) (*Commitment, error) {
	if len(b) > MaxCommitmentSize {
		return nil, fmt.Errorf("%w: commitment of %d bytes", ErrTooLarge, len(b))
	}
	root, err := scanTop(b, 2)
	if err != nil {
		return nil, err
	}
	if root.major != majMap {
		return nil, fmt.Errorf("%w: commitment is not a map", ErrWrongType)
	}
	c, err := buildCommitment(root, v1)
	if err != nil {
		return nil, err
	}
	if err := requireCanonical(c, b); err != nil {
		return nil, err
	}
	return c, nil
}

// DecodeSigned parses and strictly validates an envelope of either version:
// the commitment's key 1 selects the schema after the well-formedness pass.
func DecodeSigned(b []byte) (*SignedCommitment, error) {
	return decodeSigned(b, true)
}

func decodeSigned(b []byte, v1 bool) (*SignedCommitment, error) {
	if len(b) > MaxSignedSize {
		return nil, fmt.Errorf("%w: envelope of %d bytes", ErrTooLarge, len(b))
	}
	root, err := scanTop(b, 1)
	if err != nil {
		return nil, err
	}
	if root.major != majMap {
		return nil, fmt.Errorf("%w: envelope is not a map", ErrWrongType)
	}

	var cn, sn *node
	var c *Commitment
	for _, e := range root.entries {
		switch e.key {
		case 1:
			if e.val.major != majMap {
				return nil, fmt.Errorf("%w: envelope.commitment", ErrWrongType)
			}
			if size := e.val.end - e.val.start; size > MaxCommitmentSize {
				return nil, fmt.Errorf("%w: commitment of %d bytes", ErrTooLarge, size)
			}
			cn = e.val
			var err error
			if c, err = buildCommitment(cn, v1); err != nil {
				return nil, err
			}
		case 2:
			if e.val.major != majBstr {
				return nil, fmt.Errorf("%w: envelope.signature", ErrWrongType)
			}
			if len(e.val.b) != 64 {
				return nil, fmt.Errorf("%w: signature length %d", ErrFieldSize, len(e.val.b))
			}
			sn = e.val
		default:
			return nil, fmt.Errorf("%w: envelope key %d", ErrUnknownKey, e.key)
		}
	}
	if cn == nil || sn == nil {
		return nil, fmt.Errorf("%w: envelope needs keys 1 and 2", ErrMissingField)
	}

	s := &SignedCommitment{Commitment: *c, Signature: bytes.Clone(sn.b)}

	if err := requireCanonical(c, b[cn.start:cn.end]); err != nil {
		return nil, err
	}
	if c.PayloadRef.anchorZero {
		return s, nil
	}
	enc, err := EncodeSigned(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNonCanonical, err)
	}
	if !bytes.Equal(enc, b) {
		return nil, fmt.Errorf("%w: envelope", ErrNonCanonical)
	}
	return s, nil
}

// requireCanonical rejects input that does not re-encode to the same bytes, guarding against encoder or decoder bugs.
//
// A present anchor of 0 cannot re-encode, so the comparison is left out for
// it; static validation refuses such a commitment whatever else it holds.
func requireCanonical(c *Commitment, raw []byte) error {
	if c.PayloadRef.anchorZero {
		return nil
	}
	enc, err := Encode(c)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNonCanonical, err)
	}
	if !bytes.Equal(enc, raw) {
		return fmt.Errorf("%w: commitment", ErrNonCanonical)
	}
	return nil
}

// buildCommitment runs the pass-2 schema check on a commitment map and
// copies the values into the typed struct. With v1 false it is the frozen v0
// reader, which applies the v0 schema whatever the version says.
func buildCommitment(root *node, v1 bool) (*Commitment, error) {
	schema := commitmentSchema
	if v1 && schemaVersion(root) == VersionV1 {
		schema = commitmentSchemaV1
	}
	if err := checkMap(root, schema, "commitment"); err != nil {
		return nil, err
	}
	m := byKey(root)
	scope := byKey(m[7])
	action := byKey(m[8])
	ref := byKey(m[10])

	c := &Commitment{
		Version:     m[1].u,
		AgentID:     string(m[2].b),
		AgentPubKey: bytes.Clone(m[3].b),
		Nonce:       bytes.Clone(m[4].b),
		IssuedAt:    m[5].u,
		ValidUntil:  m[6].u,
		Scope:       Scope{GateID: string(scope[1].b)},
		Action:      Action{Type: string(action[3].b), Hash: bytes.Clone(action[4].b)},
		PayloadRef: PayloadRef{
			DA:         DA(ref[1].u),
			Namespace:  bytes.Clone(ref[2].b),
			Commitment: bytes.Clone(ref[3].b),
			Height:     ref[4].u,
			Signer:     optBytes(ref[5]),
		},
		CiphertextHash: bytes.Clone(m[11].b),
		PlaintextHash:  bytes.Clone(m[12].b),
		PayloadSize:    m[13].u,
		MandateRef:     optBytes(m[14]),
	}
	if a := ref[6]; a != nil {
		c.PayloadRef.Anchor = a.u
		c.PayloadRef.anchorZero = a.u == 0
	}
	return c, nil
}

func byKey(n *node) map[uint64]*node {
	m := make(map[uint64]*node, len(n.entries))
	for _, e := range n.entries {
		m[e.key] = e.val
	}
	return m
}

func optBytes(n *node) []byte {
	if n == nil {
		return nil
	}
	return bytes.Clone(n.b)
}

// EnvelopeCommitment returns the raw bytes of the commitment inside an
// envelope that is well-formed CBOR with a map under key 1, without checking
// the commitment or the signature. It lets a reader tell a commitment that
// breaks a rule from a copy whose bytes were damaged: only the first one
// hashes to the reference.
func EnvelopeCommitment(b []byte) ([]byte, error) {
	if len(b) > MaxSignedSize {
		return nil, fmt.Errorf("%w: envelope of %d bytes", ErrTooLarge, len(b))
	}
	root, err := scanTop(b, 1)
	if err != nil {
		return nil, err
	}
	if root.major != majMap {
		return nil, fmt.Errorf("%w: envelope is not a map", ErrWrongType)
	}
	for _, e := range root.entries {
		if e.key != 1 {
			continue
		}
		if e.val.major != majMap {
			return nil, fmt.Errorf("%w: envelope.commitment", ErrWrongType)
		}
		if size := e.val.end - e.val.start; size > MaxCommitmentSize {
			return nil, fmt.Errorf("%w: commitment of %d bytes", ErrTooLarge, size)
		}
		return bytes.Clone(b[e.val.start:e.val.end]), nil
	}
	return nil, fmt.Errorf("%w: envelope needs key 1", ErrMissingField)
}
