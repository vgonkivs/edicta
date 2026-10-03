package commitment

import (
	"bytes"
	"fmt"
)

// Decode parses and strictly validates bare commitment bytes.
func Decode(b []byte) (*Commitment, error) {
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
	c, err := buildCommitment(root)
	if err != nil {
		return nil, err
	}
	if err := requireCanonical(c, b); err != nil {
		return nil, err
	}
	return c, nil
}

// DecodeSigned parses and strictly validates an envelope.
func DecodeSigned(b []byte) (*SignedCommitment, error) {
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
			if c, err = buildCommitment(cn); err != nil {
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
	enc, err := EncodeSigned(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNonCanonical, err)
	}
	if !bytes.Equal(enc, b) {
		return nil, fmt.Errorf("%w: envelope", ErrNonCanonical)
	}
	return s, nil
}

// requireCanonical is rule D21, a guard against encoder or decoder bugs.
func requireCanonical(c *Commitment, raw []byte) error {
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
// copies the values into the typed struct.
func buildCommitment(root *node) (*Commitment, error) {
	if err := checkMap(root, commitmentSchema, "commitment"); err != nil {
		return nil, err
	}
	m := byKey(root)
	scope := byKey(m[7])
	action := byKey(m[8])
	order := byKey(action[2])
	cons := byKey(m[9])
	ref := byKey(m[10])

	o := &IBKROrderV0{
		Account:    string(order[1].b),
		ConID:      order[2].u,
		Symbol:     optText(order[3]),
		Side:       Side(order[4].u),
		Qty:        order[5].u,
		OrderType:  OrderType(order[6].u),
		LimitPrice: optUint(order[7]),
		Currency:   string(order[8].b),
		TIF:        TIF(order[9].u),
	}
	return &Commitment{
		Version:     m[1].u,
		AgentID:     string(m[2].b),
		AgentPubKey: bytes.Clone(m[3].b),
		Nonce:       bytes.Clone(m[4].b),
		IssuedAt:    m[5].u,
		ValidUntil:  m[6].u,
		Scope: Scope{
			GateID:  string(scope[1].b),
			Rail:    Rail(scope[2].u),
			Account: string(scope[3].b),
			ChainID: optText(scope[4]),
		},
		Action: Action{Kind: string(action[1].b), IBKROrder: o},
		Constraints: Constraints{
			MaxNotional: cons[1].u,
			PriceBound:  optUint(cons[2]),
			Deadline:    optUint(cons[3]),
		},
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
	}, nil
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

func optText(n *node) *string {
	if n == nil {
		return nil
	}
	s := string(n.b)
	return &s
}

func optUint(n *node) *uint64 {
	if n == nil {
		return nil
	}
	v := n.u
	return &v
}
