package sdk

import (
	"bytes"
	"crypto/ed25519"
	"fmt"

	"github.com/vgonkivs/edicta/commitment"
)

// input holds every field of a commitment the builder chooses. It is not
// exported because it carries a nonce and a plaintext hash that only the
// builder may draw.
type input struct {
	AgentID        string
	AgentPubKey    ed25519.PublicKey
	Nonce          [16]byte
	IssuedAt       uint64
	ValidUntil     uint64
	Scope          commitment.Scope
	Action         commitment.Action
	Constraints    commitment.Constraints
	Ref            commitment.PayloadRef
	CiphertextHash commitment.Hash
	PlaintextHash  commitment.Hash
	PayloadSize    uint64
}

// buildCommitment assembles a commitment and runs the gate's decode and static
// checks on it, so a commitment the gate would refuse at those stages is never
// returned. Rejections are the commitment package's own sentinels.
func buildCommitment(in input, p commitment.Params) (*commitment.Commitment, error) {
	c := &commitment.Commitment{
		Version:        0,
		AgentID:        in.AgentID,
		AgentPubKey:    bytes.Clone(in.AgentPubKey),
		Nonce:          bytes.Clone(in.Nonce[:]),
		IssuedAt:       in.IssuedAt,
		ValidUntil:     in.ValidUntil,
		Scope:          cloneScope(in.Scope),
		Action:         cloneAction(in.Action),
		Constraints:    cloneConstraints(in.Constraints),
		PayloadRef:     cloneRef(in.Ref),
		CiphertextHash: bytes.Clone(in.CiphertextHash[:]),
		PlaintextHash:  bytes.Clone(in.PlaintextHash[:]),
		PayloadSize:    in.PayloadSize,
	}
	raw, err := commitment.Encode(c)
	if err != nil {
		return nil, fmt.Errorf("sdk: build commitment: %w", err)
	}
	built, err := commitment.Decode(raw)
	if err != nil {
		return nil, err
	}
	if err := commitment.ValidateStatic(built, p); err != nil {
		return nil, err
	}
	return built, nil
}

func clonePtr[T any](p *T) *T {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func cloneScope(s commitment.Scope) commitment.Scope {
	s.ChainID = clonePtr(s.ChainID)
	return s
}

func cloneAction(a commitment.Action) commitment.Action {
	if a.IBKROrder != nil {
		o := *a.IBKROrder
		o.Symbol = clonePtr(o.Symbol)
		o.LimitPrice = clonePtr(o.LimitPrice)
		a.IBKROrder = &o
	}
	return a
}

func cloneConstraints(c commitment.Constraints) commitment.Constraints {
	c.PriceBound = clonePtr(c.PriceBound)
	c.Deadline = clonePtr(c.Deadline)
	return c
}

func cloneRef(r commitment.PayloadRef) commitment.PayloadRef {
	r.Namespace = bytes.Clone(r.Namespace)
	r.Commitment = bytes.Clone(r.Commitment)
	r.Signer = bytes.Clone(r.Signer)
	return r
}
