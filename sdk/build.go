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
	Version        uint64
	AgentID        string
	AgentPubKey    ed25519.PublicKey
	Nonce          [16]byte
	IssuedAt       uint64
	ValidUntil     uint64
	Scope          commitment.Scope
	Action         commitment.Action
	Ref            commitment.PayloadRef
	CiphertextHash commitment.Hash
	PlaintextHash  commitment.Hash
	PayloadSize    uint64
	MandateRef     []byte
}

// buildCommitment assembles a commitment and runs the gate's decode and static
// checks on it, so a commitment the gate would refuse at those stages is never
// returned. Rejections are the commitment package's own sentinels.
func buildCommitment(in input, p commitment.Params) (*commitment.Commitment, error) {
	c := &commitment.Commitment{
		Version:        in.Version,
		AgentID:        in.AgentID,
		AgentPubKey:    bytes.Clone(in.AgentPubKey),
		Nonce:          bytes.Clone(in.Nonce[:]),
		IssuedAt:       in.IssuedAt,
		ValidUntil:     in.ValidUntil,
		Scope:          in.Scope,
		Action:         cloneAction(in.Action),
		PayloadRef:     cloneRef(in.Ref),
		CiphertextHash: bytes.Clone(in.CiphertextHash[:]),
		PlaintextHash:  bytes.Clone(in.PlaintextHash[:]),
		PayloadSize:    in.PayloadSize,
		MandateRef:     bytes.Clone(in.MandateRef),
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

func cloneAction(a commitment.Action) commitment.Action {
	a.Hash = bytes.Clone(a.Hash)
	return a
}

func cloneRef(r commitment.PayloadRef) commitment.PayloadRef {
	r.Namespace = bytes.Clone(r.Namespace)
	r.Commitment = bytes.Clone(r.Commitment)
	r.Signer = bytes.Clone(r.Signer)
	return r
}
