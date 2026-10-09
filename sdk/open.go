package sdk

import (
	"crypto/sha256"
	"crypto/subtle"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/sdk/blob"
	"github.com/vgonkivs/edicta/sdk/payload"
)

// Opened is a decision opened by a recipient and bound to its commitment.
// Commitment.AgentPubKey is whatever key signed the envelope; the caller must
// check it against its own list of agents.
type Opened struct {
	CommitmentHash commitment.Hash
	Commitment     commitment.Commitment
	Payload        *payload.Payload
}

// OpenPayload opens the blob for k and returns the decision the signed
// envelope commits to. It checks the envelope, the blob against the
// commitment, and the plaintext hash BEFORE parsing any decrypted byte. It
// checks no time, scope or anchor.
//
// The agent key is not authenticated here: the envelope is verified against
// the key it names, and anyone can build a blob for any recipient. The caller
// MUST compare Commitment.AgentID and AgentPubKey with the agents it trusts.
func OpenPayload(envelope, blobBytes []byte, k blob.RecipientKey) (*Opened, error) {
	s, err := commitment.DecodeSigned(envelope)
	if err != nil {
		return nil, err
	}
	if err := commitment.ValidateStatic(&s.Commitment, OpenerParams()); err != nil {
		return nil, err
	}
	h, err := commitment.Verify(s)
	if err != nil {
		return nil, err
	}
	if err := commitment.CheckPayload(&s.Commitment, blobBytes); err != nil {
		return nil, err
	}
	salt, pt, err := blob.Open(blobBytes, k)
	if err != nil {
		return nil, err
	}
	defer clear(pt)
	sum := sha256.New()
	sum.Write(salt[:])
	sum.Write(pt)
	if subtle.ConstantTimeCompare(sum.Sum(nil), s.Commitment.PlaintextHash) != 1 {
		return nil, ErrPlaintextHashMismatch
	}
	p, err := payload.Decode(pt)
	if err != nil {
		return nil, err
	}
	if p.Action.Type != s.Commitment.Action.Type || commitment.CheckAction(&s.Commitment, p.Action.Data, p.Action.Salt) != nil {
		return nil, ErrPayloadMismatch
	}
	return &Opened{CommitmentHash: h, Commitment: s.Commitment, Payload: p}, nil
}
