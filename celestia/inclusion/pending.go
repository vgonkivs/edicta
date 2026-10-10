package inclusion

import (
	"bytes"
	"context"
	"fmt"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/sdk"
)

// PendingConfig configures the check of a pending reference's anchor intent.
type PendingConfig struct {
	// Intents reads the anchor intent the Recorder archived.
	Intents archive.IntentReader
	// Verifier runs the gate's intent check for the reference's da against
	// the endpoint the producer trusts: gatechain.FibreIntents for da = 1,
	// gatechain.BlobIntents for da = 2.
	Verifier gate.IntentVerifier
	// Independent states that the verifier's endpoint is not under the
	// Recorder's control. The code cannot tell; the operator attests it.
	Independent bool
}

// ValidateBasic checks the stateless fields.
func (c PendingConfig) ValidateBasic() error {
	if c.Intents == nil || c.Verifier == nil {
		return fmt.Errorf("%w: a pending verifier needs an intent reader and an intent verifier", ErrConfig)
	}
	return nil
}

// Pending is an sdk.PendingVerifier: before the agent signs a pending
// reference it reads the anchor intent at (da, commitment, h0), requires it
// to name the reference, and runs the gate's own intent check on it.
type Pending struct {
	src         gate.IntentSource
	v           gate.IntentVerifier
	independent bool
}

var _ sdk.PendingVerifier = (*Pending)(nil)

// NewPending validates cfg and returns the verifier.
func NewPending(cfg PendingConfig) (*Pending, error) {
	if err := cfg.ValidateBasic(); err != nil {
		return nil, err
	}
	return &Pending{src: archive.NewIntentSource(cfg.Intents), v: cfg.Verifier, independent: cfg.Independent}, nil
}

// VerifyPending returns T_ref, the time of the header at h0 the verifier
// read.
func (p *Pending) VerifyPending(ctx context.Context, ref commitment.PayloadRef, payloadSize uint64) (bt uint64, err error) {
	defer guard(&bt, &err)
	if err := checkRef(ctx, ref); err != nil {
		return 0, unverified("%v", err)
	}
	if !ref.Pending() {
		return 0, unverified("not a pending reference")
	}
	rec, err := p.src.Intent(ctx, ref.DA, ref.Commitment, ref.Height)
	if err != nil {
		return 0, unverified("anchor intent: %v", err)
	}
	if rec.DA != ref.DA || rec.RefHeight != ref.Height || !bytes.Equal(rec.Commitment, ref.Commitment) ||
		!bytes.Equal(rec.Namespace, ref.Namespace) || !bytes.Equal(rec.Signer, ref.Signer) {
		return 0, unverified("the anchor intent names another reference")
	}
	facts, err := p.v.VerifyIntent(ctx, ref, rec, payloadSize)
	if err != nil {
		return 0, err
	}
	if facts.RefTime == 0 {
		return 0, unverified("no header time at h0 %d", ref.Height)
	}
	return facts.RefTime, nil
}

// Independent reports the operator's attestation.
func (p *Pending) Independent() bool { return p.independent }
