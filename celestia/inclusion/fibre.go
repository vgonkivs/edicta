package inclusion

import (
	"context"
	"fmt"

	"github.com/vgonkivs/edicta/celestia/gatechain"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/sdk"
)

// FibreConfig configures the da = 1 verifier.
type FibreConfig struct {
	// Anchors reads the PayForFibre anchor through the consensus endpoint and
	// the bridge the operator chose for verification.
	Anchors *gatechain.FibreAnchors
}

// ValidateBasic checks the stateless fields.
func (c FibreConfig) ValidateBasic() error {
	if c.Anchors == nil {
		return fmt.Errorf("%w: no anchors", ErrConfig)
	}
	return nil
}

// Fibre is an sdk.InclusionVerifier for da = 1: the reference must be anchored
// by a PayForFibre tx at its height with a valid certificate, on this chain.
type Fibre struct{ a *gatechain.FibreAnchors }

var _ sdk.InclusionVerifier = (*Fibre)(nil)

// NewFibre validates cfg and returns the verifier.
func NewFibre(cfg FibreConfig) (*Fibre, error) {
	if err := cfg.ValidateBasic(); err != nil {
		return nil, err
	}
	return &Fibre{a: cfg.Anchors}, nil
}

// VerifyInclusion returns the time of the verified header at ref.Height.
func (f *Fibre) VerifyInclusion(ctx context.Context, ref commitment.PayloadRef) (bt uint64, err error) {
	defer guard(&bt, &err)
	if err := checkRef(ctx, ref); err != nil {
		return 0, unverified("%v", err)
	}
	fa, err := f.a.Lookup(ctx, ref)
	if err != nil {
		return 0, err
	}
	if fa.BlockTime == 0 {
		return 0, unverified("no header time at height %d", ref.Height)
	}
	return fa.BlockTime, nil
}

// Independent reports true: the anchor needs a validator certificate that the
// submitter cannot forge, read through endpoints the caller configured for
// verification.
func (*Fibre) Independent() bool { return true }
