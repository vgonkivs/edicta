package inclusion

import (
	"context"
	"errors"
	"fmt"

	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/sdk"
)

// ErrConfig reports an unusable verifier configuration.
var ErrConfig = errors.New("inclusion: invalid configuration")

// Level names the strength of a verifier.
type Level uint8

const (
	// LevelLight verifies validator signatures from a trust anchor.
	LevelLight Level = iota + 1
	// LevelCrossCheck compares headers of independent providers.
	LevelCrossCheck
	// LevelSelfCheck trusts the operator's own node.
	LevelSelfCheck
	// LevelFibre checks the PayForFibre tx and its validator certificate
	// against the operator's consensus endpoint, for da = 1. A self-check
	// variant: the endpoint is trusted.
	LevelFibre
)

func (l Level) String() string {
	switch l {
	case LevelLight:
		return "light (validator signatures verified)"
	case LevelCrossCheck:
		return "cross-check (weaker: no signature checked, relies on provider non-collusion)"
	case LevelSelfCheck:
		return "self-check (operator's own node)"
	case LevelFibre:
		return "fibre self-check (PayForFibre namespace data and certificate checked against the operator's consensus endpoint)"
	}
	return fmt.Sprintf("unknown level %d", uint8(l))
}

func unverified(format string, args ...any) error {
	return fmt.Errorf("%w: %w", sdk.ErrInclusionUnverified, fmt.Errorf(format, args...))
}

// guard turns a panic into an unverified error and zeroes the block time on
// every failure.
func guard(bt *uint64, err *error) {
	if r := recover(); r != nil {
		*bt, *err = 0, unverified("panic: %v", r)
		return
	}
	if *err != nil {
		*bt = 0
		if !errors.Is(*err, sdk.ErrInclusionUnverified) {
			*err = fmt.Errorf("%w: %w", sdk.ErrInclusionUnverified, *err)
		}
	}
}

func checkRef(ctx context.Context, ref commitment.PayloadRef) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if ref.Height == 0 {
		return errors.New("zero height")
	}
	if len(ref.Commitment) == 0 {
		return errors.New("empty commitment")
	}
	return nil
}

// verifyProof checks the share commitment against dataRoot, which the caller
// took from a verified or agreed header.
func verifyProof(ctx context.Context, proofs node.Reader, ref commitment.PayloadRef, dataRoot []byte) error {
	p, err := proofs.CommitmentProof(ctx, ref.Height, ref.Namespace, ref.Commitment)
	if err != nil {
		return fmt.Errorf("commitment proof: %w", err)
	}
	if p == nil {
		return errors.New("commitment proof: nil")
	}
	if err := p.Verify(dataRoot, ref.Commitment); err != nil {
		return fmt.Errorf("commitment proof: %w", err)
	}
	return nil
}
