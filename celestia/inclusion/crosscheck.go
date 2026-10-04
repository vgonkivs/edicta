package inclusion

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/commitment"
)

// Source is one header provider.
type Source struct {
	Name    string
	Headers node.Reader
	// SubmitterControlled marks the submitter's own node: it must agree but
	// does not count toward the independent minimum.
	SubmitterControlled bool
}

// CrossCheckConfig configures CrossCheck.
type CrossCheckConfig struct {
	ChainID string
	// Sources needs at least 2 distinct independent entries.
	Sources []Source
	Proofs  node.Reader
}

// CrossCheck accepts a header all sources agree on. It is weaker than Light:
// no signature is checked.
type CrossCheck struct {
	chainID string
	srcs    []Source
	proofs  node.Reader
}

// NewCrossCheck validates cfg.
func NewCrossCheck(cfg CrossCheckConfig) (*CrossCheck, error) {
	if cfg.ChainID == "" {
		return nil, fmt.Errorf("%w: no chain id", ErrConfig)
	}
	if cfg.Proofs == nil {
		return nil, fmt.Errorf("%w: no proof source", ErrConfig)
	}
	seen := map[node.Reader]bool{}
	independent := 0
	for _, s := range cfg.Sources {
		if s.Headers == nil {
			return nil, fmt.Errorf("%w: source %q has no reader", ErrConfig, s.Name)
		}
		if seen[s.Headers] {
			continue
		}
		seen[s.Headers] = true
		if !s.SubmitterControlled {
			independent++
		}
	}
	if independent < 2 {
		return nil, fmt.Errorf("%w: need at least 2 distinct independent sources, have %d", ErrConfig, independent)
	}
	return &CrossCheck{chainID: cfg.ChainID, srcs: append([]Source(nil), cfg.Sources...), proofs: cfg.Proofs}, nil
}

// Level reports LevelCrossCheck.
func (*CrossCheck) Level() Level { return LevelCrossCheck }

// Independent is true: at least two sources are not the submitter's.
func (*CrossCheck) Independent() bool { return true }

// VerifyInclusion implements sdk.InclusionVerifier.
func (c *CrossCheck) VerifyInclusion(ctx context.Context, ref commitment.PayloadRef) (bt uint64, err error) {
	defer guard(&bt, &err)
	if err := checkRef(ctx, ref); err != nil {
		return 0, err
	}
	var agreed node.Header
	for i, s := range c.srcs {
		h, err := s.Headers.HeaderAt(ctx, ref.Height)
		if err != nil {
			return 0, fmt.Errorf("source %q: %w", s.Name, err)
		}
		if h.ChainID != c.chainID || h.Height != ref.Height || len(h.DataRoot) == 0 {
			return 0, fmt.Errorf("source %q: header is %s/%d", s.Name, h.ChainID, h.Height)
		}
		if i == 0 {
			agreed = h
			continue
		}
		if !bytes.Equal(h.DataRoot, agreed.DataRoot) || !h.Time.Equal(agreed.Time) {
			return 0, fmt.Errorf("source %q disagrees with %q on header %d", s.Name, c.srcs[0].Name, ref.Height)
		}
	}
	if err := verifyProof(ctx, c.proofs, ref, agreed.DataRoot); err != nil {
		return 0, err
	}
	return uint64(agreed.Time.Truncate(time.Second).Unix()), nil
}
