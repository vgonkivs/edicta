package inclusion

import (
	"context"
	"fmt"

	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/commitment"
)

// SelfCheckConfig configures SelfCheck.
type SelfCheckConfig struct {
	ChainID string
	Node    node.Reader
}

// SelfCheck trusts the operator's own node for header and proof. It is not
// independent and is allowed only when submitter and producer are one operator.
type SelfCheck struct {
	chainID string
	node    node.Reader
}

// NewSelfCheck validates cfg.
func NewSelfCheck(cfg SelfCheckConfig) (*SelfCheck, error) {
	if cfg.ChainID == "" || cfg.Node == nil {
		return nil, fmt.Errorf("%w: chain id and node are required", ErrConfig)
	}
	return &SelfCheck{chainID: cfg.ChainID, node: cfg.Node}, nil
}

// Level reports LevelSelfCheck.
func (*SelfCheck) Level() Level { return LevelSelfCheck }

// Independent is false.
func (*SelfCheck) Independent() bool { return false }

// VerifyInclusion implements sdk.InclusionVerifier.
func (s *SelfCheck) VerifyInclusion(ctx context.Context, ref commitment.PayloadRef) (bt uint64, err error) {
	defer guard(&bt, &err)
	if err := checkRef(ctx, ref); err != nil {
		return 0, err
	}
	h, err := s.node.HeaderAt(ctx, ref.Height)
	if err != nil {
		return 0, fmt.Errorf("header %d: %w", ref.Height, err)
	}
	if h.ChainID != s.chainID || h.Height != ref.Height || len(h.DataRoot) == 0 {
		return 0, fmt.Errorf("header is %s/%d", h.ChainID, h.Height)
	}
	if err := verifyProof(ctx, s.node, ref, h.DataRoot); err != nil {
		return 0, err
	}
	return uint64(h.Time.Unix()), nil
}
