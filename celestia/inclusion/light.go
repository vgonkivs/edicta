package inclusion

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	dbm "github.com/cometbft/cometbft-db"
	"github.com/cometbft/cometbft/light"
	"github.com/cometbft/cometbft/light/provider"
	lightdb "github.com/cometbft/cometbft/light/store/db"

	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/commitment"
)

// LightConfig configures Light.
type LightConfig struct {
	ChainID string
	// Trust is the trust anchor; Period must be below the unbonding time.
	Trust     light.TrustOptions
	Primary   provider.Provider
	Witnesses []provider.Provider // at least one
	// Proofs serves commitment proofs; it need not be independent.
	Proofs node.Reader
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// Sequential disables skipping verification.
	Sequential bool
}

// Light verifies the header of the blob's block with the CometBFT light
// client (strictly more than 2/3 of voting power) and the share commitment
// against that header's data root.
type Light struct {
	mu     sync.Mutex
	cl     *light.Client
	proofs node.Reader
	now    func() time.Time
	period time.Duration
}

// NewLight builds the light client and fetches and checks the trust anchor.
func NewLight(ctx context.Context, cfg LightConfig) (*Light, error) {
	switch {
	case cfg.ChainID == "":
		return nil, fmt.Errorf("%w: no chain id", ErrConfig)
	case cfg.Primary == nil:
		return nil, fmt.Errorf("%w: no primary", ErrConfig)
	case len(cfg.Witnesses) == 0:
		return nil, fmt.Errorf("%w: no witness", ErrConfig)
	case cfg.Proofs == nil:
		return nil, fmt.Errorf("%w: no proof source", ErrConfig)
	}
	for _, w := range cfg.Witnesses {
		if w == nil {
			return nil, fmt.Errorf("%w: nil witness", ErrConfig)
		}
	}
	if err := cfg.Trust.ValidateBasic(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfig, err)
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	opts := []light.Option{light.MaxRetryAttempts(1)}
	if cfg.Sequential {
		opts = append(opts, light.SequentialVerification())
	}
	cl, err := light.NewClient(ctx, cfg.ChainID, cfg.Trust, cfg.Primary, cfg.Witnesses,
		lightdb.New(dbm.NewMemDB(), ""), opts...)
	if err != nil {
		return nil, fmt.Errorf("inclusion: light client: %w", err)
	}
	return &Light{cl: cl, proofs: cfg.Proofs, now: now, period: cfg.Trust.Period}, nil
}

// Level reports LevelLight.
func (*Light) Level() Level { return LevelLight }

// Independent is true: headers come from the agent's providers.
func (*Light) Independent() bool { return true }

// VerifyInclusion implements sdk.InclusionVerifier.
func (l *Light) VerifyInclusion(ctx context.Context, ref commitment.PayloadRef) (bt uint64, err error) {
	defer guard(&bt, &err)
	if err := checkRef(ctx, ref); err != nil {
		return 0, err
	}
	if ref.Height > uint64(1<<62) {
		return 0, fmt.Errorf("height %d out of range", ref.Height)
	}
	now := l.now()
	l.mu.Lock()
	lb, err := l.cl.VerifyLightBlockAtHeight(ctx, int64(ref.Height), now)
	l.mu.Unlock()
	if err != nil {
		return 0, fmt.Errorf("header %d: %w", ref.Height, err)
	}
	if lb == nil || lb.SignedHeader == nil || lb.Header == nil {
		return 0, fmt.Errorf("header %d: empty light block", ref.Height)
	}
	if light.HeaderExpired(lb.SignedHeader, l.period, now) {
		return 0, fmt.Errorf("header %d: outside the trusting period", ref.Height)
	}
	if lb.Height != int64(ref.Height) || lb.ChainID != l.cl.ChainID() {
		return 0, fmt.Errorf("header %d: verified block is %s/%d", ref.Height, lb.ChainID, lb.Height)
	}
	if len(lb.DataHash) == 0 || !bytes.Equal(lb.DataHash, lb.Header.DataHash) {
		return 0, fmt.Errorf("header %d: no data root", ref.Height)
	}
	if err := verifyProof(ctx, l.proofs, ref, lb.DataHash); err != nil {
		return 0, err
	}
	return uint64(lb.Time.Unix()), nil
}
