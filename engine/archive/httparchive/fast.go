package httparchive

import (
	"context"
	"fmt"

	"github.com/vgonkivs/edicta/engine/archive"
	"github.com/vgonkivs/edicta/engine/commitment"
)

const (
	maxIntent  = 65600
	maxAbsence = 1 << 24
)

var (
	_ archive.IntentReader     = (*Client)(nil)
	_ archive.AbsenceReader    = (*Client)(nil)
	_ archive.ExecResultReader = (*Client)(nil)
)

// ExecutionResult reads exec/<chain_id>/<rail_ref hex>. A server of an older
// revision answers 404 for that path, which reads as absent.
func (c *Client) ExecutionResult(ctx context.Context, chainID string, railRef []byte) (*archive.ExecutionResultRecord, error) {
	key, err := archive.ExecResultPath(chainID, railRef)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", archive.ErrNotFound, err)
	}
	return readAs[*archive.ExecutionResultRecord](ctx, c, key)
}

func (c *Client) Intent(ctx context.Context, da commitment.DA, commit []byte, refHeight uint64) (*archive.AnchorIntentRecord, error) {
	key, err := archive.IntentPath(da, commit, refHeight)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", archive.ErrNotFound, err)
	}
	return readAs[*archive.AnchorIntentRecord](ctx, c, key)
}

func (c *Client) Absence(ctx context.Context, da commitment.DA, commit []byte, height uint64) (*archive.AbsenceProofRecord, error) {
	key, err := archive.AbsencePath(da, commit, height)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", archive.ErrNotFound, err)
	}
	return readAs[*archive.AbsenceProofRecord](ctx, c, key)
}
