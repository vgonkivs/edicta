package httparchive

import (
	"context"
	"fmt"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
)

const (
	maxIntent  = 65600
	maxAbsence = 1 << 24
)

var (
	_ archive.IntentReader  = (*Client)(nil)
	_ archive.AbsenceReader = (*Client)(nil)
)

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
