package gatechain

import (
	"context"
	"errors"
	"fmt"

	"github.com/vgonkivs/edicta/celestia/heightcheck"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/retention"
)

type fibreHeaders struct{ r node.FibreChainReader }

// NewFibreHeaders serves the time of the block that holds a da = 1 anchor from
// the header of the consensus endpoint, the same one the anchor lookup checks
// the bridge's answers against. It never reads the bridge, whose header time
// would be the bridge's word.
func NewFibreHeaders(r node.FibreChainReader) gate.HeaderSource { return fibreHeaders{r: r} }

func (h fibreHeaders) BlockTime(ctx context.Context, height uint64) (uint64, error) {
	if h.r == nil {
		return 0, unavailable(fmt.Errorf("%w: no consensus reader", ErrInvalidConfig))
	}
	if err := ctx.Err(); err != nil {
		return 0, unavailable(err)
	}
	hd, err := h.r.Header(ctx, height)
	if err != nil {
		return 0, unavailable(fmt.Errorf("header at %d: %w", height, err))
	}
	if err := heightcheck.HeaderHeight(hd.Height, height); err != nil {
		return 0, unavailable(err)
	}
	if hd.AppVersion != node.FibreAppVersion {
		return 0, unavailable(fmt.Errorf("header at %d has app version %d, want %d", height, hd.AppVersion, node.FibreAppVersion))
	}
	t := blockUnix(hd.Time)
	if t == 0 {
		return 0, unavailable(fmt.Errorf("header at %d has no time", height))
	}
	return t, nil
}

type fibreParams struct{ p *retention.Params }

var _ gate.SourcedChainParams = fibreParams{}

// NewFibreParams adapts the retention observer to the gate and reports where
// each at-height value came from. A nil observer fails every read.
func NewFibreParams(p *retention.Params) gate.SourcedChainParams { return fibreParams{p: p} }

var errNoObserver = errors.New("gatechain: no retention observer")

func (f fibreParams) FibreRetention(ctx context.Context, height uint64) (uint64, error) {
	v, _, err := f.FibreRetentionSourced(ctx, height)
	return v, err
}

func (f fibreParams) FibreRetentionSourced(ctx context.Context, height uint64) (uint64, gate.RetentionSource, error) {
	if f.p == nil {
		return 0, 0, errNoObserver
	}
	v, src, err := f.p.FibreRetentionSourced(ctx, height)
	if err != nil {
		return 0, 0, err
	}
	switch src {
	case retention.SourceDirect:
		return v, gate.RetentionDirect, nil
	case retention.SourceObserved:
		return v, gate.RetentionObserved, nil
	case retention.SourceBoth:
		return v, gate.RetentionBoth, nil
	}
	return 0, 0, fmt.Errorf("gatechain: retention source %d", src)
}
