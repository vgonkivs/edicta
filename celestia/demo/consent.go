package demo

import (
	"context"
	"sync/atomic"

	"github.com/vgonkivs/edicta/celestia/railtx"
	"github.com/vgonkivs/edicta/celestia/recorder"
	"github.com/vgonkivs/edicta/examples/tia-transfer/transfer"
)

type guardedSubmitter struct {
	inner   recorder.Submitter
	consent *railtx.Consent
}

// GuardSubmitter refuses every submission until the Consent is armed. The
// Recorder's PayForBlob is the only broadcast that path can make.
func GuardSubmitter(s recorder.Submitter, c *railtx.Consent) recorder.Submitter {
	return guardedSubmitter{inner: s, consent: c}
}

func (g guardedSubmitter) Signer(ctx context.Context) ([]byte, error) { return g.inner.Signer(ctx) }

func (g guardedSubmitter) Submit(ctx context.Context, namespace, data []byte) (recorder.SubmitResult, error) {
	if err := g.consent.Check(); err != nil {
		return recorder.SubmitResult{}, err
	}
	return g.inner.Submit(ctx, namespace, data)
}

// GuardedRail wraps a transfer.Rail so that Broadcast is the only method that
// can move funds and it is gated.
type GuardedRail struct {
	transfer.Rail
	consent *railtx.Consent
	locked  atomic.Bool
	once    bool
	used    atomic.Bool
}

// GuardRail is the executor's rail: it broadcasts after the Consent is armed
// and until Lock.
func GuardRail(r transfer.Rail, c *railtx.Consent) *GuardedRail {
	return &GuardedRail{Rail: r, consent: c}
}

// GuardRailOnce allows one Broadcast after the Consent is armed.
func GuardRailOnce(r transfer.Rail, c *railtx.Consent) *GuardedRail {
	return &GuardedRail{Rail: r, consent: c, once: true}
}

// Lock makes every later Broadcast fail. It cannot be undone.
func (g *GuardedRail) Lock() { g.locked.Store(true) }

// Broadcast checks the Consent, then the lock, then the single-use budget.
func (g *GuardedRail) Broadcast(ctx context.Context, txRaw []byte) error {
	if err := g.consent.Check(); err != nil {
		return err
	}
	if g.locked.Load() {
		return ErrRailLocked
	}
	if g.once && !g.used.CompareAndSwap(false, true) {
		return ErrRailLocked
	}
	return g.Rail.Broadcast(ctx, txRaw)
}
