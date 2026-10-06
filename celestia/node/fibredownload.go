package node

import (
	"context"
	"errors"
	"fmt"
	"sync"

	appfibre "github.com/celestiaorg/celestia-app/v10/fibre"
	"github.com/celestiaorg/celestia-app/v10/fibre/state"
)

// FibreDirect downloads blobs from the storage providers through a
// download-only Fibre client: no keyring, no escrow, no submission.
type FibreDirect struct {
	c      *appfibre.Client
	states stateTracker

	once sync.Once
	err  error
}

var _ FibreDownloader = (*FibreDirect)(nil)

// NewFibreDirect starts a download-only client whose validator set and host
// queries go through the consensus endpoint g, with its TLS and token. Close
// the result.
func NewFibreDirect(ctx context.Context, g GRPCConfig) (*FibreDirect, error) {
	d := &FibreDirect{}
	cfg := appfibre.DefaultClientConfig()
	cfg.StateClientFn = func() (state.Client, error) { return d.states.dial(g) }
	c, err := appfibre.NewClient(nil, cfg)
	if err != nil {
		_ = d.states.stop(ctx)
		return nil, fmt.Errorf("%w: fibre download client: %w", ErrUnavailable, err)
	}
	d.c = c
	if err := c.Start(ctx); err != nil {
		_ = c.Stop(ctx)
		_ = d.states.stop(ctx)
		return nil, wrapCtx(ctx, fmt.Errorf("start fibre download client: %w", err))
	}
	return d, nil
}

// Close stops the client and closes its consensus connection. It runs once;
// later calls return the first result.
func (d *FibreDirect) Close(ctx context.Context) error {
	d.once.Do(func() { d.err = errors.Join(d.c.Stop(ctx), d.states.stop(ctx)) })
	return d.err
}

// Download reconstructs the blob with the validator set at promiseHeight.
func (d *FibreDirect) Download(ctx context.Context, id [33]byte, promiseHeight, maxSize uint64) ([]byte, error) {
	b, err := d.c.Download(ctx, appfibre.BlobID(id[:]), appfibre.WithHeight(promiseHeight))
	if err != nil {
		if errors.Is(err, appfibre.ErrNotFound) {
			return nil, fmt.Errorf("%w: %w", ErrNotFound, err)
		}
		return nil, wrapCtxNotFound(ctx, err)
	}
	defer b.Free()
	if uint64(len(b.Data())) > maxSize {
		return nil, fmt.Errorf("%w: blob of %d bytes, limit %d", ErrTooLarge, len(b.Data()), maxSize)
	}
	// The blob's buffers are pooled, so the bytes are copied out first.
	return append([]byte(nil), b.Data()...), nil
}

// wrapCtxNotFound classifies a download error as unavailable unless the
// library said the blob is missing: an error text must not turn into absence.
func wrapCtxNotFound(ctx context.Context, err error) error {
	if cerr := ctx.Err(); cerr != nil {
		return fmt.Errorf("%w: %w", ErrUnavailable, errors.Join(cerr, err))
	}
	return fmt.Errorf("%w: %w", ErrUnavailable, err)
}
