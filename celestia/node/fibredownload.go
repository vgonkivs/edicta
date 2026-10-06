package node

import (
	"context"
	"errors"
	"fmt"

	appfibre "github.com/celestiaorg/celestia-app/v10/fibre"
	"github.com/celestiaorg/celestia-app/v10/fibre/state"
)

// FibreDirect downloads blobs from the storage providers through a
// download-only Fibre client: no keyring, no escrow, no submission.
type FibreDirect struct {
	c      *appfibre.Client
	states []state.Client
}

var _ FibreDownloader = (*FibreDirect)(nil)

// NewFibreDirect starts a download-only client whose validator set and host
// queries go through the consensus endpoint g, with its TLS and token. Close
// the result.
func NewFibreDirect(ctx context.Context, g GRPCConfig) (*FibreDirect, error) {
	d := &FibreDirect{}
	cfg := appfibre.DefaultClientConfig()
	// The library's Stop does not close the state client it was given.
	cfg.StateClientFn = func() (state.Client, error) {
		sc, err := dialStateClient(g.Addr, g.TLS, g.Token)
		if err == nil {
			d.states = append(d.states, sc)
		}
		return sc, err
	}
	c, err := appfibre.NewClient(nil, cfg)
	if err != nil {
		_ = d.stopStates(ctx)
		return nil, fmt.Errorf("%w: fibre download client: %w", ErrUnavailable, err)
	}
	d.c = c
	if err := c.Start(ctx); err != nil {
		_ = c.Stop(ctx)
		_ = d.stopStates(ctx)
		return nil, wrapCtx(ctx, fmt.Errorf("start fibre download client: %w", err))
	}
	return d, nil
}

func (d *FibreDirect) stopStates(ctx context.Context) error {
	var errs []error
	for _, sc := range d.states {
		errs = append(errs, sc.Stop(ctx))
	}
	d.states = nil
	return errors.Join(errs...)
}

// Close stops the client and closes its consensus connection.
func (d *FibreDirect) Close(ctx context.Context) error {
	return errors.Join(d.c.Stop(ctx), d.stopStates(ctx))
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
