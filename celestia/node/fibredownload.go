package node

import (
	"context"
	"errors"
	"fmt"

	appfibre "github.com/celestiaorg/celestia-app/v10/fibre"
	"github.com/celestiaorg/celestia-app/v10/fibre/state"
	"github.com/celestiaorg/celestia-node/api/client"
)

// FibreDirect downloads blobs from the storage providers through a
// download-only Fibre client: no keyring, no escrow, no submission.
type FibreDirect struct {
	c *appfibre.Client
}

var _ FibreDownloader = (*FibreDirect)(nil)

// NewFibreDirect starts a download-only client whose validator set and host
// queries go through the consensus endpoint g, with its TLS and token. Close
// the result.
func NewFibreDirect(ctx context.Context, g GRPCConfig) (*FibreDirect, error) {
	cfg := appfibre.DefaultClientConfig()
	cfg.StateClientFn = func() (state.Client, error) { return dialStateClient(g.Addr, g.TLS, g.Token) }
	c, err := appfibre.NewClient(nil, cfg)
	if err != nil {
		return nil, fmt.Errorf("%w: fibre download client: %w", ErrUnavailable, err)
	}
	if err := c.Start(ctx); err != nil {
		_ = c.Stop(ctx)
		return nil, wrapCtx(ctx, fmt.Errorf("start fibre download client: %w", err))
	}
	return &FibreDirect{c: c}, nil
}

// Close stops the client and its consensus connection.
func (d *FibreDirect) Close(ctx context.Context) error { return d.c.Stop(ctx) }

// Download reconstructs the blob with the validator set at promiseHeight.
func (d *FibreDirect) Download(ctx context.Context, id [33]byte, promiseHeight uint64) ([]byte, error) {
	b, err := d.c.Download(ctx, appfibre.BlobID(id[:]), appfibre.WithHeight(promiseHeight))
	if err != nil {
		if errors.Is(err, appfibre.ErrNotFound) {
			return nil, fmt.Errorf("%w: %w", ErrNotFound, err)
		}
		return nil, wrapCtxNotFound(ctx, err)
	}
	// The blob's buffers are pooled, so the bytes are copied out first.
	data := append([]byte(nil), b.Data()...)
	b.Free()
	return data, nil
}

// wrapCtxNotFound classifies a download error as unavailable unless the
// library said the blob is missing: an error text must not turn into absence.
func wrapCtxNotFound(ctx context.Context, err error) error {
	if cerr := ctx.Err(); cerr != nil {
		return fmt.Errorf("%w: %w", ErrUnavailable, errors.Join(cerr, err))
	}
	return fmt.Errorf("%w: %w", ErrUnavailable, err)
}

type bridgeDownloader struct {
	rc *client.ReadClient
}

// NewFibreBridgeDownloader downloads through the Fibre module of a bridge
// node. The caller keeps ownership of rc and closes it.
func NewFibreBridgeDownloader(rc *client.ReadClient) (FibreDownloader, error) {
	if rc == nil {
		return nil, errors.New("node: nil read client")
	}
	return bridgeDownloader{rc: rc}, nil
}

// Download asks the bridge, which has no height option and uses the head
// validator set.
func (d bridgeDownloader) Download(ctx context.Context, id [33]byte, _ uint64) ([]byte, error) {
	r, err := d.rc.Fibre.Download(ctx, appfibre.BlobID(id[:]))
	if err != nil {
		return nil, wrapCtx(ctx, err)
	}
	if r == nil {
		return nil, fmt.Errorf("%w: empty bridge download", ErrUnavailable)
	}
	return r.Data, nil
}
