package node

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cosmos/cosmos-sdk/crypto/keyring"

	appfibre "github.com/celestiaorg/celestia-app/v10/fibre"
	"github.com/celestiaorg/celestia-app/v10/fibre/state"
	fibretypes "github.com/celestiaorg/celestia-app/v10/x/fibre/types"
	libshare "github.com/celestiaorg/go-square/v4/share"
)

// FibreUpload is what an upload without payment returns. Every field comes
// from the client library: the caller re-checks the promise it uses.
type FibreUpload struct {
	// Msg is a MsgPayForFibre in protobuf carrying the client-signed promise
	// and the validator signatures in the order of the validator set at
	// PromiseHeight. Its signer is unset: SignPFF sets it.
	Msg           []byte
	PromiseHeight uint64
	Created       time.Time
}

// FibreUploader uploads da = 1 blobs and collects the availability
// certificate without broadcasting or paying anything. The promise signer is
// the key the uploader was built with; the escrow of that key pays once a
// PayForFibre tx carrying the promise lands, or the promise times out.
type FibreUploader interface {
	// Upload returns once the signatures reach the safety threshold. ctx
	// also carries the shard uploads that continue after it returns, so the
	// caller decides when to end it.
	Upload(ctx context.Context, namespace, data []byte) (FibreUpload, error)
	// Endpoint is the consensus gRPC address (host:port) the uploader reads
	// its validator sets from.
	Endpoint() string
	// Close waits for background uploads until ctx ends, then stops.
	Close(ctx context.Context) error
}

// uploadClient is the part of the library client the uploader uses.
type uploadClient interface {
	Upload(ctx context.Context, ns libshare.Namespace, blob *appfibre.Blob, opts ...appfibre.UploadOption) (appfibre.SignedPaymentPromise, error)
	Stop(ctx context.Context) error
}

type fibreUploader struct {
	c        uploadClient
	keyName  string
	endpoint string
	stop     func(context.Context) error
	once     sync.Once
	err      error
}

// NewFibreUploader builds a library Fibre client on the consensus endpoint g
// that signs promises with keyName of kr. It never deposits to the escrow.
func NewFibreUploader(ctx context.Context, g GRPCConfig, kr keyring.Keyring, keyName string) (FibreUploader, error) {
	if err := g.ValidateBasic(); err != nil {
		return nil, err
	}
	if kr == nil || keyName == "" {
		return nil, errors.New("node: the fibre uploader needs a keyring and a key name")
	}
	cfg := appfibre.DefaultClientConfig()
	cfg.DefaultKeyName = keyName
	cfg.Escrow.AutoFund = false
	states := &stateTracker{}
	cfg.StateClientFn = func() (state.Client, error) { return states.dial(g) }
	c, err := appfibre.NewClient(kr, cfg)
	if err != nil {
		_ = states.stop(ctx)
		return nil, fmt.Errorf("node: fibre client: %w", err)
	}
	if err := c.Start(ctx); err != nil {
		_ = states.stop(ctx)
		return nil, wrapCtxNotFound(ctx, fmt.Errorf("node: fibre client: %w", err))
	}
	stop := func(ctx context.Context) error {
		return errors.Join(c.Stop(ctx), states.stop(context.WithoutCancel(ctx)))
	}
	return &fibreUploader{c: c, keyName: keyName, endpoint: g.Addr, stop: stop}, nil
}

func (u *fibreUploader) Endpoint() string { return u.endpoint }

func (u *fibreUploader) Close(ctx context.Context) error {
	u.once.Do(func() { u.err = u.stop(ctx) })
	return u.err
}

func (u *fibreUploader) Upload(ctx context.Context, namespace, data []byte) (FibreUpload, error) {
	ns, err := libshare.NewNamespaceFromBytes(namespace)
	if err != nil {
		return FibreUpload{}, fmt.Errorf("node: namespace: %w", err)
	}
	b, err := appfibre.NewBlob(data, appfibre.DefaultBlobConfigV0())
	if err != nil {
		return FibreUpload{}, fmt.Errorf("node: fibre blob: %w", err)
	}
	// Upload holds its own reference for the shards still in flight.
	defer b.Free()
	sp, err := u.c.Upload(ctx, ns, b, appfibre.WithKeyName(u.keyName))
	if err != nil {
		return FibreUpload{}, wrapCtxNotFound(ctx, err)
	}
	if sp.PaymentPromise == nil {
		return FibreUpload{}, fmt.Errorf("%w: upload returned no promise", ErrUnsupported)
	}
	pp, err := sp.ToProto()
	if err != nil {
		return FibreUpload{}, fmt.Errorf("%w: promise: %w", ErrUnsupported, err)
	}
	msg := fibretypes.MsgPayForFibre{PaymentPromise: *pp, ValidatorSignatures: sp.ValidatorSignatures}
	raw, err := msg.Marshal()
	if err != nil {
		return FibreUpload{}, fmt.Errorf("%w: pay for fibre: %w", ErrUnsupported, err)
	}
	return FibreUpload{Msg: raw, PromiseHeight: sp.Height, Created: sp.CreationTimestamp}, nil
}
