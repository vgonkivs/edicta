package node

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"cosmossdk.io/math"
	"github.com/celestiaorg/celestia-node/api/client"
	celfibre "github.com/celestiaorg/celestia-node/fibre"
	nodefibre "github.com/celestiaorg/celestia-node/nodebuilder/fibre"
	"github.com/celestiaorg/celestia-node/state/txclient"
	libshare "github.com/celestiaorg/go-square/v4/share"
	"github.com/cosmos/cosmos-sdk/types/bech32"
)

const (
	signerBech32Prefix = "celestia"
	escrowDenom        = "utia"
	blobIDLen          = 33
)

// Escrow is the signer's Fibre escrow account.
type Escrow struct {
	// AvailableUtia excludes pending withdrawals.
	AvailableUtia         uint64
	PendingWithdrawalUtia uint64
}

// FibreResult is what the node claims about one submit. Every field is
// unverified: the caller re-reads the chain.
type FibreResult struct {
	BlobID        [blobIDLen]byte
	Height        uint64
	TxHash        [32]byte
	PromiseHeight uint64
	Namespace     []byte
	Commitment    [32]byte
	BlobSize      uint32
}

// FibreSubmitter publishes da = 1 blobs through the operator's own consensus
// node. It can upload and read the escrow; it cannot move funds. It is
// trusted for liveness only.
type FibreSubmitter interface {
	// Address is the 20-byte account that signs the promise and the pay-for-fibre tx.
	Address(ctx context.Context) ([]byte, error)
	Escrow(ctx context.Context) (Escrow, error)
	// SubmitFibre uploads, pays and waits for inclusion. ctx also carries the
	// shard uploads that continue after it returns; the caller decides when
	// to end it.
	SubmitFibre(ctx context.Context, namespace, data []byte) (FibreResult, error)
	// Endpoint is the consensus gRPC address (host:port) it submits through.
	Endpoint() string
}

// fibreModule is the part of the Fibre module the adapter uses. Upload sends
// the pay-for-fibre tx from a goroutine nobody can cancel, and Deposit and
// Withdraw move funds; none of them is reachable from here.
type fibreModule interface {
	Submit(ctx context.Context, ns libshare.Namespace, data []byte, cfg *txclient.TxConfig) (*nodefibre.SubmitResult, error)
	QueryEscrowAccount(ctx context.Context, signer string) (*celfibre.EscrowAccount, error)
}

type fibreSubmitter struct {
	m        fibreModule
	address  func(context.Context) ([]byte, error)
	endpoint string
}

// newClientFibreSubmitter wraps a client built by dialSigning together with
// the endpoint it was dialled with. Submit passes no TxConfig, so the promise
// signer, the pay-for-fibre signer and Address are the client's default key.
func newClientFibreSubmitter(c *client.Client, endpoint string) (FibreSubmitter, error) {
	if c == nil || c.State == nil || c.Fibre == nil {
		return nil, errors.New("node: client has no fibre submit side")
	}
	if endpoint == "" {
		return nil, errors.New("node: no consensus address")
	}
	address := func(ctx context.Context) ([]byte, error) {
		a, err := c.State.AccountAddress(ctx)
		if err != nil {
			return nil, err
		}
		return a.Bytes(), nil
	}
	return newFibreSubmitter(c.Fibre, address, endpoint), nil
}

func newFibreSubmitter(m fibreModule, address func(context.Context) ([]byte, error), endpoint string) FibreSubmitter {
	return fibreSubmitter{m: m, address: address, endpoint: endpoint}
}

func (s fibreSubmitter) Endpoint() string { return s.endpoint }

func (s fibreSubmitter) Address(ctx context.Context) ([]byte, error) {
	a, err := s.address(ctx)
	if err != nil {
		return nil, wrapCtxNotFound(ctx, err)
	}
	if len(a) != 20 {
		return nil, fmt.Errorf("%w: signer address is %d bytes", ErrUnsupported, len(a))
	}
	return append([]byte(nil), a...), nil
}

func (s fibreSubmitter) Escrow(ctx context.Context) (Escrow, error) {
	addr, err := s.Address(ctx)
	if err != nil {
		return Escrow{}, err
	}
	signer, err := bech32.ConvertAndEncode(signerBech32Prefix, addr)
	if err != nil {
		return Escrow{}, fmt.Errorf("%w: %w", ErrUnsupported, err)
	}
	acc, err := s.m.QueryEscrowAccount(ctx, signer)
	if err != nil {
		if ctx.Err() == nil && strings.Contains(err.Error(), "escrow account not found") {
			return Escrow{}, nil
		}
		return Escrow{}, wrapCtxNotFound(ctx, err)
	}
	if acc == nil {
		return Escrow{}, fmt.Errorf("%w: no escrow account in the answer", ErrUnsupported)
	}
	return escrowOf(acc.Balance.Denom, acc.Balance.Amount, acc.AvailableBalance.Denom, acc.AvailableBalance.Amount)
}

func escrowOf(balDenom string, bal math.Int, availDenom string, avail math.Int) (Escrow, error) {
	if balDenom != escrowDenom || availDenom != escrowDenom {
		return Escrow{}, fmt.Errorf("%w: escrow in %q and %q, want %s", ErrUnsupported, balDenom, availDenom, escrowDenom)
	}
	if bal.IsNil() || avail.IsNil() || !bal.IsUint64() || !avail.IsUint64() {
		return Escrow{}, fmt.Errorf("%w: escrow amount out of range", ErrUnsupported)
	}
	b, a := bal.Uint64(), avail.Uint64()
	if a > b {
		return Escrow{}, fmt.Errorf("%w: available escrow above the balance", ErrUnsupported)
	}
	return Escrow{AvailableUtia: a, PendingWithdrawalUtia: b - a}, nil
}

func (s fibreSubmitter) SubmitFibre(ctx context.Context, namespace, data []byte) (FibreResult, error) {
	ns, err := libshare.NewNamespaceFromBytes(namespace)
	if err != nil {
		return FibreResult{}, fmt.Errorf("node: namespace: %w", err)
	}
	r, err := s.m.Submit(ctx, ns, data, nil)
	if err != nil {
		return FibreResult{}, wrapCtxNotFound(ctx, err)
	}
	if r == nil || r.PaymentPromise == nil || len(r.BlobID) != blobIDLen {
		return FibreResult{}, fmt.Errorf("%w: incomplete submit result", ErrUnsupported)
	}
	raw, err := hex.DecodeString(r.TxHash)
	if err != nil || len(raw) != 32 {
		return FibreResult{}, fmt.Errorf("%w: tx hash %q", ErrUnsupported, r.TxHash)
	}
	p := r.PaymentPromise
	out := FibreResult{
		Height:        r.Height,
		PromiseHeight: p.ValsetHeight,
		Namespace:     p.Namespace.Bytes(),
		Commitment:    p.Commitment,
		BlobSize:      p.BlobSize,
	}
	copy(out.BlobID[:], r.BlobID)
	copy(out.TxHash[:], raw)
	return out, nil
}
