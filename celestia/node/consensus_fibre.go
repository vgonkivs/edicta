package node

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	apptx "github.com/celestiaorg/celestia-app/v10/app/grpc/tx"
	fibretypes "github.com/celestiaorg/celestia-app/v10/x/fibre/types"
	coregrpc "github.com/cometbft/cometbft/rpc/grpc"

	"github.com/vgonkivs/edicta/celestia/heightcheck"
)

// TxPlacement is where the node says a committed tx is.
type TxPlacement struct {
	Height uint64
	Index  uint32
	// Code is the execution code; the caller decides what it means.
	Code   uint32
	Status string
}

// txCommitted is the status celestia-app reports for a tx in a block.
const txCommitted = "COMMITTED"

// TxPlace reads the placement of the tx with the given hash. A tx that is
// not committed is ErrNotFound.
func (c *ConsensusClient) TxPlace(ctx context.Context, hash [32]byte) (TxPlacement, error) {
	r, err := apptx.NewTxClient(c.conn).TxStatus(ctx, &apptx.TxStatusRequest{TxId: strings.ToUpper(hex.EncodeToString(hash[:]))})
	if err != nil {
		return TxPlacement{}, classifyGRPC(ctx, err)
	}
	if r.Status != txCommitted {
		return TxPlacement{}, fmt.Errorf("%w: tx status %q", ErrNotFound, r.Status)
	}
	if r.Height <= 0 {
		return TxPlacement{}, fmt.Errorf("%w: committed tx at height %d", ErrUnavailable, r.Height)
	}
	return TxPlacement{Height: uint64(r.Height), Index: r.Index, Code: r.ExecutionCode, Status: r.Status}, nil
}

// ValidatorSet returns the protobuf tendermint.types.ValidatorSet at height.
// The node must echo the height; an endpoint that does not is marked.
func (c *ConsensusClient) ValidatorSet(ctx context.Context, height uint64) ([]byte, error) {
	h, err := int64Height(height)
	if err != nil {
		return nil, err
	}
	r, err := c.blocks.ValidatorSet(ctx, &coregrpc.ValidatorSetRequest{Height: h})
	if err != nil {
		return nil, classifyGRPC(ctx, err)
	}
	if r.ValidatorSet == nil {
		return nil, fmt.Errorf("%w: no validator set at height %d", ErrUnavailable, height)
	}
	if r.Height < 0 {
		return nil, fmt.Errorf("%w: validator set at height %d", ErrUnavailable, r.Height)
	}
	if err := heightcheck.HeaderHeight(uint64(r.Height), height); err != nil {
		c.flag.Mark()
		return nil, heightIgnored(err)
	}
	b, err := r.ValidatorSet.Marshal()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	return b, nil
}

// EscrowAccount is a read-only x/fibre query; a missing account holds nothing.
func (c *ConsensusClient) EscrowAccount(ctx context.Context, bech string) (Escrow, error) {
	r, err := c.fibre.EscrowAccount(ctx, &fibretypes.QueryEscrowAccountRequest{Signer: bech})
	if err != nil {
		return Escrow{}, classifyGRPC(ctx, err)
	}
	if !r.Found || r.EscrowAccount == nil {
		return Escrow{}, nil
	}
	a := r.EscrowAccount
	return escrowOf(a.Balance.Denom, a.Balance.Amount, a.AvailableBalance.Denom, a.AvailableBalance.Amount)
}
