package railverify

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/celestiaorg/celestia-app/v10/pkg/appconsts"
	"github.com/celestiaorg/celestia-app/v10/pkg/da"
	fibretypes "github.com/celestiaorg/celestia-app/v10/x/fibre/types"
	blobtx "github.com/celestiaorg/go-square/v4/tx"

	"github.com/vgonkivs/edicta/verifier"
)

// RebuildDataRoot computes the data root of a block from its transactions
// the way celestia-app does when it validates a proposal: classify, build the
// square, extend it and hash the row and column roots. The square size limit
// only has to be no smaller than the proposer's, so the protocol's upper
// bound is used.
func RebuildDataRoot(txs [][]byte) (root []byte, err error) {
	// The transactions are a node's answer, and the square builder is not
	// written for hostile input.
	defer func() {
		if r := recover(); r != nil {
			root, err = nil, fmt.Errorf("railverify: block does not build a square: %v", r)
		}
	}()
	if len(txs) == 0 {
		return nil, errors.New("railverify: block has no transactions")
	}
	eds, err := da.ConstructEDS(txs, appconsts.Version, -1)
	if err != nil {
		return nil, fmt.Errorf("railverify: block does not build a square: %w", err)
	}
	dah, err := da.NewDataAvailabilityHeader(eds)
	if err != nil {
		return nil, fmt.Errorf("railverify: data availability header: %w", err)
	}
	return dah.Hash(), nil
}

// bindIndex finds the position of the transaction among the block's
// transactions when no inclusion proof bound it. Any source may serve the
// block: the transactions are rebuilt into the square and used only if its
// data root is the trusted header's, so the order they come in is the
// block's own. The block must come from the app version whose square rules
// are rebuilt, have as many transactions as results, and hold the
// transaction once and as a normal one. The error return is for a finding that ends the whole check.
func (c *bankSend) bindIndex(ctx context.Context, a *answer, results int, srcs []BlockSource) (ProofInfo, bool, error) {
	if a.hdr.Version.App != appconsts.Version || !normalTx(a.tx.Bytes) {
		return ProofInfo{}, false, nil
	}
	for _, src := range srcs {
		txs, err := src.BlockTxs(ctx, a.tx.Height)
		if cerr := ctx.Err(); cerr != nil {
			return ProofInfo{}, false, verifier.WithReason(verifier.ReasonTimeout, nil, cerr)
		}
		if err != nil || len(txs) != results {
			continue
		}
		root, err := RebuildDataRoot(txs)
		if err != nil || !bytes.Equal(root, a.hdr.DataHash) {
			continue
		}
		at, n := -1, 0
		for i, t := range txs {
			if bytes.Equal(t, a.tx.Bytes) {
				at = i
				n++
			}
		}
		if n == 1 {
			return ProofInfo{IndexBound: true, Index: at}, true, nil
		}
	}
	return ProofInfo{}, false, nil
}

// normalTx is true for a transaction that is neither a blob transaction nor a
// pay-for-fibre one, the kinds that sit after the normal ones in the block.
func normalTx(tx []byte) bool {
	if _, isBlob, _ := blobtx.UnmarshalBlobTx(tx); isBlob {
		return false
	}
	_, isFibre, err := fibretypes.TryParseFibreTx(tx)
	return err == nil && !isFibre
}
