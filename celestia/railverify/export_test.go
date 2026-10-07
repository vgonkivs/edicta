package railverify

import (
	"context"

	"github.com/vgonkivs/edicta/celestia/headertrust"
)

// ProveResultOf runs the result proof alone, over a header chain and results
// sources, so that the live vectors can be checked without a transaction that
// matches an authorized action.
func ProveResultOf(ctx context.Context, headers headertrust.HeaderChain, height uint64, chainID string, info ProofInfo, srcs []ResultsSource) (proven bool, code uint32, problem error, err error) {
	c := &bankSend{headers: headers}
	rp, err := c.proveResult(ctx, height, chainID, info, srcs)
	return rp.proven, rp.code, rp.problem, err
}
