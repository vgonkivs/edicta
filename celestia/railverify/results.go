package railverify

import (
	"bytes"
	"context"
	"fmt"

	abci "github.com/cometbft/cometbft/abci/types"
	core "github.com/cometbft/cometbft/types"

	"github.com/vgonkivs/edicta/verifier"
)

// ResultsRoot is the LastResultsHash that the block after these results
// carries: the RFC 6962 root over the deterministic part of every result, as
// celestia-core computes it (types.NewResults, state.TxResultsHash).
func ResultsRoot(results []TxResult) (root []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			root, err = nil, fmt.Errorf("railverify: results do not encode: %v", r)
		}
	}()
	rs := make([]*abci.ExecTxResult, len(results))
	for i, r := range results {
		rs[i] = &abci.ExecTxResult{Code: r.Code, Data: r.Data, GasWanted: r.GasWanted, GasUsed: r.GasUsed}
	}
	return core.NewResults(rs).Hash(), nil
}

// resultProof is what the result proof established, or why it did not.
type resultProof struct {
	proven bool
	code   uint32
	// results is the number of results of the block when they hash to the
	// trusted root.
	results int
	problem error
}

// proveResult runs the result proof of the bank-send profile: the results of
// the block at height, from any source, must hash to last_results_hash of the
// trusted header at height + 1, and the transaction's index in them must be
// bound. A source that fails or serves results that do not hash to the root
// is skipped. The error return is for a finding that ends the whole check.
func (c *bankSend) proveResult(ctx context.Context, height uint64, chainID string, info ProofInfo, srcs []ResultsSource) (resultProof, error) {
	raw, err := c.headers.Header(ctx, height+1)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return resultProof{}, verifier.WithReason(verifier.ReasonTimeout, nil, cerr)
		}
		reason, names := headerReason(err)
		if reason == verifier.ReasonHeaderDisagreement {
			return resultProof{}, verifier.WithReason(reason, names, err)
		}
		return resultProof{problem: verifier.WithReason(verifier.ReasonResultHeaderUnreachable, names,
			fmt.Errorf("the header at height %d is not trusted: %w", height+1, err))}, nil
	}
	hdr, err := decodeHeader(raw, height+1)
	if err != nil || hdr.ChainID != chainID {
		return resultProof{problem: verifier.Reasonf(verifier.ReasonResultHeaderUnreachable, nil,
			"the header at height %d is unusable", height+1)}, nil
	}

	mismatch := ""
	for _, src := range srcs {
		results, err := src.BlockResults(ctx, height)
		if cerr := ctx.Err(); cerr != nil {
			return resultProof{}, verifier.WithReason(verifier.ReasonTimeout, nil, cerr)
		}
		if err != nil {
			continue
		}
		root, err := ResultsRoot(results)
		if err != nil || !bytes.Equal(root, hdr.LastResultsHash) {
			if mismatch == "" {
				mismatch = src.Name()
			}
			continue
		}
		code, ok := boundCode(results, info)
		if !ok {
			return resultProof{results: len(results), problem: verifier.Reasonf(verifier.ReasonResultIndexUnbound, []string{src.Name()},
				"nothing binds the position of the transaction among the %d results of block %d", len(results), height)}, nil
		}
		return resultProof{proven: true, code: code}, nil
	}
	if mismatch != "" {
		return resultProof{problem: verifier.WithReason(verifier.ReasonResultsRootMismatch, []string{mismatch},
			fmt.Errorf("%w: block %d, last_results_hash of block %d", ErrResultsProof, height, height+1))}, nil
	}
	return resultProof{}, nil
}

// boundCode picks the code of the transaction among results that hash to the
// trusted root. Either the proof bound the position, or every result of the
// block has the same code, which then is the transaction's whatever its
// position.
func boundCode(results []TxResult, info ProofInfo) (uint32, bool) {
	if info.IndexBound && info.Index >= 0 && info.Index < len(results) {
		return results[info.Index].Code, true
	}
	if len(results) == 0 {
		return 0, false
	}
	for _, r := range results[1:] {
		if r.Code != results[0].Code {
			return 0, false
		}
	}
	return results[0].Code, true
}
