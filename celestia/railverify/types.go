// Package railverify checks that a rail transaction named by a receipt is the
// action the gate authorized. It is the verifier's execution checker for the
// bank-send profile; the core verifier knows nothing of the rail.
package railverify

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/vgonkivs/edicta/verifier"
)

// A source that does not know the transaction, serves other bytes or a bad
// proof, or cannot be reached, gives no fact: the check is unchecked, never
// failed. Such an answer shows a bad source, not a bad execution.
var (
	ErrTxNotFound          = fmt.Errorf("railverify: transaction not found: %w", verifier.ErrExecutionUnchecked)
	ErrTxSourceUnavailable = fmt.Errorf("railverify: transaction source unavailable: %w", verifier.ErrExecutionUnchecked)
	ErrTxHashMismatch      = fmt.Errorf("railverify: transaction bytes do not hash to the receipt's rail_ref: %w", verifier.ErrExecutionUnchecked)
	ErrTxProof             = fmt.Errorf("railverify: inclusion proof does not verify against the header: %w", verifier.ErrExecutionUnchecked)
	ErrChainConfig         = fmt.Errorf("railverify: the checker is configured for another chain: %w", verifier.ErrExecutionUnchecked)
	ErrResultsProof        = fmt.Errorf("railverify: block results do not hash to last_results_hash: %w", verifier.ErrExecutionUnchecked)
)

// Violations that bound objects prove: the receipt is signed by the gate, the
// bytes hash to its rail_ref, and the action is bound by its hash.
var (
	ErrRailRefMalformed = fmt.Errorf("railverify: rail_ref is not 64 lower-case hex characters: %w", verifier.ErrExecutionViolation)
	ErrTxMalformed      = fmt.Errorf("railverify: transaction is not a canonical TxRaw: %w", verifier.ErrExecutionViolation)
)

// The rest are the core's own findings, under the names this profile uses.
var (
	ErrChainMismatch     = verifier.ErrExecutionChain
	ErrTxFailed          = verifier.ErrExecutionFailed
	ErrResultUnconfirmed = verifier.ErrExecutionResultUnconfirmed
)

// RawTx is a transaction as a tx source reports it. Proof is the source's
// proof member, as served; it is empty when none was asked for or given.
type RawTx struct {
	Bytes  []byte
	Height uint64
	Code   uint32
	Proof  []byte
}

// TxSource looks a transaction up by the SHA-256 of its bytes. Name is the
// normalized host, the unit that distinct-source rules count.
type TxSource interface {
	Name() string
	Tx(ctx context.Context, hash [32]byte, prove bool) (RawTx, error)
}

// TxResult is the part of an ExecTxResult that the block's results hash
// covers. The other fields (log, info, events, codespace) are not part of
// consensus and are ignored.
type TxResult struct {
	Code      uint32
	Data      []byte
	GasWanted int64
	GasUsed   int64
}

// ResultsSource serves the results of a block. A node may not keep them, and
// a source that fails is skipped.
type ResultsSource interface {
	Name() string
	BlockResults(ctx context.Context, height uint64) ([]TxResult, error)
}

// BlockSource serves the transactions of a block as the block holds them,
// in block order. Nothing it serves is believed until the square they build
// has the trusted header's data root.
type BlockSource interface {
	Name() string
	BlockTxs(ctx context.Context, height uint64) ([][]byte, error)
}

// Config pins the chain the checker accepts.
type Config struct {
	ChainID string
	HRP     string
}

// ValidateBasic checks the fields that need no dependency.
func (c Config) ValidateBasic() error {
	if strings.TrimSpace(c.ChainID) == "" {
		return errors.New("railverify: no chain id")
	}
	if strings.TrimSpace(c.HRP) == "" {
		return errors.New("railverify: no address prefix")
	}
	return nil
}
