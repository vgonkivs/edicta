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

// A source that does not know the transaction, or cannot be reached, gives
// no fact: the check is unchecked, never failed.
var (
	ErrTxNotFound          = fmt.Errorf("railverify: transaction not found: %w", verifier.ErrExecutionUnchecked)
	ErrTxSourceUnavailable = fmt.Errorf("railverify: transaction source unavailable: %w", verifier.ErrExecutionUnchecked)
)

// The rest are contradictions.
var (
	ErrTxHashMismatch = errors.New("railverify: transaction bytes do not hash to the receipt's rail_ref")
	ErrTxMalformed    = errors.New("railverify: transaction is not a canonical TxRaw")
	ErrChainMismatch  = errors.New("railverify: chain id mismatch")
	ErrTxFailed       = errors.New("railverify: transaction failed on chain")
	ErrTxProof        = errors.New("railverify: inclusion proof does not verify against the header")
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
