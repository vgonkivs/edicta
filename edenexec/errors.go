// SPDX-License-Identifier: Apache-2.0

package edenexec

import (
	"errors"
	"fmt"
)

// ErrViolation is the class of findings that rest only on signed facts: the
// rail_ref the gate and the executor signed, and its keccak preimage. No
// source can produce one.
var ErrViolation = errors.New("edenexec: violation")

var (
	// ErrWrongTx: the transaction the receipt names is not the authorized one.
	ErrWrongTx = fmt.Errorf("%w: the transaction is not the authorized one", ErrViolation)

	ErrMalformedRailRef  = errors.New("edenexec: rail_ref is not 64 lower-case hex characters")
	ErrNotFound          = errors.New("edenexec: transaction not found")
	ErrSourceUnavailable = errors.New("edenexec: source unavailable")
	ErrHashMismatch      = errors.New("edenexec: served transaction does not hash to the rail_ref")
	ErrTxType            = errors.New("edenexec: transaction type cannot be rebuilt")
	ErrChainConfig       = errors.New("edenexec: source serves another chain")
	ErrCodeMismatch      = errors.New("edenexec: escrow code differs from the table")
	ErrUnconfirmed       = errors.New("edenexec: transaction below the confirmation depth")
	ErrDisagree          = errors.New("edenexec: sources disagree")
	ErrLogMismatch       = errors.New("edenexec: receipt logs are not the deposit")
	ErrBelowLevel        = errors.New("edenexec: required level not reached")
	ErrBlockProof        = errors.New("edenexec: block does not rebuild to its header")
	ErrActionRefused     = errors.New("edenexec: action is not a form T deposit of this build")
)

// Reason is a settlement reason of the profile. These are not core reasons.
type Reason string

const (
	ReasonMalformedRailRef  Reason = "malformed_rail_ref"
	ReasonWrongTx           Reason = "wrong_tx"
	ReasonNotFound          Reason = "settlement_not_found"
	ReasonSourceUnavailable Reason = "settlement_source_unavailable"
	ReasonHashMismatch      Reason = "settlement_hash_mismatch"
	ReasonTxType            Reason = "settlement_tx_type"
	ReasonChainConfig       Reason = "settlement_chain_config"
	ReasonCodeMismatch      Reason = "settlement_code_mismatch"
	ReasonUnconfirmed       Reason = "settlement_unconfirmed"
	ReasonDisagree          Reason = "settlement_disagree"
	ReasonLogMismatch       Reason = "settlement_log_mismatch"
	ReasonBelowLevel        Reason = "settlement_below_level"
	ReasonBlockProof        Reason = "settlement_block_proof"
	ReasonActionRefused     Reason = "settlement_action_refused"
)

// Warning names of the time comparisons; they never change the outcome.
const (
	WarnAfterExpires    = "after_expires"
	WarnBeforeReference = "before_reference"
)

var reasonSentinels = []struct {
	err    error
	reason Reason
}{
	{ErrWrongTx, ReasonWrongTx},
	{ErrMalformedRailRef, ReasonMalformedRailRef},
	{ErrNotFound, ReasonNotFound},
	{ErrSourceUnavailable, ReasonSourceUnavailable},
	{ErrHashMismatch, ReasonHashMismatch},
	{ErrTxType, ReasonTxType},
	{ErrChainConfig, ReasonChainConfig},
	{ErrCodeMismatch, ReasonCodeMismatch},
	{ErrUnconfirmed, ReasonUnconfirmed},
	{ErrDisagree, ReasonDisagree},
	{ErrLogMismatch, ReasonLogMismatch},
	{ErrBelowLevel, ReasonBelowLevel},
	{ErrBlockProof, ReasonBlockProof},
	{ErrActionRefused, ReasonActionRefused},
}

// ReasonOf maps an error of this package to its reason. Any other error is a
// source that could not be read.
func ReasonOf(err error) Reason {
	for _, s := range reasonSentinels {
		if errors.Is(err, s.err) {
			return s.reason
		}
	}
	return ReasonSourceUnavailable
}

// Sentinel returns the error of a reason, the inverse of ReasonOf.
func (r Reason) Sentinel() error {
	for _, s := range reasonSentinels {
		if s.reason == r {
			return s.err
		}
	}
	return ErrSourceUnavailable
}

func wrapf(sentinel error, format string, a ...any) error {
	return fmt.Errorf("%w: %s", sentinel, fmt.Sprintf(format, a...))
}
