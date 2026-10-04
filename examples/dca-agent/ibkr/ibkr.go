// Package ibkr holds the executor-side checks of the IBKR order profile.
package ibkr

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/examples/dca-agent/ibkrorder"
)

var (
	// ErrAccountMismatch means the order is for an account this executor does
	// not trade.
	ErrAccountMismatch = errors.New("ibkr: order account is not the executor's account")
	// ErrRiskLimit means the order notional exceeds the operator's limit.
	ErrRiskLimit = errors.New("ibkr: order notional above the risk limit")
)

// CheckConfig is the operator's configuration. MaxNotional has scale 1e8 and
// 0 disables the limit.
type CheckConfig struct {
	Account     string
	MaxNotional uint64
}

// CheckOrder parses the authorized bytes as they are and applies the
// executor's checks in order: decoding, value rules, account, risk limit. The
// broker request must be built from the returned order only.
func CheckOrder(cfg CheckConfig, action []byte) (*ibkrorder.Order, error) {
	o, err := ibkrorder.Decode(action)
	if err != nil {
		return nil, err
	}
	if err := ibkrorder.Validate(o); err != nil {
		return nil, err
	}
	if o.Account != cfg.Account {
		return nil, fmt.Errorf("%w: %q", ErrAccountMismatch, o.Account)
	}
	if cfg.MaxNotional != 0 && !ibkrorder.NotionalAtMost(o.Qty, *o.LimitPrice, cfg.MaxNotional) {
		return nil, ErrRiskLimit
	}
	return o, nil
}

// ClientOrderID is the broker-side id of a decision: the full hash in
// lowercase hex, 64 characters.
func ClientOrderID(h commitment.Hash) string { return hex.EncodeToString(h[:]) }
