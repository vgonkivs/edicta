// Package tiatransfer is the policy extractor for bank-send actions on a
// Celestia chain paying utia.
package tiatransfer

import (
	"errors"
	"fmt"

	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankmsg"
	"github.com/vgonkivs/edicta/policy"
)

const (
	ID    = "celestia/tia-transfer/v1"
	HRP   = "celestia"
	Denom = "utia"
	Scale = 6
)

// ErrDenom is returned for a message in any denom other than utia.
var ErrDenom = errors.New("tiatransfer: denom is not utia")

// Extractor maps a bank-send action to transfer facts. It is stateless.
type Extractor struct{}

func New() Extractor { return Extractor{} }

func (Extractor) ID() string { return ID }

func (Extractor) ActionType() string { return bankaction.ActionType }

// Extract accepts only canonical bank-send bytes whose message uses the
// celestia prefix and the utia denom. The sender is not checked here.
func (Extractor) Extract(action []byte) (policy.Facts, error) {
	a, err := bankaction.Decode(action)
	if err != nil {
		return policy.Facts{}, fmt.Errorf("tiatransfer: action: %w", err)
	}
	m, err := bankmsg.Decode(a.Msg, HRP)
	if err != nil {
		return policy.Facts{}, fmt.Errorf("tiatransfer: msg: %w", err)
	}
	if m.Denom != Denom {
		return policy.Facts{}, fmt.Errorf("%w: %q", ErrDenom, m.Denom)
	}
	f := policy.Facts{
		Kind:      "transfer",
		Asset:     "cosmos:" + a.ChainID + "/" + Denom,
		Amount:    policy.AmountFromUint64(m.Amount),
		Scale:     Scale,
		Recipient: "cosmos:" + a.ChainID + ":" + m.To,
	}
	if err := f.Validate(); err != nil {
		return policy.Facts{}, fmt.Errorf("tiatransfer: facts: %w", err)
	}
	return f, nil
}
