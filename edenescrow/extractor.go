// SPDX-License-Identifier: Apache-2.0

package edenescrow

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/vgonkivs/edicta/policy"
)

// Facts are the policy facts of a decoded action. The amount is the deposit,
// the cap the facilitator may later settle: the gate must count the maximum
// before the money leaves. The facilitator, times, fees and the purpose
// binding are no facts; the signer pins the facilitator.
func (a TxAction) Facts() policy.Facts {
	chain := caipChain(a.ChainID)
	return policy.Facts{
		Kind:      Kind,
		Asset:     chain + "/native",
		Amount:    bytes.Clone(a.Value),
		Scale:     Scale,
		Recipient: chain + ":0x" + hex.EncodeToString(a.Deposit.PayTo[:]),
	}
}

// txExtractor is the policy extractor of one extractor ID and its table.
type txExtractor struct{ t table }

// New returns the extractor this build registers for ActionType.
func New() policy.Extractor { return txExtractor{t: builtTable} }

func (x txExtractor) ID() string { return x.t.id }

func (txExtractor) ActionType() string { return ActionType }

// Extract decodes with the ID's table; a refusal is the decoder's sentinel,
// which the registry reports as policy.ErrFactsInvalid.
func (x txExtractor) Extract(action []byte) (policy.Facts, error) {
	a, err := x.t.decode(action)
	if err != nil {
		return policy.Facts{}, err
	}
	f := a.Facts()
	if err := f.Validate(); err != nil {
		return policy.Facts{}, fmt.Errorf("edenescrow: facts: %w", err)
	}
	return f, nil
}
