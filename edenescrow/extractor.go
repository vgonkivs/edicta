// SPDX-License-Identifier: Apache-2.0

package edenescrow

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/vgonkivs/edicta/policy"
)

// maxAmountBytes is the longest amount policy facts carry.
const maxAmountBytes = 32

// FeeBound is gas_limit * max_fee_per_gas: the most gas the transaction can
// burn, since the sender pays gas_used * effective_gas_price.
func (a TxAction) FeeBound() *big.Int {
	return new(big.Int).Mul(new(big.Int).SetUint64(a.GasLimit), new(big.Int).SetBytes(a.MaxFeePerGas))
}

// Facts are the policy facts of a decoded action. The amount is the most
// the payer can lose to the transaction: the deposit, which is the cap the
// facilitator may later settle, plus the fee bound. The gate must count the
// maximum before the money leaves, so neither the settled amount nor the gas
// used is a fact. A sum above 32 bytes is refused rather than saturated: a
// clamped amount would understate the spend.
func (a TxAction) Facts() (policy.Facts, error) {
	sum := new(big.Int).Add(new(big.Int).SetBytes(a.Value), a.FeeBound())
	amount := sum.Bytes()
	if len(amount) > maxAmountBytes {
		return policy.Facts{}, &ruleError{sentinel: policy.ErrFactsInvalid, rule: "EF3",
			msg: fmt.Sprintf("value plus fee bound needs %d bytes", len(amount))}
	}
	chain := caipChain(a.ChainID)
	return policy.Facts{
		Kind:      Kind,
		Asset:     chain + "/native",
		Amount:    amount,
		Scale:     Scale,
		Recipient: chain + ":0x" + hex.EncodeToString(a.Deposit.PayTo[:]),
	}, nil
}

// txExtractor is the policy extractor of one extractor ID and its table.
type txExtractor struct{ t table }

// New returns the extractor this build registers for ActionType.
func New() policy.Extractor { return txExtractor{t: builtTable} }

func (x txExtractor) ID() string { return x.t.id }

func (txExtractor) ActionType() string { return ActionType }

// Extract decodes with the ID's table; a refusal is the decoder's sentinel
// or the amount rule's, which the registry reports as
// policy.ErrFactsInvalid.
func (x txExtractor) Extract(action []byte) (policy.Facts, error) {
	a, err := x.t.decode(action)
	if err != nil {
		return policy.Facts{}, err
	}
	f, err := a.Facts()
	if err != nil {
		return policy.Facts{}, err
	}
	if err := f.Validate(); err != nil {
		return policy.Facts{}, fmt.Errorf("edenescrow: facts: %w", err)
	}
	return f, nil
}
