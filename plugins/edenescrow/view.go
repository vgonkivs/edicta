// SPDX-License-Identifier: Apache-2.0

package edenescrow

import (
	"encoding/hex"
	"math/big"
	"strconv"
)

// DepositView is the deposit a decoded action makes, for logs, responses and
// the settlement report. It is not policy facts: no mandate rule reads it,
// the gate never computes it, and nothing hashes or signs it. Integers are
// decimal strings, since the value and the fee bound exceed what a JSON
// number carries exactly.
type DepositView struct {
	PaymentIDHex   string `json:"payment_id_hex"`
	PayTo          string `json:"pay_to"`
	Facilitator    string `json:"facilitator"`
	Escrow         string `json:"escrow"`
	ExpiresAt      string `json:"expires_at"`
	RefundAfter    string `json:"refund_after"`
	Value          string `json:"value"`
	FeeBound       string `json:"fee_bound"`
	TIAPriceUSDHex string `json:"tia_price_usd_hex"`
}

// DepositView returns the view of the decoded action.
func (a TxAction) DepositView() DepositView {
	d := a.Deposit
	return DepositView{
		PaymentIDHex:   hex.EncodeToString(d.PaymentID[:]),
		PayTo:          "0x" + hex.EncodeToString(d.PayTo[:]),
		Facilitator:    "0x" + hex.EncodeToString(d.Facilitator[:]),
		Escrow:         "0x" + hex.EncodeToString(a.To[:]),
		ExpiresAt:      strconv.FormatUint(d.ExpiresAt, 10),
		RefundAfter:    strconv.FormatUint(d.RefundAfter, 10),
		Value:          new(big.Int).SetBytes(a.Value).String(),
		FeeBound:       a.FeeBound().String(),
		TIAPriceUSDHex: hex.EncodeToString(d.TIAPriceUSD[:]),
	}
}
