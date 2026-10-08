package demo

import (
	"errors"
	"fmt"
	"math/big"
)

// BudgetParams are the inputs of ComputeBudget.
type BudgetParams struct {
	MinGasPrice *big.Rat
	SendGas     uint64 // gas limit of a bank send
	PFBGas      uint64 // gas estimate of one PayForBlob
	Amount      uint64 // the demo's transfer
	MaxAmount   uint64 // per-send funding maximum
}

// Balances are the current balances of the three accounts.
type Balances struct{ Funder, Recorder, Executor uint64 }

// Budget is what must be moved: shortfalls only.
type Budget struct {
	Recorder, Executor         uint64 // amounts to send to each account
	FunderFees                 uint64 // the funder's own fees for those sends
	Total                      uint64 // what the funder must hold
	WantRecorder, WantExecutor uint64 // target balances
	SendFee, PFBFee            uint64
}

// Sends is the number of funding sends the budget needs.
func (b Budget) Sends() uint64 {
	var n uint64
	if b.Recorder > 0 {
		n++
	}
	if b.Executor > 0 {
		n++
	}
	return n
}

// feeFor is ceil(gas x price x 1.2).
func feeFor(price *big.Rat, gas uint64) (uint64, error) {
	r := new(big.Rat).SetInt(new(big.Int).SetUint64(gas))
	r.Mul(r, price)
	r.Mul(r, big.NewRat(6, 5))
	q, m := new(big.Int).QuoRem(r.Num(), r.Denom(), new(big.Int))
	if m.Sign() > 0 {
		q.Add(q, big.NewInt(1))
	}
	if !q.IsUint64() {
		return 0, errors.New("demo: fee overflows")
	}
	return q.Uint64(), nil
}

// ComputeBudget is pure. The Recorder pays three PayForBlobs (the decision,
// the over-limit decision the policy refuses, and the rogue executor's). The executor holds the demo
// amount, the rogue amount plus one, and four transaction fees.
func ComputeBudget(p BudgetParams, have Balances) (Budget, error) {
	if p.MinGasPrice == nil || p.MinGasPrice.Sign() < 0 || p.Amount == 0 {
		return Budget{}, errors.New("demo: bad budget inputs")
	}
	sendFee, err := feeFor(p.MinGasPrice, p.SendGas)
	if err != nil {
		return Budget{}, err
	}
	pfbFee, err := feeFor(p.MinGasPrice, p.PFBGas)
	if err != nil {
		return Budget{}, err
	}
	wantRec := 3 * pfbFee
	wantExec := 2*p.Amount + 1 + 4*sendFee
	b := Budget{SendFee: sendFee, PFBFee: pfbFee, WantRecorder: wantRec, WantExecutor: wantExec}
	b.Recorder = shortfall(wantRec, have.Recorder)
	b.Executor = shortfall(wantExec, have.Executor)
	if p.MaxAmount > 0 && (b.Recorder > p.MaxAmount || b.Executor > p.MaxAmount) {
		return Budget{}, fmt.Errorf("%w: recorder %d, executor %d, maximum %d", ErrShortfallAboveMax, b.Recorder, b.Executor, p.MaxAmount)
	}
	b.FunderFees = b.Sends() * sendFee
	b.Total = b.Recorder + b.Executor + b.FunderFees
	return b, nil
}

func shortfall(want, have uint64) uint64 {
	if have >= want {
		return 0
	}
	return want - have
}
