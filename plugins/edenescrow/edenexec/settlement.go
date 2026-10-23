// SPDX-License-Identifier: Apache-2.0

package edenexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/vgonkivs/edicta/internal/evm"
	"github.com/vgonkivs/edicta/plugins/edenescrow"
)

// Status of a settlement report. It is verdict-neutral: nothing here moves
// a decision's verdict.
type Status string

const (
	StatusPass      Status = "pass"
	StatusUnchecked Status = "unchecked"
	StatusViolated  Status = "violated"
)

// Results of one source in the report.
const (
	SourceUsed     = "used"
	SourceAgree    = "agree"
	SourceSetAside = "set_aside"
)

// SourceResult is what one source asked contributed.
type SourceResult struct {
	Name     string
	Class    SourceClass
	Operator string
	// OperatorExplicit: the label was configured; otherwise the host
	// stands in.
	OperatorExplicit bool
	Result           string // used, agree or set_aside
	// State tells a set-aside source's answer apart: not found,
	// unconfirmed, unavailable or another rule.
	State  SourceState
	Reason Reason // for set_aside
	Err    error
}

// DAReport is the own ev-node's word on the block's data in Celestia.
type DAReport struct {
	Source   string
	Included bool
	Height   uint64
	Err      error
}

// Report is the settlement report of one decision.
type Report struct {
	Status Status
	// Reason and Err are set for unchecked and violated.
	Reason Reason
	Err    error
	// Level and Outcome are set for pass.
	Level   Level
	Outcome Outcome

	RailRef   string
	ChainID   uint64
	Block     uint64
	BlockHash [32]byte
	Index     uint64
	BlockTime uint64
	// Payer is the address the signature recovers to, once the bytes passed.
	Payer    [20]byte
	HasPayer bool
	// HasBlock says Block, BlockHash, Index and BlockTime are set.
	HasBlock bool
	Warnings []string
	DA       *DAReport
	// Deposit is the decoded action's deposit, whenever the action decoded.
	Deposit *edenescrow.DepositView
	Sources []SourceResult
	// State is set by Await: the combined state of its last poll.
	State AwaitState
	// Seen is set by Await: some source served a transaction for the
	// rail_ref in some poll of the wait, which rules out not executed.
	Seen bool
}

// probe is one source's answers for the target.
type probe struct {
	src    Source
	reason Reason
	err    error
	// depthOnly: everything up to the depth answered, and only the depth
	// failed.
	depthOnly bool
	// notFound: the source answered that it does not know the transaction.
	notFound bool
	// seen: the source served a transaction for the rail_ref, whatever
	// rule set it aside afterwards.
	seen bool

	passed    bool
	blockHash [32]byte
	number    uint64
	index     uint64
	receipt   []byte
	header    HeaderView
	outcome   Outcome
}

func (p *probe) setAside(err error) {
	p.reason, p.err = ReasonOf(err), err
}

// run is one evaluation over the sources.
type run struct {
	c      *Checker
	t      Target
	R      [32]byte
	row    edenescrow.Row
	signed []byte
	// payer is set once signed passed the exact-transaction rule.
	payer    [20]byte
	hasPayer bool
	// violation is set by the exact-transaction rule.
	violation error
}

// Settlement checks the target against every source, in configuration
// order, and reports the highest level reached. The error is only for a
// cancelled context; every finding is in the report.
func (c *Checker) Settlement(ctx context.Context, t Target) (Report, error) {
	rep, _ := c.evaluate(ctx, t, c.cfg.MinLevel, LevelReceiptProven, c.srcs)
	return rep, ctx.Err()
}

// SettlementOfAction is Settlement for the committed action bytes: bytes
// that do not decode under this build's table give an unchecked report with
// settlement_action_refused, and no rule runs.
func (c *Checker) SettlementOfAction(ctx context.Context, action []byte, railRef string, expires, tRef uint64) (Report, error) {
	t, err := NewTarget(action, railRef, expires, tRef)
	if err != nil {
		return Report{Status: StatusUnchecked, Reason: ReasonActionRefused, Err: err, RailRef: railRef}, ctx.Err()
	}
	return c.Settlement(ctx, t)
}

// evaluate asks every source in order, since a source that disagrees or
// still shows the transaction changes the combined result; only a violation
// stops it early.
func (c *Checker) evaluate(ctx context.Context, t Target, minLevel, maxLevel Level, srcs []Source) (Report, []probe) {
	rep := Report{RailRef: t.RailRef, ChainID: t.Action.ChainID}
	unchecked := func(err error) Report {
		rep.Status, rep.Reason, rep.Err = StatusUnchecked, ReasonOf(err), err
		return rep
	}
	if len(t.Action.Unsigned()) == 0 {
		return unchecked(wrapf(ErrActionRefused, "the action was not decoded")), nil
	}
	row, ok := edenescrow.Lookup(t.Action.ChainID)
	if !ok || row.Escrow != t.Action.To {
		return unchecked(wrapf(ErrActionRefused, "chain %d is not a row of this build", t.Action.ChainID)), nil
	}
	view := t.Action.DepositView()
	rep.Deposit = &view
	R, err := ParseRailRef(t.RailRef)
	if err != nil {
		return unchecked(err), nil
	}
	r := &run{c: c, t: t, R: R, row: row}
	var probes []probe
	for _, src := range srcs {
		if ctx.Err() != nil {
			break
		}
		p := r.probe(ctx, src)
		probes = append(probes, p)
		if r.violation != nil {
			// The finding rests on the bytes this source served, whose
			// keccak is the signed rail_ref.
			rep.Sources = sourceResults(probes, len(probes)-1)
			r.fillPayer(&rep)
			rep.Status, rep.Reason, rep.Err = StatusViolated, ReasonWrongTx, r.violation
			return rep, probes
		}
	}
	r.fillPayer(&rep)
	if ctx.Err() != nil {
		rep.Sources = sourceResults(probes, -1)
		return unchecked(wrapf(ErrSourceUnavailable, "%v", ctx.Err())), probes
	}
	return r.judge(ctx, rep, probes, minLevel, maxLevel), probes
}

func (r *run) fillPayer(rep *Report) {
	rep.Payer, rep.HasPayer = r.payer, r.hasPayer
}

// probe runs, on one source: the source domain, the bytes, then the exact
// transaction once, inclusion, status and the deposit event. Any failure
// sets the source aside with its reason.
func (r *run) probe(ctx context.Context, src Source) (p probe) {
	p.src = src
	fail := func(err error) probe {
		p.setAside(err)
		return p
	}
	unavailable := func(what string, err error) probe {
		if errors.Is(err, ErrNotFound) {
			return fail(err)
		}
		return fail(fmt.Errorf("%w: %s: %w", ErrSourceUnavailable, what, err))
	}

	chainID, err := src.ChainID(ctx)
	if err != nil {
		return unavailable("eth_chainId", err)
	}
	if chainID != r.t.Action.ChainID {
		return fail(wrapf(ErrChainConfig, "source serves chain %d, the action names %d", chainID, r.t.Action.ChainID))
	}
	code, err := src.CodeHash(ctx, r.row.Escrow)
	if err != nil {
		return unavailable("eth_getCode", err)
	}
	if code != r.row.CodeHash {
		return fail(wrapf(ErrCodeMismatch, "code hash %x at the escrow", code))
	}

	tx, err := src.Transaction(ctx, r.R)
	if errors.Is(err, ErrNotFound) {
		p.notFound = true
		return fail(err)
	}
	if err != nil {
		return unavailable("eth_getTransactionByHash", err)
	}
	p.seen = true
	if tx.Hash != r.R {
		return fail(wrapf(ErrHashMismatch, "served transaction names hash %x", tx.Hash))
	}
	signed, err := RebuildSigned(tx)
	if err != nil {
		return fail(err)
	}
	if got := evm.Keccak256(signed); got != r.R {
		return fail(wrapf(ErrHashMismatch, "rebuilt bytes hash to %x", got))
	}
	if r.signed == nil {
		r.signed = signed
		payer, err := CheckExactTx(signed, r.t.Action)
		if err != nil {
			r.violation = err
			return p
		}
		r.payer, r.hasPayer = payer, true
	} else if !bytes.Equal(signed, r.signed) {
		return fail(wrapf(ErrHashMismatch, "rebuilt bytes differ from another source's with the same hash"))
	}

	if !tx.Included {
		p.depthOnly = true
		return fail(wrapf(ErrUnconfirmed, "the transaction is pending"))
	}
	head, err := src.Head(ctx)
	if err != nil {
		return unavailable("eth_blockNumber", err)
	}
	if head < tx.BlockNumber || head-tx.BlockNumber < r.c.cfg.ConfirmDepth {
		p.depthOnly = true
		return fail(wrapf(ErrUnconfirmed, "block %d, head %d, depth %d needed", tx.BlockNumber, head, r.c.cfg.ConfirmDepth))
	}

	rc, err := src.Receipt(ctx, r.R)
	if errors.Is(err, ErrNotFound) {
		return fail(wrapf(ErrDisagree, "no receipt for a transaction in block %d", tx.BlockNumber))
	}
	if err != nil {
		return unavailable("eth_getTransactionReceipt", err)
	}
	if rc.TxHash != r.R || rc.BlockHash != tx.BlockHash || rc.BlockNumber != tx.BlockNumber || rc.Index != tx.Index {
		return fail(wrapf(ErrDisagree, "the receipt names another transaction, block or index than the transaction"))
	}
	outcome, err := CheckDeposit(rc, r.t.Action, r.payer, r.row.Escrow)
	if err != nil {
		return fail(err)
	}
	enc, err := ReceiptEncoding(rc)
	if err != nil {
		return fail(fmt.Errorf("%w: %w", ErrDisagree, err))
	}
	hd, err := src.Header(ctx, tx.BlockHash)
	if errors.Is(err, ErrNotFound) {
		return fail(wrapf(ErrDisagree, "no header for block %x", tx.BlockHash))
	}
	if err != nil {
		return unavailable("eth_getBlockByHash", err)
	}
	if hd.Hash != tx.BlockHash || hd.Number != tx.BlockNumber {
		return fail(wrapf(ErrDisagree, "the header names another block than the transaction"))
	}
	p.passed, p.blockHash, p.number, p.index = true, tx.BlockHash, tx.BlockNumber, tx.Index
	p.receipt, p.header, p.outcome = enc, hd, outcome
	return p
}

// judge applies the levels and the outcome rule to the probes.
func (r *run) judge(ctx context.Context, rep Report, probes []probe, minLevel, maxLevel Level) Report {
	// The caller combines the probes as the sources answered them; the
	// marks below are the report's alone.
	probes = slices.Clone(probes)
	var passing []int
	for i, p := range probes {
		if p.passed {
			passing = append(passing, i)
		}
	}
	unchecked := func(err error, used int) Report {
		rep.Sources = sourceResults(probes, used)
		rep.Status, rep.Reason, rep.Err = StatusUnchecked, ReasonOf(err), err
		return rep
	}
	if len(passing) == 0 {
		return unchecked(r.noneReached(probes, minLevel, false), -1)
	}
	first := probes[passing[0]]
	if combineProbes(probes).disputed {
		// Never a violation: a lagging source catches up, a rolled-back
		// block disappears everywhere.
		for _, i := range passing[1:] {
			p := &probes[i]
			if p.blockHash != first.blockHash || p.index != first.index || !bytes.Equal(p.receipt, first.receipt) {
				p.passed = false
				p.setAside(wrapf(ErrDisagree, "block, index or receipt differ from %s", first.src.Name()))
				return unchecked(wrapf(ErrDisagree, "%s and %s disagree on the block, the index or the receipt",
					first.src.Name(), p.src.Name()), passing[0])
			}
		}
	}
	level := LevelNodeAttested
	if combineProbes(probes).passingOps >= r.c.cfg.MinSources && maxLevel >= LevelMultiSource {
		level = LevelMultiSource
	}
	var (
		proofErr error
		proven   HeaderView
	)
	if level == LevelMultiSource && maxLevel >= LevelReceiptProven {
		if proven, proofErr = r.blockProof(ctx, probes, passing, first); proofErr == nil {
			level = LevelReceiptProven
		}
	}
	if level < minLevel {
		if minLevel == LevelReceiptProven && level == LevelMultiSource {
			return unchecked(proofErr, passing[0])
		}
		return unchecked(r.noneReached(probes, minLevel, true), passing[0])
	}
	rep.Status, rep.Level, rep.Outcome = StatusPass, level, first.outcome
	rep.HasBlock, rep.Block, rep.BlockHash, rep.Index = true, first.number, first.blockHash, first.index
	rep.BlockTime = first.header.Time
	if level == LevelReceiptProven {
		// Only the proven header's fields hash to the block hash; the used
		// source's own header may differ in anything but its claimed hash.
		rep.Block, rep.BlockTime = proven.Number, proven.Time
	}
	rep.Warnings = timeWarnings(rep.BlockTime, r.t.Expires, r.t.TRef)
	rep.Sources = sourceResults(probes, passing[0])
	if r.c.da != nil {
		rep.DA = &DAReport{Source: r.c.da.Name()}
		rep.DA.Height, rep.DA.Included, rep.DA.Err = r.c.da.DataDAHeight(ctx, first.number)
	}
	return rep
}

// noneReached is the reason when no source reached the level: a source that
// failed only at the depth means retry later; some passing but too few is
// below the level; otherwise the first source's reason.
func (r *run) noneReached(probes []probe, minLevel Level, somePassed bool) error {
	for _, p := range probes {
		if p.depthOnly {
			return p.err
		}
	}
	if somePassed {
		return wrapf(ErrBelowLevel, "%s needs %d agreeing operators", minLevel, r.c.cfg.MinSources)
	}
	if len(probes) == 0 {
		return wrapf(ErrSourceUnavailable, "no source was asked")
	}
	return probes[0].err
}

// blockProof tries the passing sources in order until one serves a block
// whose contents rebuild the header the agreeing sources named, and returns
// that header.
func (r *run) blockProof(ctx context.Context, probes []probe, passing []int, first probe) (HeaderView, error) {
	var last error
	for _, i := range passing {
		src := probes[i].src
		txs, err := src.BlockTransactions(ctx, first.blockHash)
		if err != nil {
			last = wrapf(ErrBlockProof, "%s: transactions: %v", src.Name(), err)
			continue
		}
		receipts, err := src.BlockReceipts(ctx, first.blockHash)
		if err != nil {
			last = wrapf(ErrBlockProof, "%s: receipts: %v", src.Name(), err)
			continue
		}
		if err := VerifyBlock(probes[i].header, first.blockHash, txs, receipts, first.index, r.signed, first.receipt); err != nil {
			last = fmt.Errorf("%s: %w", src.Name(), err)
			continue
		}
		return probes[i].header, nil
	}
	return HeaderView{}, last
}

// sourceResults lists every source asked; used is the index of the source
// whose data the report uses, -1 for none.
func sourceResults(probes []probe, used int) []SourceResult {
	out := make([]SourceResult, 0, len(probes))
	for i, p := range probes {
		o := observe(p)
		sr := SourceResult{Name: p.src.Name(), Class: p.src.Class(), Operator: o.operator,
			OperatorExplicit: o.explicit, State: o.state}
		switch {
		case i == used:
			sr.Result = SourceUsed
		case p.passed:
			sr.Result = SourceAgree
		default:
			sr.Result, sr.Reason, sr.Err = SourceSetAside, p.reason, p.err
		}
		out = append(out, sr)
	}
	return out
}

func combineProbes(probes []probe) combined {
	obs := make([]observation, len(probes))
	for i, p := range probes {
		obs[i] = observe(p)
	}
	return combine(obs)
}

// ownFirst orders the operator's own nodes before the public RPCs, keeping
// the configuration order within each class.
func ownFirst(srcs []Source) []Source {
	out := slices.Clone(srcs)
	slices.SortStableFunc(out, func(a, b Source) int {
		ao, bo := a.Class() == ClassOwnNode, b.Class() == ClassOwnNode
		switch {
		case ao && !bo:
			return -1
		case bo && !ao:
			return 1
		}
		return 0
	})
	return out
}
