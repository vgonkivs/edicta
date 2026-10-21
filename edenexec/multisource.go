// SPDX-License-Identifier: Apache-2.0

package edenexec

import (
	"bytes"
	"encoding/binary"
)

// SourceState is what one source's answers amount to.
type SourceState string

const (
	// StatePass: every rule passed at the confirmation depth.
	StatePass SourceState = "pass"
	// StateNotFound: the source answered that it does not know the
	// transaction.
	StateNotFound SourceState = "not_found"
	// StateUnconfirmed: the source serves the transaction below the depth.
	StateUnconfirmed SourceState = "unconfirmed"
	// StateUnavailable: the source could not be read.
	StateUnavailable SourceState = "unavailable"
	// StateSetAside: any other rule failed; the source counts for neither
	// side.
	StateSetAside SourceState = "set_aside"
)

// AwaitState is the state Await combines from the sources.
type AwaitState string

const (
	AwaitPending     AwaitState = "pending"
	AwaitExecuted    AwaitState = "executed"
	AwaitReverted    AwaitState = "reverted"
	AwaitDisputed    AwaitState = "disputed"
	AwaitNotExecuted AwaitState = "not_executed"
	AwaitUnknown     AwaitState = "unknown"
)

// observation is one source's contribution to the combination.
type observation struct {
	operator string
	state    SourceState
	outcome  Outcome
	// binding is the block hash, the index and the receipt's consensus
	// encoding: equal bindings are byte-equal claims.
	binding []byte
	// served: the source served bytes that hash to the rail_ref, whatever
	// rule set it aside afterwards.
	served bool
}

func observe(p probe) observation {
	o := observation{operator: OperatorOf(p.src), served: p.seen}
	switch {
	case p.passed:
		o.state, o.outcome = StatePass, p.outcome
		o.binding = append(append(bytes.Clone(p.blockHash[:]), binary.BigEndian.AppendUint64(nil, p.index)...), p.receipt...)
	case p.notFound:
		o.state = StateNotFound
	case p.depthOnly:
		o.state = StateUnconfirmed
	case p.reason == ReasonSourceUnavailable:
		o.state = StateUnavailable
	default:
		o.state = StateSetAside
	}
	return o
}

// combined is the multi-source view of one poll.
type combined struct {
	// disputed: two passing sources differ in their binding.
	disputed bool
	// passingOps counts the distinct operators of the passing sources.
	passingOps int
	outcome    Outcome
	// notFoundOps counts the distinct operators that answered not found.
	notFoundOps int
	// showsDeposit: some source's answer rules out not executed.
	showsDeposit bool
}

// showsDeposit says whether one source's answer rules out calling the
// transaction not executed. A passing or an unconfirmed source does; a set
// aside one counts for neither side, even when it served the bytes
// (served).
func showsDeposit(o observation) bool {
	return o.state == StatePass || o.state == StateUnconfirmed
}

func combine(obs []observation) combined {
	var (
		c        combined
		first    []byte
		passing  = map[string]bool{}
		notFound = map[string]bool{}
	)
	for _, o := range obs {
		c.showsDeposit = c.showsDeposit || showsDeposit(o)
		switch o.state {
		case StatePass:
			if first == nil {
				first, c.outcome = o.binding, o.outcome
			} else if !bytes.Equal(first, o.binding) {
				c.disputed = true
			}
			passing[o.operator] = true
		case StateNotFound:
			notFound[o.operator] = true
		}
	}
	c.passingOps, c.notFoundOps = len(passing), len(notFound)
	return c
}

// awaitState applies the multi-source rule in order: a disagreement is
// disputed; enough agreeing operators give the outcome at L1, and one is
// enough only when L0 was configured; before the deadline anything else is
// pending; after it, not executed needs no source showing the deposit and
// at least minSources operators answering not found, and anything else is
// unknown. A disagreement is never not executed.
func awaitState(c combined, awaitLevel Level, minSources int, untilPassed bool) (AwaitState, Level) {
	outcome := AwaitExecuted
	if c.outcome == OutcomeReverted {
		outcome = AwaitReverted
	}
	switch {
	case c.disputed:
		return AwaitDisputed, 0
	case c.passingOps >= minSources:
		return outcome, LevelMultiSource
	case c.passingOps >= 1 && awaitLevel == LevelNodeAttested:
		return outcome, LevelNodeAttested
	case !untilPassed:
		return AwaitPending, 0
	case c.passingOps == 0 && !c.showsDeposit && c.notFoundOps >= minSources:
		return AwaitNotExecuted, 0
	}
	return AwaitUnknown, 0
}

// RecordAllowed says whether a record request may name this transaction:
// only for an outcome the configured level reached.
func (r Report) RecordAllowed() bool {
	return r.State == AwaitExecuted || r.State == AwaitReverted
}

// PaymentSignatureAllowed says whether the deposit is executed on the word
// of at least two operators, the floor for signing a payment proof.
func (r Report) PaymentSignatureAllowed() bool {
	return r.State == AwaitExecuted && r.Level >= LevelMultiSource
}

// NonceReleaseAllowed says whether the operator may release the nonce.
func (r Report) NonceReleaseAllowed() bool { return r.State == AwaitNotExecuted }
