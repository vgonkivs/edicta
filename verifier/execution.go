package verifier

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
)

// ExecutionJudgement is the outcome rule applied to a checker's facts. Err
// says what was found: the violation for a fail, the cause for an unchecked.
type ExecutionJudgement struct {
	Status  Status
	Reason  Reason
	Err     error
	Sources []string
}

// JudgeExecution classifies facts that a checker returned without an error.
// A violation counts only when verified facts prove it: a proven inclusion
// ties the height and the chain to the trusted header, and a proven result
// ties the code. Everything that rests on a source's word is unchecked, and a
// pass needs a proven result: agreeing sources never make one.
func JudgeExecution(f ExecutionFacts, anchorHeight uint64) ExecutionJudgement {
	proven := f.Inclusion == InclusionProven
	resultProven := proven && f.Result == ResultProven
	named := f.blamed()
	fail := func(err error) ExecutionJudgement { return ExecutionJudgement{Status: StatusFail, Err: err} }
	unchecked := func(reason Reason, err error) ExecutionJudgement {
		return ExecutionJudgement{Status: StatusUnchecked, Reason: reason, Err: err, Sources: named}
	}

	switch {
	case proven && f.ChainMismatch:
		return fail(ErrExecutionChain)
	case proven && f.Height <= anchorHeight:
		return fail(fmt.Errorf("%w: height %d, anchor height %d", ErrExecutionBeforeAnchor, f.Height, anchorHeight))
	case resultProven && f.Outcome == OutcomeFailure:
		return fail(ErrExecutionFailed)
	case f.ChainMismatch:
		return unchecked(ReasonChainUnbound, errors.New("the block names another chain than the action, and no proof ties the transaction to it"))
	case f.Height <= anchorHeight:
		return unchecked(ReasonHeightUnproven, fmt.Errorf("height %d is not above the anchor height %d, and no proof binds the height", f.Height, anchorHeight))
	case f.CrossCheck == CrossMismatch && !resultProven:
		return unchecked(ReasonCrossDisagree, errors.New("tx sources disagree on the height, the bytes or the code"))
	case !resultProven && f.Outcome != OutcomeSuccess:
		return unchecked(ReasonCodeUnproven, ErrExecutionResultUnconfirmed)
	case resultProven:
		return ExecutionJudgement{Status: StatusPass}
	}
	if proven && f.ResultProblem != nil {
		if reason, _, ok := ReasonOf(f.ResultProblem); ok {
			return unchecked(reason, f.ResultProblem)
		}
	}
	return unchecked(ReasonResultUnproven, errors.New("the result code is not proven: no result proof against the trusted chain"))
}

// JudgeCheck classifies what a checker returned. An error that proves a
// violation fails; any other error is a source problem and is unchecked, with
// the reason and the sources it carries. Facts that cannot be judged are
// unchecked. Otherwise the outcome rule decides. The core and the profile
// tests use this one function, so a test shows what the verifier does.
func JudgeCheck(f ExecutionFacts, err error, anchorHeight uint64) ExecutionJudgement {
	if err != nil {
		if errors.Is(err, ErrExecutionViolation) {
			return ExecutionJudgement{Status: StatusFail, Err: err}
		}
		reason, srcs, ok := ReasonOf(err)
		if !ok {
			reason = ReasonTxSourceUnavailable
		}
		return ExecutionJudgement{Status: StatusUnchecked, Reason: reason, Err: err, Sources: srcs}
	}
	if msg := factsProblem(f); msg != "" {
		return ExecutionJudgement{
			Status: StatusUnchecked, Reason: ReasonTxSourceUnavailable,
			Err: fmt.Errorf("the checker returned unusable facts: %s", msg),
		}
	}
	return JudgeExecution(f, anchorHeight)
}

// blamed lists the sources a finding rests on: the one used and every cross
// source that disagreed or failed.
func (f ExecutionFacts) blamed() []string {
	var out []string
	for _, s := range f.Sources {
		switch s.Result {
		case SourceUsed, SourceDisagree, SourceFault:
			out = append(out, s.Name)
		}
	}
	return out
}

// factsProblem says what is wrong with facts that cannot be judged at all.
func factsProblem(f ExecutionFacts) string {
	switch {
	case f.Height == 0:
		return "no height"
	case len(f.HeaderHash) == 0:
		return "no header hash"
	case f.Inclusion != InclusionProven && f.Inclusion != InclusionNodeAttested:
		return fmt.Sprintf("inclusion %q", f.Inclusion)
	case f.Outcome != OutcomeSuccess && f.Outcome != OutcomeFailure:
		return fmt.Sprintf("outcome %q", f.Outcome)
	case f.Result != ResultProven && f.Result != ResultCrossConfirmed && f.Result != ResultNodeAttested:
		return fmt.Sprintf("result %q", f.Result)
	case f.CrossCheck != CrossPass && f.CrossCheck != CrossMismatch && f.CrossCheck != CrossUnavailable && f.CrossCheck != CrossOff:
		return fmt.Sprintf("cross-check result %q", f.CrossCheck)
	}
	return ""
}

// execution asks the rail checker registered for the action type about the
// transaction in the receipt, and holds its facts to the outcome rule. It
// never passes unless the receipt, the header trust and the checker all did,
// and a source can make it unchecked but never failed.
func (r *run) execution() {
	blocked := func(on, msg string) { r.unchecked(CheckExecution, ReasonBlocked, errors.New(msg), on) }

	if c, ok := r.rep.Check(CheckReceipt); !ok || c.Status != StatusPass || r.rep.Receipt == nil {
		blocked(string(CheckReceipt), "no receipt that passed")
		return
	}
	if r.rep.State != archive.StateAuthorized || !r.rep.AuthorizationVerified {
		blocked(string(CheckAuthorization), "the decision is not authorized")
		return
	}
	for _, c := range r.rep.Checks {
		if c.Status == StatusFail {
			blocked(string(c.Name), "another check failed")
			return
		}
	}
	if c, ok := r.rep.Check(CheckHeaderTrust); !ok || c.Status != StatusPass || r.v.trust == nil {
		blocked(string(CheckHeaderTrust), "no trusted header")
		return
	}
	chk := r.v.executions[r.c.Action.Type]
	if chk == nil {
		r.unchecked(CheckExecution, ReasonNoChecker, fmt.Errorf("no execution checker for action type %q", r.c.Action.Type))
		return
	}
	if c, ok := r.rep.Check(CheckAction); ok && c.Reason == ReasonPolicyPrivate {
		if err := r.reveal(chk); err != nil {
			r.unchecked(CheckExecution, ReasonTimeout, err)
			return
		}
	}
	if c, ok := r.rep.Check(CheckAction); ok && c.Reason == ReasonPolicyPrivate {
		r.unchecked(CheckExecution, ReasonPolicyPrivate, errors.New("the action is private and no reveal applies"))
		return
	}
	if c, ok := r.rep.Check(CheckAction); !ok || c.Status != StatusPass || r.action == nil {
		blocked(string(CheckAction), "the action did not pass its check")
		return
	}
	if err := commitment.CheckAction(r.c, r.action, r.salt); err != nil {
		blocked(string(CheckAction), fmt.Sprintf("the action bytes are not the committed ones: %v", err))
		return
	}
	facts, err := chk.CheckExecution(r.ctx, ExecutionInput{
		CommitmentHash: r.h, ActionType: r.c.Action.Type, Action: bytes.Clone(r.action),
		RailRef: r.rep.Receipt.RailRef, AnchorHeight: r.c.PayloadRef.Height,
	})
	if facts.Height != 0 || len(facts.Sources) > 0 {
		r.rep.Execution = &ExecutionInfo{
			RailRef: r.rep.Receipt.RailRef, Height: facts.Height, HeaderHash: bytes.Clone(facts.HeaderHash),
			BlockTime: facts.BlockTime, Inclusion: facts.Inclusion, Outcome: facts.Outcome, Result: facts.Result,
			CrossCheck: facts.CrossCheck, Sources: append([]ExecutionSource(nil), facts.Sources...),
		}
	}
	if cerr := r.ctx.Err(); cerr != nil {
		r.unchecked(CheckExecution, ReasonTimeout, cerr)
		return
	}
	if err == nil && factsProblem(facts) == "" {
		// The header the checker used must be the trusted chain's own at that
		// height, whatever the checker did to read it.
		if j, bad := r.headerAtHeight(facts); bad {
			r.apply(j)
			return
		}
		r.rep.Receipt.ProvenExecution = facts.Inclusion == InclusionProven
		if facts.Inclusion != InclusionProven {
			r.warn("execution: no inclusion proof, so the transaction height %d, and with it the order of the anchor before the transaction, is what the transaction source says", facts.Height)
		}
		if r.rep.Authorization != nil && facts.BlockTime > r.rep.Authorization.Expires {
			r.warn("execution_after_expires: the transaction block time %d is after the Authorization expiry %d", facts.BlockTime, r.rep.Authorization.Expires)
		}
	}
	r.apply(JudgeCheck(facts, err, r.c.PayloadRef.Height))
}

// headerAtHeight holds the facts' header to header trust. It returns a
// judgement and true if that stops the check.
func (r *run) headerAtHeight(facts ExecutionFacts) (ExecutionJudgement, bool) {
	res, err := r.v.trust.Trusted(r.ctx, facts.Height, facts.HeaderHash)
	switch {
	case r.ctx.Err() != nil:
		return ExecutionJudgement{Status: StatusUnchecked, Reason: ReasonTimeout, Err: r.ctx.Err()}, true
	case err != nil:
		// The table lists only three header reasons for execution; any other
		// trouble means no source gave a header that links.
		reason, srcs, ok := ReasonOf(err)
		if !ok || (reason != ReasonHeaderAboveCheckpoint && reason != ReasonHeaderDisagreement) {
			reason = ReasonHeaderNotLinking
		}
		return ExecutionJudgement{
			Status: StatusUnchecked, Reason: reason, Sources: srcs,
			Err: fmt.Errorf("header at the transaction height %d: %w", facts.Height, err),
		}, true
	case !res.Checked:
		return ExecutionJudgement{
			Status: StatusUnchecked, Reason: ReasonHeaderNotLinking,
			Err: errors.New("header trust did not check the header at the transaction height"),
		}, true
	case res.CrossCheck == CrossMismatch:
		return ExecutionJudgement{
			Status: StatusUnchecked, Reason: ReasonHeaderDisagreement,
			Err: fmt.Errorf("height %d: %s", facts.Height, DisagreementText),
		}, true
	}
	return ExecutionJudgement{}, false
}

// apply records a judgement as the execution check. A disagreement about a
// header also concerns the trusted chain itself, so header trust is unchecked
// with the same reason: the report must not keep a pass for a chain that a
// source contradicts.
func (r *run) apply(j ExecutionJudgement) {
	switch j.Status {
	case StatusPass:
		r.pass(CheckExecution)
	case StatusFail:
		r.fail(CheckExecution, fmt.Errorf("%w: %w", ErrExecutionInvalid, j.Err))
	default:
		r.unchecked(CheckExecution, j.Reason, j.Err, j.Sources...)
		if j.Reason == ReasonHeaderDisagreement {
			r.rep.HeaderTrust.Status = TrustUnchecked
			r.rep.HeaderTrust.CrossCheck = CrossMismatch
			r.replaceCheck(Check{
				Name: CheckHeaderTrust, Status: StatusUnchecked, Reason: ReasonHeaderDisagreement,
				Err: fmt.Errorf("%w: %s", ErrHeaderTrust, DisagreementText), Sources: j.Sources,
			})
		}
	}
}
