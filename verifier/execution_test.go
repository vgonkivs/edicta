package verifier_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/test/gatefix"
	"github.com/vgonkivs/edicta/verifier"
)

const execHeight = anchorHeight + 3

var execHash = func() []byte { h := sha256.Sum256([]byte("exec-header")); return h[:] }()

var errContradiction = errors.New("fake checker: the transaction is not the authorized action")

type fakeChecker struct {
	facts verifier.ExecutionFacts
	err   error
	calls []verifier.ExecutionInput
	// onCall runs inside the call, to model a deadline that expires there.
	onCall func()
}

func (f *fakeChecker) CheckExecution(_ context.Context, in verifier.ExecutionInput) (verifier.ExecutionFacts, error) {
	f.calls = append(f.calls, in)
	if f.onCall != nil {
		f.onCall()
	}
	if f.err != nil {
		return verifier.ExecutionFacts{}, f.err
	}
	return f.facts, nil
}

func goodFacts() verifier.ExecutionFacts {
	return verifier.ExecutionFacts{
		Height: execHeight, HeaderHash: execHash, BlockTime: authorizedAt + 20,
		Inclusion: "proven", Outcome: "success", Result: "proven", CrossCheck: "pass",
		Sources: []verifier.ExecutionSource{{Name: "rpc-a.example", Role: verifier.RolePrimary, Result: verifier.SourceUsed}},
	}
}

// heightTrust answers for the execution height itself and leaves the anchor
// height to the rig's trust.
type heightTrust struct {
	base  verifier.HeaderTrust
	hash  []byte
	err   error
	res   verifier.TrustResult
	asked []uint64
	got   [][]byte
}

func (h *heightTrust) Trusted(ctx context.Context, height uint64, hash []byte) (verifier.TrustResult, error) {
	if height != execHeight {
		return h.base.Trusted(ctx, height, hash)
	}
	h.asked = append(h.asked, height)
	h.got = append(h.got, bytes.Clone(hash))
	if h.err != nil {
		return h.res, h.err
	}
	if !bytes.Equal(h.hash, hash) {
		return verifier.TrustResult{}, errFakeTrust
	}
	return h.res, nil
}

type execRig struct {
	*rig
	chk   *fakeChecker
	trust *heightTrust
}

func newExecRig(t *testing.T, p *parts, mod func(*verifier.ExecutionFacts)) *execRig {
	t.Helper()
	r := newRig(t, p)
	f := goodFacts()
	if mod != nil {
		mod(&f)
	}
	e := &execRig{rig: r, chk: &fakeChecker{facts: f}}
	e.trust = &heightTrust{
		base: r.trust, hash: execHash,
		res: verifier.TrustResult{Checked: true, CheckpointH: checkpointH, CheckpointHash: bytes.Repeat([]byte{0xcc}, 32), CrossCheck: "pass"},
	}
	r.deps.Trust = e.trust
	r.deps.Executions = map[string]verifier.ExecutionChecker{gatefix.ActionType: e.chk}
	return e
}

func (e *execRig) run(t *testing.T) verifier.Report {
	t.Helper()
	return e.rig.verify(t, verifier.WithReceipt(validReceipt(t, e.p)), verifier.WithExecutionCheck())
}

func TestExecutionIsOptional(t *testing.T) {
	p := newParts(t)
	e := newExecRig(t, p, nil)
	rep := e.rig.verify(t, verifier.WithReceipt(validReceipt(t, p)))
	assert.Empty(t, e.chk.calls)
	_, ok := rep.Check(verifier.CheckExecution)
	assert.False(t, ok)
	assert.Nil(t, rep.Execution)
	assert.Equal(t, verifier.VerdictValid, rep.Verdict)
	require.NotNil(t, rep.Receipt)
	assert.False(t, rep.Receipt.ProvenExecution)
}

func TestExecutionPassesAndIsReported(t *testing.T) {
	p := newParts(t)
	e := newExecRig(t, p, nil)
	rep := e.run(t)

	passed(t, rep, verifier.CheckExecution)
	assert.Equal(t, verifier.VerdictValid, rep.Verdict)

	require.Len(t, e.chk.calls, 1)
	in := e.chk.calls[0]
	assert.Equal(t, p.hash, in.CommitmentHash)
	assert.Equal(t, gatefix.ActionType, in.ActionType)
	assert.Equal(t, p.action, in.Action, "the archived action bytes, as matched by the action check")
	assert.Equal(t, railRef, in.RailRef, "the rail reference of the receipt")

	require.NotNil(t, rep.Execution)
	ex := rep.Execution
	assert.Equal(t, railRef, ex.RailRef)
	assert.Equal(t, execHeight, ex.Height)
	assert.Equal(t, execHash, ex.HeaderHash)
	assert.Equal(t, authorizedAt+20, ex.BlockTime)
	assert.Equal(t, "proven", ex.Inclusion)
	assert.Equal(t, "success", ex.Outcome)
	assert.Equal(t, "proven", ex.Result)
	assert.Equal(t, "pass", ex.CrossCheck)
	assert.Equal(t, goodFacts().Sources, ex.Sources)

	assert.Equal(t, []uint64{execHeight}, e.trust.asked, "the header at the transaction height goes through header trust")
	assert.Equal(t, [][]byte{execHash}, e.trust.got)
	require.NotNil(t, rep.Receipt)
	assert.True(t, rep.Receipt.ProvenExecution)
	assert.True(t, rep.Receipt.GateAttested)
}

func TestExecutionNodeAttestedIsNotProven(t *testing.T) {
	e := newExecRig(t, newParts(t), func(f *verifier.ExecutionFacts) {
		f.Inclusion, f.Result = "node-attested", "cross-confirmed"
	})
	rep := e.run(t)
	passed(t, rep, verifier.CheckExecution)
	assert.Equal(t, verifier.VerdictValid, rep.Verdict)
	assert.False(t, rep.Receipt.ProvenExecution)
	assert.Equal(t, "node-attested", rep.Execution.Inclusion)
	assert.Contains(t, strings.Join(rep.Warnings, "\n"), "no inclusion proof", "the ordering rests on the source's height")

	proven := newExecRig(t, newParts(t), nil)
	assert.NotContains(t, strings.Join(proven.run(t).Warnings, "\n"), "no inclusion proof")
}

func TestExecutionRequestedIsRequiredForValid(t *testing.T) {
	t.Run("no receipt", func(t *testing.T) {
		e := newExecRig(t, newParts(t), nil)
		rep := e.rig.verify(t, verifier.WithExecutionCheck())
		c, ok := rep.Check(verifier.CheckExecution)
		require.True(t, ok, "a check that never ran cannot pass by being absent")
		assert.Equal(t, verifier.StatusUnchecked, c.Status)
		assert.Equal(t, verifier.ReasonBlocked, c.Reason)
		assert.Equal(t, []string{"receipt"}, c.Sources, "the check names what it waits for")
		require.Error(t, c.Err)
		assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
		assert.Empty(t, e.chk.calls)
		assert.Nil(t, rep.Execution)
	})
	t.Run("bad receipt", func(t *testing.T) {
		p := newParts(t)
		e := newExecRig(t, p, nil)
		bad := signReceipt(t, gatefix.Key(t, "agent2"), p, nil)
		rep := e.rig.verify(t, verifier.WithReceipt(bad), verifier.WithExecutionCheck())
		rc, ok := rep.Check(verifier.CheckReceipt)
		require.True(t, ok)
		assert.Equal(t, verifier.StatusUnchecked, rc.Status, "a receipt of a key that is not on record says nothing about the decision")
		assert.Equal(t, verifier.ReasonReceiptMismatch, rc.Reason)
		c, ok := rep.Check(verifier.CheckExecution)
		require.True(t, ok)
		assert.Equal(t, verifier.StatusUnchecked, c.Status)
		assert.Equal(t, verifier.ReasonBlocked, c.Reason)
		assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
		assert.Empty(t, e.chk.calls, "a receipt that did not pass names no rail reference to trust")
		assert.False(t, rep.Receipt != nil && rep.Receipt.ProvenExecution)
	})
	t.Run("no checker for the action type", func(t *testing.T) {
		p := newParts(t)
		for name, m := range map[string]map[string]verifier.ExecutionChecker{
			"nil map":    nil,
			"other type": {"application/other": &fakeChecker{facts: goodFacts()}},
			"empty map":  {},
		} {
			e := newExecRig(t, p, nil)
			e.rig.deps.Executions = m
			rep := e.run(t)
			c, ok := rep.Check(verifier.CheckExecution)
			require.True(t, ok, name)
			assert.Equal(t, verifier.StatusUnchecked, c.Status, name)
			assert.Equal(t, verifier.ReasonNoChecker, c.Reason, name)
			assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict, name)
		}
	})
}

func TestExecutionNeedsTheAuthorizedStateAndNoOtherFailure(t *testing.T) {
	t.Run("pending", func(t *testing.T) {
		p := newParts(t)
		p.auth = nil
		e := newExecRig(t, p, nil)
		rep := e.rig.verify(t, verifier.WithReceipt(validReceipt(t, p)), verifier.WithExecutionCheck())
		assert.Equal(t, verifier.VerdictNotAuthorized, rep.Verdict)
		assert.Empty(t, e.chk.calls, "no receipt is evidence for a decision that was not authorized")
		assert.Nil(t, rep.Execution)
		if c, ok := rep.Check(verifier.CheckExecution); ok {
			assert.NotEqual(t, verifier.StatusPass, c.Status)
		}
	})
	t.Run("rejected", func(t *testing.T) {
		p := newParts(t)
		p.auth = nil
		p.markers = []string{"ErrExpired"}
		e := newExecRig(t, p, nil)
		rep := e.rig.verify(t, verifier.WithReceipt(validReceipt(t, p)), verifier.WithExecutionCheck())
		assert.Equal(t, verifier.VerdictNotAuthorized, rep.Verdict)
		assert.Empty(t, e.chk.calls)
	})
	t.Run("payload does not recompute", func(t *testing.T) {
		p := newParts(t)
		p.permissive = true
		p.blob = bytes.Clone(p.blob)
		p.blob[len(p.blob)-1] ^= 1
		e := newExecRig(t, p, nil)
		rep := e.run(t)
		c, ok := rep.Check(verifier.CheckPayload)
		require.True(t, ok)
		assert.Equal(t, verifier.StatusUnchecked, c.Status, "a damaged copy is a source problem")
		assert.Equal(t, verifier.ReasonSourceCorrupt, c.Reason)
		assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
	})
	t.Run("header trust did not pass", func(t *testing.T) {
		p := newParts(t)
		e := newExecRig(t, p, nil)
		e.rig.trust.hashes = map[uint64][]byte{p.ev.Height: bytes.Repeat([]byte{1}, 32)}
		rep := e.run(t)
		c, ok := rep.Check(verifier.CheckHeaderTrust)
		require.True(t, ok)
		assert.Equal(t, verifier.StatusUnchecked, c.Status)
		assert.Equal(t, verifier.ReasonChainMismatch, c.Reason)
		assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
		assert.Empty(t, e.chk.calls)
		ec, ok := rep.Check(verifier.CheckExecution)
		require.True(t, ok)
		assert.Equal(t, verifier.ReasonBlocked, ec.Reason)
		assert.Equal(t, []string{"header_trust"}, ec.Sources)
		assert.False(t, rep.Receipt != nil && rep.Receipt.ProvenExecution)
	})
}

func TestExecutionCheckerErrorsAreClassified(t *testing.T) {
	t.Run("a contradiction fails and keeps its cause", func(t *testing.T) {
		e := newExecRig(t, newParts(t), nil)
		e.chk.err = fmt.Errorf("railverify: %w: %w", verifier.ErrExecutionViolation, errContradiction)
		rep := e.run(t)
		c := failed(t, rep, verifier.CheckExecution)
		assert.ErrorIs(t, c.Err, verifier.ErrExecutionInvalid)
		assert.ErrorIs(t, c.Err, errContradiction)
		assert.Equal(t, verifier.VerdictInvalid, rep.Verdict)
		assert.False(t, rep.Receipt.ProvenExecution)
	})
	t.Run("an error that does not prove a violation is a source problem", func(t *testing.T) {
		for name, err := range map[string]error{
			"marked as no facts": fmt.Errorf("source down: %w", verifier.ErrExecutionUnchecked),
			"unmarked":           errContradiction,
		} {
			e := newExecRig(t, newParts(t), nil)
			e.chk.err = err
			rep := e.run(t)
			c, ok := rep.Check(verifier.CheckExecution)
			require.True(t, ok, name)
			assert.Equal(t, verifier.StatusUnchecked, c.Status, name)
			assert.NotErrorIs(t, c.Err, verifier.ErrExecutionInvalid, name)
			assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict, name)
			assert.False(t, rep.Receipt.ProvenExecution, name)
		}
	})
	t.Run("the reason and the sources of the checker's error are kept", func(t *testing.T) {
		e := newExecRig(t, newParts(t), nil)
		e.chk.err = verifier.WithReason(verifier.ReasonTxNotFound, []string{"rpc-a.example"}, fmt.Errorf("gone: %w", verifier.ErrExecutionUnchecked))
		rep := e.run(t)
		c, ok := rep.Check(verifier.CheckExecution)
		require.True(t, ok)
		assert.Equal(t, verifier.ReasonTxNotFound, c.Reason)
		assert.Equal(t, []string{"rpc-a.example"}, c.Sources)
	})
	t.Run("a header disagreement also leaves header trust unchecked", func(t *testing.T) {
		e := newExecRig(t, newParts(t), nil)
		e.chk.err = verifier.WithReason(verifier.ReasonHeaderDisagreement, []string{"rpc-x.example"}, fmt.Errorf("%w: cross", verifier.ErrExecutionUnchecked))
		rep := e.run(t)
		c, ok := rep.Check(verifier.CheckExecution)
		require.True(t, ok)
		assert.Equal(t, verifier.ReasonHeaderDisagreement, c.Reason)
		ht, ok := rep.Check(verifier.CheckHeaderTrust)
		require.True(t, ok)
		assert.Equal(t, verifier.StatusUnchecked, ht.Status, "a contradiction about the chain cannot leave a pass behind it")
		assert.Equal(t, verifier.ReasonHeaderDisagreement, ht.Reason)
		assert.Equal(t, verifier.TrustUnchecked, rep.HeaderTrust.Status)
		assert.Equal(t, "mismatch", rep.HeaderTrust.CrossCheck)
		assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
	})
	t.Run("a run that timed out during the check", func(t *testing.T) {
		e := newExecRig(t, newParts(t), nil)
		ctx, cancel := context.WithCancel(context.Background())
		e.chk.onCall = cancel
		e.chk.err = errContradiction
		rep, err := e.rig.verifier(t).Verify(ctx, e.p.hash, verifier.WithReceipt(validReceipt(t, e.p)), verifier.WithExecutionCheck())
		require.NoError(t, err)
		c, ok := rep.Check(verifier.CheckExecution)
		require.True(t, ok)
		assert.Equal(t, verifier.StatusUnchecked, c.Status)
		assert.Equal(t, verifier.ReasonTimeout, c.Reason)
	})
}

func TestExecutionHasToComeAfterTheAnchor(t *testing.T) {
	tests := []struct {
		name   string
		height uint64
		// inclusion is the level of the facts; a height is only a source's
		// claim unless a proof binds it.
		inclusion string
		result    string
		pass      bool
		// reason is set when the outcome is unchecked, not a violation.
		reason verifier.Reason
	}{
		{"one block after", anchorHeight + 1, "proven", "proven", true, ""},
		{"later", execHeight, "proven", "proven", true, ""},
		{"the anchor block itself", anchorHeight, "proven", "proven", false, ""},
		{"one block before", anchorHeight - 1, "proven", "proven", false, ""},
		{"genesis", 1, "proven", "proven", false, ""},
		{"the anchor block itself, no proof", anchorHeight, "node-attested", "cross-confirmed", false, verifier.ReasonHeightUnproven},
		{"one block before, no proof", anchorHeight - 1, "node-attested", "cross-confirmed", false, verifier.ReasonHeightUnproven},
		{"zero is no height at all", 0, "proven", "proven", false, verifier.ReasonTxSourceUnavailable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newExecRig(t, newParts(t), func(f *verifier.ExecutionFacts) {
				f.Height, f.Inclusion, f.Result = tc.height, tc.inclusion, tc.result
			})
			anchorHash := sha256.Sum256(goodHeader())
			e.rig.deps.Trust = knownHeaders{
				{anchorHeight, string(anchorHash[:])}: true,
				{tc.height, string(execHash)}:         true,
			}
			rep := e.run(t)
			if tc.pass {
				passed(t, rep, verifier.CheckExecution)
				assert.Equal(t, verifier.VerdictValid, rep.Verdict)
				return
			}
			if tc.reason != "" {
				unchecked(t, rep, verifier.CheckExecution, tc.reason)
				assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict, "a height that no proof binds does not make the decision invalid")
				return
			}
			c := failed(t, rep, verifier.CheckExecution)
			assert.ErrorIs(t, c.Err, verifier.ErrExecutionInvalid)
			assert.ErrorIs(t, c.Err, verifier.ErrExecutionBeforeAnchor)
			assert.Equal(t, verifier.VerdictInvalid, rep.Verdict)
			assert.True(t, rep.Receipt.ProvenExecution, "the proof of inclusion holds, and shows the transaction was too early")
		})
	}
}

// knownHeaders trusts exactly the listed (height, hash) pairs, so that a
// test can isolate one rule from header trust.
type knownHeaders map[struct {
	height uint64
	hash   string
}]bool

func (k knownHeaders) Trusted(_ context.Context, height uint64, hash []byte) (verifier.TrustResult, error) {
	if !k[struct {
		height uint64
		hash   string
	}{height, string(hash)}] {
		return verifier.TrustResult{}, errFakeTrust
	}
	return verifier.TrustResult{Checked: true, CheckpointH: checkpointH, CheckpointHash: bytes.Repeat([]byte{0xcc}, 32), CrossCheck: "pass"}, nil
}

func TestExecutionHeaderGoesThroughHeaderTrust(t *testing.T) {
	t.Run("a header the chain does not have", func(t *testing.T) {
		e := newExecRig(t, newParts(t), nil)
		e.trust.hash = bytes.Repeat([]byte{9}, 32)
		rep := e.run(t)
		passed(t, rep, verifier.CheckHeaderTrust)
		c, ok := rep.Check(verifier.CheckExecution)
		require.True(t, ok)
		assert.Equal(t, verifier.StatusUnchecked, c.Status, "the header comes from an online source, so the fault is the source's")
		assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
		assert.False(t, rep.Receipt.ProvenExecution)
	})
	t.Run("trusted header does not reach the height", func(t *testing.T) {
		e := newExecRig(t, newParts(t), nil)
		e.trust.err = fmt.Errorf("%w: checkpoint %d, needed %d", verifier.ErrTrustInput, anchorHeight+2, execHeight)
		rep := e.run(t)
		passed(t, rep, verifier.CheckHeaderTrust)
		c, ok := rep.Check(verifier.CheckExecution)
		require.True(t, ok)
		assert.Equal(t, verifier.StatusUnchecked, c.Status)
		assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
		assert.False(t, rep.Receipt.ProvenExecution)
	})
	t.Run("trust did not check", func(t *testing.T) {
		e := newExecRig(t, newParts(t), nil)
		e.trust.res.Checked = false
		rep := e.run(t)
		c, ok := rep.Check(verifier.CheckExecution)
		require.True(t, ok)
		assert.Equal(t, verifier.StatusUnchecked, c.Status)
		assert.False(t, rep.Receipt.ProvenExecution)
		assert.NotEqual(t, verifier.VerdictValid, rep.Verdict)
	})
	t.Run("no trusted header at all", func(t *testing.T) {
		e := newExecRig(t, newParts(t), nil)
		e.rig.deps.Trust = nil
		rep := e.run(t)
		c, ok := rep.Check(verifier.CheckExecution)
		require.True(t, ok)
		assert.Equal(t, verifier.StatusUnchecked, c.Status)
		assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
		assert.Empty(t, e.chk.calls, "no other check may fail, and header trust is unchecked, so the rail is not even asked")
	})
	t.Run("an unrelated trust failure at the execution height", func(t *testing.T) {
		e := newExecRig(t, newParts(t), nil)
		e.trust.err = errors.New("headertrust: header chain does not link to the trusted header")
		rep := e.run(t)
		c, ok := rep.Check(verifier.CheckExecution)
		require.True(t, ok)
		assert.Equal(t, verifier.StatusUnchecked, c.Status)
		assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
	})
}

func TestExecutionCrossCheck(t *testing.T) {
	tests := []struct {
		cross string
		// proven: the result is bound by a result proof, so a source that
		// contradicts it changes nothing.
		proven bool
		pass   bool
		reason verifier.Reason
	}{
		{"pass", true, true, ""},
		{"unavailable", true, true, ""},
		{"off", true, true, ""},
		{"mismatch", true, true, ""},
		{"mismatch", false, false, verifier.ReasonCrossDisagree},
		{"unavailable", false, false, verifier.ReasonResultUnproven},
		{"off", false, false, verifier.ReasonResultUnproven},
		{"pass", false, true, ""},
		{"", true, false, verifier.ReasonTxSourceUnavailable},
		{"bogus", true, false, verifier.ReasonTxSourceUnavailable},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("%s/proven=%t", tc.cross, tc.proven), func(t *testing.T) {
			e := newExecRig(t, newParts(t), func(f *verifier.ExecutionFacts) {
				f.CrossCheck = tc.cross
				if !tc.proven {
					f.Result = "node-attested"
					if tc.cross == "pass" {
						f.Result = "cross-confirmed"
					}
				}
			})
			rep := e.run(t)
			if !tc.pass {
				c := unchecked(t, rep, verifier.CheckExecution, tc.reason)
				assert.NotErrorIs(t, c.Err, verifier.ErrExecutionInvalid, "a disagreement between sources is never a finding")
				assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
				return
			}
			passed(t, rep, verifier.CheckExecution)
			assert.Equal(t, tc.cross, rep.Execution.CrossCheck, "reported as it is, never as a pass")
			assert.Equal(t, verifier.VerdictValid, rep.Verdict)
		})
	}
}

func TestExecutionFactsAreHeldToTheCore(t *testing.T) {
	tests := []struct {
		name string
		mod  func(*verifier.ExecutionFacts)
		// included: the facts are usable and their inclusion proof holds,
		// so the report says so even though the outcome is not a pass.
		included bool
	}{
		{"inclusion is neither proven nor node-attested", func(f *verifier.ExecutionFacts) { f.Inclusion = "trust-me" }, false},
		{"inclusion is empty", func(f *verifier.ExecutionFacts) { f.Inclusion = "" }, false},
		{"result is not one of the three", func(f *verifier.ExecutionFacts) { f.Result = "trust-me" }, false},
		{"result is empty", func(f *verifier.ExecutionFacts) { f.Result = "" }, false},
		{"outcome is empty", func(f *verifier.ExecutionFacts) { f.Outcome = "" }, false},
		{"no header hash", func(f *verifier.ExecutionFacts) { f.HeaderHash = nil }, false},
		{"a proven result with no proven inclusion", func(f *verifier.ExecutionFacts) { f.Inclusion = "node-attested" }, false},
		{"cross-confirmed without a cross pass", func(f *verifier.ExecutionFacts) { f.Result, f.CrossCheck = "cross-confirmed", "unavailable" }, true},
		{"a result that only one source attests", func(f *verifier.ExecutionFacts) { f.Result = "node-attested" }, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newExecRig(t, newParts(t), tc.mod)
			rep := e.run(t)
			c, ok := rep.Check(verifier.CheckExecution)
			require.True(t, ok)
			assert.Equal(t, verifier.StatusUnchecked, c.Status)
			assert.NotEqual(t, verifier.VerdictValid, rep.Verdict)
			assert.Equal(t, tc.included, rep.Receipt.ProvenExecution)
		})
	}
}

func TestExecutionFailsOnlyOnAProvenFailedResult(t *testing.T) {
	t.Run("proven failure", func(t *testing.T) {
		e := newExecRig(t, newParts(t), func(f *verifier.ExecutionFacts) { f.Outcome = "failure" })
		rep := e.run(t)
		c := failed(t, rep, verifier.CheckExecution)
		assert.ErrorIs(t, c.Err, verifier.ErrExecutionFailed)
		assert.Equal(t, verifier.VerdictInvalid, rep.Verdict)
	})
	for _, result := range []string{"cross-confirmed", "node-attested"} {
		t.Run("a failure that only sources attest ("+result+")", func(t *testing.T) {
			e := newExecRig(t, newParts(t), func(f *verifier.ExecutionFacts) { f.Outcome, f.Result = "failure", result })
			rep := e.run(t)
			c := unchecked(t, rep, verifier.CheckExecution, verifier.ReasonCodeUnproven)
			assert.ErrorIs(t, c.Err, verifier.ErrExecutionResultUnconfirmed)
			assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
		})
	}
	t.Run("another chain under a proof", func(t *testing.T) {
		e := newExecRig(t, newParts(t), func(f *verifier.ExecutionFacts) { f.ChainMismatch = true })
		rep := e.run(t)
		c := failed(t, rep, verifier.CheckExecution)
		assert.ErrorIs(t, c.Err, verifier.ErrExecutionChain)
	})
	t.Run("another chain with no proof", func(t *testing.T) {
		e := newExecRig(t, newParts(t), func(f *verifier.ExecutionFacts) {
			f.ChainMismatch, f.Inclusion, f.Result = true, "node-attested", "cross-confirmed"
		})
		rep := e.run(t)
		unchecked(t, rep, verifier.CheckExecution, verifier.ReasonChainUnbound)
	})
}

func TestExecutionResultProblemNamesTheCause(t *testing.T) {
	problem := verifier.WithReason(verifier.ReasonResultsRootMismatch, []string{"rpc-b.example"}, errors.New("root differs"))
	e := newExecRig(t, newParts(t), func(f *verifier.ExecutionFacts) {
		f.Result, f.CrossCheck, f.ResultProblem = "node-attested", "off", problem
	})
	rep := e.run(t)
	unchecked(t, rep, verifier.CheckExecution, verifier.ReasonResultsRootMismatch)
	assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)

	// A problem with no proven inclusion says nothing about the results.
	e = newExecRig(t, newParts(t), func(f *verifier.ExecutionFacts) {
		f.Inclusion, f.Result, f.CrossCheck, f.ResultProblem = "node-attested", "node-attested", "off", problem
	})
	unchecked(t, e.run(t), verifier.CheckExecution, verifier.ReasonResultUnproven)
}

func TestExecutionAfterExpiresWarnsButDoesNotChangeTheVerdict(t *testing.T) {
	tests := []struct {
		name string
		at   uint64
		warn bool
	}{
		{"before expires", authExpires - 1, false},
		{"at expires", authExpires, false},
		{"one second after", authExpires + 1, true},
		{"long after", authExpires + 3600, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newExecRig(t, newParts(t), func(f *verifier.ExecutionFacts) { f.BlockTime = tc.at })
			rep := e.run(t)
			passed(t, rep, verifier.CheckExecution)
			assert.Equal(t, verifier.VerdictValid, rep.Verdict)
			joined := fmt.Sprint(rep.Warnings)
			if tc.warn {
				assert.Contains(t, joined, "execution_after_expires")
				assert.True(t, rep.Receipt.ProvenExecution, "the warning does not undo the proof of inclusion")
			} else {
				assert.NotContains(t, joined, "execution_after_expires")
			}
		})
	}
}

func TestNewRefusesANilExecutionChecker(t *testing.T) {
	r := newRig(t, newParts(t))
	var nilChecker verifier.ExecutionChecker
	r.deps.Executions = map[string]verifier.ExecutionChecker{gatefix.ActionType: nilChecker}
	_, err := verifier.New(r.deps)
	assert.ErrorIs(t, err, verifier.ErrInvalidConfig)
}
