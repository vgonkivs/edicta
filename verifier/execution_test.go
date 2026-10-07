package verifier_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
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
}

func (f *fakeChecker) CheckExecution(_ context.Context, in verifier.ExecutionInput) (verifier.ExecutionFacts, error) {
	f.calls = append(f.calls, in)
	if f.err != nil {
		return verifier.ExecutionFacts{}, f.err
	}
	return f.facts, nil
}

func goodFacts() verifier.ExecutionFacts {
	return verifier.ExecutionFacts{
		Height: execHeight, HeaderHash: execHash, BlockTime: authorizedAt + 20,
		Inclusion: "proven", Result: "node-attested", CrossCheck: "pass", Sources: []string{"rpc-a.example"},
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
	assert.Equal(t, "node-attested", ex.Result)
	assert.Equal(t, "pass", ex.CrossCheck)
	assert.Equal(t, []string{"rpc-a.example"}, ex.Sources)

	assert.Equal(t, []uint64{execHeight}, e.trust.asked, "the header at the transaction height goes through header trust")
	assert.Equal(t, [][]byte{execHash}, e.trust.got)
	require.NotNil(t, rep.Receipt)
	assert.True(t, rep.Receipt.ProvenExecution)
	assert.True(t, rep.Receipt.GateAttested)
}

func TestExecutionNodeAttestedIsNotProven(t *testing.T) {
	e := newExecRig(t, newParts(t), func(f *verifier.ExecutionFacts) { f.Inclusion = "node-attested" })
	rep := e.run(t)
	passed(t, rep, verifier.CheckExecution)
	assert.Equal(t, verifier.VerdictValid, rep.Verdict)
	assert.False(t, rep.Receipt.ProvenExecution)
	assert.Equal(t, "node-attested", rep.Execution.Inclusion)
}

func TestExecutionRequestedIsRequiredForValid(t *testing.T) {
	t.Run("no receipt", func(t *testing.T) {
		e := newExecRig(t, newParts(t), nil)
		rep := e.rig.verify(t, verifier.WithExecutionCheck())
		c, ok := rep.Check(verifier.CheckExecution)
		require.True(t, ok, "a check that never ran cannot pass by being absent")
		assert.Equal(t, verifier.StatusUnchecked, c.Status)
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
		failed(t, rep, verifier.CheckReceipt)
		c, ok := rep.Check(verifier.CheckExecution)
		require.True(t, ok)
		assert.Equal(t, verifier.StatusUnchecked, c.Status)
		assert.Equal(t, verifier.VerdictInvalid, rep.Verdict)
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
		failed(t, rep, verifier.CheckPayload)
		c, ok := rep.Check(verifier.CheckExecution)
		require.True(t, ok)
		assert.Equal(t, verifier.StatusUnchecked, c.Status)
		assert.Equal(t, verifier.VerdictInvalid, rep.Verdict)
		assert.Empty(t, e.chk.calls)
	})
	t.Run("header trust failed", func(t *testing.T) {
		p := newParts(t)
		e := newExecRig(t, p, nil)
		e.rig.trust.hashes = map[uint64][]byte{p.ev.Height: bytes.Repeat([]byte{1}, 32)}
		rep := e.run(t)
		failed(t, rep, verifier.CheckHeaderTrust)
		assert.Equal(t, verifier.VerdictInvalid, rep.Verdict)
		assert.Empty(t, e.chk.calls)
		assert.False(t, rep.Receipt != nil && rep.Receipt.ProvenExecution)
	})
}

func TestExecutionCheckerErrorsAreClassified(t *testing.T) {
	t.Run("a contradiction fails and keeps its cause", func(t *testing.T) {
		e := newExecRig(t, newParts(t), nil)
		e.chk.err = fmt.Errorf("railverify: %w", errContradiction)
		rep := e.run(t)
		c := failed(t, rep, verifier.CheckExecution)
		assert.ErrorIs(t, c.Err, verifier.ErrExecutionInvalid)
		assert.ErrorIs(t, c.Err, errContradiction)
		assert.Equal(t, verifier.VerdictInvalid, rep.Verdict)
		assert.False(t, rep.Receipt.ProvenExecution)
	})
	t.Run("missing facts are unchecked, not invalid", func(t *testing.T) {
		e := newExecRig(t, newParts(t), nil)
		e.chk.err = fmt.Errorf("source down: %w", verifier.ErrExecutionUnchecked)
		rep := e.run(t)
		c, ok := rep.Check(verifier.CheckExecution)
		require.True(t, ok)
		assert.Equal(t, verifier.StatusUnchecked, c.Status)
		assert.ErrorIs(t, c.Err, verifier.ErrExecutionUnchecked)
		assert.NotErrorIs(t, c.Err, verifier.ErrExecutionInvalid)
		assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
		assert.False(t, rep.Receipt.ProvenExecution)
	})
}

func TestExecutionHasToComeAfterTheAnchor(t *testing.T) {
	tests := []struct {
		name   string
		height uint64
		pass   bool
	}{
		{"one block after", anchorHeight + 1, true},
		{"later", execHeight, true},
		{"the anchor block itself", anchorHeight, false},
		{"one block before", anchorHeight - 1, false},
		{"genesis", 1, false},
		{"zero", 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newExecRig(t, newParts(t), func(f *verifier.ExecutionFacts) { f.Height = tc.height })
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
			c := failed(t, rep, verifier.CheckExecution)
			assert.ErrorIs(t, c.Err, verifier.ErrExecutionInvalid)
			assert.Equal(t, verifier.VerdictInvalid, rep.Verdict)
			assert.False(t, rep.Receipt.ProvenExecution)
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
		c := failed(t, rep, verifier.CheckExecution)
		assert.ErrorIs(t, c.Err, verifier.ErrExecutionInvalid)
		assert.Equal(t, verifier.VerdictInvalid, rep.Verdict)
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
		c := failed(t, rep, verifier.CheckExecution)
		assert.ErrorIs(t, c.Err, verifier.ErrExecutionInvalid)
	})
}

func TestExecutionCrossCheck(t *testing.T) {
	tests := []struct {
		cross string
		pass  bool
	}{
		{"pass", true},
		{"unavailable", true},
		{"off", true},
		{"mismatch", false},
		{"", false},
		{"bogus", false},
	}
	for _, tc := range tests {
		t.Run(tc.cross, func(t *testing.T) {
			e := newExecRig(t, newParts(t), func(f *verifier.ExecutionFacts) { f.CrossCheck = tc.cross })
			rep := e.run(t)
			if !tc.pass {
				c := failed(t, rep, verifier.CheckExecution)
				assert.ErrorIs(t, c.Err, verifier.ErrExecutionInvalid)
				assert.Equal(t, verifier.VerdictInvalid, rep.Verdict)
				assert.False(t, rep.Receipt.ProvenExecution)
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
	}{
		{"inclusion is neither proven nor node-attested", func(f *verifier.ExecutionFacts) { f.Inclusion = "trust-me" }},
		{"inclusion is empty", func(f *verifier.ExecutionFacts) { f.Inclusion = "" }},
		{"result claims more than node-attested", func(f *verifier.ExecutionFacts) { f.Result = "proven" }},
		{"result is empty", func(f *verifier.ExecutionFacts) { f.Result = "" }},
		{"no header hash", func(f *verifier.ExecutionFacts) { f.HeaderHash = nil }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newExecRig(t, newParts(t), tc.mod)
			rep := e.run(t)
			c, ok := rep.Check(verifier.CheckExecution)
			require.True(t, ok)
			assert.NotEqual(t, verifier.StatusPass, c.Status)
			assert.NotEqual(t, verifier.VerdictValid, rep.Verdict)
			assert.False(t, rep.Receipt.ProvenExecution)
		})
	}
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
