package verifier_test

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/test/gatefix"
	"github.com/vgonkivs/edicta/verifier"
)

var requiredChecks = []verifier.CheckName{
	verifier.CheckDecision, verifier.CheckEnvelope, verifier.CheckAction, verifier.CheckAuthorization,
	verifier.CheckPayload, verifier.CheckAnchor, verifier.CheckAnchorTime, verifier.CheckHeaderTrust,
}

type trustFunc func(ctx context.Context, height uint64, hash []byte) (verifier.TrustResult, error)

func (f trustFunc) Trusted(ctx context.Context, height uint64, hash []byte) (verifier.TrustResult, error) {
	return f(ctx, height, hash)
}

// damagedReader reads a decision whose Authorization record does not decode.
type damagedReader struct {
	verifier.Reader
}

func (damagedReader) State(context.Context, commitment.Hash) (archive.DecisionState, error) {
	return archive.DecisionState{}, fmt.Errorf("authorization: %w", archive.ErrCorrupt)
}

func (damagedReader) Authorization(context.Context, commitment.Hash) (*archive.AuthorizationRecord, error) {
	return nil, fmt.Errorf("authorization: %w", archive.ErrCorrupt)
}

// otherDecisionsAuthorization serves an Authorization signed by the gate for
// another decision, as a copy that was swapped under this decision's key.
type otherDecisionsAuthorization struct {
	verifier.Reader
	auth []byte
}

func (o otherDecisionsAuthorization) Authorization(context.Context, commitment.Hash) (*archive.AuthorizationRecord, error) {
	return &archive.AuthorizationRecord{SignedAuthorization: o.auth, AuthorizedAt: authorizedAt}, nil
}

func TestAuthorizationOfAnotherDecisionIsASourceProblem(t *testing.T) {
	p := newParts(t)
	r := newRig(t, p)
	otherHash := p.hash
	otherHash[0] ^= 1
	r.deps.Archive = otherDecisionsAuthorization{Reader: r.store, auth: signAuth(t, gateKey(t), otherHash, p.c, commitment.PathDA, authExpires)}
	rep := r.verify(t)
	assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
	c := unchecked(t, rep, verifier.CheckAuthorization, verifier.ReasonSourceCorrupt)
	requireOnly(t, c.Err, verifier.ErrAuthorizationInvalid)
	assert.False(t, rep.AuthorizationVerified)
}

func TestAgentKeyEqualToAGateKeyFailsTheEnvelope(t *testing.T) {
	p := newParts(t)
	c := gatefix.WithKey(t, p.c, "gate1")
	p.c = c
	p.env, p.hash = gatefix.Sign(t, "gate1", c)
	p.auth = signAuth(t, gateKey(t), p.hash, c, commitment.PathDA, authExpires)

	rep := newRig(t, p).verify(t)
	assert.Equal(t, verifier.VerdictInvalid, rep.Verdict)
	c1 := failed(t, rep, verifier.CheckEnvelope)
	requireOnly(t, c1.Err, verifier.ErrEnvelopeInvalid)
}

func TestValidNeedsEveryRequiredCheckToPass(t *testing.T) {
	scenarios := map[string]func(r *rig){
		"trust is absent":          func(r *rig) { r.deps.Trust = nil },
		"trust checked nothing":    func(r *rig) { r.trust.res = verifier.TrustResult{} },
		"anchor verifier declines": func(r *rig) { r.deps.Anchors[commitment.DACelestiaBlob] = declines{} },
		"trust input is missing": func(r *rig) {
			r.deps.Trust = trustFunc(func(context.Context, uint64, []byte) (verifier.TrustResult, error) {
				return verifier.TrustResult{}, verifier.ErrTrustInput
			})
		},
		"complete": func(*rig) {},
	}
	for name, mod := range scenarios {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, newParts(t))
			mod(r)
			rep := r.verify(t)
			if rep.Verdict != verifier.VerdictValid {
				assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
				return
			}
			for _, n := range requiredChecks {
				passed(t, rep, n)
			}
		})
	}
}

type declines struct{}

func (declines) VerifyAnchor(commitment.PayloadRef, *archive.EvidenceRecord) (verifier.AnchorFacts, error) {
	return verifier.AnchorFacts{}, verifier.ErrAnchorUnsupported
}

func TestInsufficientTrustInputIsUncheckedWithTheCheckpointReported(t *testing.T) {
	r := newRig(t, newParts(t))
	cpHash := bytes.Repeat([]byte{0xab}, 32)
	r.deps.Trust = trustFunc(func(context.Context, uint64, []byte) (verifier.TrustResult, error) {
		return verifier.TrustResult{CheckpointH: anchorHeight - 1, CheckpointHash: cpHash},
			fmt.Errorf("%w: checkpoint below the height", verifier.ErrTrustInput)
	})
	rep := r.verify(t)
	assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
	assert.Equal(t, verifier.TrustUnchecked, rep.HeaderTrust.Status)
	c, ok := rep.Check(verifier.CheckHeaderTrust)
	require.True(t, ok)
	assert.Equal(t, verifier.StatusUnchecked, c.Status)
	require.ErrorIs(t, c.Err, verifier.ErrTrustInput)
	assert.Equal(t, anchorHeight-1, rep.HeaderTrust.CheckpointH)
	assert.Equal(t, cpHash, rep.HeaderTrust.CheckpointHash)
}

func TestHeaderTrustFieldsAreReportedWhateverTheStatus(t *testing.T) {
	cpHash := bytes.Repeat([]byte{0xcd}, 32)
	tests := []struct {
		name   string
		res    verifier.TrustResult
		err    error
		status verifier.TrustStatus
		cross  string
	}{
		{"contradicted", verifier.TrustResult{CheckpointH: checkpointH, CheckpointHash: cpHash, CrossCheck: "mismatch"}, errFakeTrust, verifier.TrustUnchecked, "mismatch"},
		{"unchecked", verifier.TrustResult{CheckpointH: checkpointH, CheckpointHash: cpHash}, nil, verifier.TrustUnchecked, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, newParts(t))
			r.deps.Trust = trustFunc(func(context.Context, uint64, []byte) (verifier.TrustResult, error) { return tc.res, tc.err })
			rep := r.verify(t)
			assert.Equal(t, tc.status, rep.HeaderTrust.Status)
			assert.Equal(t, checkpointH, rep.HeaderTrust.CheckpointH)
			assert.Equal(t, cpHash, rep.HeaderTrust.CheckpointHash)
			assert.Equal(t, tc.cross, rep.HeaderTrust.CrossCheck)
		})
	}
}

func TestReceiptIsCheckedOnlyWhenNothingFailed(t *testing.T) {
	tests := []struct {
		name  string
		parts func(p *parts)
		rig   func(r *rig)
		ran   bool
	}{
		{"nothing failed", func(*parts) {}, func(*rig) {}, true},
		{"unchecked trust does not stop it", func(*parts) {}, func(r *rig) { r.deps.Trust = nil }, true},
		{"an anchor that did not verify does not stop it", func(p *parts) { p.ev.Header = []byte("garbage") }, func(*rig) {}, true},
		{"header trust that did not hold does not stop it", func(*parts) {}, func(r *rig) { r.trust.err = errFakeTrust }, true},
		{"anchor time failed", func(*parts) {}, func(r *rig) { r.anchor.blockTime = r.p.c.IssuedAt + r.deps.Config.Params.SkewS + 1 }, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newParts(t)
			tc.parts(p)
			r := newRig(t, p)
			tc.rig(r)
			rep := r.verify(t, verifier.WithReceipt(validReceipt(t, p)))
			_, ok := rep.Check(verifier.CheckReceipt)
			assert.Equal(t, tc.ran, ok)
			assert.Equal(t, tc.ran, rep.Receipt != nil)
		})
	}
}

func TestAuthorizationVerifiedIsNotTheVerdict(t *testing.T) {
	r := newRig(t, newParts(t))
	r.trust.err = errFakeTrust
	rep := r.verify(t)
	assert.True(t, rep.AuthorizationVerified, "the Authorization itself verified")
	assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict, "another check could not be done")
}

func TestCorruptAuthorizationRecordIsReportedUnderAuthorization(t *testing.T) {
	r := newRig(t, newParts(t))
	r.deps.Archive = damagedReader{r.store}
	rep := r.verify(t)
	assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
	passed(t, rep, verifier.CheckDecision)
	c := unchecked(t, rep, verifier.CheckAuthorization, verifier.ReasonSourceCorrupt)
	requireOnly(t, c.Err, verifier.ErrAuthorizationInvalid)
	require.ErrorIs(t, c.Err, archive.ErrCorrupt)
	assert.False(t, rep.AuthorizationVerified)
}

func TestUnsupportedAnchorIsUncheckedNotInvalid(t *testing.T) {
	r := newRig(t, newParts(t))
	r.deps.Anchors[commitment.DACelestiaBlob] = declines{}
	rep := r.verify(t)
	assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
	c, ok := rep.Check(verifier.CheckAnchor)
	require.True(t, ok)
	assert.Equal(t, verifier.StatusUnchecked, c.Status)
	require.ErrorIs(t, c.Err, verifier.ErrAnchorUnsupported)
	assert.Equal(t, verifier.TrustUnchecked, rep.HeaderTrust.Status)
}

func TestDA1ReportRulesHoldInTheGenericLayer(t *testing.T) {
	tests := []struct {
		name       string
		settlement string
		precision  string
		ok         bool
	}{
		{"robust", "node-attested", "robust", true},
		{"bucket-dependent", "node-attested", "bucket-dependent", true},
		{"settlement missing", "", "robust", false},
		{"precision missing", "node-attested", "", false},
		{"precision unknown", "node-attested", "exact", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, newFibreParts(t))
			r.anchor.settlement, r.anchor.precision = tc.settlement, tc.precision
			rep := r.verify(t)
			if tc.ok {
				assert.Equal(t, verifier.VerdictValid, rep.Verdict)
				return
			}
			assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
			c := unchecked(t, rep, verifier.CheckAnchor, verifier.ReasonSourceCorrupt)
			requireOnly(t, c.Err, verifier.ErrAnchorInvalid)
		})
	}
}

func TestParamsAreInTheReport(t *testing.T) {
	r := newRig(t, newParts(t))
	r.deps.Config.Params.SkewS = 120
	r.deps.Config.Params.BlobRetentionS = 7200
	rep := r.verify(t)
	assert.Equal(t, r.deps.Config.Params, rep.Params)

	absent := newRig(t, newParts(t))
	h := r.p.hash
	h[0] ^= 1
	rep, err := absent.verifier(t).Verify(context.Background(), h)
	require.NoError(t, err)
	assert.Equal(t, absent.deps.Config.Params, rep.Params, "also for a decision that is not there")
}

func TestSkewParameterDecidesTheAnchorTimeRule(t *testing.T) {
	for _, tc := range []struct {
		skew uint64
		ok   bool
	}{{30, false}, {120, true}} {
		r := newRig(t, newParts(t))
		r.anchor.blockTime = r.p.c.IssuedAt + 100
		r.deps.Config.Params.SkewS = tc.skew
		rep := r.verify(t)
		if tc.ok {
			passed(t, rep, verifier.CheckAnchorTime)
		} else {
			failed(t, rep, verifier.CheckAnchorTime)
		}
	}
}

func TestReplayConsistencyRules(t *testing.T) {
	tests := []struct {
		name  string
		fibre bool
		tweak func(t *testing.T, p *parts)
	}{
		{"archived blob retention differs", false, func(_ *testing.T, p *parts) { p.k2.BlobRetentionS = 7200 }},
		{"archived promise creation differs", true, func(_ *testing.T, p *parts) { p.k2.PromiseCreated-- }},
		{"checked at valid until", false, func(_ *testing.T, p *parts) { p.k2.CheckedAt = p.c.ValidUntil }},
		{"authorized at valid until", false, func(_ *testing.T, p *parts) { p.authAt = p.c.ValidUntil }},
		{"expires before it was issued", false, func(t *testing.T, p *parts) {
			p.authAt = authExpires + 1
			p.auth = signAuth(t, gateKey(t), p.hash, p.c, commitment.PathDA, authExpires)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newParts(t)
			if tc.fibre {
				p = newFibreParts(t)
			}
			tc.tweak(t, p)
			r := newRig(t, p)
			r.anchor.proofForm = 1

			rr := replay(t, r)
			require.True(t, rr.K2.Replayable)
			assert.False(t, rr.K2.Consistent)
			require.ErrorIs(t, rr.K2.Err, verifier.ErrGateInconsistent)
			assert.Equal(t, verifier.VerdictUnchecked, rr.Report.Verdict, "the library verdict folds the replay in; the inputs are unsigned")
			c := unchecked(t, rr.Report, verifier.CheckRetention, verifier.ReasonReplayInconsistent)
			require.ErrorIs(t, c.Err, verifier.ErrGateInconsistent)

			rep := r.verify(t)
			assert.Equal(t, verifier.VerdictValid, rep.Verdict, "plain verification does not replay")
			_, ok := rep.Check(verifier.CheckRetention)
			assert.False(t, ok)
		})
	}
}

func TestReplayOfAConsistentRecordStaysValid(t *testing.T) {
	rr := replay(t, newRig(t, newParts(t)))
	assert.Equal(t, verifier.VerdictValid, rr.Report.Verdict)
	assert.True(t, rr.K2.Consistent)
}

func TestReplayOfAnUnverifiedAnchorIsNotReplayable(t *testing.T) {
	r := newRig(t, newParts(t))
	r.deps.Anchors[commitment.DACelestiaBlob] = declines{}
	rr := replay(t, r)
	assert.False(t, rr.K2.Replayable)
	assert.NotEmpty(t, rr.K2.Reason)
	assert.Equal(t, verifier.VerdictUnchecked, rr.Report.Verdict)
}
