package verifier_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/test/gatefix"
	"github.com/vgonkivs/edicta/verifier"
)

const fastWindow = 3

// pendingParts makes p a pending reference with a fast Authorization whose
// deadline is h0 + fastWindow, and evidence at h0 + 1 whose promise height
// is h0.
func pendingParts(t *testing.T, p *parts) *parts {
	t.Helper()
	cc := gatefix.Clone(p.c)
	cc.PayloadRef.Anchor = commitment.AnchorPending
	p.c = cc
	p.env, p.hash = gatefix.Sign(t, "agent1", cc)
	h0 := cc.PayloadRef.Height
	p.ev.Height = h0 + 1
	if p.da == commitment.DAFibre {
		p.ev.PromiseHeight = h0
	}
	p.k2.FastWindow = fastWindow
	p.auth = signAuthorization(t, gateKey(t), commitment.Authorization{
		Version: commitment.Version, CommitmentHash: p.hash[:], ActionHash: cc.Action.Hash, GateID: gatefix.GateID,
		Expires: authExpires, Path: commitment.PathDA, Mode: commitment.ModeFast, AnchorDeadline: h0 + fastWindow,
	})
	return p
}

// fakePending confirms the listed header hashes before it answers; a hash
// the verifier refuses makes its height the first one not proven.
type fakePending struct {
	window    verifier.AbsenceWindow
	confirm   map[uint64][]byte
	header    verifier.ChainHeader
	headerErr error
	signer    string
	asked     int
}

func (f *fakePending) Header(context.Context, commitment.PayloadRef, uint64) (verifier.ChainHeader, error) {
	return f.header, f.headerErr
}

func (f *fakePending) Absence(ctx context.Context, _ commitment.PayloadRef, _ uint64, confirm verifier.Confirm) (verifier.AbsenceWindow, error) {
	f.asked++
	for h, hash := range f.confirm {
		if !confirm(ctx, h, hash) {
			return verifier.AbsenceWindow{Result: verifier.AbsenceUnproven, FirstUnproven: h, Cause: errors.New("header not trusted")}, nil
		}
	}
	return f.window, nil
}

func (f *fakePending) IntentSigner(context.Context, commitment.PayloadRef, uint64, string) (string, error) {
	return f.signer, nil
}

// cpTrust is a header trust that knows its checkpoint height.
type cpTrust struct {
	*fakeTrust
	at uint64
}

func (c cpTrust) CheckpointHeight(context.Context) (uint64, error) { return c.at, nil }

func pendingRig(t *testing.T, p *parts, w verifier.AbsenceWindow) (*rig, *fakePending) {
	t.Helper()
	r := newRig(t, pendingParts(t, p))
	fp := &fakePending{window: w}
	r.deps.Pending = fp
	return r, fp
}

func withoutEvidence(r *rig) { r.deps.Archive = noEvidence{r.store} }

func TestPendingEvidenceInWindowPasses(t *testing.T) {
	p := pendingParts(t, newFibreParts(t))
	r := newRig(t, p)
	rep := r.verify(t)
	passed(t, rep, verifier.CheckAnchor)
	passed(t, rep, verifier.CheckHeaderTrust)
	passed(t, rep, verifier.CheckAnchorTime)
	require.NotNil(t, rep.Fast)
	h0 := p.c.PayloadRef.Height
	assert.Equal(t, verifier.FastInfo{H0: h0, AnchorDeadline: h0 + fastWindow, AnchorHeight: h0 + 1,
		Publication: verifier.PublicationAnchored}, *rep.Fast)
	assert.ElementsMatch(t, []uint64{h0 + 1, h0}, r.trust.asked)
	// Fast mode makes the policy check required, and the rig has no allow.
	assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
	unchecked(t, rep, verifier.CheckPolicy, verifier.ReasonPolicyVerdictUnavailable)
}

func TestPendingFibrePromiseMustBeAtH0(t *testing.T) {
	p := pendingParts(t, newFibreParts(t))
	r := newRig(t, p)
	r.anchor.promiseHeight = func(*archive.EvidenceRecord) uint64 { return p.c.PayloadRef.Height + 1 }
	r.trust.hashes[p.c.PayloadRef.Height+1] = r.trust.hashes[p.ev.Height]
	r.deps.Pending = &fakePending{window: verifier.AbsenceWindow{Result: verifier.AbsenceUnproven, FirstUnproven: p.c.PayloadRef.Height}}
	rep := r.verify(t)
	unchecked(t, rep, verifier.CheckAnchor, verifier.ReasonAbsenceUnproven)
	assert.NotEmpty(t, rep.Warnings)
}

func TestPendingBlobTakesTRefFromH0(t *testing.T) {
	p := pendingParts(t, newParts(t))
	r := newRig(t, p)
	h0 := p.c.PayloadRef.Height
	ref := sha256.Sum256([]byte("header at h0"))
	r.trust.hashes[h0] = ref[:]
	r.deps.Pending = &fakePending{header: verifier.ChainHeader{Hash: ref[:], Time: blockTime - 5}}
	rep := r.verify(t)
	passed(t, rep, verifier.CheckAnchor)
	passed(t, rep, verifier.CheckHeaderTrust)
	passed(t, rep, verifier.CheckAnchorTime)
	assert.Equal(t, blockTime-5, rep.BlockTime)
	assert.Equal(t, verifier.PublicationAnchored, rep.Fast.Publication)

	t.Run("no header source", func(t *testing.T) {
		r := newRig(t, p)
		rep := r.verify(t)
		passed(t, rep, verifier.CheckAnchor)
		unchecked(t, rep, verifier.CheckHeaderTrust, verifier.ReasonHeaderSourceUnavailable)
		unchecked(t, rep, verifier.CheckAnchorTime, verifier.ReasonBlocked)
		assert.Equal(t, verifier.PublicationUnknown, rep.Fast.Publication)
	})
}

func TestPendingEvidenceBelowH0IsSourceCorrupt(t *testing.T) {
	p := pendingParts(t, newParts(t))
	p.ev.Height = p.c.PayloadRef.Height - 1
	rep := newRig(t, p).verify(t)
	c := unchecked(t, rep, verifier.CheckAnchor, verifier.ReasonSourceCorrupt)
	require.ErrorIs(t, c.Err, verifier.ErrAnchorInvalid)
	assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
}

func TestPendingWithoutEvidence(t *testing.T) {
	absent := verifier.AbsenceWindow{Result: verifier.AbsenceAbsent, Heights: fastWindow + 1, Bytes: 1000, ChainID: "c"}

	t.Run("checkpoint below the deadline", func(t *testing.T) {
		r, fp := pendingRig(t, newParts(t), absent)
		withoutEvidence(r)
		r.deps.Trust = cpTrust{r.trust, r.p.c.PayloadRef.Height + fastWindow - 1}
		rep := r.verify(t)
		unchecked(t, rep, verifier.CheckAnchor, verifier.ReasonAnchorPending)
		assert.Zero(t, fp.asked, "nothing is fetched while the window is open")
		assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
		assert.Equal(t, verifier.PublicationUnknown, rep.Fast.Publication)
	})
	t.Run("results proof at the deadline needs one more header", func(t *testing.T) {
		r, fp := pendingRig(t, newParts(t), verifier.AbsenceWindow{})
		withoutEvidence(r)
		d := r.p.c.PayloadRef.Height + fastWindow
		fp.window = verifier.AbsenceWindow{Result: verifier.AbsenceUnproven, FirstUnproven: d, ResultsAtDeadline: true}
		r.deps.Trust = cpTrust{r.trust, d}
		rep := r.verify(t)
		unchecked(t, rep, verifier.CheckAnchor, verifier.ReasonAnchorPending)
	})
	t.Run("absence proven", func(t *testing.T) {
		r, _ := pendingRig(t, newFibreParts(t), absent)
		withoutEvidence(r)
		rep := r.verify(t)
		c := failed(t, rep, verifier.CheckAnchor)
		require.ErrorIs(t, c.Err, verifier.ErrAnchorAbsent)
		assert.Equal(t, verifier.VerdictInvalid, rep.Verdict)
		assert.Equal(t, verifier.PublicationFailed, rep.Fast.Publication)
		assert.Equal(t, verifier.IntentSignerUnknown, rep.Fast.IntentSigner)
		assert.Zero(t, rep.Fast.AnchorHeight)
		require.NotNil(t, rep.Fast.Absence)
		assert.Equal(t, uint64(1000), rep.Fast.Absence.Bytes)
	})
	t.Run("absence proven, blob: the reference's signer", func(t *testing.T) {
		r, _ := pendingRig(t, newParts(t), absent)
		withoutEvidence(r)
		rep := r.verify(t)
		failed(t, rep, verifier.CheckAnchor)
		assert.Equal(t, hex.EncodeToString(r.p.c.PayloadRef.Signer), rep.Fast.IntentSigner)
	})
	t.Run("absence proven, intent signer from chain data", func(t *testing.T) {
		r, fp := pendingRig(t, newFibreParts(t), absent)
		withoutEvidence(r)
		fp.signer = "aa"
		rep := r.verify(t)
		failed(t, rep, verifier.CheckAnchor)
		assert.Equal(t, "aa", rep.Fast.IntentSigner)
	})
	t.Run("a height not proven", func(t *testing.T) {
		r, fp := pendingRig(t, newParts(t), verifier.AbsenceWindow{})
		withoutEvidence(r)
		h := r.p.c.PayloadRef.Height + 1
		fp.window = verifier.AbsenceWindow{Result: verifier.AbsenceUnproven, FirstUnproven: h, Cause: errors.New("no proof"), Sources: []string{"archive"}}
		rep := r.verify(t)
		c := unchecked(t, rep, verifier.CheckAnchor, verifier.ReasonAbsenceUnproven)
		assert.Contains(t, c.Err.Error(), "height 4200001")
		assert.Equal(t, []string{"archive"}, c.Sources)
	})
	t.Run("a header the trusted chain lacks", func(t *testing.T) {
		r, fp := pendingRig(t, newParts(t), absent)
		withoutEvidence(r)
		d := r.p.c.PayloadRef.Height + fastWindow
		fp.confirm = map[uint64][]byte{d: {1, 2, 3}}
		rep := r.verify(t)
		unchecked(t, rep, verifier.CheckAnchor, verifier.ReasonAbsenceUnproven)
	})
	t.Run("the proof shows the anchor present", func(t *testing.T) {
		r, fp := pendingRig(t, newParts(t), verifier.AbsenceWindow{})
		withoutEvidence(r)
		fp.window = verifier.AbsenceWindow{Result: verifier.AbsencePresent, AnchorHeight: r.p.c.PayloadRef.Height + 2}
		rep := r.verify(t)
		unchecked(t, rep, verifier.CheckAnchor, verifier.ReasonEvidenceUnavailable)
		assert.Equal(t, r.p.c.PayloadRef.Height+2, rep.Fast.AnchorHeight)
		assert.Equal(t, verifier.PublicationUnknown, rep.Fast.Publication)
	})
	t.Run("no absence source", func(t *testing.T) {
		r := newRig(t, pendingParts(t, newParts(t)))
		withoutEvidence(r)
		rep := r.verify(t)
		c := unchecked(t, rep, verifier.CheckAnchor, verifier.ReasonAbsenceUnproven)
		require.ErrorIs(t, c.Err, verifier.ErrNoAbsenceSource)
	})
	t.Run("no header trust", func(t *testing.T) {
		r, fp := pendingRig(t, newParts(t), absent)
		withoutEvidence(r)
		r.deps.Trust = nil
		rep := r.verify(t)
		unchecked(t, rep, verifier.CheckAnchor, verifier.ReasonBlocked)
		unchecked(t, rep, verifier.CheckHeaderTrust, verifier.ReasonNoTrustedHeader)
		assert.Zero(t, fp.asked)
	})
	t.Run("evidence that does not verify", func(t *testing.T) {
		p := pendingParts(t, newParts(t))
		p.ev.BlobProof = []byte("bad")
		rep := newRigWith(t, p, absent).verify(t)
		failed(t, rep, verifier.CheckAnchor)
		assert.NotEmpty(t, rep.Warnings)
	})
}

// newRigWith rewrites the archive of p and serves the given window.
func newRigWith(t *testing.T, p *parts, w verifier.AbsenceWindow) *rig {
	t.Helper()
	r := newRig(t, p)
	r.deps.Pending = &fakePending{window: w}
	return r
}

func TestPendingLateEvidence(t *testing.T) {
	p := pendingParts(t, newParts(t))
	h0 := p.c.PayloadRef.Height
	p.ev.Height = h0 + fastWindow + 1
	r := newRigWith(t, p, verifier.AbsenceWindow{Result: verifier.AbsenceAbsent})
	h := sha256.Sum256(goodHeader())
	r.trust.hashes[p.ev.Height] = h[:]
	rep := r.verify(t)
	failed(t, rep, verifier.CheckAnchor)
	assert.Equal(t, h0+fastWindow+1, rep.Fast.AnchorHeight)
	assert.Equal(t, verifier.PublicationFailed, rep.Fast.Publication)

	r = newRigWith(t, p, verifier.AbsenceWindow{Result: verifier.AbsenceUnproven, FirstUnproven: h0 + 2})
	r.trust.hashes[p.ev.Height] = h[:]
	rep = r.verify(t)
	unchecked(t, rep, verifier.CheckAnchor, verifier.ReasonAbsenceUnproven)
	assert.Equal(t, h0+fastWindow+1, rep.Fast.AnchorHeight)
	assert.Equal(t, verifier.PublicationUnknown, rep.Fast.Publication)
}

func TestPendingWithoutVerifiedAuthorizationIsBlocked(t *testing.T) {
	p := pendingParts(t, newParts(t))
	p.auth[len(p.auth)-1] ^= 1
	rep := newRigWith(t, p, verifier.AbsenceWindow{Result: verifier.AbsenceAbsent}).verify(t)
	c := unchecked(t, rep, verifier.CheckAnchor, verifier.ReasonBlocked)
	assert.Equal(t, []string{string(verifier.CheckAuthorization)}, c.Sources)
	assert.Nil(t, rep.Fast)
}

func TestReplayChecksTheFastWindow(t *testing.T) {
	for _, tc := range []struct {
		window uint64
		want   verifier.Status
	}{{fastWindow, verifier.StatusPass}, {fastWindow - 1, verifier.StatusUnchecked}} {
		p := pendingParts(t, newParts(t))
		p.k2.FastWindow = tc.window
		r := newRig(t, p)
		h0 := p.c.PayloadRef.Height
		ref := sha256.Sum256([]byte("header at h0"))
		r.trust.hashes[h0] = ref[:]
		r.deps.Pending = &fakePending{header: verifier.ChainHeader{Hash: ref[:], Time: blockTime}}
		rr := replay(t, r)
		c, ok := rr.Report.Check(verifier.CheckRetention)
		require.True(t, ok)
		assert.Equal(t, tc.want, c.Status, "fast window %d: %v", tc.window, c.Err)
	}
}
