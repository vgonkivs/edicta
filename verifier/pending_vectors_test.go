package verifier_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/verifier"
)

type fastCase struct {
	ID            string `json:"id"`
	Decision      string `json:"decision"`
	Authorization string `json:"authorization"`
	TrustedHead   string `json:"trusted_head"`
	NeedsResults  bool   `json:"needs_results"`
	Request       string `json:"request"`
	Evidence      *struct {
		Height   string `json:"height"`
		Verifies bool   `json:"verifies"`
	} `json:"evidence"`
	Absence []struct {
		Height string `json:"height"`
		Result string `json:"result"`
	} `json:"absence"`
	Expect struct {
		Anchor *struct {
			Status        string `json:"status"`
			Reason        string `json:"reason"`
			Rule          string `json:"rule"`
			FirstUnproven string `json:"first_unproven"`
		} `json:"anchor"`
		Replay *struct {
			Status string `json:"status"`
			Reason string `json:"reason"`
		} `json:"retention_replay"`
		Report struct {
			Mode           string `json:"mode"`
			H0             string `json:"h0"`
			AnchorDeadline string `json:"anchor_deadline"`
			AnchorHeight   string `json:"anchor_height"`
			Publication    string `json:"publication"`
			IntentSigner   string `json:"intent_signer"`
		} `json:"report"`
		Verdict string `json:"verdict"`
	} `json:"expect"`
}

func loadFastCases(t *testing.T) (uint64, []fastCase) {
	t.Helper()
	raw, err := os.ReadFile("../spec/vectors/v1/verify.json")
	require.NoError(t, err)
	var d struct {
		Revision string     `json:"revision"`
		Window   string     `json:"window"`
		Cases    []fastCase `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(raw, &d))
	require.Equal(t, "v1.0", d.Revision)
	w, err := strconv.ParseUint(d.Window, 10, 64)
	require.NoError(t, err)
	return w, d.Cases
}

// windowPending answers the absence window from per-height results the way
// the absence package combines them: a present height wins, else the first
// height that is not absent is the first one not proven.
type windowPending struct {
	h0, deadline uint64
	results      map[uint64]string
	needsResults bool
	header       verifier.ChainHeader
	asked        int
}

func (w *windowPending) Header(context.Context, commitment.PayloadRef, uint64) (verifier.ChainHeader, error) {
	if w.header.Hash == nil {
		return verifier.ChainHeader{}, errors.New("no header")
	}
	return w.header, nil
}

func (w *windowPending) Absence(context.Context, commitment.PayloadRef, uint64, verifier.Confirm) (verifier.AbsenceWindow, error) {
	w.asked++
	out := verifier.AbsenceWindow{Heights: int(w.deadline - w.h0 + 1), ChainID: "c", ResultsAtDeadline: w.needsResults}
	for h := w.h0; h <= w.deadline; h++ {
		if w.results[h] == "present" {
			out.Result, out.AnchorHeight = verifier.AbsencePresent, h
			return out, nil
		}
	}
	for h := w.h0; h <= w.deadline; h++ {
		if w.results[h] != "absent" {
			out.Result, out.FirstUnproven, out.Cause = verifier.AbsenceUnproven, h, errors.New("no absence proof")
			return out, nil
		}
	}
	out.Result = verifier.AbsenceAbsent
	return out, nil
}

func (w *windowPending) IntentSigner(context.Context, commitment.PayloadRef, uint64, string) (string, error) {
	return "", nil
}

// The fast-mode cases of v1/verify.json, on the rig: heights are taken as
// offsets from the vector's h0.
func TestPendingVerifyVectors(t *testing.T) {
	window, cases := loadFastCases(t)
	require.Equal(t, uint64(fastWindow), window)
	ran := 0
	for _, c := range cases {
		if c.Decision != "decision_pending_fibre" && c.Decision != "decision_pending_blob" {
			continue // the included control runs in TestVerifyStrictDecision
		}
		if c.Authorization != "authorization_fast_fibre" && c.Authorization != "authorization_fast_blob" &&
			c.Authorization != "authorization_fast_fibre_window_2" {
			continue // AM1 and AM2: TestVerifyAuthorizationContradictions
		}
		ran++
		t.Run(c.ID, func(t *testing.T) {
			p := newFibreParts(t)
			if c.Decision == "decision_pending_blob" {
				p = newParts(t)
			}
			pendingParts(t, p)
			if c.Authorization == "authorization_fast_fibre_window_2" {
				p.k2.FastWindow = fastWindow - 1
			}
			vh0, err := strconv.ParseUint(c.Expect.Report.H0, 10, 64)
			require.NoError(t, err)
			h0 := p.c.PayloadRef.Height
			at := func(s string) uint64 {
				t.Helper()
				v, err := strconv.ParseUint(s, 10, 64)
				require.NoError(t, err)
				return h0 + v - vh0
			}
			if c.Evidence != nil {
				p.ev.Height = at(c.Evidence.Height)
				if !c.Evidence.Verifies {
					if p.da == commitment.DAFibre {
						p.ev.SystemBlobProof = []byte("bad")
					} else {
						p.ev.BlobProof = []byte("bad")
					}
				}
			}
			r := newRig(t, p)
			if c.Evidence == nil {
				withoutEvidence(r)
			}
			wp := &windowPending{h0: h0, deadline: h0 + fastWindow, results: map[uint64]string{}, needsResults: c.NeedsResults}
			for _, a := range c.Absence {
				wp.results[at(a.Height)] = a.Result
			}
			if p.da == commitment.DACelestiaBlob {
				ref := sha256.Sum256([]byte("header at h0"))
				r.trust.hashes[h0] = ref[:]
				wp.header = verifier.ChainHeader{Hash: ref[:], Time: blockTime}
			}
			r.deps.Pending = wp
			r.deps.Trust = cpTrust{r.trust, at(c.TrustedHead)}

			var rep verifier.Report
			if c.Request == "replay" {
				rep = replay(t, r).Report
			} else {
				rep = r.verify(t)
			}

			passed(t, rep, verifier.CheckAuthorization)
			ea := c.Expect.Anchor
			require.NotNil(t, ea)
			got, ok := rep.Check(verifier.CheckAnchor)
			require.True(t, ok)
			assert.Equal(t, ea.Status, string(got.Status), "%v", got.Err)
			if ea.Reason != "" {
				assert.Equal(t, verifier.Reason(ea.Reason), got.Reason)
			}
			if ea.Rule == "anchor_absent" {
				require.ErrorIs(t, got.Err, verifier.ErrAnchorAbsent)
			}
			if ea.FirstUnproven != "" {
				require.NotNil(t, rep.Fast.Absence)
				assert.Equal(t, at(ea.FirstUnproven), rep.Fast.Absence.FirstUnproven)
				assert.Contains(t, got.Err.Error(), strconv.FormatUint(at(ea.FirstUnproven), 10))
			}
			if c.Expect.Replay != nil {
				rc, ok := rep.Check(verifier.CheckRetention)
				require.True(t, ok)
				assert.Equal(t, c.Expect.Replay.Status, string(rc.Status), "%v", rc.Err)
				if c.Expect.Replay.Reason != "" {
					assert.Equal(t, verifier.Reason(c.Expect.Replay.Reason), rc.Reason)
				}
			}

			er := c.Expect.Report
			require.Equal(t, "fast", er.Mode)
			require.NotNil(t, rep.Fast)
			assert.Equal(t, h0, rep.Fast.H0)
			assert.Equal(t, at(er.AnchorDeadline), rep.Fast.AnchorDeadline)
			if er.AnchorHeight == "" {
				assert.Zero(t, rep.Fast.AnchorHeight)
			} else {
				assert.Equal(t, at(er.AnchorHeight), rep.Fast.AnchorHeight)
			}
			if er.Publication != "" {
				assert.Equal(t, verifier.Publication(er.Publication), rep.Fast.Publication)
			}
			switch {
			case er.IntentSigner == "":
				assert.Empty(t, rep.Fast.IntentSigner)
			case p.da == commitment.DACelestiaBlob:
				assert.Equal(t, hex.EncodeToString(p.c.PayloadRef.Signer), rep.Fast.IntentSigner)
			default:
				assert.Equal(t, er.IntentSigner, rep.Fast.IntentSigner)
			}

			if c.Expect.Verdict == "valid" {
				// Fast mode makes the policy check required and the rig has
				// no policy_allow record: that is the only gap to valid.
				assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
				unchecked(t, rep, verifier.CheckPolicy, verifier.ReasonPolicyVerdictUnavailable)
				for _, ch := range rep.Checks {
					if ch.Name != verifier.CheckPolicy && ch.Status == verifier.StatusUnchecked {
						assert.Fail(t, "only policy may be unchecked", "%s: %s %v", ch.Name, ch.Reason, ch.Err)
					}
				}
				assert.Equal(t, verifier.PublicationAnchored, rep.Fast.Publication)
			} else {
				assert.Equal(t, verifier.Verdict(c.Expect.Verdict), rep.Verdict)
			}
			if c.Expect.Anchor.Reason == "anchor_pending" && !c.NeedsResults {
				assert.Zero(t, wp.asked, "no absence proof is read while the window is open")
			}
		})
	}
	assert.Equal(t, 14, ran, "every fast-mode case of the file ran")
}

// Boundaries of the window not in the vector file: evidence exactly at h0
// passes; evidence one height past the deadline is late.
func TestPendingWindowEdges(t *testing.T) {
	t.Run("evidence at h0", func(t *testing.T) {
		p := pendingParts(t, newParts(t))
		h0 := p.c.PayloadRef.Height
		p.ev.Height = h0
		r := newRig(t, p)
		hh := sha256.Sum256(goodHeader())
		r.deps.Pending = &fakePending{header: verifier.ChainHeader{Hash: hh[:], Time: blockTime}}
		rep := r.verify(t)
		passed(t, rep, verifier.CheckAnchor)
		passed(t, rep, verifier.CheckHeaderTrust)
		assert.Equal(t, h0, rep.Fast.AnchorHeight)
		assert.Equal(t, verifier.PublicationAnchored, rep.Fast.Publication)
	})
	t.Run("evidence at deadline + 1 with no absence source", func(t *testing.T) {
		p := pendingParts(t, newParts(t))
		h0 := p.c.PayloadRef.Height
		p.ev.Height = h0 + fastWindow + 1
		rep := newRig(t, p).verify(t)
		c := unchecked(t, rep, verifier.CheckAnchor, verifier.ReasonAbsenceUnproven)
		require.ErrorIs(t, c.Err, verifier.ErrNoAbsenceSource)
		assert.Equal(t, h0+fastWindow+1, rep.Fast.AnchorHeight)
		assert.Equal(t, verifier.PublicationUnknown, rep.Fast.Publication)
	})
	t.Run("late evidence whose header the chain lacks is not reported", func(t *testing.T) {
		p := pendingParts(t, newParts(t))
		h0 := p.c.PayloadRef.Height
		p.ev.Height = h0 + fastWindow + 1
		r := newRigWith(t, p, verifier.AbsenceWindow{Result: verifier.AbsenceAbsent})
		delete(r.trust.hashes, p.ev.Height)
		rep := r.verify(t)
		failed(t, rep, verifier.CheckAnchor)
		assert.Zero(t, rep.Fast.AnchorHeight)
		assert.NotEmpty(t, rep.Warnings)
	})
	t.Run("checkpoint exactly at the deadline decides", func(t *testing.T) {
		r, fp := pendingRig(t, newParts(t), verifier.AbsenceWindow{Result: verifier.AbsenceAbsent})
		withoutEvidence(r)
		r.deps.Trust = cpTrust{r.trust, r.p.c.PayloadRef.Height + fastWindow}
		rep := r.verify(t)
		failed(t, rep, verifier.CheckAnchor)
		assert.Equal(t, 1, fp.asked)
	})
	t.Run("a cross-check mismatch does not confirm an absence header", func(t *testing.T) {
		r, fp := pendingRig(t, newParts(t), verifier.AbsenceWindow{Result: verifier.AbsenceAbsent})
		withoutEvidence(r)
		h0 := r.p.c.PayloadRef.Height
		hh := sha256.Sum256([]byte("absence header"))
		r.trust.hashes[h0] = hh[:]
		r.trust.res.CrossCheck = verifier.CrossMismatch
		fp.confirm = map[uint64][]byte{h0: hh[:]}
		rep := r.verify(t)
		unchecked(t, rep, verifier.CheckAnchor, verifier.ReasonAbsenceUnproven)
	})
	t.Run("an error from header trust does not confirm", func(t *testing.T) {
		r, fp := pendingRig(t, newParts(t), verifier.AbsenceWindow{Result: verifier.AbsenceAbsent})
		withoutEvidence(r)
		h0 := r.p.c.PayloadRef.Height
		r.trust.err = errors.New("source down")
		fp.confirm = map[uint64][]byte{h0: {1}}
		rep := r.verify(t)
		unchecked(t, rep, verifier.CheckAnchor, verifier.ReasonAbsenceUnproven)
	})
	t.Run("a cancelled context stops the run", func(t *testing.T) {
		r, _ := pendingRig(t, newParts(t), verifier.AbsenceWindow{Result: verifier.AbsenceAbsent})
		withoutEvidence(r)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := r.verifier(t).Verify(ctx, r.p.hash)
		require.ErrorIs(t, err, context.Canceled)
	})
}
