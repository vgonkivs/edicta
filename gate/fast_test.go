package gate_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/gatetest"
	"github.com/vgonkivs/edicta/gate/registry"
	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/test/gatefix"
)

// fEnv is a fast-mode gate with one pending decision staged: the intent, its
// facts, the archived blob and, for da = 1, the retention at h0.
type fEnv struct {
	*gatefix.Env
	t      *testing.T
	c      *commitment.Commitment
	rec    gate.AnchorIntent
	facts  gate.IntentFacts
	h0     uint64
	tRef   uint64
	issued uint64
}

const fastDelay = 50

func fastMandate(t *testing.T, delay uint64) *policy.Mandate {
	m := baseMandate(t)
	m.FastModeMaxDelay = delay
	return m
}

func newFastEnv(t *testing.T, da commitment.DA, m *policy.Mandate, extra ...gatefix.Option) *fEnv {
	t.Helper()
	tmpl, blob := gatefix.Template(t), gatefix.Blob(t)
	if da == commitment.DAFibre {
		tmpl, blob = gatefix.FibreTemplate(t), gatefix.FibreBlob()
	}
	opts := append([]gatefix.Option{
		gatefix.WithConfig(func(c *gate.Config) {
			c.FastMode = true
			c.PendingNamespaces = [][]byte{tmpl.PayloadRef.Namespace}
		}),
		gatefix.WithDeps(func(d *gate.Deps) { d.Archiver = &recordingArchiver{} }),
	}, extra...)
	e := gatefix.New(t, policyOpts(t, m, opts...)...)
	_, mh, err := policy.VerifyMandate(e.Cfg.Mandate)
	require.NoError(t, err)

	issued := gatefix.Now - 10
	c := gatefix.Times(tmpl, issued, issued+600)
	c.Version = commitment.Version
	c.MandateRef = mh[:]
	c.PayloadRef.Anchor = commitment.AnchorPending
	f := &fEnv{Env: e, t: t, c: c, h0: c.PayloadRef.Height, tRef: issued - 20, issued: issued}
	f.rec = gate.AnchorIntent{
		DA: da, Commitment: c.PayloadRef.Commitment, Namespace: c.PayloadRef.Namespace, RefHeight: f.h0,
		Tx: []byte("intent tx " + string(rune('0'+da))), Signer: c.PayloadRef.Signer, CreatedAt: f.tRef - 5,
	}
	f.facts = gate.IntentFacts{DA: da, RefTime: f.tRef, Head: f.h0 + 2, HeadTime: f.tRef + 6}
	if da == commitment.DAFibre {
		f.facts.CreatedAt, f.facts.PromiseTimeout, f.facts.ChainWindow = f.rec.CreatedAt, 3600, 1000
		e.Chain.SetAt(f.h0, 14400)
		e.DA.Put(c.PayloadRef, blob)
	} else {
		f.rec.CreatedAt = f.tRef + 1
	}
	e.Archive.Put(c.PayloadRef, blob)
	f.stage()
	return f
}

func (f *fEnv) stage() {
	f.Intents.Put(f.rec)
	f.Verifier.Set(f.rec.Tx, f.facts)
}

func (f *fEnv) authorize() (gate.Result, error) {
	b, _ := gatefix.Sign(f.t, "agent1", f.c)
	return f.Authorize(b)
}

func (f *fEnv) requireFast(res gate.Result, err error, deadline uint64) *commitment.SignedAuthorization {
	f.t.Helper()
	require.NoError(f.t, err)
	sa, _, derr := commitment.DecodeSignedAuthorization(res.Authorization)
	require.NoError(f.t, derr)
	assert.EqualValues(f.t, commitment.ModeFast, sa.Authorization.Mode)
	assert.Equal(f.t, deadline, sa.Authorization.AnchorDeadline)
	assert.Equal(f.t, deadline-f.h0, res.K2.FastWindow)
	assert.Equal(f.t, f.tRef, res.K2.BlockTime, "K2 runs on T_ref")
	return sa
}

func TestFastBlobAuthorizes(t *testing.T) {
	f := newFastEnv(t, commitment.DACelestiaBlob, fastMandate(t, fastDelay))
	res, err := f.authorize()
	f.requireFast(res, err, f.h0+fastDelay)
	assert.Equal(t, registry.PathArchive, res.Path, "a pending blob is not on chain at h0")

	sv, _, err := policy.DecodeSignedVerdict(res.PolicyVerdict)
	require.NoError(t, err)
	assert.Equal(t, f.tRef, sv.Verdict.AnchorTime, "the policy clock is T_ref")

	bs := f.Broadcaster.Broadcasts()
	require.Len(t, bs, 1)
	assert.Equal(t, commitment.DACelestiaBlob, bs[0].DA)
	assert.Equal(t, gatefix.Blob(t), bs[0].Blob)

	// A retry gets the stored Authorization and does not run K-fast again.
	calls := f.Verifier.Calls()
	again, err := f.authorize()
	require.ErrorIs(t, err, gate.ErrNonceUsed)
	assert.Equal(t, res.Authorization, again.Authorization)
	assert.Equal(t, calls, f.Verifier.Calls())
}

func TestFastFibreWindowIsTheSmallestBound(t *testing.T) {
	for name, tc := range map[string]struct {
		gateWindow, delay, chain, want uint64
	}{
		"gate":    {100, 500, 1000, 100},
		"mandate": {100, 40, 1000, 40},
		"chain":   {100, 500, 30, 30},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFastEnv(t, commitment.DAFibre, fastMandate(t, tc.delay),
				gatefix.WithConfig(func(c *gate.Config) { c.FastWindowBlocks = tc.gateWindow }))
			f.facts.ChainWindow = tc.chain
			f.stage()
			res, err := f.authorize()
			f.requireFast(res, err, f.h0+tc.want)
			assert.Equal(t, f.rec.CreatedAt, res.K2.RetentionStart, "start is the intent's created_at")
			assert.Len(t, f.Broadcaster.Broadcasts(), 1, "rebroadcast is on by default")
		})
	}
}

func TestFastIntentRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		da     commitment.DA
		mutate func(f *fEnv)
		want   error
	}{
		"intent missing": {commitment.DACelestiaBlob, func(f *fEnv) { f.Intents.Fail(errors.New("not found")) }, gate.ErrAnchorIntentUnavailable},
		"record namespace differs": {commitment.DACelestiaBlob, func(f *fEnv) {
			f.rec.Namespace = append([]byte(nil), f.rec.Namespace...)
			f.rec.Namespace[28] ^= 1
			f.stage()
		}, gate.ErrAnchorIntentInvalid},
		"record signer differs": {commitment.DACelestiaBlob, func(f *fEnv) {
			f.rec.Signer = make([]byte, 20)
			f.stage()
		}, gate.ErrAnchorIntentInvalid},
		"pfb for another blob":       {commitment.DACelestiaBlob, func(f *fEnv) { f.Verifier.Fail(gate.ErrAnchorIntentInvalid) }, gate.ErrAnchorIntentInvalid},
		"certificate below quorum":   {commitment.DAFibre, func(f *fEnv) { f.Verifier.Fail(gate.ErrCertInvalid) }, gate.ErrCertInvalid},
		"chain down":                 {commitment.DAFibre, func(f *fEnv) { f.Verifier.Fail(errors.New("dial")) }, gate.ErrChainUnavailable},
		"created_at not the promise": {commitment.DAFibre, func(f *fEnv) { f.facts.CreatedAt++; f.stage() }, gate.ErrAnchorIntentInvalid},
		"h0 too old":                 {commitment.DAFibre, func(f *fEnv) { f.facts.Head = f.h0 + 11; f.stage() }, gate.ErrH0TooOld},
		"head below h0":              {commitment.DAFibre, func(f *fEnv) { f.facts.Head = f.h0 - 1; f.stage() }, gate.ErrChainUnavailable},
		"chain window zero":          {commitment.DAFibre, func(f *fEnv) { f.facts.ChainWindow = 0; f.stage() }, gate.ErrAnchorWindowClosed},
		"promise about to expire": {commitment.DAFibre, func(f *fEnv) {
			f.facts.HeadTime = f.facts.CreatedAt + f.facts.PromiseTimeout - 15
			f.stage()
		}, gate.ErrAnchorWindowClosed},
		"timeout height below the slack": {commitment.DACelestiaBlob, func(f *fEnv) {
			f.facts.TimeoutHeight = f.facts.Head + 2
			f.stage()
		}, gate.ErrAnchorWindowClosed},
		"node refuses the broadcast": {commitment.DACelestiaBlob, func(f *fEnv) {
			f.Broadcaster.FailBroadcast(errors.New("insufficient fee"))
		}, gate.ErrAnchorIntentRejected},
		"lookup fails": {commitment.DACelestiaBlob, func(f *fEnv) { f.Broadcaster.FailLookup(errors.New("dial")) }, gate.ErrChainUnavailable},
		"included after the deadline": {commitment.DACelestiaBlob, func(f *fEnv) {
			f.Broadcaster.SetStatus(f.rec.Tx, gate.TxStatus{Included: true, Height: f.h0 + fastDelay + 1})
		}, gate.ErrAnchorWindowClosed},
		"included with a nonzero code": {commitment.DACelestiaBlob, func(f *fEnv) {
			f.Broadcaster.SetStatus(f.rec.Tx, gate.TxStatus{Included: true, Height: f.h0 + 1, Code: 11})
		}, gate.ErrAnchorWindowClosed},
		"archived blob differs from the commitment": {commitment.DACelestiaBlob, func(f *fEnv) {
			f.Archive.Put(f.c.PayloadRef, gatefix.BlobY(f.t))
		}, gate.ErrAnchorIntentRejected},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFastEnv(t, tc.da, fastMandate(t, fastDelay))
			tc.mutate(f)
			res, err := f.authorize()
			require.ErrorIs(t, err, tc.want)
			assert.Empty(t, res.Authorization)
			f.RequireUntouched(f.c)
		})
	}
}

func TestFastBlobMismatchBeforeTheBroadcast(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(f *fEnv)
		want   error
	}{
		"blob off its DA commitment": {func(f *fEnv) {
			f.Archive.Put(f.c.PayloadRef, gatefix.BlobY(f.t))
		}, gate.ErrAnchorIntentRejected},
		"size differs from the decision": {func(f *fEnv) {
			f.c.PayloadSize++
		}, commitment.ErrPayloadSizeMismatch},
		"hash differs from the decision": {func(f *fEnv) {
			f.c.CiphertextHash = append([]byte(nil), f.c.CiphertextHash...)
			f.c.CiphertextHash[0] ^= 1
		}, commitment.ErrPayloadHashMismatch},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFastEnv(t, commitment.DACelestiaBlob, fastMandate(t, fastDelay))
			tc.mutate(f)
			res, err := f.authorize()
			require.ErrorIs(t, err, tc.want)
			if tc.want != gate.ErrAnchorIntentRejected {
				assert.NotErrorIs(t, err, gate.ErrAnchorIntentRejected, "a payload verdict is final, not a retryable rejection")
			}
			assert.Empty(t, res.Authorization)
			assert.Empty(t, f.Broadcaster.Broadcasts())
			f.RequireUntouched(f.c)
		})
	}
}

func TestFastAnchorAlreadyInWindowWaivesTheSlack(t *testing.T) {
	f := newFastEnv(t, commitment.DAFibre, fastMandate(t, 5))
	f.facts.Head = f.h0 + 5
	f.stage()
	_, err := f.authorize()
	require.ErrorIs(t, err, gate.ErrAnchorWindowClosed)

	f.Broadcaster.SetStatus(f.rec.Tx, gate.TxStatus{Included: true, Height: f.h0 + 4})
	res, err := f.authorize()
	f.requireFast(res, err, f.h0+5)
	assert.Empty(t, f.Broadcaster.Broadcasts(), "an included anchor is not broadcast again")
}

func TestFastRebroadcastOffSkipsTheLookup(t *testing.T) {
	off := false
	f := newFastEnv(t, commitment.DAFibre, fastMandate(t, fastDelay),
		gatefix.WithConfig(func(c *gate.Config) { c.RebroadcastIntent = &off }))
	res, err := f.authorize()
	f.requireFast(res, err, f.h0+fastDelay)
	assert.Zero(t, f.Broadcaster.Lookups())
	assert.Empty(t, f.Broadcaster.Broadcasts())
}

func TestFastModeNeedsTheMandatesConsent(t *testing.T) {
	f := newFastEnv(t, commitment.DACelestiaBlob, fastMandate(t, 0))
	require.NotEmpty(t, f.Logs.Records(0), "the gate warns at start")
	res, err := f.authorize()
	require.ErrorIs(t, err, policy.ErrFastModeNotAllowed)
	sv, _, derr := policy.DecodeSignedVerdict(res.PolicyVerdict)
	require.NoError(t, derr)
	assert.Equal(t, "ErrFastModeNotAllowed", sv.Verdict.Reason)
	assert.Nil(t, sv.Verdict.Facts)
	assert.Zero(t, f.Verifier.Calls(), "K-fast never runs without consent")
	assert.Zero(t, f.Intents.Reads())
	f.RequireUntouched(f.c)
}

func TestFastPendingNamespaceMustBeListed(t *testing.T) {
	f := newFastEnv(t, commitment.DACelestiaBlob, fastMandate(t, fastDelay),
		gatefix.WithConfig(func(c *gate.Config) {
			c.PendingNamespaces = [][]byte{gatefix.MustHex(t, "000000000000000000000000000000000000006564696374612f6f7468")}
		}))
	res, err := f.authorize()
	require.ErrorIs(t, err, gate.ErrNamespaceNotAllowed)
	assert.False(t, res.DecisionArchived, "a stage 1 refusal archives nothing")
	assert.Zero(t, f.Intents.Reads())
}

func TestFastIssuedBeforeTRef(t *testing.T) {
	f := newFastEnv(t, commitment.DACelestiaBlob, fastMandate(t, fastDelay))
	f.facts.RefTime = f.issued + f.Cfg.SkewS + 1
	f.stage()
	_, err := f.authorize()
	f.RequireRejected(f.c, err, commitment.ErrIssuedBeforeAnchor)
}

func TestFastModeNeedsTheIntentDependencies(t *testing.T) {
	for name, drop := range map[string]func(d *gate.Deps){
		"intents":     func(d *gate.Deps) { d.Intents = nil },
		"broadcaster": func(d *gate.Deps) { d.Broadcaster = nil },
		"verifier":    func(d *gate.Deps) { delete(d.IntentVerifiers, commitment.DAFibre) },
	} {
		t.Run(name, func(t *testing.T) {
			tmpl := gatefix.Template(t)
			_, err := gatefix.TryNew(t, policyOpts(t, fastMandate(t, fastDelay),
				gatefix.WithConfig(func(c *gate.Config) {
					c.FastMode = true
					c.PendingNamespaces = [][]byte{tmpl.PayloadRef.Namespace}
				}),
				gatefix.WithDeps(func(d *gate.Deps) { d.Archiver = &recordingArchiver{} }),
				gatefix.WithDeps(drop))...)
			require.ErrorIs(t, err, gate.ErrInvalidConfig)
		})
	}
}

func TestDeadlineVectors(t *testing.T) {
	var af struct {
		Window []struct {
			ID    string `json:"id"`
			Input struct {
				DA            string `json:"da"`
				Window        string `json:"fast_window_blocks"`
				H0            string `json:"h0"`
				Head          string `json:"head"`
				MaxAge        string `json:"max_h0_age"`
				Delay         string `json:"fast_mode_max_delay"`
				Slack         string `json:"min_fast_slack_blocks"`
				ChainWindow   string `json:"chain_window"`
				TimeoutHeight string `json:"timeout_height"`
				IncludedAt    string `json:"included_at"`
				IncludedCode  string `json:"included_code"`
				Promise       *struct {
					THead    string `json:"t_head"`
					Creation string `json:"creation"`
					Timeout  string `json:"timeout"`
					MinSlack string `json:"min_slack"`
				} `json:"promise"`
			} `json:"input"`
			Expect struct {
				Deadline string `json:"anchor_deadline"`
				Error    string `json:"expect_error"`
			} `json:"expect"`
		} `json:"window"`
	}
	gatefix.ReadVector(t, "anchor.json", &af)
	require.NotEmpty(t, af.Window)
	waived := 0
	for _, v := range af.Window {
		t.Run(v.ID, func(t *testing.T) {
			in := v.Input
			setCfg := func(cfg *gate.Config) {
				cfg.FastWindowBlocks, cfg.MaxH0AgeBlocks = gatefix.U64(t, in.Window), gatefix.U64(t, in.MaxAge)
				cfg.MinFastSlackBlocks = gatefix.U64(t, in.Slack)
				if p := in.Promise; p != nil {
					cfg.MinPromiseSlackSeconds = gatefix.U64(t, p.MinSlack)
				}
			}
			da := commitment.DA(gatefix.U64(t, in.DA))
			f := gate.IntentFacts{DA: da, ChainWindow: optU64(t, in.ChainWindow),
				TimeoutHeight: optU64(t, in.TimeoutHeight), PromiseTimeout: 3600, CreatedAt: 1 << 40}
			if p := in.Promise; p != nil {
				f.HeadTime, f.CreatedAt, f.PromiseTimeout = gatefix.U64(t, p.THead), gatefix.U64(t, p.Creation), gatefix.U64(t, p.Timeout)
			}
			h0, head, delay := gatefix.U64(t, in.H0), gatefix.U64(t, in.Head), gatefix.U64(t, in.Delay)
			var want error
			if v.Expect.Error != "" {
				var ok bool
				want, ok = gatefix.Sentinel(v.Expect.Error)
				require.True(t, ok, v.Expect.Error)
			}

			if in.IncludedAt == "" {
				cfg := gate.DefaultConfig()
				setCfg(&cfg)
				d, _, err := gate.Deadline(h0, head, f, cfg, delay)
				if want != nil {
					require.ErrorIs(t, err, want)
					return
				}
				require.NoError(t, err)
				assert.Equal(t, gatefix.U64(t, v.Expect.Deadline), d)
				return
			}

			// The waiver lives in the gate, so an inclusion vector runs
			// through it: heights are moved onto the fixture's h0, which
			// leaves every bound in the vector unchanged.
			require.Nil(t, in.Promise, "an inclusion vector with a promise needs the promise times staged")
			waived++
			e := newFastEnv(t, da, fastMandate(t, delay), gatefix.WithConfig(setCfg))
			e.facts.Head = e.h0 + head - h0
			e.facts.ChainWindow, e.facts.TimeoutHeight = f.ChainWindow, 0
			if f.TimeoutHeight != 0 {
				e.facts.TimeoutHeight = e.h0 + f.TimeoutHeight - h0
			}
			e.stage()
			e.Broadcaster.SetStatus(e.rec.Tx, gate.TxStatus{Included: true,
				Height: e.h0 + gatefix.U64(t, in.IncludedAt) - h0, Code: uint32(optU64(t, in.IncludedCode))})
			res, err := e.authorize()
			assert.Empty(t, e.Broadcaster.Broadcasts(), "an included anchor is never broadcast again")
			if want != nil {
				require.ErrorIs(t, err, want)
				assert.Empty(t, res.Authorization)
				e.RequireUntouched(e.c)
				return
			}
			e.requireFast(res, err, e.h0+gatefix.U64(t, v.Expect.Deadline)-h0)
		})
	}
	require.GreaterOrEqual(t, waived, 2, "the inclusion vectors ran through the gate")
}

func TestPendingK2Vectors(t *testing.T) {
	var af struct {
		K2 []struct {
			ID         string `json:"id"`
			DA         string `json:"da"`
			TRef       string `json:"t_ref"`
			ValidUntil string `json:"valid_until"`
			Retention  string `json:"retention_s"`
			CreatedAt  string `json:"intent_created_at"`
			Form       string `json:"form"`
			Expect     struct {
				Start  string `json:"start"`
				Within bool   `json:"within"`
			} `json:"expect"`
		} `json:"k2"`
	}
	gatefix.ReadVector(t, "anchor.json", &af)
	ran := 0
	for _, v := range af.K2 {
		if v.Form != "pending" {
			continue
		}
		ran++
		t.Run(v.ID, func(t *testing.T) {
			da := commitment.DA(gatefix.U64(t, v.DA))
			tRef, vu := gatefix.U64(t, v.TRef), gatefix.U64(t, v.ValidUntil)
			issued := vu - 600
			// The vectors' T_ref lies hours before issued_at; only the
			// retention window is under test, so the decision age bound is
			// set out of the way.
			m := fastMandate(t, fastDelay)
			m.MaxDecisionAge = 86400
			fc := gatetest.NewDACommitter()
			tmpl := gatefix.FibreTemplate(t)
			fc.Bind(tmpl.PayloadRef.Commitment, gatefix.FibreBlob())
			f := newFastEnv(t, da, m, gatefix.WithNow(issued+1),
				gatefix.WithParams(commitment.Params{FibreRetentionS: 14400, BlobRetentionS: gatefix.U64(t, v.Retention), SkewS: 30}),
				gatefix.WithDeps(func(d *gate.Deps) { d.Committers[commitment.DAFibre] = fc }))
			f.c = gatefix.Times(f.c, issued, vu)
			f.tRef = tRef
			f.facts.RefTime, f.facts.HeadTime = tRef, tRef
			if da == commitment.DAFibre {
				f.Chain.SetAt(f.h0, gatefix.U64(t, v.Retention))
				f.rec.CreatedAt = gatefix.U64(t, v.CreatedAt)
				f.facts.CreatedAt = f.rec.CreatedAt
			}
			f.stage()
			res, err := f.authorize()
			require.NoError(t, err)
			want := registry.PathArchive
			if v.Expect.Within && da == commitment.DAFibre {
				want = registry.PathDA
			}
			assert.Equal(t, want, res.Path)
		})
	}
	require.GreaterOrEqual(t, ran, 5)
}

// A failed commit leaves nothing behind: the retry runs K-fast again and
// gets a fast-mode Authorization.
func TestFastNothingWrittenBeforeTheCommit(t *testing.T) {
	f := newFastEnv(t, commitment.DACelestiaBlob, fastMandate(t, fastDelay), gatefix.WithFaultyRegistry())
	f.Faulty.FailNext("ConsumeState", errors.New("disk full"))
	res, err := f.authorize()
	require.ErrorIs(t, err, gate.ErrRegistryUnavailable)
	assert.Empty(t, res.Authorization)
	f.RequireUntouched(f.c)

	res, err = f.authorize()
	f.requireFast(res, err, f.h0+fastDelay)
	assert.Equal(t, 2, f.Verifier.Calls())
}
