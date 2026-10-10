package gate_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/test/gatefix"
)

func TestDeadlineBoundaries(t *testing.T) {
	const h0 = 1000
	cfg := gate.DefaultConfig() // window 100, age 10, slack 3, promise slack 15 s
	fibre := func(head uint64) gate.IntentFacts {
		return gate.IntentFacts{DA: commitment.DAFibre, Head: head, HeadTime: 5000, CreatedAt: 4000, PromiseTimeout: 3600, ChainWindow: 1000}
	}
	blob := func(head, timeout uint64) gate.IntentFacts {
		return gate.IntentFacts{DA: commitment.DACelestiaBlob, Head: head, TimeoutHeight: timeout}
	}
	for name, tc := range map[string]struct {
		f           gate.IntentFacts
		delay       uint64
		want        uint64
		err         error
		provisional bool
	}{
		"age at the limit":                {f: fibre(h0 + 10), delay: 50, want: h0 + 50},
		"age one past the limit":          {f: fibre(h0 + 11), delay: 50, err: gate.ErrH0TooOld},
		"head below h0":                   {f: fibre(h0 - 1), delay: 50, err: gate.ErrChainUnavailable},
		"mandate bound zero":              {f: fibre(h0), delay: 0, err: gate.ErrAnchorWindowClosed},
		"deadline exactly head + slack":   {f: fibre(h0 + 7), delay: 10, want: h0 + 10},
		"deadline one below the slack":    {f: fibre(h0 + 8), delay: 10, want: h0 + 10, err: gate.ErrAnchorWindowClosed, provisional: true},
		"deadline at the head":            {f: fibre(h0 + 10), delay: 10, want: h0 + 10, err: gate.ErrAnchorWindowClosed, provisional: true},
		"deadline below the head":         {f: fibre(h0 + 9), delay: 5, want: h0 + 5, err: gate.ErrAnchorWindowClosed, provisional: true},
		"blob ignores the chain window":   {f: gate.IntentFacts{DA: commitment.DACelestiaBlob, Head: h0, ChainWindow: 1}, delay: 50, want: h0 + 50},
		"blob timeout lowers":             {f: blob(h0+1, h0+20), delay: 50, want: h0 + 20},
		"blob timeout above is ignored":   {f: blob(h0+1, h0+60), delay: 50, want: h0 + 50},
		"blob timeout zero is no bound":   {f: blob(h0+1, 0), delay: 50, want: h0 + 50},
		"blob timeout at head + slack":    {f: blob(h0+1, h0+4), delay: 50, want: h0 + 4},
		"blob timeout below head + slack": {f: blob(h0+2, h0+4), delay: 50, want: h0 + 4, err: gate.ErrAnchorWindowClosed, provisional: true},
		"promise one second inside the slack": {f: gate.IntentFacts{DA: commitment.DAFibre, Head: h0, HeadTime: 4000 + 3600 - 16,
			CreatedAt: 4000, PromiseTimeout: 3600, ChainWindow: 1000}, delay: 50, want: h0 + 50},
		"promise exactly at the slack": {f: gate.IntentFacts{DA: commitment.DAFibre, Head: h0, HeadTime: 4000 + 3600 - 15,
			CreatedAt: 4000, PromiseTimeout: 3600, ChainWindow: 1000}, delay: 50, want: h0 + 50, err: gate.ErrAnchorWindowClosed, provisional: true},
	} {
		t.Run(name, func(t *testing.T) {
			d, provisional, err := gate.Deadline(h0, tc.f.Head, tc.f, cfg, tc.delay)
			assert.Equal(t, tc.provisional, provisional)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
				if tc.provisional {
					assert.Equal(t, tc.want, d, "a provisional failure still states the deadline the lookup checks against")
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, d)
		})
	}
}

func TestFastStaleH0(t *testing.T) {
	t.Run("age at the limit authorizes", func(t *testing.T) {
		f := newFastEnv(t, commitment.DAFibre, fastMandate(t, fastDelay))
		f.facts.Head = f.h0 + f.Cfg.MaxH0AgeBlocks
		f.stage()
		res, err := f.authorize()
		f.requireFast(res, err, f.h0+fastDelay)
	})
	// An h0 too old is final even if the anchor is already in: the lookup is
	// never asked.
	t.Run("too old even when included", func(t *testing.T) {
		f := newFastEnv(t, commitment.DACelestiaBlob, fastMandate(t, fastDelay))
		f.facts.Head = f.h0 + f.Cfg.MaxH0AgeBlocks + 1
		f.stage()
		f.Broadcaster.SetStatus(f.rec.Tx, gate.TxStatus{Included: true, Height: f.h0 + 1})
		res, err := f.authorize()
		require.ErrorIs(t, err, gate.ErrH0TooOld)
		assert.Empty(t, res.Authorization)
		assert.Zero(t, f.Broadcaster.Lookups())
		assert.Empty(t, f.Broadcaster.Broadcasts())
		f.RequireUntouched(f.c)
	})
}

// The included anchor decides a provisional slack failure: inside
// [h0, deadline] with code 0 it passes, even with the deadline already
// below the head; anywhere else it is refused and nothing is broadcast.
func TestFastIncludedAnchorAgainstTheWindow(t *testing.T) {
	const delay = 5
	for name, tc := range map[string]struct {
		st   gate.TxStatus
		pass bool
	}{
		"at h0":               {gate.TxStatus{Included: true}, true},
		"at the deadline":     {gate.TxStatus{Included: true, Height: delay}, true},
		"after the deadline":  {gate.TxStatus{Included: true, Height: delay + 1}, false},
		"before h0 (replay)":  {gate.TxStatus{Included: true, Height: ^uint64(0)}, false},
		"in window, failed":   {gate.TxStatus{Included: true, Height: 2, Code: 5}, false},
		"not included at all": {gate.TxStatus{}, false},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFastEnv(t, commitment.DAFibre, fastMandate(t, delay))
			f.facts.Head = f.h0 + 8 // deadline h0+5 is below the head
			f.stage()
			st := tc.st
			switch {
			case st.Height == ^uint64(0):
				st.Height = f.h0 - 1
			case st.Included:
				st.Height += f.h0
			}
			f.Broadcaster.SetStatus(f.rec.Tx, st)
			res, err := f.authorize()
			assert.Empty(t, f.Broadcaster.Broadcasts(), "a provisional failure is never broadcast")
			if tc.pass {
				f.requireFast(res, err, f.h0+delay)
				return
			}
			require.ErrorIs(t, err, gate.ErrAnchorWindowClosed)
			assert.Empty(t, res.Authorization)
			f.RequireUntouched(f.c)
		})
	}
}

// Without the provisional failure, an anchor that was included before h0
// (an old tx replayed under a new reference height) is refused too.
func TestFastIntentIncludedBeforeH0IsRefused(t *testing.T) {
	for _, da := range []commitment.DA{commitment.DAFibre, commitment.DACelestiaBlob} {
		f := newFastEnv(t, da, fastMandate(t, fastDelay))
		f.Broadcaster.SetStatus(f.rec.Tx, gate.TxStatus{Included: true, Height: f.h0 - 1})
		res, err := f.authorize()
		require.ErrorIs(t, err, gate.ErrAnchorWindowClosed, "da %d", da)
		assert.Empty(t, res.Authorization)
		assert.Empty(t, f.Broadcaster.Broadcasts())
		f.RequireUntouched(f.c)
	}
}

// RebroadcastIntent off skips the Fibre lookup only while the slack holds;
// a provisional failure still asks the node.
func TestFastRebroadcastOffStillLooksUpAProvisionalFailure(t *testing.T) {
	off := false
	f := newFastEnv(t, commitment.DAFibre, fastMandate(t, 5),
		gatefix.WithConfig(func(c *gate.Config) { c.RebroadcastIntent = &off }))
	f.facts.Head = f.h0 + 3
	f.stage()
	f.Broadcaster.SetStatus(f.rec.Tx, gate.TxStatus{Included: true, Height: f.h0 + 2})
	res, err := f.authorize()
	f.requireFast(res, err, f.h0+5)
	assert.Equal(t, 1, f.Broadcaster.Lookups())
	assert.Empty(t, f.Broadcaster.Broadcasts())
}

// A blob intent is always broadcast with its blob: without the BlobTx the
// anchor cannot exist.
func TestFastBlobIsBroadcastWithRebroadcastOff(t *testing.T) {
	off := false
	f := newFastEnv(t, commitment.DACelestiaBlob, fastMandate(t, fastDelay),
		gatefix.WithConfig(func(c *gate.Config) { c.RebroadcastIntent = &off }))
	res, err := f.authorize()
	f.requireFast(res, err, f.h0+fastDelay)
	bs := f.Broadcaster.Broadcasts()
	require.Len(t, bs, 1)
	assert.Equal(t, gatefix.Blob(t), bs[0].Blob)
}

// lyingIntents returns a record whose key differs from the one asked for.
type lyingIntents struct {
	gate.IntentSource
	mutate func(*gate.AnchorIntent)
}

func (l lyingIntents) Intent(ctx context.Context, da commitment.DA, commit []byte, h uint64) (*gate.AnchorIntent, error) {
	r, err := l.IntentSource.Intent(ctx, da, commit, h)
	if err != nil {
		return nil, err
	}
	l.mutate(r)
	return r, nil
}

// An intent source that answers with the intent of another reference is
// treated as no intent at all: retryable, nothing verified, nothing written.
func TestFastIntentForAnotherReference(t *testing.T) {
	for name, mutate := range map[string]func(*gate.AnchorIntent){
		"another commitment": func(r *gate.AnchorIntent) { r.Commitment = make([]byte, 32) },
		"another h0":         func(r *gate.AnchorIntent) { r.RefHeight++ },
		"another da":         func(r *gate.AnchorIntent) { r.DA = commitment.DAFibre },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFastEnv(t, commitment.DACelestiaBlob, fastMandate(t, fastDelay),
				gatefix.WithDeps(func(d *gate.Deps) {
					d.Intents = lyingIntents{IntentSource: d.Intents, mutate: mutate}
				}))
			res, err := f.authorize()
			require.ErrorIs(t, err, gate.ErrAnchorIntentUnavailable)
			assert.Empty(t, res.Authorization)
			assert.Zero(t, f.Verifier.Calls())
			assert.Zero(t, f.Broadcaster.Lookups())
			f.RequireUntouched(f.c)
		})
	}
}

// The verifier must report the reference's da and a reference time; an
// answer without them is the chain's failure, never an Authorization.
func TestFastVerifierFactsAreChecked(t *testing.T) {
	for name, mutate := range map[string]func(*gate.IntentFacts){
		"other da":    func(f *gate.IntentFacts) { f.DA = commitment.DAFibre },
		"no ref time": func(f *gate.IntentFacts) { f.RefTime = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFastEnv(t, commitment.DACelestiaBlob, fastMandate(t, fastDelay))
			mutate(&f.facts)
			f.stage()
			res, err := f.authorize()
			require.ErrorIs(t, err, gate.ErrChainUnavailable)
			assert.Empty(t, res.Authorization)
			assert.Empty(t, f.Broadcaster.Broadcasts())
			f.RequireUntouched(f.c)
		})
	}
}

// Many concurrent requests for one pending decision issue one Authorization
// and every one of them carries the same bytes.
func TestFastConcurrentRequestsIssueOneAuthorization(t *testing.T) {
	f := newFastEnv(t, commitment.DACelestiaBlob, fastMandate(t, fastDelay))
	b, _ := gatefix.Sign(t, "agent1", f.c)
	const n = 8
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		fresh  int
		issued [][]byte
	)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := f.Authorize(b)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				fresh++
			} else if !errors.Is(err, gate.ErrNonceUsed) {
				return
			}
			issued = append(issued, res.Authorization)
		}()
	}
	wg.Wait()
	assert.Equal(t, 1, fresh, "exactly one request issues the Authorization")
	require.NotEmpty(t, issued)
	for _, a := range issued {
		assert.Equal(t, issued[0], a)
	}
	sa, _, err := commitment.DecodeSignedAuthorization(issued[0])
	require.NoError(t, err)
	assert.Equal(t, f.h0+fastDelay, sa.Authorization.AnchorDeadline)
}
