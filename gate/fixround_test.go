package gate_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/registry"
	"github.com/vgonkivs/edicta/gate/registry/boltreg"
	"github.com/vgonkivs/edicta/test/gatefix"
)

// A replay that is already past the nonce peek must not get a second
// Authorization when the clock steps forward, the entry is pruned and the clock steps back
// before the reservation.
func TestClockStepAndPruneCannotResurrectAConsumedNonce(t *testing.T) {
	for name, open := range registries() {
		t.Run(name, func(t *testing.T) {
			e, c, b, _ := happy(t, gatefix.WithRegistry(open(t)), gatefix.WithFaultyRegistry())
			_, err := e.Authorize(b)
			require.NoError(t, err)

			later := gatefix.Now + 7200
			c2 := gatefix.Times(gatefix.Fresh(gatefix.Template(t), 2), later-10, later+890)
			c2.PayloadRef.Height++ // a header time of its own, so E's anchor is untouched
			e.StageDA(c2, gatefix.Blob(t))
			b2, _ := gatefix.Sign(t, "agent1", c2)

			var pruned int
			e.Faulty.Before("Get", func() {
				e.Clock.Set(later)
				_, err := e.Authorize(b2)
				assert.NoError(t, err)
				pruned, err = e.Gate.Prune(context.Background())
				assert.NoError(t, err)
				e.Clock.Set(gatefix.Now)
			})
			_, err = e.Authorize(b)
			require.Equal(t, 1, pruned, "the scenario needs the executed entry to be pruned")
			require.ErrorIs(t, err, gate.ErrClockRegression)
			_, err = e.Entry(c)
			require.ErrorIs(t, err, registry.ErrNotFound)
		})
	}
}

// The clock moves back beyond the tolerance while the payload is fetched.
func TestClockStepBackDuringFetchIsRefused(t *testing.T) {
	for name, open := range registries() {
		t.Run(name, func(t *testing.T) {
			e, _, b, _ := happy(t, gatefix.WithRegistry(open(t)))
			_, err := e.Authorize(b)
			require.NoError(t, err)
			c2 := gatefix.Fresh(gatefix.Template(t), 2)
			e.StageDA(c2, gatefix.Blob(t))
			b2, _ := gatefix.Sign(t, "agent1", c2)
			e.DA.OnFetch(func() { e.Clock.Set(gatefix.Now - 120) })
			_, err = e.Authorize(b2)
			require.ErrorIs(t, err, gate.ErrClockRegression)
			_, err = e.Entry(c2)
			require.ErrorIs(t, err, registry.ErrNotFound)
		})
	}
}

type signerMode int32

const (
	signOK signerMode = iota
	signPanic
	signHang
	signZero
)

type modalSigner struct {
	inner gate.Signer
	mode  atomic.Int32
	stop  chan struct{}
}

func (s *modalSigner) PublicKey() ed25519.PublicKey { return s.inner.PublicKey() }
func (s *modalSigner) Sign(ctx context.Context, msg []byte) ([]byte, error) {
	switch signerMode(s.mode.Load()) {
	case signPanic:
		panic("signer bug")
	case signHang:
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.stop:
			return nil, errors.New("signer released by the test")
		}
	case signZero:
		return make([]byte, 64), nil
	}
	return s.inner.Sign(ctx, msg)
}

// authorizeWithin fails the test, instead of waiting for the test binary's own
// timeout, when Authorize does not return in time; a hanging signer is released.
func authorizeWithin(t *testing.T, e *gatefix.Env, b []byte, d time.Duration, s *modalSigner) (gate.Result, error) {
	t.Helper()
	type out struct {
		res gate.Result
		err error
	}
	ch := make(chan out, 1)
	go func() {
		res, err := e.Authorize(b)
		ch <- out{res, err}
	}()
	select {
	case o := <-ch:
		return o.res, o.err
	case <-time.After(d):
		close(s.stop)
		require.FailNow(t, "Authorize did not return: the gate does not bound the signer call")
		return gate.Result{}, nil
	}
}

func newModalSigner(t *testing.T, mode signerMode) *modalSigner {
	inner, err := gate.NewEd25519Signer(gatefix.Key(t, "gate1"))
	require.NoError(t, err)
	s := &modalSigner{inner: inner, stop: make(chan struct{})}
	s.mode.Store(int32(mode))
	return s
}

type stallParams struct {
	inner      gate.ChainParams
	stallAtTip bool
	stallAtH   bool
}

func (p stallParams) FibreRetention(ctx context.Context, h uint64) (uint64, error) {
	if (h == 0 && p.stallAtTip) || (h != 0 && p.stallAtH) {
		<-ctx.Done()
		return 0, ctx.Err()
	}
	return p.inner.FibreRetention(ctx, h)
}

type stallHeaders struct{}

func (stallHeaders) BlockTime(ctx context.Context, _ uint64) (uint64, error) {
	<-ctx.Done()
	return 0, ctx.Err()
}

type stallAnchors struct{}

func (stallAnchors) FindAnchor(ctx context.Context, _ commitment.PayloadRef) (gate.Anchor, error) {
	<-ctx.Done()
	return gate.Anchor{}, ctx.Err()
}

type stallAllowlist struct{}

func (stallAllowlist) PubKey(ctx context.Context, _ string) ([32]byte, error) {
	<-ctx.Done()
	return [32]byte{}, ctx.Err()
}

// A stalled chain or allowlist call is cut by the gate's own timeout, before
// the caller's context expires, and no nonce is consumed.
func TestStalledDependenciesAreCutByChainTimeout(t *testing.T) {
	cases := []struct {
		name  string
		fibre bool
		set   func(d *gate.Deps)
		want  []error
	}{
		{"latest retention", true, func(d *gate.Deps) { d.Params = stallParams{inner: d.Params, stallAtTip: true} }, []error{gate.ErrChainUnavailable}},
		{"header", false, func(d *gate.Deps) { d.Headers = stallHeaders{} }, []error{gate.ErrChainUnavailable}},
		{"anchor", false, func(d *gate.Deps) { d.Anchors = stallAnchors{} }, []error{gate.ErrChainUnavailable}},
		{"retention at the anchor height", true, func(d *gate.Deps) { d.Params = stallParams{inner: d.Params, stallAtH: true} }, []error{gate.ErrRetentionUnavailable, gate.ErrChainUnavailable}},
		{"allowlist", false, func(d *gate.Deps) { d.Allowlist = stallAllowlist{} }, []error{gate.ErrAllowlistUnavailable, gate.ErrChainUnavailable}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := gatefix.New(t, gatefix.WithDeps(tc.set), gatefix.WithConfig(func(c *gate.Config) { c.ChainTimeout = 20 * time.Millisecond }))
			var c *commitment.Commitment
			var blob []byte
			if tc.fibre {
				c, blob = gatefix.FibreTemplate(t), gatefix.FibreBlob()
			} else {
				c, blob = gatefix.Template(t), gatefix.Blob(t)
			}
			e.StageDA(c, blob)
			b, _ := gatefix.Sign(t, "agent1", c)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, err := e.Gate.Authorize(ctx, b, gatefix.Action(t), gatefix.Salt(t))
			require.NoError(t, ctx.Err(), "the gate must return before the caller's deadline")
			matched := false
			for _, w := range tc.want {
				matched = matched || errors.Is(err, w)
			}
			require.Truef(t, matched, "got %v", err)
			e.RequireUntouched(c)
		})
	}
}

func TestDefaultChainTimeoutIsSet(t *testing.T) {
	require.Positive(t, gate.DefaultConfig().ChainTimeout)
}

type flakyAllowlist struct{ err error }

func (a flakyAllowlist) PubKey(context.Context, string) ([32]byte, error) { return [32]byte{}, a.err }

func TestAllowlistTransientErrorHasASentinelAndKeepsItsCause(t *testing.T) {
	errDB := errors.New("allowlist database down")
	e, c, b, _ := happy(t, gatefix.WithDeps(func(d *gate.Deps) { d.Allowlist = flakyAllowlist{err: errDB} }))
	_, err := e.Authorize(b)
	e.RequireRejected(c, err, gate.ErrAllowlistUnavailable)
	require.ErrorIs(t, err, errDB)
	require.NotErrorIs(t, err, gate.ErrAgentNotAllowed)
}

type epochRegistry struct {
	registry.Registry
	epoch uint64
}

func (r epochRegistry) Meta(ctx context.Context) (registry.Meta, error) {
	m, err := r.Registry.Meta(ctx)
	m.Epoch = r.epoch
	return m, err
}

func TestRegistryEpochMustBeSetAndNotAheadOfTheClock(t *testing.T) {
	t.Run("memreg refuses epoch 0", func(t *testing.T) {
		_, err := newMemRegErr(0)
		require.Error(t, err)
	})
	t.Run("boltreg refuses epoch 0", func(t *testing.T) {
		_, err := boltreg.Open(filepath.Join(t.TempDir(), "n.db"), 0)
		require.Error(t, err)
	})
	t.Run("gate.New refuses a registry whose epoch is 0", func(t *testing.T) {
		_, err := gatefix.TryNew(t, gatefix.WithRegistry(epochRegistry{Registry: gatefix.MemReg(t, 1), epoch: 0}))
		require.Error(t, err)
	})
	t.Run("gate.New refuses an epoch ahead of the clock beyond the tolerance", func(t *testing.T) {
		_, err := gatefix.TryNew(t, gatefix.WithRegistry(gatefix.MemReg(t, gatefix.Now+61)))
		require.Error(t, err)
	})
	t.Run("an epoch ahead of the clock by the tolerance is accepted", func(t *testing.T) {
		_, err := gatefix.TryNew(t, gatefix.WithRegistry(gatefix.MemReg(t, gatefix.Now+60)))
		require.NoError(t, err)
	})
}

func TestOnlyOneGatePerRegistry(t *testing.T) {
	e := gatefix.New(t)
	_, err := gate.New(context.Background(), e.Cfg, e.Deps)
	require.ErrorIs(t, err, gate.ErrRegistryInUse)

	// A refused New must not have touched the running gate's entries.
	e2, c, b, _ := happy(t)
	first, err := e2.Authorize(b)
	require.NoError(t, err)
	_, err = gate.New(context.Background(), e2.Cfg, e2.Deps)
	require.ErrorIs(t, err, gate.ErrRegistryInUse)
	ent, err := e2.Entry(c)
	require.NoError(t, err)
	require.Equal(t, first.Authorization, ent.Authorization, "a refused New must leave the running gate's entries alone")

	require.NoError(t, e2.Gate.Close())
	g, err := gate.New(context.Background(), e2.Cfg, e2.Deps)
	require.NoError(t, err)
	require.NoError(t, g.Close())
}

func TestNewRequiresACommitterForBlobCommitments(t *testing.T) {
	for name, m := range map[string]map[commitment.DA]gate.DACommitter{
		"nil map":        nil,
		"empty map":      {},
		"fibre only":     {commitment.DAFibre: failingCommitter{}},
		"nil blob entry": {commitment.DACelestiaBlob: nil},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := gatefix.TryNew(t, gatefix.WithDeps(func(d *gate.Deps) { d.Committers = m }))
			require.Error(t, err)
		})
	}
}

// Mutation gaps.

// Size errors outrank hash errors across the two paths.
func TestSizeMismatchOutranksHashMismatchAcrossPaths(t *testing.T) {
	flipped := gatefix.Blob(t)
	flipped[0] ^= 1
	short := gatefix.Blob(t)[:100]
	for name, srcs := range map[string][2][]byte{
		"DA short, archive flipped": {short, flipped},
		"DA flipped, archive short": {flipped, short},
	} {
		t.Run(name, func(t *testing.T) {
			e, c, b, _ := blobEnv(t)
			e.DA.Put(c.PayloadRef, srcs[0])
			e.Archive.Put(c.PayloadRef, srcs[1])
			_, err := e.Authorize(b)
			e.RequireRejected(c, err, commitment.ErrPayloadSizeMismatch)
			require.NotErrorIs(t, err, commitment.ErrPayloadHashMismatch)
		})
	}
}

// The byte budget serialises fetches: with a budget of one payload, the
// second fetch waits for the first.
func TestFetchBudgetSerialisesFetches(t *testing.T) {
	e, c0, _, _ := happy(t, gatefix.WithConfig(func(c *gate.Config) { c.MaxFetchBytes = 301 }))
	hold := make(chan struct{})
	var first sync.Once
	e.DA.OnFetch(func() { first.Do(func() { <-hold }) })
	envs := make([][]byte, 2)
	for i := range envs {
		c := gatefix.Fresh(c0, byte(i+1))
		e.StageDA(c, gatefix.Blob(t))
		envs[i], _ = gatefix.Sign(t, "agent1", c)
	}
	var wg sync.WaitGroup
	for _, b := range envs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.Authorize(b)
			assert.NoError(t, err)
		}()
	}
	require.Eventually(t, func() bool { return e.DA.Fetches() >= 1 }, 10*time.Second, time.Millisecond)
	require.Never(t, func() bool { return e.DA.Fetches() > 1 }, 200*time.Millisecond, 5*time.Millisecond,
		"a second fetch started while the budget was used up")
	close(hold)
	wg.Wait()
	require.Equal(t, 2, e.DA.Fetches())
}

// Smaller items.

func TestFailureCausesStayMatchable(t *testing.T) {
	cause := errors.New("underlying failure")
	t.Run("header source", func(t *testing.T) {
		e, c, b, _ := happy(t)
		e.Headers.Fail(cause)
		_, err := e.Authorize(b)
		e.RequireRejected(c, err, gate.ErrChainUnavailable)
		require.ErrorIs(t, err, cause)
	})
	t.Run("anchor source", func(t *testing.T) {
		e, c, b, _ := happy(t)
		e.Anchors.Fail(cause)
		_, err := e.Authorize(b)
		e.RequireRejected(c, err, gate.ErrChainUnavailable)
		require.ErrorIs(t, err, cause)
	})
	t.Run("latest retention", func(t *testing.T) {
		e, c, b, _ := happyFibre(t)
		e.Chain.FailLatest(cause)
		_, err := e.Authorize(b)
		e.RequireRejected(c, err, gate.ErrChainUnavailable)
		require.ErrorIs(t, err, cause)
	})
	t.Run("consume", func(t *testing.T) {
		e, c, b, _ := happy(t, gatefix.WithFaultyRegistry())
		e.Faulty.FailNext("Consume", cause)
		_, err := e.Authorize(b)
		e.RequireRejected(c, err, gate.ErrRegistryUnavailable)
		require.ErrorIs(t, err, cause)
	})
}

func TestAnchorForAnotherHeightIsRefused(t *testing.T) {
	e := gatefix.New(t)
	c := gatefix.Template(t)
	th := gatefix.BlockTime(c)
	e.Headers.Set(c.PayloadRef.Height, th)
	e.Anchors.Set(c.PayloadRef, gate.Anchor{Height: c.PayloadRef.Height + 1, RetentionStart: th})
	e.DA.Put(c.PayloadRef, gatefix.Blob(t))
	b, _ := gatefix.Sign(t, "agent1", c)
	_, err := e.Authorize(b)
	e.RequireRejected(c, err, gate.ErrAnchorNotFound)
}

func TestAdmissionEventCarriesTheCommitmentHash(t *testing.T) {
	t.Run("executed", func(t *testing.T) {
		e, _, b, h := happy(t)
		_, err := e.Authorize(b)
		require.NoError(t, err)
		ev := e.Metrics.Events()
		require.Len(t, ev, 1)
		require.Equal(t, h, ev[0].CommitmentHash)
	})
	t.Run("rejected after the signature check", func(t *testing.T) {
		e, c, b, h := happy(t)
		e.Anchors.Fail(errors.New("down"))
		_, err := e.Authorize(b)
		e.RequireRejected(c, err, gate.ErrChainUnavailable)
		ev := e.Metrics.Events()
		require.Len(t, ev, 1)
		require.Equal(t, h, ev[0].CommitmentHash)
	})
}

type errCommitter struct{ err error }

func (c errCommitter) Check(commitment.PayloadRef, []byte) error { return c.err }

func TestArbitraryCommitterErrorRefusesAdmission(t *testing.T) {
	for name, cerr := range map[string]error{
		"plain":    errors.New("boom"),
		"deadline": context.DeadlineExceeded,
		"canceled": context.Canceled,
	} {
		t.Run(name, func(t *testing.T) {
			e := gatefix.New(t, gatefix.WithDeps(func(d *gate.Deps) {
				d.Committers = map[commitment.DA]gate.DACommitter{commitment.DACelestiaBlob: errCommitter{err: cerr}}
			}))
			c := gatefix.Template(t)
			routeArchive(e, c)
			e.Archive.Put(c.PayloadRef, gatefix.Blob(t))
			b, _ := gatefix.Sign(t, "agent1", c)
			_, err := e.Authorize(b)
			e.RequireRejected(c, err, gate.ErrDACommitmentMismatch)
		})
	}
}

// Raising the clock tolerance across a restart must not let a pruned nonce be
// reserved again, even while the clock is far behind the watermark.
func TestRaisedToleranceCannotResurrectAPrunedNonce(t *testing.T) {
	for name, open := range registries() {
		t.Run(name, func(t *testing.T) {
			e, c, b, _ := happy(t, gatefix.WithRegistry(open(t)))
			_, err := e.Authorize(b)
			require.NoError(t, err)

			later := gatefix.Now + 7200
			e.Clock.Set(later)
			c2 := gatefix.Times(gatefix.Fresh(gatefix.Template(t), 2), later-10, later+890)
			c2.PayloadRef.Height++ // a header time of its own, so E's anchor is untouched
			e.StageDA(c2, gatefix.Blob(t))
			b2, _ := gatefix.Sign(t, "agent1", c2)
			_, err = e.Authorize(b2)
			require.NoError(t, err)
			n, err := e.Gate.Prune(context.Background())
			require.NoError(t, err)
			require.Equal(t, 1, n, "the scenario needs the executed entry to be pruned")

			e.Cfg.ClockTolerance, e.Cfg.PruneGrace = 8000, 8001
			e.Clock.Set(gatefix.Now)
			require.NoError(t, e.Restart())
			_, err = e.Authorize(b)
			require.ErrorIs(t, err, gate.ErrClockRegression)
			require.ErrorIs(t, err, registry.ErrPrunedWindow)
			_, err = e.Entry(c)
			require.ErrorIs(t, err, registry.ErrNotFound)
		})
	}
}

func TestClosedGateRefusesEverything(t *testing.T) {
	e, c, b, _ := happy(t)
	require.NoError(t, e.Gate.Close())
	ctx := context.Background()

	res, err := e.Gate.Authorize(ctx, b, gatefix.Action(t), gatefix.Salt(t))
	require.ErrorIs(t, err, gate.ErrClosed)
	require.Nil(t, res.Authorization)
	_, err = e.Record(b, "ref-1")
	require.ErrorIs(t, err, gate.ErrClosed)
	_, err = e.Gate.Prune(ctx)
	require.ErrorIs(t, err, gate.ErrClosed)
	e.RequireUntouched(c)
}

func TestNewRefusesAZeroClockReading(t *testing.T) {
	_, err := gatefix.TryNew(t, gatefix.WithNow(0))
	require.Error(t, err)
}
