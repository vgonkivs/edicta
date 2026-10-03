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

	"github.com/vgonkivs/prior/commitment"
	"github.com/vgonkivs/prior/gate"
	"github.com/vgonkivs/prior/gate/registry"
	"github.com/vgonkivs/prior/gate/registry/boltreg"
	"github.com/vgonkivs/prior/test/gatefix"
)

// A replay that is already past the nonce peek must not execute a second time
// when the clock steps forward, the entry is pruned and the clock steps back
// before the reservation.
func TestClockStepAndPruneCannotResurrectAnExecutedNonce(t *testing.T) {
	for name, open := range registries() {
		t.Run(name, func(t *testing.T) {
			e, c, b, _ := happy(t, gatefix.WithRegistry(open(t)), gatefix.WithFaultyRegistry())
			_, err := e.Admit(b)
			require.NoError(t, err)

			later := gatefix.Now + 7200
			c2 := gatefix.Times(gatefix.Fresh(gatefix.Template(t), 2), later-10, later+890)
			c2.PayloadRef.Height++ // a header time of its own, so E's anchor is untouched
			e.StageDA(c2, gatefix.Blob(t))
			b2, _ := gatefix.Sign(t, "agent1", c2)

			var pruned int
			e.Faulty.Before("Get", func() {
				e.Clock.Set(later)
				_, err := e.Admit(b2)
				assert.NoError(t, err)
				pruned, err = e.Gate.Prune(context.Background())
				assert.NoError(t, err)
				e.Clock.Set(gatefix.Now)
			})
			_, err = e.Admit(b)
			require.Equal(t, 1, pruned, "the scenario needs the executed entry to be pruned")
			require.ErrorIs(t, err, gate.ErrClockRegression)
			require.Equal(t, 2, e.Exec.Calls(), "the first decision and the second one, never the first twice")
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
			_, err := e.Admit(b)
			require.NoError(t, err)
			c2 := gatefix.Fresh(gatefix.Template(t), 2)
			e.StageDA(c2, gatefix.Blob(t))
			b2, _ := gatefix.Sign(t, "agent1", c2)
			e.DA.OnFetch(func() { e.Clock.Set(gatefix.Now - 120) })
			before := e.Exec.Calls()
			_, err = e.Admit(b2)
			require.ErrorIs(t, err, gate.ErrClockRegression)
			require.Equal(t, before, e.Exec.Calls(), "the refused admission must not execute")
			_, err = e.Entry(c2)
			require.ErrorIs(t, err, registry.ErrNotFound)
		})
	}
}

func TestReplayWithAnotherHashReportsNothingOfTheStoredEntry(t *testing.T) {
	t.Run("stored entry executed", func(t *testing.T) {
		e, _, b, h := happy(t)
		first, err := e.Admit(b)
		require.NoError(t, err)
		c2 := gatefix.Template(t)
		c2.Action.IBKROrder.Qty--
		e.StageDA(c2, gatefix.Blob(t))
		b2, h2 := gatefix.Sign(t, "agent1", c2)
		res, err := e.Admit(b2)
		require.ErrorIs(t, err, gate.ErrNonceUsed)
		require.NotEqual(t, h, h2)
		require.Equal(t, h2, res.CommitmentHash)
		require.Zero(t, res.State)
		require.Zero(t, res.Path)
		require.Nil(t, res.Receipt)

		same, err := e.Admit(b)
		require.ErrorIs(t, err, gate.ErrNonceUsed)
		require.Equal(t, registry.StateExecuted, same.State)
		require.Equal(t, registry.PathDA, same.Path)
		require.Equal(t, first.Receipt, same.Receipt)
	})
	t.Run("stored entry unknown", func(t *testing.T) {
		e, _, h := unknownEntry(t)
		_ = h
		c2 := gatefix.Template(t)
		c2.Action.IBKROrder.Qty--
		e.StageDA(c2, gatefix.Blob(t))
		b2, _ := gatefix.Sign(t, "agent1", c2)
		res, err := e.Admit(b2)
		require.ErrorIs(t, err, gate.ErrNonceUsed)
		require.Zero(t, res.State)
		require.Zero(t, res.Path)
	})
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

// admitWithin fails the test, instead of waiting for the test binary's own
// timeout, when Admit does not return in time; a hanging signer is released.
func admitWithin(t *testing.T, e *gatefix.Env, b []byte, d time.Duration, s *modalSigner) (gate.Result, error) {
	t.Helper()
	type out struct {
		res gate.Result
		err error
	}
	ch := make(chan out, 1)
	go func() {
		res, err := e.Admit(b)
		ch <- out{res, err}
	}()
	select {
	case o := <-ch:
		return o.res, o.err
	case <-time.After(d):
		close(s.stop)
		require.FailNow(t, "Admit did not return: the gate does not bound the signer call")
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

// A signer that panics, hangs or returns a bad signature after the order was
// placed leaves an Executed entry without a receipt.
func TestBrokenSignerLeavesExecutedWithoutReceipt(t *testing.T) {
	for name, mode := range map[string]signerMode{"panic": signPanic, "hang": signHang, "bad signature": signZero} {
		t.Run(name, func(t *testing.T) {
			s := newModalSigner(t, mode)
			e, c, b, _ := happy(t, gatefix.WithSigner(s), gatefix.WithConfig(func(cfg *gate.Config) {
				cfg.ExecTimeout = 20 * time.Millisecond
			}))
			res, err := admitWithin(t, e, b, 30*time.Second, s)
			require.ErrorIs(t, err, gate.ErrReceiptPending)
			require.Equal(t, registry.StateExecuted, res.State)
			require.Nil(t, res.Receipt)
			ent, err := e.Entry(c)
			require.NoError(t, err)
			require.Equal(t, registry.StateExecuted, ent.State)
			require.Nil(t, ent.Receipt)
			require.Equal(t, 1, e.Exec.Calls())

			_, err = e.Admit(b)
			require.ErrorIs(t, err, gate.ErrNonceUsed)

			s.mode.Store(int32(signOK))
			_, err = e.Gate.Reconcile(context.Background())
			require.NoError(t, err)
			ent, _ = e.Entry(c)
			require.NotNil(t, ent.Receipt, "a working signer must be able to sign it later")
			require.Equal(t, 1, e.Exec.Calls())
		})
	}
}

func TestBrokenSignerDuringReconcileAndManualResolve(t *testing.T) {
	for name, mode := range map[string]signerMode{"panic": signPanic, "bad signature": signZero} {
		t.Run(name, func(t *testing.T) {
			s := newModalSigner(t, signOK)
			e, c, _ := unknownEntry(t, gatefix.WithSigner(s))
			s.mode.Store(int32(mode))
			e.Exec.SetLookup(gate.ExecResult{Outcome: gate.OutcomeExecuted, RailRef: "555"}, nil)
			require.NotPanics(t, func() { _, _ = e.Gate.Reconcile(context.Background()) })
			ent, _ := e.Entry(c)
			require.Equal(t, registry.StateExecuted, ent.State)
			require.Nil(t, ent.Receipt)

			e2, c2, _ := unknownEntry(t, gatefix.WithSigner(s))
			require.NotPanics(t, func() {
				_, _ = e2.Gate.ResolveManually(context.Background(), gatefix.KeyOf(c2), gate.ManualResolution{
					Outcome: gate.ManualExecuted, RailRef: "1", Operator: "op", Note: "n"})
			})
			ent, _ = e2.Entry(c2)
			require.Equal(t, registry.StateExecuted, ent.State)
			require.Nil(t, ent.Receipt)
		})
	}
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
		{"latest retention", false, func(d *gate.Deps) { d.Params = stallParams{inner: d.Params, stallAtTip: true} }, []error{gate.ErrChainUnavailable}},
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
			_, err := e.Gate.Admit(ctx, b)
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
	_, err := e.Admit(b)
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
	e2.Gate.SetAfterReserve(func() error { return errCrash })
	_, err = e2.Admit(b)
	require.ErrorIs(t, err, errCrash)
	_, err = gate.New(context.Background(), e2.Cfg, e2.Deps)
	require.ErrorIs(t, err, gate.ErrRegistryInUse)
	ent, err := e2.Entry(c)
	require.NoError(t, err)
	require.Equal(t, registry.StateReserved, ent.State, "a refused New must not recover entries of the running gate")

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

func archiveUnknown(t *testing.T) (*gatefix.Env, *commitment.Commitment) {
	t.Helper()
	e := gatefix.New(t)
	c := gatefix.Template(t)
	routeArchive(e, c)
	e.Archive.Put(c.PayloadRef, gatefix.Blob(t))
	b, _ := gatefix.Sign(t, "agent1", c)
	e.Exec.SetError(errors.New("timeout"))
	res, err := e.Admit(b)
	require.ErrorIs(t, err, gate.ErrExecutionUnknown)
	require.Equal(t, registry.PathArchive, res.Path)
	return e, c
}

func TestReceiptPathSurvivesReconcileAndManualResolve(t *testing.T) {
	t.Run("reconcile", func(t *testing.T) {
		e, c := archiveUnknown(t)
		e.Exec.SetLookup(gate.ExecResult{Outcome: gate.OutcomeExecuted, RailRef: "555"}, nil)
		_, err := e.Gate.Reconcile(context.Background())
		require.NoError(t, err)
		ent, _ := e.Entry(c)
		h, _ := commitment.HashOf(c)
		gatefix.CheckReceipt(t, gate.Result{Receipt: ent.Receipt}, h, "555", commitment.ReceiptPathArchive, gatefix.GateID, gatefix.Pub(t, "gate1"), 0)
	})
	t.Run("manual", func(t *testing.T) {
		e, c := archiveUnknown(t)
		ent, err := e.Gate.ResolveManually(context.Background(), gatefix.KeyOf(c), gate.ManualResolution{
			Outcome: gate.ManualExecuted, RailRef: "556", Operator: "op", Note: "n"})
		require.NoError(t, err)
		h, _ := commitment.HashOf(c)
		gatefix.CheckReceipt(t, gate.Result{Receipt: ent.Receipt}, h, "556", commitment.ReceiptPathArchive, gatefix.GateID, gatefix.Pub(t, "gate1"), 0)
	})
	t.Run("resign", func(t *testing.T) {
		s := newModalSigner(t, signZero)
		e := gatefix.New(t, gatefix.WithSigner(s))
		c := gatefix.Template(t)
		routeArchive(e, c)
		e.Archive.Put(c.PayloadRef, gatefix.Blob(t))
		b, h := gatefix.Sign(t, "agent1", c)
		_, err := e.Admit(b)
		require.ErrorIs(t, err, gate.ErrReceiptPending)
		s.mode.Store(int32(signOK))
		_, err = e.Gate.Reconcile(context.Background())
		require.NoError(t, err)
		ent, _ := e.Entry(c)
		gatefix.CheckReceipt(t, gate.Result{Receipt: ent.Receipt}, h, gatefix.RailRef, commitment.ReceiptPathArchive, gatefix.GateID, gatefix.Pub(t, "gate1"), 0)
		require.Equal(t, registry.SourceResign, ent.History[len(ent.History)-1].Source)
	})
}

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
			_, err := e.Admit(b)
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
			_, err := e.Admit(b)
			assert.NoError(t, err)
		}()
	}
	require.Eventually(t, func() bool { return e.DA.Fetches() >= 1 }, 10*time.Second, time.Millisecond)
	require.Never(t, func() bool { return e.DA.Fetches() > 1 }, 200*time.Millisecond, 5*time.Millisecond,
		"a second fetch started while the budget was used up")
	close(hold)
	wg.Wait()
	require.Equal(t, 2, e.DA.Fetches())
	require.Equal(t, 2, e.Exec.Calls())
}

// Smaller items.

func TestLostReserveRaceReportsTheStoredPath(t *testing.T) {
	e, c, b, h := happy(t, gatefix.WithFaultyRegistry())
	e.Faulty.Before("Reserve", func() {
		require.NoError(t, e.Reg.Reserve(context.Background(), registry.Entry{
			Key: gatefix.KeyOf(c), CommitmentHash: h, State: registry.StateReserved,
			Path: registry.PathArchive, ReservedAt: gatefix.Now, ValidUntil: c.ValidUntil,
		}, 60))
	})
	res, err := e.Admit(b)
	require.ErrorIs(t, err, gate.ErrNonceUsed)
	require.Equal(t, registry.PathArchive, res.Path)
	require.Zero(t, e.Exec.Calls())
}

func TestReconcileReturnsLookupErrors(t *testing.T) {
	e, _, _ := unknownEntry(t)
	errLookup := errors.New("rail unreachable")
	e.Exec.SetLookup(gate.ExecResult{}, errLookup)
	rep, err := e.Gate.Reconcile(context.Background())
	require.ErrorIs(t, err, errLookup)
	require.Equal(t, 1, rep.StillUnknown)
}

func TestRecoverRecordsTheGateClock(t *testing.T) {
	e, c, b, _ := happy(t)
	e.Gate.SetAfterReserve(func() error { return errCrash })
	_, err := e.Admit(b)
	require.ErrorIs(t, err, errCrash)
	e.Clock.Set(gatefix.Now + 30)
	require.NoError(t, e.Restart())
	ent, err := e.Entry(c)
	require.NoError(t, err)
	require.Len(t, ent.History, 1)
	require.EqualValues(t, gatefix.Now+30, ent.History[0].At)
}

func TestFailureCausesStayMatchable(t *testing.T) {
	cause := errors.New("underlying failure")
	t.Run("header source", func(t *testing.T) {
		e, c, b, _ := happy(t)
		e.Headers.Fail(cause)
		_, err := e.Admit(b)
		e.RequireRejected(c, err, gate.ErrChainUnavailable)
		require.ErrorIs(t, err, cause)
	})
	t.Run("anchor source", func(t *testing.T) {
		e, c, b, _ := happy(t)
		e.Anchors.Fail(cause)
		_, err := e.Admit(b)
		e.RequireRejected(c, err, gate.ErrChainUnavailable)
		require.ErrorIs(t, err, cause)
	})
	t.Run("latest retention", func(t *testing.T) {
		e, c, b, _ := happy(t)
		e.Chain.FailLatest(cause)
		_, err := e.Admit(b)
		e.RequireRejected(c, err, gate.ErrChainUnavailable)
		require.ErrorIs(t, err, cause)
	})
	t.Run("reserve", func(t *testing.T) {
		e, c, b, _ := happy(t, gatefix.WithFaultyRegistry())
		e.Faulty.FailNext("Reserve", cause)
		_, err := e.Admit(b)
		e.RequireRejected(c, err, gate.ErrRegistryUnavailable)
		require.ErrorIs(t, err, cause)
	})
	t.Run("resolve after execution", func(t *testing.T) {
		e, _, b, _ := happy(t, gatefix.WithFaultyRegistry())
		e.Faulty.FailNext("Resolve", cause)
		_, err := e.Admit(b)
		require.ErrorIs(t, err, gate.ErrReceiptPending)
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
	_, err := e.Admit(b)
	e.RequireRejected(c, err, gate.ErrAnchorNotFound)
}

func TestAdmissionEventCarriesTheCommitmentHash(t *testing.T) {
	t.Run("executed", func(t *testing.T) {
		e, _, b, h := happy(t)
		_, err := e.Admit(b)
		require.NoError(t, err)
		ev := e.Metrics.Events()
		require.Len(t, ev, 1)
		require.Equal(t, h, ev[0].CommitmentHash)
	})
	t.Run("rejected after the signature check", func(t *testing.T) {
		e, c, b, h := happy(t)
		e.Anchors.Fail(errors.New("down"))
		_, err := e.Admit(b)
		e.RequireRejected(c, err, gate.ErrChainUnavailable)
		ev := e.Metrics.Events()
		require.Len(t, ev, 1)
		require.Equal(t, h, ev[0].CommitmentHash)
	})
}

type ctxCommitter struct{ err error }

func (c ctxCommitter) Check(context.Context, commitment.PayloadRef, []byte) error { return c.err }

func TestCommitterContextErrorIsUnavailableNotMismatch(t *testing.T) {
	for name, cerr := range map[string]error{"deadline": context.DeadlineExceeded, "canceled": context.Canceled} {
		t.Run(name, func(t *testing.T) {
			e := gatefix.New(t, gatefix.WithDeps(func(d *gate.Deps) {
				d.Committers = map[commitment.DA]gate.DACommitter{commitment.DACelestiaBlob: ctxCommitter{err: cerr}}
			}))
			c := gatefix.Template(t)
			routeArchive(e, c)
			e.Archive.Put(c.PayloadRef, gatefix.Blob(t))
			b, _ := gatefix.Sign(t, "agent1", c)
			_, err := e.Admit(b)
			e.RequireRejected(c, err, gate.ErrPayloadUnavailable)
			require.NotErrorIs(t, err, gate.ErrDACommitmentMismatch)
		})
	}
}

// Raising the clock tolerance across a restart must not let a pruned nonce be
// reserved again, even while the clock is far behind the watermark.
func TestRaisedToleranceCannotResurrectAPrunedNonce(t *testing.T) {
	for name, open := range registries() {
		t.Run(name, func(t *testing.T) {
			e, c, b, _ := happy(t, gatefix.WithRegistry(open(t)))
			_, err := e.Admit(b)
			require.NoError(t, err)

			later := gatefix.Now + 7200
			e.Clock.Set(later)
			c2 := gatefix.Times(gatefix.Fresh(gatefix.Template(t), 2), later-10, later+890)
			c2.PayloadRef.Height++ // a header time of its own, so E's anchor is untouched
			e.StageDA(c2, gatefix.Blob(t))
			b2, _ := gatefix.Sign(t, "agent1", c2)
			_, err = e.Admit(b2)
			require.NoError(t, err)
			n, err := e.Gate.Prune(context.Background())
			require.NoError(t, err)
			require.Equal(t, 1, n, "the scenario needs the executed entry to be pruned")

			e.Cfg.ClockTolerance, e.Cfg.PruneGrace = 8000, 8001
			e.Clock.Set(gatefix.Now)
			require.NoError(t, e.Restart())
			_, err = e.Admit(b)
			require.ErrorIs(t, err, gate.ErrClockRegression)
			require.ErrorIs(t, err, registry.ErrPrunedWindow)
			require.Equal(t, 2, e.Exec.Calls(), "the first decision once, plus the second decision")
			_, err = e.Entry(c)
			require.ErrorIs(t, err, registry.ErrNotFound)
		})
	}
}

func TestClosedGateRefusesEverything(t *testing.T) {
	e, c, b, _ := happy(t)
	require.NoError(t, e.Gate.Close())
	ctx := context.Background()

	res, err := e.Gate.Admit(ctx, b)
	require.ErrorIs(t, err, gate.ErrClosed)
	require.Zero(t, res.State)
	_, err = e.Gate.Reconcile(ctx)
	require.ErrorIs(t, err, gate.ErrClosed)
	_, err = e.Gate.ResolveManually(ctx, gatefix.KeyOf(c), gate.ManualResolution{
		Outcome: gate.ManualRejected, Operator: "op", Note: "n"})
	require.ErrorIs(t, err, gate.ErrClosed)
	_, err = e.Gate.Prune(ctx)
	require.ErrorIs(t, err, gate.ErrClosed)
	e.RequireUntouched(c)
}

func TestNewRefusesAZeroClockReading(t *testing.T) {
	_, err := gatefix.TryNew(t, gatefix.WithNow(0))
	require.Error(t, err)
}
