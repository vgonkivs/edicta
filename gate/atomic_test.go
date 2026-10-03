package gate_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
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

var errCrash = errors.New("simulated crash")

func registries() map[string]func(t *testing.T) registry.Registry {
	return map[string]func(t *testing.T) registry.Registry{
		"memreg": func(t *testing.T) registry.Registry { return gatefix.MemReg(t, gatefix.Epoch) },
		"boltreg": func(t *testing.T) registry.Registry {
			r, err := boltreg.Open(filepath.Join(t.TempDir(), "nonces.db"), gatefix.Epoch)
			require.NoError(t, err)
			t.Cleanup(func() { _ = r.Close() })
			return r
		},
	}
}

func TestConcurrentReplayExecutesOnce(t *testing.T) {
	for name, open := range registries() {
		t.Run(name, func(t *testing.T) {
			e, c, b, _ := happy(t, gatefix.WithRegistry(open(t)))
			const n = 64
			release := make(chan struct{})
			e.Exec.OnExecute(func(context.Context, gate.ExecRequest) { <-release })
			var wg sync.WaitGroup
			var ok, used, other atomic.Int32
			losers := make(chan struct{}, n)
			for i := 0; i < n; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, err := e.Admit(append([]byte(nil), b...))
					switch {
					case err == nil:
						ok.Add(1)
					case errors.Is(err, gate.ErrNonceUsed):
						used.Add(1)
						losers <- struct{}{}
					default:
						other.Add(1)
						assert.Fail(t, fmt.Sprintf("unexpected error: %v", err))
						losers <- struct{}{}
					}
				}()
			}
			// The winner is blocked in Execute until every loser has returned.
			for i := 0; i < n-1; i++ {
				select {
				case <-losers:
				case <-time.After(30 * time.Second):
					close(release)
					require.FailNow(t, "a replay did not return: the nonce check let it through to the executor")
				}
			}
			close(release)
			wg.Wait()
			require.EqualValuesf(t, 1, ok.Load(), "ok=%d used=%d other=%d", ok.Load(), used.Load(), other.Load())
			require.EqualValuesf(t, n-1, used.Load(), "ok=%d used=%d other=%d", ok.Load(), used.Load(), other.Load())
			require.EqualValuesf(t, 0, other.Load(), "ok=%d used=%d other=%d", ok.Load(), used.Load(), other.Load())
			require.EqualValuesf(t, 1, e.Exec.Calls(), "executor calls %d", e.Exec.Calls())
			ent, err := e.Entry(c)
			require.NoErrorf(t, err, "entry %+v", ent)
			require.Equalf(t, registry.StateExecuted, ent.State, "entry %+v %v", ent, err)
		})
	}
}

func TestConcurrentDistinctNoncesAllExecute(t *testing.T) {
	e, _, _, _ := happy(t)
	const n = 16
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		c := gatefix.Fresh(gatefix.Template(t), byte(i))
		e.StageDA(c, gatefix.Blob(t))
		b, _ := gatefix.Sign(t, "agent1", c)
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.Admit(b)
			assert.NoError(t, err, "Admit")
		}()
	}
	wg.Wait()
	require.Equal(t, n, e.Exec.Calls())
}

func TestExecutorOutcomes(t *testing.T) {
	cases := []struct {
		name      string
		setup     func(e *gatefix.Env)
		wantErr   error
		wantState registry.State
	}{
		{"error", func(e *gatefix.Env) { e.Exec.SetError(errors.New("connection reset")) }, gate.ErrExecutionUnknown, registry.StateUnknown},
		{"deadline exceeded", func(e *gatefix.Env) { e.Exec.SetError(context.DeadlineExceeded) }, gate.ErrExecutionUnknown, registry.StateUnknown},
		{"unknown outcome without error", func(e *gatefix.Env) {
			e.Exec.SetResult(gate.ExecResult{Outcome: gate.OutcomeUnknown})
		}, gate.ErrExecutionUnknown, registry.StateUnknown},
		{"hang until the execution timeout", func(e *gatefix.Env) {
			e.Cfg.ExecTimeout = 20 * time.Millisecond
			e.Exec.Hang()
		}, gate.ErrExecutionUnknown, registry.StateUnknown},
		{"definite rejection", func(e *gatefix.Env) {
			e.Exec.SetResult(gate.ExecResult{Outcome: gate.OutcomeRejected})
		}, gate.ErrExecutionRejected, registry.StateRejected},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, c, b, _ := happy(t, gatefix.WithConfig(func(cfg *gate.Config) { cfg.ExecTimeout = 20 * time.Millisecond }))
			tc.setup(e)
			res, err := e.Admit(b)
			require.ErrorIs(t, err, tc.wantErr)
			require.Equalf(t, tc.wantState, res.State, "result %+v", res)
			require.Nilf(t, res.Receipt, "result %+v", res)
			ent, _ := e.Entry(c)
			require.Equalf(t, tc.wantState, ent.State, "entry %+v", ent)
			require.Lenf(t, ent.History, 1, "entry %+v", ent)
			require.EqualValuesf(t, registry.StateReserved, ent.History[0].PrevState, "entry %+v", ent)
			// The nonce stays used and nothing is sent again.
			for i := 0; i < 3; i++ {
				_, err := e.Admit(b)
				require.ErrorIs(t, err, gate.ErrNonceUsed, "replay")
			}
			_, err = e.Gate.Reconcile(context.Background())
			require.NoError(t, err)
			require.EqualValuesf(t, 1, e.Exec.Calls(), "executor called %d times", e.Exec.Calls())
			ev := e.Metrics.Events()
			require.Lenf(t, ev, 4, "metrics %+v", ev)
			require.ErrorIsf(t, ev[0].Err, tc.wantErr, "metrics %+v", ev)
			require.EqualValuesf(t, tc.wantState, ev[0].State, "metrics %+v", ev)
		})
	}
}

func TestExecutionSurvivesCallerCancel(t *testing.T) {
	e, c, b, _ := happy(t)
	ctx, cancel := context.WithCancel(context.Background())
	var ctxErr error
	e.Exec.OnExecute(func(ctx context.Context, _ gate.ExecRequest) {
		cancel()
		ctxErr = ctx.Err()
	})
	res, err := e.Gate.Admit(ctx, b)
	require.NoErrorf(t, err, "res %+v err", res)
	require.Equalf(t, registry.StateExecuted, res.State, "res %+v err %v", res, err)
	require.NoError(t, ctxErr, "executor context was cancelled with the caller's")
	ent, _ := e.Entry(c)
	require.Equalf(t, registry.StateExecuted, ent.State, "entry %+v", ent)
}

func TestRegistryFailures(t *testing.T) {
	t.Run("reserve fails: nothing sent, nonce free", func(t *testing.T) {
		e, c, b, _ := happy(t, gatefix.WithFaultyRegistry())
		e.Faulty.FailNext("Reserve", errors.New("disk full"))
		_, err := e.Admit(b)
		e.RequireRejected(c, err, gate.ErrRegistryUnavailable)
		_, err = e.Admit(b)
		require.NoError(t, err, "retry")
	})
	t.Run("resolve fails after execution: receipt pending, replay blocked", func(t *testing.T) {
		e, c, b, _ := happy(t, gatefix.WithFaultyRegistry())
		e.Faulty.FailNext("Resolve", errors.New("disk full"))
		res, err := e.Admit(b)
		require.ErrorIs(t, err, gate.ErrReceiptPending)
		require.Nil(t, res.Receipt, "receipt returned although it was not stored")
		ent, _ := e.Entry(c)
		require.Equalf(t, registry.StateReserved, ent.State, "entry %+v", ent)
		_, err = e.Admit(b)
		require.ErrorIs(t, err, gate.ErrNonceUsed, "replay")
		// Restart moves Reserved to Unknown; lookup then confirms it.
		err = e.Restart()
		require.NoError(t, err)
		e.Exec.SetLookup(gate.ExecResult{Outcome: gate.OutcomeExecuted, RailRef: gatefix.RailRef}, nil)
		rep, err := e.Gate.Reconcile(context.Background())
		require.NoErrorf(t, err, "report %+v err", rep)
		require.EqualValuesf(t, 1, rep.Executed, "report %+v err %v", rep, err)
		ent, _ = e.Entry(c)
		require.Equalf(t, registry.StateExecuted, ent.State, "entry %+v", ent)
		require.NotNilf(t, ent.Receipt, "entry %+v", ent)
		require.EqualValuesf(t, 1, e.Exec.Calls(), "executor calls %d", e.Exec.Calls())
	})
	t.Run("signing fails: executed without receipt, reconcile signs it later", func(t *testing.T) {
		signer, err := gate.NewEd25519Signer(gatefix.Key(t, "gate1"))
		require.NoError(t, err)
		bad := &flakySigner{inner: signer}
		bad.fail.Store(true)
		e, c, b, h := happy(t, gatefix.WithSigner(bad))
		res, err := e.Admit(b)
		require.ErrorIs(t, err, gate.ErrReceiptPending)
		require.Equalf(t, registry.StateExecuted, res.State, "result %+v", res)
		require.Nilf(t, res.Receipt, "result %+v", res)
		ent, _ := e.Entry(c)
		require.Equalf(t, registry.StateExecuted, ent.State, "entry %+v", ent)
		require.Nilf(t, ent.Receipt, "entry %+v", ent)
		_, err = e.Admit(b)
		require.ErrorIs(t, err, gate.ErrNonceUsed, "replay")
		bad.fail.Store(false)
		_, err = e.Gate.Reconcile(context.Background())
		require.NoError(t, err)
		ent, _ = e.Entry(c)
		require.NotNil(t, ent.Receipt, "receipt not re-signed")
		gatefix.CheckReceipt(t, gate.Result{Receipt: ent.Receipt}, h, gatefix.RailRef, commitment.ReceiptPathDA, gatefix.GateID, gatefix.Pub(t, "gate1"), 0)
		require.EqualValuesf(t, 1, e.Exec.Calls(), "executor calls %d", e.Exec.Calls())
	})
}

type flakySigner struct {
	inner gate.Signer
	fail  atomic.Bool
}

func (s *flakySigner) PublicKey() ed25519.PublicKey { return s.inner.PublicKey() }
func (s *flakySigner) Sign(ctx context.Context, msg []byte) ([]byte, error) {
	if s.fail.Load() {
		return nil, errors.New("hsm unavailable")
	}
	return s.inner.Sign(ctx, msg)
}

// TestCrashHooks: a crash at each point leaves the nonce used and never
// leads to a second Execute.
func TestCrashHooks(t *testing.T) {
	type hook struct {
		name      string
		set       func(g *gate.Gate)
		wantExecs int
	}
	hooks := []hook{
		{"after reserve", func(g *gate.Gate) { g.SetAfterReserve(func() error { return errCrash }) }, 0},
		{"after execute", func(g *gate.Gate) { g.SetAfterExecute(func() error { return errCrash }) }, 1},
		{"before resolve", func(g *gate.Gate) { g.SetBeforeResolve(func() error { return errCrash }) }, 1},
	}
	for name, open := range registries() {
		for _, h := range hooks {
			t.Run(name+"/"+h.name, func(t *testing.T) {
				e, c, b, _ := happy(t, gatefix.WithRegistry(open(t)))
				h.set(e.Gate)
				_, err := e.Admit(b)
				require.ErrorIs(t, err, errCrash)
				require.Equal(t, h.wantExecs, e.Exec.Calls())
				ent, _ := e.Entry(c)
				require.Equalf(t, registry.StateReserved, ent.State, "entry after crash %+v", ent)
				// A concurrent or retried submission is blocked.
				err = e.Restart()
				require.NoError(t, err)
				ent, _ = e.Entry(c)
				require.Equal(t, registry.StateUnknown, ent.State)
				require.Len(t, ent.History, 1)
				require.Equal(t, registry.SourceRecover, ent.History[0].Source)
				require.Equal(t, registry.StateReserved, ent.History[0].PrevState)
				_, err = e.Admit(b)
				require.ErrorIs(t, err, gate.ErrNonceUsed, "replay after restart")
				require.Equalf(t, h.wantExecs, e.Exec.Calls(), "executor calls after replay %d", e.Exec.Calls())
			})
		}
	}
}

// TestRecoverNeverExecutes: crash after reserve, restart, reconcile. The rail
// has no order, so the entry turns Rejected only after the settle window.
func TestRecoverNeverExecutes(t *testing.T) {
	e, c, b, _ := happy(t)
	e.Gate.SetAfterReserve(func() error { return errCrash })
	_, err := e.Admit(b)
	require.ErrorIs(t, err, errCrash)
	err = e.Restart()
	require.NoError(t, err)
	e.Exec.SetLookup(gate.ExecResult{Outcome: gate.OutcomeNotFound}, nil)

	settled := c.ValidUntil + 300
	e.Clock.Set(settled) // exactly at the end of the window: still not final
	rep, err := e.Gate.Reconcile(context.Background())
	require.NoErrorf(t, err, "at the window end: %+v", rep)
	require.EqualValuesf(t, 1, rep.StillUnknown, "at the window end: %+v %v", rep, err)
	require.EqualValuesf(t, 0, rep.Rejected, "at the window end: %+v %v", rep, err)
	ent, _ := e.Entry(c)
	require.Equalf(t, registry.StateUnknown, ent.State, "entry %+v", ent)
	e.Clock.Set(settled + 1)
	rep, err = e.Gate.Reconcile(context.Background())
	require.NoErrorf(t, err, "after the window: %+v", rep)
	require.EqualValuesf(t, 1, rep.Rejected, "after the window: %+v %v", rep, err)
	ent, _ = e.Entry(c)
	require.Equalf(t, registry.StateRejected, ent.State, "entry %+v", ent)
	require.Nilf(t, ent.Receipt, "entry %+v", ent)
	require.Lenf(t, ent.History, 2, "entry %+v", ent)
	require.EqualValuesf(t, registry.SourceLookup, ent.History[1].Source, "entry %+v", ent)
	require.EqualValuesf(t, 0, e.Exec.Calls(), "executor called %d times", e.Exec.Calls())
	ids := e.Exec.LookupIDs()
	want, _ := commitment.ClientOrderID(commitment.RailIBKR, ent.CommitmentHash)
	require.NotEmpty(t, ids)
	require.EqualValues(t, want, ids[0])
}

func TestReconcileFromUnknown(t *testing.T) {
	setup := func(t *testing.T) (*gatefix.Env, *commitment.Commitment, commitment.Hash) {
		e, c, b, h := happy(t)
		e.Exec.SetError(errors.New("timeout"))
		_, err := e.Admit(b)
		require.ErrorIs(t, err, gate.ErrExecutionUnknown)
		return e, c, h
	}
	t.Run("lookup finds the order", func(t *testing.T) {
		e, c, h := setup(t)
		e.Exec.SetLookup(gate.ExecResult{Outcome: gate.OutcomeExecuted, RailRef: "5550001"}, nil)
		e.Clock.Advance(10 * time.Second)
		rep, err := e.Gate.Reconcile(context.Background())
		require.NoErrorf(t, err, "%+v", rep)
		require.EqualValuesf(t, 1, rep.Executed, "%+v %v", rep, err)
		ent, _ := e.Entry(c)
		require.Equalf(t, registry.StateExecuted, ent.State, "entry %+v", ent)
		require.EqualValuesf(t, "5550001", ent.RailRef, "entry %+v", ent)
		require.EqualValuesf(t, gatefix.Now+10, ent.ExecutedAt, "entry %+v", ent)
		last := ent.History[len(ent.History)-1]
		require.Equalf(t, registry.SourceLookup, last.Source, "history %+v", ent.History)
		require.Equalf(t, "gate", last.By, "history %+v", ent.History)
		require.Equalf(t, registry.StateUnknown, last.PrevState, "history %+v", ent.History)
		gatefix.CheckReceipt(t, gate.Result{Receipt: ent.Receipt}, h, "5550001", commitment.ReceiptPathDA, gatefix.GateID, gatefix.Pub(t, "gate1"), gatefix.Now+10)
		require.EqualValues(t, 1, e.Exec.Calls(), "re-executed")
	})
	for name, lk := range map[string]struct {
		res gate.ExecResult
		err error
	}{
		"lookup unknown":            {gate.ExecResult{Outcome: gate.OutcomeUnknown}, nil},
		"lookup fails":              {gate.ExecResult{}, errors.New("rail down")},
		"lookup claims rejected":    {gate.ExecResult{Outcome: gate.OutcomeRejected}, nil},
		"lookup not found too soon": {gate.ExecResult{Outcome: gate.OutcomeNotFound}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			e, c, _ := setup(t)
			e.Exec.SetLookup(lk.res, lk.err)
			before, _ := e.Entry(c)
			rep, _ := e.Gate.Reconcile(context.Background())
			require.EqualValuesf(t, 1, rep.StillUnknown, "report %+v", rep)
			after, _ := e.Entry(c)
			require.Equalf(t, after, before, "entry written\nbefore %+v\nafter  %+v", before, after)
		})
	}
}

func unknownEntry(t *testing.T, opts ...gatefix.Option) (*gatefix.Env, *commitment.Commitment, commitment.Hash) {
	t.Helper()
	e, c, b, h := happy(t, opts...)
	e.Exec.SetError(errors.New("timeout"))
	_, err := e.Admit(b)
	require.ErrorIs(t, err, gate.ErrExecutionUnknown)
	return e, c, h
}

func TestResolveManually(t *testing.T) {
	ctx := context.Background()
	t.Run("executed", func(t *testing.T) {
		e, c, h := unknownEntry(t)
		e.Clock.Advance(7 * time.Second)
		ent, err := e.Gate.ResolveManually(ctx, gatefix.KeyOf(c), gate.ManualResolution{
			Outcome: gate.ManualExecuted, RailRef: "424242", Operator: "op-1", Note: "found in the TWS order log"})
		require.NoError(t, err)
		require.Equalf(t, registry.StateExecuted, ent.State, "entry %+v", ent)
		require.EqualValuesf(t, "424242", ent.RailRef, "entry %+v", ent)
		require.EqualValuesf(t, gatefix.Now+7, ent.ExecutedAt, "entry %+v", ent)
		last := ent.History[len(ent.History)-1]
		require.Len(t, ent.History, 2)
		require.Equal(t, registry.Resolution{Source: registry.SourceManual, By: "op-1", At: gatefix.Now + 7,
			Note: "found in the TWS order log", PrevState: registry.StateUnknown}, last)
		gatefix.CheckReceipt(t, gate.Result{Receipt: ent.Receipt}, h, "424242", commitment.ReceiptPathDA, gatefix.GateID, gatefix.Pub(t, "gate1"), gatefix.Now+7)
		stored, _ := e.Entry(c)
		require.Equal(t, ent, stored, "returned entry differs from the stored one")
		require.EqualValuesf(t, 1, e.Exec.Calls(), "executor %d lookups %d", e.Exec.Calls(), e.Exec.LookupCalls())
		require.EqualValuesf(t, 0, e.Exec.LookupCalls(), "executor %d lookups %d", e.Exec.Calls(), e.Exec.LookupCalls())
	})
	t.Run("rejected", func(t *testing.T) {
		e, c, _ := unknownEntry(t)
		ent, err := e.Gate.ResolveManually(ctx, gatefix.KeyOf(c), gate.ManualResolution{
			Outcome: gate.ManualRejected, Operator: "op-1", Note: "no order at the broker"})
		require.NoError(t, err)
		require.Equalf(t, registry.StateRejected, ent.State, "entry %+v", ent)
		require.Nilf(t, ent.Receipt, "entry %+v", ent)
		require.Equalf(t, "", ent.RailRef, "entry %+v", ent)
		require.EqualValues(t, 1, e.Exec.Calls(), "executor called")
	})
	t.Run("never re-enables execution", func(t *testing.T) {
		for _, out := range []gate.ManualResolution{
			{Outcome: gate.ManualExecuted, RailRef: "1", Operator: "op", Note: "n"},
			{Outcome: gate.ManualRejected, Operator: "op", Note: "n"},
		} {
			e, c, _ := unknownEntry(t)
			_, err := e.Gate.ResolveManually(ctx, gatefix.KeyOf(c), out)
			require.NoError(t, err)
			b, _ := gatefix.Sign(t, "agent1", c)
			_, err = e.Admit(b)
			require.ErrorIs(t, err, gate.ErrNonceUsed, "admit after manual resolve")
			require.EqualValuesf(t, 1, e.Exec.Calls(), "executor calls %d", e.Exec.Calls())
		}
	})
	t.Run("refused from every state but Unknown", func(t *testing.T) {
		res := gate.ManualResolution{Outcome: gate.ManualExecuted, RailRef: "1", Operator: "op", Note: "n"}
		// Reserved
		e, c, b, _ := happy(t)
		e.Gate.SetAfterReserve(func() error { return errCrash })
		_, _ = e.Admit(b)
		_, err := e.Gate.ResolveManually(ctx, gatefix.KeyOf(c), res)
		require.ErrorIs(t, err, gate.ErrNotUnknown, "Reserved")
		ent, _ := e.Entry(c)
		require.Equalf(t, registry.StateReserved, ent.State, "Reserved entry changed: %+v", ent)
		require.Lenf(t, ent.History, 0, "Reserved entry changed: %+v", ent)
		// Executed
		e, c, b, _ = happy(t)
		_, err = e.Admit(b)
		require.NoError(t, err)
		before, _ := e.Entry(c)
		_, err = e.Gate.ResolveManually(ctx, gatefix.KeyOf(c), res)
		require.ErrorIs(t, err, gate.ErrNotUnknown, "Executed")
		after, _ := e.Entry(c)
		require.Equal(t, after, before, "Executed entry changed")
		// Rejected
		e, c, b, _ = happy(t)
		e.Exec.SetResult(gate.ExecResult{Outcome: gate.OutcomeRejected})
		_, _ = e.Admit(b)
		_, err = e.Gate.ResolveManually(ctx, gatefix.KeyOf(c), res)
		require.ErrorIs(t, err, gate.ErrNotUnknown, "Rejected")
		// Absent
		_, err = e.Gate.ResolveManually(ctx, registry.Key{}, res)
		require.ErrorIs(t, err, registry.ErrNotFound, "absent")
		// Twice
		e2, c2, _ := unknownEntry(t)
		_, err = e2.Gate.ResolveManually(ctx, gatefix.KeyOf(c2), res)
		require.NoError(t, err)
		_, err = e2.Gate.ResolveManually(ctx, gatefix.KeyOf(c2), res)
		require.ErrorIs(t, err, gate.ErrNotUnknown, "second resolve")
	})
	t.Run("invalid input is refused without a write", func(t *testing.T) {
		long := func(n int) string {
			b := make([]byte, n)
			for i := range b {
				b[i] = 'a'
			}
			return string(b)
		}
		ok := gate.ManualResolution{Outcome: gate.ManualExecuted, RailRef: "1", Operator: "op", Note: "n"}
		with := func(f func(r *gate.ManualResolution)) gate.ManualResolution { r := ok; f(&r); return r }
		bad := map[string]gate.ManualResolution{
			"outcome zero":          with(func(r *gate.ManualResolution) { r.Outcome = 0 }),
			"outcome unknown value": with(func(r *gate.ManualResolution) { r.Outcome = 3 }),
			"executed without ref":  with(func(r *gate.ManualResolution) { r.RailRef = "" }),
			"ref with space":        with(func(r *gate.ManualResolution) { r.RailRef = "a b" }),
			"ref too long":          with(func(r *gate.ManualResolution) { r.RailRef = long(129) }),
			"rejected with ref":     with(func(r *gate.ManualResolution) { r.Outcome = gate.ManualRejected }),
			"empty operator":        with(func(r *gate.ManualResolution) { r.Operator = "" }),
			"operator too long":     with(func(r *gate.ManualResolution) { r.Operator = long(65) }),
			"operator with space":   with(func(r *gate.ManualResolution) { r.Operator = "a b" }),
			"empty note":            with(func(r *gate.ManualResolution) { r.Note = "" }),
			"note too long":         with(func(r *gate.ManualResolution) { r.Note = long(513) }),
			"note with newline":     with(func(r *gate.ManualResolution) { r.Note = "a\nb" }),
			"note with non-ascii":   with(func(r *gate.ManualResolution) { r.Note = "café" }),
		}
		for name, r := range bad {
			e, c, _ := unknownEntry(t)
			before, _ := e.Entry(c)
			_, err := e.Gate.ResolveManually(ctx, gatefix.KeyOf(c), r)
			require.ErrorIsf(t, err, gate.ErrInvalidResolution, "%s", name)
			after, _ := e.Entry(c)
			require.Equalf(t, after, before, "%s: entry written", name)
		}
		// Boundaries that are valid.
		e, c, _ := unknownEntry(t)
		_, err := e.Gate.ResolveManually(ctx, gatefix.KeyOf(c), gate.ManualResolution{
			Outcome: gate.ManualExecuted, RailRef: long(128), Operator: long(64), Note: long(512)})
		require.NoError(t, err, "maximum lengths")
	})
}

// TestManualAndAutomaticRace: whichever resolves first wins; the other sees
// the entry as no longer Unknown and changes nothing.
func TestManualAndAutomaticRace(t *testing.T) {
	ctx := context.Background()
	manual := gate.ManualResolution{Outcome: gate.ManualRejected, Operator: "op-1", Note: "no order"}
	t.Run("manual wins while reconcile is looking up", func(t *testing.T) {
		e, c, _ := unknownEntry(t)
		e.Exec.SetLookup(gate.ExecResult{Outcome: gate.OutcomeExecuted, RailRef: "777"}, nil)
		var once sync.Once
		e.Exec.OnLookup(func() {
			once.Do(func() {
				_, err := e.Gate.ResolveManually(ctx, gatefix.KeyOf(c), manual)
				assert.NoError(t, err, "manual")
			})
		})
		rep, err := e.Gate.Reconcile(ctx)
		if err != nil {
			require.ErrorIs(t, err, registry.ErrStateConflict)
		}
		require.EqualValuesf(t, 0, rep.Executed, "reconcile overrode the manual decision: %+v", rep)
		ent, _ := e.Entry(c)
		require.Equalf(t, registry.StateRejected, ent.State, "entry %+v", ent)
		require.Lenf(t, ent.History, 2, "entry %+v", ent)
		require.EqualValuesf(t, registry.SourceManual, ent.History[1].Source, "entry %+v", ent)
		require.EqualValues(t, 1, e.Exec.Calls(), "executor called")
	})
	t.Run("reconcile wins while manual resolve is writing", func(t *testing.T) {
		e, c, _ := unknownEntry(t, gatefix.WithFaultyRegistry())
		e.Exec.SetLookup(gate.ExecResult{Outcome: gate.OutcomeExecuted, RailRef: "777"}, nil)
		e.Faulty.Before("Resolve", func() {
			_, err := e.Gate.Reconcile(ctx)
			assert.NoError(t, err, "nested Reconcile")
		})
		_, err := e.Gate.ResolveManually(ctx, gatefix.KeyOf(c), manual)
		require.ErrorIs(t, err, registry.ErrStateConflict)
		ent, _ := e.Entry(c)
		require.Equalf(t, registry.StateExecuted, ent.State, "entry %+v", ent)
		require.EqualValuesf(t, "777", ent.RailRef, "entry %+v", ent)
		require.Lenf(t, ent.History, 2, "entry %+v", ent)
		require.EqualValuesf(t, registry.SourceLookup, ent.History[1].Source, "entry %+v", ent)
		require.EqualValues(t, 1, e.Exec.Calls(), "executor called")
	})
}

func TestSettleWindowUsesValidUntil(t *testing.T) {
	e, c, _ := unknownEntry(t)
	e.Exec.SetLookup(gate.ExecResult{Outcome: gate.OutcomeNotFound}, nil)
	e.Clock.Set(c.ValidUntil + e.Cfg.SettleS)
	rep, _ := e.Gate.Reconcile(context.Background())
	require.EqualValuesf(t, 0, rep.Rejected, "rejected at the end of the settle window: %+v", rep)
}
