package gate_test

import (
	"context"
	"errors"
	"math/big"
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

func TestExecutorPanicIsAmbiguousNotFatal(t *testing.T) {
	e, c, b, _ := happy(t)
	e.Exec.OnExecute(func(context.Context, gate.ExecRequest) { panic("adapter bug") })
	res, err := e.Admit(b)
	require.ErrorIs(t, err, gate.ErrExecutionUnknown)
	require.Equal(t, registry.StateUnknown, res.State)
	ent, err := e.Entry(c)
	require.NoError(t, err)
	require.Equal(t, registry.StateUnknown, ent.State)
	_, err = e.Admit(b)
	require.ErrorIs(t, err, gate.ErrNonceUsed)
	require.Equal(t, 1, e.Exec.Calls())
}

func TestExecutedWithUnusableRailRefStaysUnknown(t *testing.T) {
	for name, ref := range map[string]string{"empty": "", "space": "a b", "too long": string(make([]byte, 129)), "non-ascii": "café"} {
		t.Run(name, func(t *testing.T) {
			e, c, b, _ := happy(t)
			e.Exec.SetResult(gate.ExecResult{Outcome: gate.OutcomeExecuted, RailRef: ref})
			res, err := e.Admit(b)
			require.ErrorIs(t, err, gate.ErrExecutionUnknown)
			require.Nil(t, res.Receipt)
			ent, _ := e.Entry(c)
			require.Equal(t, registry.StateUnknown, ent.State)
			require.Nil(t, ent.Receipt)
			require.Equal(t, 1, e.Exec.Calls())
		})
	}
}

// A signature with S replaced by S+L verifies in a lax implementation and
// would give a second valid envelope for the same decision.
func TestMalleableSignatureIsRejected(t *testing.T) {
	e, c, _, _ := happy(t)
	s, _, err := commitment.Sign(gatefix.Key(t, "agent1"), c)
	require.NoError(t, err)
	l, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	le := func(b []byte) *big.Int {
		r := make([]byte, len(b))
		for i := range b {
			r[len(b)-1-i] = b[i]
		}
		return new(big.Int).SetBytes(r)
	}
	sv := le(s.Signature[32:])
	sv.Add(sv, l)
	buf := sv.FillBytes(make([]byte, 32))
	mal := append([]byte(nil), s.Signature[:32]...)
	for i := 31; i >= 0; i-- {
		mal = append(mal, buf[i])
	}
	b, err := commitment.EncodeSigned(&commitment.SignedCommitment{Commitment: s.Commitment, Signature: mal})
	require.NoError(t, err)
	_, err = e.Admit(b)
	e.RequireRejected(c, err, commitment.ErrSignatureInvalid)
}

// Many different envelopes that all use one (agent, nonce): one wins.
func TestConcurrentSameNonceDifferentOrders(t *testing.T) {
	for name, open := range registries() {
		t.Run(name, func(t *testing.T) {
			e, c0, _, _ := happy(t, gatefix.WithRegistry(open(t)))
			const n = 32
			var wg sync.WaitGroup
			var ok, used atomic.Int32
			for i := 0; i < n; i++ {
				c := gatefix.Clone(c0)
				c.Action.IBKROrder.Qty -= uint64(i)
				e.StageDA(c, gatefix.Blob(t))
				b, _ := gatefix.Sign(t, "agent1", c)
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, err := e.Admit(b)
					switch {
					case err == nil:
						ok.Add(1)
					case errors.Is(err, gate.ErrNonceUsed):
						used.Add(1)
					default:
						assert.NoError(t, err)
					}
				}()
			}
			wg.Wait()
			require.EqualValues(t, 1, ok.Load())
			require.EqualValues(t, n-1, used.Load())
			require.Equal(t, 1, e.Exec.Calls())
		})
	}
}

func TestConcurrentReconcileResolvesOnce(t *testing.T) {
	e, c, _ := unknownEntry(t)
	e.Exec.SetLookup(gate.ExecResult{Outcome: gate.OutcomeExecuted, RailRef: "555"}, nil)
	const n = 8
	var wg sync.WaitGroup
	var executed atomic.Int32
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rep, err := e.Gate.Reconcile(context.Background())
			if err != nil {
				assert.ErrorIs(t, err, registry.ErrStateConflict)
			}
			executed.Add(int32(rep.Executed))
		}()
	}
	wg.Wait()
	ent, err := e.Entry(c)
	require.NoError(t, err)
	require.Equal(t, registry.StateExecuted, ent.State)
	require.Len(t, ent.History, 2)
	require.EqualValues(t, 1, executed.Load())
	require.Equal(t, 1, e.Exec.Calls())
}

// Admit, Reconcile and Prune running together must keep every invariant and
// pass the race detector.
func TestAdmitReconcilePruneTogether(t *testing.T) {
	for name, open := range registries() {
		t.Run(name, func(t *testing.T) {
			e, c0, _, _ := happy(t, gatefix.WithRegistry(open(t)))
			e.Exec.SetLookup(gate.ExecResult{Outcome: gate.OutcomeNotFound}, nil)
			const n = 24
			stop := make(chan struct{})
			var bg sync.WaitGroup
			for _, f := range []func(){
				func() { _, _ = e.Gate.Reconcile(context.Background()) },
				func() { _, _ = e.Gate.Prune(context.Background()) },
			} {
				bg.Add(1)
				go func() {
					defer bg.Done()
					for {
						select {
						case <-stop:
							return
						default:
							f()
						}
					}
				}()
			}
			var wg sync.WaitGroup
			for i := 0; i < n; i++ {
				c := gatefix.Fresh(c0, byte(i+1))
				e.StageDA(c, gatefix.Blob(t))
				b, _ := gatefix.Sign(t, "agent1", c)
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, err := e.Admit(b)
					assert.NoError(t, err)
					_, err = e.Admit(b)
					assert.ErrorIs(t, err, gate.ErrNonceUsed)
				}()
			}
			wg.Wait()
			close(stop)
			bg.Wait()
			require.Equal(t, n, e.Exec.Calls())
		})
	}
}

func TestFetchBudgetSmallerThanPayloadStillAdmits(t *testing.T) {
	e, _, b, _ := happy(t, gatefix.WithConfig(func(c *gate.Config) { c.MaxFetchBytes = 10 }))
	_, err := e.Admit(b)
	require.NoError(t, err)
}

func TestCancelDuringFetchWritesNothing(t *testing.T) {
	e, c, b, _ := happy(t)
	ctx, cancel := context.WithCancel(context.Background())
	e.DA.OnFetch(cancel)
	_, err := e.Gate.Admit(ctx, b)
	e.RequireRejected(c, err, context.Canceled)
}

func TestBothSourcesHangUntilTheirTimeouts(t *testing.T) {
	e, c, b, _ := happy(t, gatefix.WithConfig(func(cfg *gate.Config) {
		cfg.DATimeout = 20 * time.Millisecond
		cfg.ArchiveTimeout = 20 * time.Millisecond
	}))
	e.DA.Hang()
	e.Archive.Hang()
	_, err := e.Admit(b)
	e.RequireRejected(c, err, gate.ErrPayloadUnavailable)
}

// The durable registry keeps the Executed entry across a reopen: a replay
// gets the stored receipt and never reaches the executor.
func TestBoltReplayAfterReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "n.db")
	reg, err := boltreg.Open(path, gatefix.Epoch)
	require.NoError(t, err)
	e, _, b, _ := happy(t, gatefix.WithRegistry(reg))
	first, err := e.Admit(b)
	require.NoError(t, err)
	require.NoError(t, reg.Close())

	reg2, err := boltreg.Open(path, gatefix.Epoch+1)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reg2.Close() })
	e2, _, _, _ := happy(t, gatefix.WithRegistry(reg2))
	res, err := e2.Admit(b)
	require.ErrorIs(t, err, gate.ErrNonceUsed)
	require.Equal(t, registry.StateExecuted, res.State)
	require.Equal(t, first.Receipt, res.Receipt)
	require.Zero(t, e2.Exec.Calls())
}

// The process dies between the two transactions: the reservation is on disk,
// the resolution is not. The restarted gate finds Unknown and resolves it by
// lookup without sending again.
func TestBoltCrashBetweenTransactions(t *testing.T) {
	for _, point := range []string{"after execute", "before resolve"} {
		t.Run(point, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "n.db")
			reg, err := boltreg.Open(path, gatefix.Epoch)
			require.NoError(t, err)
			e, c, b, h := happy(t, gatefix.WithRegistry(reg))
			if point == "after execute" {
				e.Gate.SetAfterExecute(func() error { return errCrash })
			} else {
				e.Gate.SetBeforeResolve(func() error { return errCrash })
			}
			_, err = e.Admit(b)
			require.ErrorIs(t, err, errCrash)
			require.Equal(t, 1, e.Exec.Calls())
			require.NoError(t, reg.Close())

			reg2, err := boltreg.Open(path, gatefix.Epoch)
			require.NoError(t, err)
			t.Cleanup(func() { _ = reg2.Close() })
			e2, _, _, _ := happy(t, gatefix.WithRegistry(reg2))
			ent, err := e2.Entry(c)
			require.NoError(t, err)
			require.Equal(t, registry.StateUnknown, ent.State)
			e2.Exec.SetLookup(gate.ExecResult{Outcome: gate.OutcomeExecuted, RailRef: "777"}, nil)
			rep, err := e2.Gate.Reconcile(context.Background())
			require.NoError(t, err)
			require.Equal(t, 1, rep.Executed)
			ent, _ = e2.Entry(c)
			require.Equal(t, registry.StateExecuted, ent.State)
			gatefix.CheckReceipt(t, gate.Result{Receipt: ent.Receipt}, h, "777", commitment.ReceiptPathDA, gatefix.GateID, gatefix.Pub(t, "gate1"), 0)
			require.Zero(t, e2.Exec.Calls())
		})
	}
}
