// Package regtest is the conformance suite every registry.Registry
// implementation must pass. It is used by tests only.
package regtest

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate/registry"
)

const (
	// Epoch is the creation time the suite passes to Opener.
	Epoch = uint64(100)
	// Tolerance is the clock tolerance the suite passes to Consume.
	Tolerance = uint64(60)
)

// Opener returns a new empty registry whose creation time is epoch.
type Opener func(t *testing.T, epoch uint64) registry.Registry

var ctx = context.Background()

func key(i byte) registry.Key {
	var k registry.Key
	k.PubKey[0], k.PubKey[31] = i, 0xaa
	k.Nonce[0], k.Nonce[15] = i, 0xbb
	return k
}

func fresh(i byte) registry.Entry {
	return registry.Entry{
		Key:            key(i),
		CommitmentHash: commitment.Hash{i, 1},
		ActionHash:     commitment.Hash{i, 2},
		Path:           registry.PathDA,
		AuthorizedAt:   1000 + uint64(i),
		ValidUntil:     2000,
		Authorization:  []byte{0xa2, i},
	}
}

func must(t *testing.T, err error, msgAndArgs ...any) {
	t.Helper()
	require.NoError(t, err, msgAndArgs...)
}

func get(t *testing.T, r registry.Registry, k registry.Key) registry.Entry {
	t.Helper()
	e, err := r.Get(ctx, k)
	require.NoError(t, err, "Get")
	return e
}

// Run executes the suite.
func Run(t *testing.T, open Opener) {
	t.Run("Meta", func(t *testing.T) {
		r := open(t, Epoch)
		m, err := r.Meta(ctx)
		must(t, err)
		require.Equal(t, registry.Meta{Epoch: Epoch, Watermark: Epoch}, m)
	})

	t.Run("ConsumeAndGet", func(t *testing.T) {
		r := open(t, Epoch)
		e := fresh(1)
		must(t, r.Consume(ctx, e, Tolerance))
		require.Equal(t, e, get(t, r, e.Key))
		_, err := r.Get(ctx, key(9))
		require.ErrorIs(t, err, registry.ErrNotFound, "missing key")
	})

	t.Run("ConsumeTwice", func(t *testing.T) {
		r := open(t, Epoch)
		e := fresh(1)
		must(t, r.Consume(ctx, e, Tolerance))
		other := fresh(1)
		other.CommitmentHash = commitment.Hash{9}
		other.ActionHash = commitment.Hash{8}
		other.Authorization = []byte("other")
		err := r.Consume(ctx, other, Tolerance)
		require.ErrorIs(t, err, registry.ErrExists)
		var ee *registry.ExistsError
		require.ErrorAs(t, err, &ee)
		require.Equal(t, e, ee.Existing, "the error carries the stored entry")
		require.Equal(t, e, get(t, r, e.Key), "the loser overwrote the entry")
	})

	t.Run("KeyIsPubKeyAndNonce", func(t *testing.T) {
		r := open(t, Epoch)
		a := fresh(1)
		b := fresh(2)
		b.Key.Nonce = a.Key.Nonce // same nonce, other agent
		c := fresh(3)
		c.Key.PubKey = a.Key.PubKey // same agent, other nonce
		for _, e := range []registry.Entry{a, b, c} {
			must(t, r.Consume(ctx, e, Tolerance))
		}
	})

	t.Run("InvalidEntryIsRefusedAndWritesNothing", func(t *testing.T) {
		bad := map[string]func(e *registry.Entry){
			"empty authorization": func(e *registry.Entry) { e.Authorization = nil },
			"zero-length":         func(e *registry.Entry) { e.Authorization = []byte{} },
			"path zero":           func(e *registry.Entry) { e.Path = 0 },
			"path three":          func(e *registry.Entry) { e.Path = 3 },
		}
		for name, mut := range bad {
			r := open(t, Epoch)
			e := fresh(1)
			mut(&e)
			err := r.Consume(ctx, e, Tolerance)
			require.ErrorIsf(t, err, registry.ErrInvalidEntry, "%s", name)
			_, err = r.Get(ctx, e.Key)
			require.ErrorIsf(t, err, registry.ErrNotFound, "%s", name)
			m, _ := r.Meta(ctx)
			require.Equalf(t, registry.Meta{Epoch: Epoch, Watermark: Epoch}, m, "%s: meta changed", name)
		}
		require.NoError(t, registry.CheckConsume(fresh(1)))
		require.ErrorIs(t, registry.CheckConsume(registry.Entry{}), registry.ErrInvalidEntry)
	})

	t.Run("WatermarkIsMaxAuthorizedAt", func(t *testing.T) {
		r := open(t, Epoch)
		hi := fresh(1)
		hi.AuthorizedAt = 5000
		must(t, r.Consume(ctx, hi, Tolerance))
		lo := fresh(2)
		lo.AuthorizedAt = 4990
		must(t, r.Consume(ctx, lo, Tolerance))
		m, _ := r.Meta(ctx)
		require.EqualValues(t, 5000, m.Watermark)
		require.Equal(t, Epoch, m.Epoch)
	})

	t.Run("ReturnedEntriesAreCopies", func(t *testing.T) {
		r := open(t, Epoch)
		e := fresh(1)
		must(t, r.Consume(ctx, e, Tolerance))
		must(t, r.AttachReceipt(ctx, e.Key, e.CommitmentHash, []byte("receipt")))
		got := get(t, r, e.Key)
		got.Authorization[0] ^= 0xff
		got.Receipt[0] ^= 0xff
		again := get(t, r, e.Key)
		require.Equal(t, e.Authorization, again.Authorization, "stored entry aliases the returned one")
		require.Equal(t, []byte("receipt"), again.Receipt, "stored entry aliases the returned one")
	})

	t.Run("StoredBytesAreCopies", func(t *testing.T) {
		r := open(t, Epoch)
		e := fresh(1)
		in := append([]byte(nil), e.Authorization...)
		must(t, r.Consume(ctx, e, Tolerance))
		e.Authorization[0] ^= 0xff
		require.Equal(t, in, get(t, r, e.Key).Authorization, "the registry kept the caller's slice")
	})

	t.Run("AttachReceipt", func(t *testing.T) {
		r := open(t, Epoch)
		e := fresh(1)
		must(t, r.Consume(ctx, e, Tolerance))
		require.Nil(t, get(t, r, e.Key).Receipt)

		err := r.AttachReceipt(ctx, e.Key, commitment.Hash{7}, []byte("x"))
		require.ErrorIs(t, err, registry.ErrStateConflict, "wrong commitment hash")
		require.Nil(t, get(t, r, e.Key).Receipt)
		err = r.AttachReceipt(ctx, key(9), e.CommitmentHash, []byte("x"))
		require.ErrorIs(t, err, registry.ErrNotFound, "absent key")

		must(t, r.AttachReceipt(ctx, e.Key, e.CommitmentHash, []byte("first")))
		got := get(t, r, e.Key)
		want := e
		want.Receipt = []byte("first")
		require.Equal(t, want, got, "only the receipt may change")

		err = r.AttachReceipt(ctx, e.Key, e.CommitmentHash, []byte("second"))
		require.ErrorIs(t, err, registry.ErrStateConflict, "second receipt")
		require.Equal(t, want, get(t, r, e.Key))
	})

	t.Run("AttachReceiptDoesNotTouchMeta", func(t *testing.T) {
		r := open(t, Epoch)
		e := fresh(1)
		must(t, r.Consume(ctx, e, Tolerance))
		before, _ := r.Meta(ctx)
		must(t, r.AttachReceipt(ctx, e.Key, e.CommitmentHash, []byte("r")))
		after, _ := r.Meta(ctx)
		require.Equal(t, before, after)
	})

	t.Run("RemovedStateMachine", func(t *testing.T) {
		r := open(t, Epoch)
		var x any = r
		_, hasRecover := x.(interface {
			Recover(context.Context, uint64) (int, error)
		})
		_, hasPending := x.(interface {
			Pending(context.Context) ([]registry.Entry, error)
		})
		_, hasResolve := x.(interface {
			Resolve(context.Context, registry.Key, uint8, registry.Entry) error
		})
		require.False(t, hasRecover, "Recover is gone")
		require.False(t, hasPending, "Pending is gone")
		require.False(t, hasResolve, "Resolve is gone")
	})

	t.Run("Prune", func(t *testing.T) {
		r := open(t, Epoch)
		mk := func(i byte, validUntil uint64, receipt bool) {
			e := fresh(i)
			e.ValidUntil = validUntil
			must(t, r.Consume(ctx, e, Tolerance))
			if receipt {
				must(t, r.AttachReceipt(ctx, e.Key, e.CommitmentHash, []byte("r")))
			}
		}
		mk(1, 499, true)  // pruned
		mk(2, 499, false) // pruned: an entry without a receipt goes too
		mk(3, 500, true)  // equal to the cutoff: kept
		mk(4, 900, false) // young
		n, err := r.Prune(ctx, 500)
		must(t, err)
		require.Equal(t, 2, n)
		for _, i := range []byte{1, 2} {
			_, err := r.Get(ctx, key(i))
			require.ErrorIsf(t, err, registry.ErrNotFound, "entry %d survived", i)
		}
		for _, i := range []byte{3, 4} {
			get(t, r, key(i))
		}
		must(t, r.Consume(ctx, fresh(1), Tolerance))
		require.True(t, registry.Prunable(registry.Entry{ValidUntil: 499}, 500))
		require.False(t, registry.Prunable(registry.Entry{ValidUntil: 500}, 500))
	})

	t.Run("ConsumeBelowWatermarkIsRefusedAndWritesNothing", func(t *testing.T) {
		r := open(t, Epoch)
		hi := fresh(1)
		hi.AuthorizedAt = 5000
		must(t, r.Consume(ctx, hi, Tolerance))

		low := fresh(2)
		low.AuthorizedAt = 5000 - Tolerance - 1
		err := r.Consume(ctx, low, Tolerance)
		require.ErrorIs(t, err, registry.ErrBelowWatermark)
		_, err = r.Get(ctx, low.Key)
		require.ErrorIs(t, err, registry.ErrNotFound)
		m, err := r.Meta(ctx)
		must(t, err)
		require.EqualValues(t, 5000, m.Watermark)

		edge := fresh(3)
		edge.AuthorizedAt = 5000 - Tolerance
		must(t, r.Consume(ctx, edge, Tolerance))
		m, _ = r.Meta(ctx)
		require.EqualValues(t, 5000, m.Watermark, "an accepted older entry must not lower the watermark")
	})

	t.Run("ConsumeToleranceIsPerCall", func(t *testing.T) {
		r := open(t, Epoch)
		hi := fresh(1)
		hi.AuthorizedAt = 5000
		must(t, r.Consume(ctx, hi, Tolerance))
		low := fresh(2)
		low.AuthorizedAt = 4000
		require.ErrorIs(t, r.Consume(ctx, low, 0), registry.ErrBelowWatermark)
		must(t, r.Consume(ctx, low, 1000))
	})

	t.Run("WatermarkOverflowIsSaturated", func(t *testing.T) {
		r := open(t, Epoch)
		hi := fresh(1)
		hi.AuthorizedAt = 5000
		must(t, r.Consume(ctx, hi, Tolerance))
		low := fresh(2)
		low.AuthorizedAt = 10
		require.ErrorIs(t, r.Consume(ctx, low, 0), registry.ErrBelowWatermark)
		must(t, r.Consume(ctx, low, ^uint64(0)), "a huge tolerance must not wrap around")
		require.True(t, registry.BelowWatermark(1, 0, 2))
		require.False(t, registry.BelowWatermark(^uint64(0), ^uint64(0), ^uint64(0)))
	})

	t.Run("ExistsIsReportedBeforeNothingIsWritten", func(t *testing.T) {
		r := open(t, Epoch)
		e := fresh(1)
		must(t, r.Consume(ctx, e, Tolerance))
		before, _ := r.Meta(ctx)
		again := fresh(1)
		again.AuthorizedAt = 1500
		require.ErrorIs(t, r.Consume(ctx, again, Tolerance), registry.ErrExists)
		after, _ := r.Meta(ctx)
		require.Equal(t, before, after, "a refused Consume must not raise the watermark")
	})

	t.Run("ClaimRefusesASecondOwnerUntilReleased", func(t *testing.T) {
		r := open(t, Epoch)
		cl, ok := r.(registry.Claimer)
		require.True(t, ok, "registry does not implement Claimer")
		release, err := cl.Claim()
		must(t, err)
		_, err = cl.Claim()
		require.ErrorIs(t, err, registry.ErrInUse)
		release()
		release2, err := cl.Claim()
		must(t, err)
		release2()
	})

	t.Run("PruneCutoffRefusesEntriesInThePrunedWindow", func(t *testing.T) {
		r := open(t, Epoch)
		m, err := r.Meta(ctx)
		must(t, err)
		require.Zero(t, m.PruneCutoff)

		done := fresh(1)
		done.ValidUntil = 400
		must(t, r.Consume(ctx, done, Tolerance))
		n, err := r.Prune(ctx, 500)
		must(t, err)
		require.Equal(t, 1, n)
		m, _ = r.Meta(ctx)
		require.EqualValues(t, 500, m.PruneCutoff)

		inside := fresh(2)
		inside.ValidUntil = 499
		require.ErrorIs(t, r.Consume(ctx, inside, Tolerance), registry.ErrPrunedWindow)
		_, err = r.Get(ctx, inside.Key)
		require.ErrorIs(t, err, registry.ErrNotFound)
		after, _ := r.Meta(ctx)
		require.Equal(t, m, after, "a refused Consume must not change the meta")

		// The pruned key itself is refused too, whatever the tolerance.
		require.ErrorIs(t, r.Consume(ctx, done, Tolerance), registry.ErrPrunedWindow)
		require.ErrorIs(t, r.Consume(ctx, done, ^uint64(0)), registry.ErrPrunedWindow)

		edge := fresh(3)
		edge.ValidUntil = 500
		must(t, r.Consume(ctx, edge, Tolerance))
	})

	t.Run("PruneCutoffOnlyGrows", func(t *testing.T) {
		r := open(t, Epoch)
		_, err := r.Prune(ctx, 700)
		must(t, err)
		_, err = r.Prune(ctx, 300)
		must(t, err)
		m, _ := r.Meta(ctx)
		require.EqualValues(t, 700, m.PruneCutoff)
	})

	t.Run("ConcurrentConsumeOneWinner", func(t *testing.T) {
		r := open(t, Epoch)
		const n = 32
		var wins, losses atomic.Int32
		var wg sync.WaitGroup
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				e := fresh(1)
				e.CommitmentHash = commitment.Hash{byte(i)}
				switch err := r.Consume(ctx, e, Tolerance); {
				case err == nil:
					wins.Add(1)
				case errors.Is(err, registry.ErrExists):
					losses.Add(1)
				default:
					assert.Fail(t, fmt.Sprintf("Consume: %v", err))
				}
			}()
		}
		wg.Wait()
		require.EqualValues(t, 1, wins.Load())
		require.EqualValues(t, n-1, losses.Load())
	})

	t.Run("ConcurrentAttachReceiptOneWinner", func(t *testing.T) {
		r := open(t, Epoch)
		e := fresh(1)
		must(t, r.Consume(ctx, e, Tolerance))
		const n = 16
		var wins, conflicts atomic.Int32
		var wg sync.WaitGroup
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				switch err := r.AttachReceipt(ctx, e.Key, e.CommitmentHash, []byte{byte(i)}); {
				case err == nil:
					wins.Add(1)
				case errors.Is(err, registry.ErrStateConflict):
					conflicts.Add(1)
				default:
					assert.Fail(t, fmt.Sprintf("AttachReceipt: %v", err))
				}
			}()
		}
		wg.Wait()
		require.EqualValues(t, 1, wins.Load())
		require.EqualValues(t, n-1, conflicts.Load())
		require.Len(t, get(t, r, e.Key).Receipt, 1)
	})

	// The cutoff check lives in the marking transaction: an entry below the
	// cutoff can never be left behind by a racing Prune.
	t.Run("ConcurrentConsumeAndPruneKeepTheCutoffInvariant", func(t *testing.T) {
		r := open(t, Epoch)
		var wg sync.WaitGroup
		for i := range byte(40) {
			wg.Add(1)
			go func() {
				defer wg.Done()
				e := fresh(i)
				e.ValidUntil = 300 + uint64(i)*10
				err := r.Consume(ctx, e, Tolerance)
				if err != nil {
					assert.ErrorIs(t, err, registry.ErrPrunedWindow)
				}
			}()
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := r.Prune(ctx, 300+uint64(i)*10)
				assert.NoError(t, err)
			}()
		}
		wg.Wait()
		m, err := r.Meta(ctx)
		must(t, err)
		for i := range byte(40) {
			e, err := r.Get(ctx, key(i))
			if err == nil {
				require.GreaterOrEqualf(t, e.ValidUntil, m.PruneCutoff, "entry %d is inside the pruned window", i)
			} else {
				require.ErrorIs(t, err, registry.ErrNotFound)
			}
		}
	})
}

// StateOpener returns a new empty state registry whose creation time is epoch.
type StateOpener func(t *testing.T, epoch uint64) registry.StateRegistry

func cell(b ...byte) registry.StateCell { return registry.NewStateCell(b) }

// RunState executes the suite for the policy cells.
func RunState(t *testing.T, open StateOpener) {
	var k registry.StateKey
	k[0] = 7
	tx := func(expect, next registry.StateCell) registry.StateTx {
		return registry.StateTx{Key: k, Expect: expect.Version, Next: next}
	}

	t.Run("AbsentCellIsZero", func(t *testing.T) {
		r := open(t, Epoch)
		c, err := r.State(ctx, k)
		must(t, err)
		require.Equal(t, registry.StateCell{}, c)
	})

	t.Run("UpdateIsCompareAndSwap", func(t *testing.T) {
		r := open(t, Epoch)
		c1, c2 := cell(1), cell(2)
		must(t, r.UpdateState(ctx, tx(registry.StateCell{}, c1)))
		got, err := r.State(ctx, k)
		must(t, err)
		require.Equal(t, c1, got)
		require.ErrorIs(t, r.UpdateState(ctx, tx(registry.StateCell{}, c2)), registry.ErrStateConflict)
		require.ErrorIs(t, r.UpdateState(ctx, tx(c2, c2)), registry.ErrStateConflict)
		must(t, r.UpdateState(ctx, tx(c1, c2)))
	})

	t.Run("InvalidTxIsRefused", func(t *testing.T) {
		r := open(t, Epoch)
		bad := registry.StateTx{Key: k, Next: registry.StateCell{Version: commitment.Hash{1}, Value: []byte{1}}}
		require.ErrorIs(t, r.UpdateState(ctx, bad), registry.ErrInvalidEntry)
		require.ErrorIs(t, r.ConsumeState(ctx, fresh(1), Tolerance, bad), registry.ErrInvalidEntry)
		require.ErrorIs(t, r.UpdateState(ctx, tx(registry.StateCell{}, registry.StateCell{})), registry.ErrInvalidEntry)
		_, err := r.Get(ctx, key(1))
		require.ErrorIs(t, err, registry.ErrNotFound)
	})

	t.Run("ConsumeStateWritesBoth", func(t *testing.T) {
		r := open(t, Epoch)
		e := fresh(1)
		e.Verdict = []byte{0xa1, 1}
		c1 := cell(1)
		must(t, r.ConsumeState(ctx, e, Tolerance, tx(registry.StateCell{}, c1)))
		require.Equal(t, e, get(t, r, e.Key))
		got, err := r.State(ctx, k)
		must(t, err)
		require.Equal(t, c1, got)
		m, err := r.Meta(ctx)
		must(t, err)
		require.Equal(t, e.AuthorizedAt, m.Watermark)
		must(t, r.AttachReceipt(ctx, e.Key, e.CommitmentHash, []byte{9}))
		require.Equal(t, e.Verdict, get(t, r, e.Key).Verdict, "the verdict survives AttachReceipt")
	})

	t.Run("RefusalsWriteNothing", func(t *testing.T) {
		r := open(t, Epoch)
		c1, c2 := cell(1), cell(2)
		must(t, r.ConsumeState(ctx, fresh(1), Tolerance, tx(registry.StateCell{}, c1)))

		// Existing nonce wins over a conflicting cell.
		err := r.ConsumeState(ctx, fresh(1), Tolerance, tx(registry.StateCell{}, c2))
		var ee *registry.ExistsError
		require.ErrorAs(t, err, &ee)

		// A stale cell version is a conflict and leaves the nonce unused.
		err = r.ConsumeState(ctx, fresh(2), Tolerance, tx(registry.StateCell{}, c2))
		require.ErrorIs(t, err, registry.ErrStateConflict)
		_, err = r.Get(ctx, key(2))
		require.ErrorIs(t, err, registry.ErrNotFound)

		// A watermark refusal leaves the cell alone.
		old := fresh(3)
		old.AuthorizedAt = 1
		err = r.ConsumeState(ctx, old, 0, tx(c1, c2))
		require.ErrorIs(t, err, registry.ErrBelowWatermark)
		got, err := r.State(ctx, k)
		must(t, err)
		require.Equal(t, c1, got)
		_, err = r.Get(ctx, key(3))
		require.ErrorIs(t, err, registry.ErrNotFound)

		// The prune refusal precedes the conflict check.
		_, err = r.Prune(ctx, 5000)
		must(t, err)
		pruned := fresh(4)
		err = r.ConsumeState(ctx, pruned, Tolerance, tx(registry.StateCell{}, c2))
		require.ErrorIs(t, err, registry.ErrPrunedWindow)
	})

	t.Run("ConcurrentConsumeStateOneWinner", func(t *testing.T) {
		r := open(t, Epoch)
		const n = 16
		var wins, conflicts atomic.Int32
		var wg sync.WaitGroup
		for i := 1; i <= n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := r.ConsumeState(ctx, fresh(byte(i)), Tolerance, tx(registry.StateCell{}, cell(byte(i))))
				switch {
				case err == nil:
					wins.Add(1)
				case errors.Is(err, registry.ErrStateConflict):
					conflicts.Add(1)
				default:
					t.Errorf("unexpected error: %v", err)
				}
			}()
		}
		wg.Wait()
		require.EqualValues(t, 1, wins.Load())
		require.EqualValues(t, n-1, conflicts.Load())
		marked := 0
		for i := 1; i <= n; i++ {
			if _, err := r.Get(ctx, key(byte(i))); err == nil {
				marked++
			}
		}
		require.Equal(t, 1, marked, "only the winner marks its nonce")
	})
}
