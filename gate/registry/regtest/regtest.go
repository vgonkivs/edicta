// Package regtest is the conformance suite every registry.Registry
// implementation must pass. It is used by tests only.
package regtest

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/prior/commitment"
	"github.com/vgonkivs/prior/gate/registry"
)

const (
	// Epoch is the creation time the suite passes to Opener.
	Epoch = uint64(100)
	// Tolerance is the clock tolerance the suite passes to Reserve.
	Tolerance = uint64(60)
	// RecoverAt is the clock reading the suite passes to Recover.
	RecoverAt = uint64(7777)
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
		State:          registry.StateReserved,
		Path:           registry.PathDA,
		ReservedAt:     1000 + uint64(i),
		ValidUntil:     2000,
	}
}

func step(e registry.Entry, to registry.State, src registry.Source) registry.Entry {
	n := e
	n.History = append(append([]registry.Resolution(nil), e.History...), registry.Resolution{
		Source: src, By: "gate", At: 1500, PrevState: e.State,
	})
	n.State = to
	if to == registry.StateExecuted {
		n.RailRef = "ref-1"
		n.ExecutedAt = 1500
		n.Receipt = []byte("receipt")
	}
	return n
}

func must(t *testing.T, err error) {
	t.Helper()
	require.NoError(t, err)
}

func get(t *testing.T, r registry.Registry, k registry.Key) registry.Entry {
	t.Helper()
	e, err := r.Get(ctx, k)
	require.NoError(t, err, "Get")
	return e
}

// reach puts a new entry in the wanted state through legal transitions.
func reach(t *testing.T, r registry.Registry, i byte, s registry.State) registry.Entry {
	t.Helper()
	e := fresh(i)
	must(t, r.Reserve(ctx, e, Tolerance))
	if s == registry.StateReserved {
		return get(t, r, e.Key)
	}
	next := step(e, s, registry.SourceRail)
	must(t, r.Resolve(ctx, e.Key, registry.StateReserved, next))
	return get(t, r, e.Key)
}

// Run executes the suite.
func Run(t *testing.T, open Opener) {
	t.Run("Meta", func(t *testing.T) {
		r := open(t, Epoch)
		m, err := r.Meta(ctx)
		must(t, err)
		require.Equalf(t, Epoch, m.Epoch, "meta %+v", m)
		require.Equalf(t, Epoch, m.Watermark, "meta %+v", m)
	})

	t.Run("ReserveAndGet", func(t *testing.T) {
		r := open(t, Epoch)
		e := fresh(1)
		must(t, r.Reserve(ctx, e, Tolerance))
		got := get(t, r, e.Key)
		require.Equal(t, registry.StateReserved, got.State)
		require.Equal(t, e.Key, got.Key)
		require.Equal(t, e.CommitmentHash, got.CommitmentHash)
		require.Equal(t, e.Path, got.Path)
		require.Equal(t, e.ReservedAt, got.ReservedAt)
		require.Equal(t, e.ValidUntil, got.ValidUntil)
		require.Empty(t, got.History)
		_, err := r.Get(ctx, key(9))
		require.ErrorIs(t, err, registry.ErrNotFound, "missing key")
	})

	t.Run("ReserveTwice", func(t *testing.T) {
		r := open(t, Epoch)
		e := fresh(1)
		must(t, r.Reserve(ctx, e, Tolerance))
		other := fresh(1)
		other.CommitmentHash = commitment.Hash{9}
		err := r.Reserve(ctx, other, Tolerance)
		require.ErrorIs(t, err, registry.ErrExists)
		var ee *registry.ExistsError
		require.ErrorAs(t, err, &ee)
		require.Equalf(t, e.CommitmentHash, ee.Existing.CommitmentHash, "ExistsError %+v", ee)
		got := get(t, r, e.Key)
		require.Equal(t, e.CommitmentHash, got.CommitmentHash, "the loser overwrote the entry")
	})

	t.Run("KeyIsPubKeyAndNonce", func(t *testing.T) {
		r := open(t, Epoch)
		a := fresh(1)
		b := fresh(2)
		b.Key.Nonce = a.Key.Nonce // same nonce, other agent
		c := fresh(3)
		c.Key.PubKey = a.Key.PubKey // same agent, other nonce
		for _, e := range []registry.Entry{a, b, c} {
			must(t, r.Reserve(ctx, e, Tolerance))
		}
	})

	t.Run("WatermarkIsMaxReservedAt", func(t *testing.T) {
		r := open(t, Epoch)
		hi := fresh(1)
		hi.ReservedAt = 5000
		must(t, r.Reserve(ctx, hi, Tolerance))
		lo := fresh(2)
		lo.ReservedAt = 4990
		must(t, r.Reserve(ctx, lo, Tolerance))
		m, _ := r.Meta(ctx)
		require.EqualValuesf(t, 5000, m.Watermark, "meta %+v", m)
		require.Equalf(t, Epoch, m.Epoch, "meta %+v", m)
	})

	t.Run("ReturnedEntriesAreCopies", func(t *testing.T) {
		r := open(t, Epoch)
		e := reach(t, r, 1, registry.StateExecuted)
		e.Receipt[0] ^= 0xff
		e.History[0].By = "mallory"
		again := get(t, r, e.Key)
		require.NotEqual(t, e.Receipt[0], again.Receipt[0], "stored entry aliases the returned one")
		require.EqualValues(t, "gate", again.History[0].By, "stored entry aliases the returned one")
	})

	t.Run("Transitions", func(t *testing.T) {
		states := []registry.State{registry.StateReserved, registry.StateExecuted, registry.StateRejected, registry.StateUnknown}
		allowed := map[[2]registry.State]bool{
			{registry.StateReserved, registry.StateExecuted}: true,
			{registry.StateReserved, registry.StateRejected}: true,
			{registry.StateReserved, registry.StateUnknown}:  true,
			{registry.StateUnknown, registry.StateExecuted}:  true,
			{registry.StateUnknown, registry.StateRejected}:  true,
		}
		for _, from := range states {
			for _, to := range states {
				t.Run(name(from)+"_to_"+name(to), func(t *testing.T) {
					r := open(t, Epoch)
					stored := reach(t, r, 1, from)
					upd := step(stored, to, registry.SourceManual)
					err := r.Resolve(ctx, stored.Key, from, upd)
					after := get(t, r, stored.Key)
					if allowed[[2]registry.State{from, to}] {
						require.NoError(t, err, "refused")
						require.Equalf(t, to, after.State, "entry %+v", after)
						require.Lenf(t, after.History, len(stored.History)+1, "entry %+v", after)
						return
					}
					require.ErrorIs(t, err, registry.ErrStateConflict)
					require.Equalf(t, stored, after, "refused transition changed the entry\n%+v\n%+v", after, stored)
				})
			}
		}
	})

	t.Run("ExecutedWithoutReceiptCanBeSignedOnce", func(t *testing.T) {
		r := open(t, Epoch)
		e := fresh(1)
		must(t, r.Reserve(ctx, e, Tolerance))
		noReceipt := step(e, registry.StateExecuted, registry.SourceRail)
		noReceipt.Receipt = nil
		must(t, r.Resolve(ctx, e.Key, registry.StateReserved, noReceipt))
		stored := get(t, r, e.Key)
		require.Nilf(t, stored.Receipt, "receipt %x", stored.Receipt)
		upd := step(stored, registry.StateExecuted, registry.SourceLookup)
		upd.Receipt = []byte("signed")
		must(t, r.Resolve(ctx, e.Key, registry.StateExecuted, upd))
		got := get(t, r, e.Key)
		require.Equalf(t, hex.EncodeToString([]byte("signed")), hex.EncodeToString(got.Receipt), "entry %+v", got)
		require.EqualValuesf(t, "ref-1", got.RailRef, "entry %+v", got)
		again := step(get(t, r, e.Key), registry.StateExecuted, registry.SourceLookup)
		again.Receipt = []byte("other")
		err := r.Resolve(ctx, e.Key, registry.StateExecuted, again)
		require.ErrorIs(t, err, registry.ErrStateConflict, "second receipt")
	})

	t.Run("ResolveChecksFromState", func(t *testing.T) {
		r := open(t, Epoch)
		stored := reach(t, r, 1, registry.StateReserved)
		upd := step(stored, registry.StateExecuted, registry.SourceRail)
		err := r.Resolve(ctx, stored.Key, registry.StateUnknown, upd)
		require.ErrorIs(t, err, registry.ErrStateConflict, "wrong from")
		require.Equal(t, registry.StateReserved, get(t, r, stored.Key).State, "entry changed")
		err = r.Resolve(ctx, key(9), registry.StateReserved, upd)
		require.ErrorIs(t, err, registry.ErrNotFound, "absent key")
	})

	t.Run("HistoryIsAppendOnly", func(t *testing.T) {
		r := open(t, Epoch)
		stored := reach(t, r, 1, registry.StateUnknown)
		bad := map[string]func(u *registry.Entry){
			"no new record":   func(u *registry.Entry) { u.History = stored.History },
			"two new records": func(u *registry.Entry) { u.History = append(u.History, u.History[len(u.History)-1]) },
			"history dropped": func(u *registry.Entry) { u.History = u.History[len(u.History)-1:] },
			"old record rewritten": func(u *registry.Entry) {
				h := append([]registry.Resolution(nil), u.History...)
				h[0].By = "someone"
				u.History = h
			},
		}
		for name, mut := range bad {
			upd := step(stored, registry.StateRejected, registry.SourceManual)
			mut(&upd)
			err := r.Resolve(ctx, stored.Key, registry.StateUnknown, upd)
			assert.Errorf(t, err, "%s: accepted", name)
			after := get(t, r, stored.Key)
			assert.Equalf(t, stored, after, "%s: entry changed", name)
		}
		good := step(stored, registry.StateRejected, registry.SourceManual)
		good.History[len(good.History)-1].Note = "checked by hand"
		good.History[len(good.History)-1].By = "op-1"
		must(t, r.Resolve(ctx, stored.Key, registry.StateUnknown, good))
		got := get(t, r, stored.Key)
		last := got.History[len(got.History)-1]
		require.Equalf(t, "checked by hand", last.Note, "history %+v", got.History)
		require.EqualValuesf(t, "op-1", last.By, "history %+v", got.History)
		require.Equalf(t, registry.SourceManual, last.Source, "history %+v", got.History)
		require.Equalf(t, registry.StateUnknown, last.PrevState, "history %+v", got.History)
		require.EqualValuesf(t, 1500, last.At, "history %+v", got.History)
	})

	t.Run("Pending", func(t *testing.T) {
		r := open(t, Epoch)
		reach(t, r, 1, registry.StateReserved)
		reach(t, r, 2, registry.StateUnknown)
		reach(t, r, 3, registry.StateExecuted)
		reach(t, r, 4, registry.StateRejected)
		p, err := r.Pending(ctx)
		must(t, err)
		var got []byte
		for _, e := range p {
			got = append(got, e.Key.PubKey[0])
		}
		sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
		require.Equalf(t, hex.EncodeToString([]byte{1, 2}), hex.EncodeToString(got), "pending keys %v", got)
	})

	t.Run("Recover", func(t *testing.T) {
		r := open(t, Epoch)
		reach(t, r, 1, registry.StateReserved)
		reach(t, r, 2, registry.StateReserved)
		reach(t, r, 3, registry.StateExecuted)
		reach(t, r, 4, registry.StateUnknown)
		n, err := r.Recover(ctx, RecoverAt)
		require.NoErrorf(t, err, "Recover = %d", n)
		require.EqualValuesf(t, 2, n, "Recover = %d, %v", n, err)
		for _, i := range []byte{1, 2} {
			e := get(t, r, key(i))
			last := e.History[len(e.History)-1]
			require.Equalf(t, registry.StateUnknown, e.State, "entry %d", i)
			require.Lenf(t, e.History, 1, "entry %d", i)
			require.Equalf(t, registry.SourceRecover, last.Source, "entry %d", i)
			require.Equalf(t, registry.StateReserved, last.PrevState, "entry %d", i)
			require.Equalf(t, "gate", last.By, "entry %d", i)
		}
		require.EqualValues(t, registry.StateExecuted, get(t, r, key(3)).State, "Recover touched an entry that was not Reserved")
		require.EqualValues(t, registry.StateUnknown, get(t, r, key(4)).State, "Recover touched an entry that was not Reserved")
		n, err = r.Recover(ctx, RecoverAt)
		require.NoErrorf(t, err, "second Recover = %d", n)
		require.EqualValuesf(t, 0, n, "second Recover = %d, %v", n, err)
	})

	t.Run("Prune", func(t *testing.T) {
		r := open(t, Epoch)
		mk := func(i byte, s registry.State, validUntil uint64) {
			e := fresh(i)
			e.ValidUntil = validUntil
			must(t, r.Reserve(ctx, e, Tolerance))
			if s != registry.StateReserved {
				must(t, r.Resolve(ctx, e.Key, registry.StateReserved, step(e, s, registry.SourceRail)))
			}
		}
		mk(1, registry.StateExecuted, 499) // pruned
		mk(2, registry.StateRejected, 499) // pruned
		mk(3, registry.StateExecuted, 500) // equal to the cutoff: kept
		mk(4, registry.StateExecuted, 900) // young
		mk(5, registry.StateReserved, 10)  // never pruned
		mk(6, registry.StateUnknown, 10)   // never pruned
		n, err := r.Prune(ctx, 500)
		require.NoErrorf(t, err, "Prune = %d", n)
		require.EqualValuesf(t, 2, n, "Prune = %d, %v", n, err)
		for _, i := range []byte{1, 2} {
			_, err := r.Get(ctx, key(i))
			require.ErrorIsf(t, err, registry.ErrNotFound, "entry %d survived", i)
		}
		for _, i := range []byte{3, 4, 5, 6} {
			get(t, r, key(i))
		}
		// A pruned key can be reserved again.
		must(t, r.Reserve(ctx, fresh(1), Tolerance))
	})

	t.Run("ReserveBelowWatermarkIsRefusedAndWritesNothing", func(t *testing.T) {
		r := open(t, Epoch)
		hi := fresh(1)
		hi.ReservedAt = 5000
		must(t, r.Reserve(ctx, hi, Tolerance))

		low := fresh(2)
		low.ReservedAt = 5000 - Tolerance - 1
		err := r.Reserve(ctx, low, Tolerance)
		require.ErrorIs(t, err, registry.ErrBelowWatermark)
		_, err = r.Get(ctx, low.Key)
		require.ErrorIs(t, err, registry.ErrNotFound)
		m, err := r.Meta(ctx)
		require.NoError(t, err)
		require.EqualValues(t, 5000, m.Watermark)

		edge := fresh(3)
		edge.ReservedAt = 5000 - Tolerance
		must(t, r.Reserve(ctx, edge, Tolerance))
		get(t, r, edge.Key)
		m, _ = r.Meta(ctx)
		require.EqualValues(t, 5000, m.Watermark, "an accepted older reservation must not lower the watermark")
	})

	t.Run("ReserveToleranceIsPerCall", func(t *testing.T) {
		r := open(t, Epoch)
		hi := fresh(1)
		hi.ReservedAt = 5000
		must(t, r.Reserve(ctx, hi, Tolerance))
		low := fresh(2)
		low.ReservedAt = 4000
		require.ErrorIs(t, r.Reserve(ctx, low, 0), registry.ErrBelowWatermark)
		must(t, r.Reserve(ctx, low, 1000))
	})

	t.Run("RecoverRecordsTheGivenTime", func(t *testing.T) {
		r := open(t, Epoch)
		reach(t, r, 1, registry.StateReserved)
		n, err := r.Recover(ctx, RecoverAt)
		require.NoError(t, err)
		require.Equal(t, 1, n)
		e := get(t, r, key(1))
		require.Len(t, e.History, 1)
		require.EqualValues(t, RecoverAt, e.History[0].At)
	})

	t.Run("ClaimRefusesASecondOwnerUntilReleased", func(t *testing.T) {
		r := open(t, Epoch)
		cl, ok := r.(registry.Claimer)
		require.True(t, ok, "registry does not implement Claimer")
		release, err := cl.Claim()
		require.NoError(t, err)
		_, err = cl.Claim()
		require.ErrorIs(t, err, registry.ErrInUse)
		release()
		release2, err := cl.Claim()
		require.NoError(t, err)
		release2()
	})

	t.Run("PruneCutoffRefusesReservationsInThePrunedWindow", func(t *testing.T) {
		r := open(t, Epoch)
		m, err := r.Meta(ctx)
		require.NoError(t, err)
		require.Zero(t, m.PruneCutoff)

		done := fresh(1)
		done.ValidUntil = 400
		must(t, r.Reserve(ctx, done, Tolerance))
		must(t, r.Resolve(ctx, done.Key, registry.StateReserved, step(done, registry.StateExecuted, registry.SourceRail)))
		n, err := r.Prune(ctx, 500)
		require.NoError(t, err)
		require.Equal(t, 1, n)
		m, _ = r.Meta(ctx)
		require.EqualValues(t, 500, m.PruneCutoff)

		inside := fresh(2)
		inside.ValidUntil = 499
		require.ErrorIs(t, r.Reserve(ctx, inside, Tolerance), registry.ErrPrunedWindow)
		_, err = r.Get(ctx, inside.Key)
		require.ErrorIs(t, err, registry.ErrNotFound)
		after, _ := r.Meta(ctx)
		require.Equal(t, m, after, "a refused reservation must not change the meta")

		// The pruned key itself is refused too.
		require.ErrorIs(t, r.Reserve(ctx, done, Tolerance), registry.ErrPrunedWindow)

		edge := fresh(3)
		edge.ValidUntil = 500
		must(t, r.Reserve(ctx, edge, Tolerance))
	})

	t.Run("PruneCutoffOnlyGrows", func(t *testing.T) {
		r := open(t, Epoch)
		_, err := r.Prune(ctx, 700)
		require.NoError(t, err)
		_, err = r.Prune(ctx, 300)
		require.NoError(t, err)
		m, _ := r.Meta(ctx)
		require.EqualValues(t, 700, m.PruneCutoff)
	})

	t.Run("ConcurrentReserveOneWinner", func(t *testing.T) {
		r := open(t, Epoch)
		const n = 32
		var wins, losses atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				e := fresh(1)
				e.CommitmentHash = commitment.Hash{byte(i)}
				switch err := r.Reserve(ctx, e, Tolerance); {
				case err == nil:
					wins.Add(1)
				case errors.Is(err, registry.ErrExists):
					losses.Add(1)
				default:
					assert.Fail(t, fmt.Sprintf("Reserve: %v", err))
				}
			}()
		}
		wg.Wait()
		require.EqualValuesf(t, 1, wins.Load(), "wins %d losses %d", wins.Load(), losses.Load())
		require.EqualValuesf(t, n-1, losses.Load(), "wins %d losses %d", wins.Load(), losses.Load())
	})

	t.Run("ConcurrentResolveOneWinner", func(t *testing.T) {
		r := open(t, Epoch)
		stored := reach(t, r, 1, registry.StateUnknown)
		const n = 16
		var wins, conflicts atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				to := registry.StateRejected
				if i%2 == 0 {
					to = registry.StateExecuted
				}
				switch err := r.Resolve(ctx, stored.Key, registry.StateUnknown, step(stored, to, registry.SourceManual)); {
				case err == nil:
					wins.Add(1)
				case errors.Is(err, registry.ErrStateConflict):
					conflicts.Add(1)
				default:
					assert.Fail(t, fmt.Sprintf("Resolve: %v", err))
				}
			}()
		}
		wg.Wait()
		require.EqualValuesf(t, 1, wins.Load(), "wins %d conflicts %d", wins.Load(), conflicts.Load())
		require.EqualValuesf(t, n-1, conflicts.Load(), "wins %d conflicts %d", wins.Load(), conflicts.Load())
		got := get(t, r, stored.Key)
		require.Lenf(t, got.History, len(stored.History)+1, "history %+v", got.History)
	})
}

func name(s registry.State) string {
	switch s {
	case registry.StateReserved:
		return "Reserved"
	case registry.StateExecuted:
		return "Executed"
	case registry.StateRejected:
		return "Rejected"
	case registry.StateUnknown:
		return "Unknown"
	}
	return "?"
}
