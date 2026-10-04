package ibkr_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/examples/dca-agent/ibkr"
	"github.com/vgonkivs/edicta/examples/dca-agent/ibkrorder"
)

const settle = uint64(60)

func withSettle(c *ibkr.ExecutorConfig) { c.SettleS = settle }

// beginHook runs f after a successful Begin.
type beginHook struct {
	ibkr.Store
	f func()
}

func (s *beginHook) Begin(ctx context.Context, h commitment.Hash, expires uint64) error {
	if err := s.Store.Begin(ctx, h, expires); err != nil {
		return err
	}
	s.f()
	return nil
}

func TestExpiryAfterBeginNeverPlaces(t *testing.T) {
	r := newRig(t, withSettle)
	r.store = &beginHook{Store: r.store, f: func() { r.clock.set(nowUnix + 300) }}
	r.restart()
	auth, action, h := r.valid()

	ref, err := r.exec.Execute(context.Background(), auth, action)
	require.ErrorIs(t, err, commitment.ErrExpired)
	assert.Empty(t, ref)
	assert.Zero(t, r.broker.PlaceCalls())

	// Nothing was sent, so the record ends without waiting for the settle time.
	_, err = r.exec.Reconcile(context.Background(), h)
	require.ErrorIs(t, err, ibkr.ErrNotPlaced)
	assert.Zero(t, r.broker.PlaceCalls())
}

func TestReconcileNeedsNoAuthorization(t *testing.T) {
	r := newRig(t, withSettle)
	auth, action, h := r.valid()
	r.broker.FailAfterPlace(errors.New("timeout"))
	_, err := r.exec.Execute(context.Background(), auth, action)
	require.ErrorIs(t, err, ibkr.ErrOutcomeUnknown)

	r.clock.set(nowUnix + 10_000) // far past the authorization
	id, err := r.exec.Reconcile(context.Background(), h)
	require.NoError(t, err)
	assert.NotEmpty(t, id)
	assert.Equal(t, 1, r.broker.PlaceCalls())

	rec, err := r.store.Get(context.Background(), h)
	require.NoError(t, err)
	assert.Equal(t, id, rec.OrderID, "the record is terminal")

	again, err := r.exec.Reconcile(context.Background(), h)
	require.NoError(t, err)
	assert.Equal(t, id, again)
}

func TestReconcileNotFoundBecomesFinalOnlyAfterSettle(t *testing.T) {
	r := newRig(t, withSettle)
	auth, action, h := r.valid()
	r.broker.FailBeforePlace(errors.New("connection refused"))
	_, err := r.exec.Execute(context.Background(), auth, action)
	require.Error(t, err)
	require.Equal(t, 1, r.broker.PlaceCalls())

	r.clock.set(nowUnix + 300 + skew + settle - 1)
	_, err = r.exec.Reconcile(context.Background(), h)
	require.ErrorIs(t, err, ibkr.ErrOutcomeUnknown, "the order may still appear")

	r.clock.set(nowUnix + 300 + skew + settle)
	_, err = r.exec.Reconcile(context.Background(), h)
	require.ErrorIs(t, err, ibkr.ErrNotPlaced)

	t.Run("a terminal record is never placed again", func(t *testing.T) {
		r.clock.set(nowUnix)
		fresh := authorize(t, gateKey(7), h, ibkrorder.ActionType, action,
			func(a *commitment.Authorization) { a.Expires = nowUnix + 3000 })
		_, err := r.exec.Execute(context.Background(), fresh, action)
		require.Error(t, err)
		assert.Equal(t, 1, r.broker.PlaceCalls())
		_, err = r.exec.Reconcile(context.Background(), h)
		require.ErrorIs(t, err, ibkr.ErrNotPlaced)
	})
}

func TestExpiredAuthorizationNeverPlaces(t *testing.T) {
	r := newRig(t, withSettle)
	auth, action, h := r.valid()
	r.clock.set(nowUnix + 300)

	_, err := r.exec.Execute(context.Background(), auth, action)
	require.ErrorIs(t, err, commitment.ErrExpired)
	assert.Zero(t, r.broker.PlaceCalls())
	_, err = r.exec.Reconcile(context.Background(), h)
	require.ErrorIs(t, err, ibkr.ErrNotFound, "an expired execution leaves no record")

	t.Run("not even after a record was begun and abandoned", func(t *testing.T) {
		r := newRig(t, withSettle)
		auth, action, h := r.valid()
		require.NoError(t, r.store.Begin(context.Background(), h, nowUnix+300))
		r.clock.set(nowUnix + 300)
		_, err := r.exec.Execute(context.Background(), auth, action)
		require.Error(t, err)
		assert.Zero(t, r.broker.PlaceCalls())
	})
}

func TestReconcileOfAFinishedRecord(t *testing.T) {
	r := newRig(t, withSettle)
	auth, action, h := r.valid()
	placed, err := r.exec.Execute(context.Background(), auth, action)
	require.NoError(t, err)
	got, err := r.exec.Reconcile(context.Background(), h)
	require.NoError(t, err)
	assert.Equal(t, placed, got)
	assert.Equal(t, 1, r.broker.PlaceCalls())
}

func TestReconcileLookupErrorChangesNothing(t *testing.T) {
	r := newRig(t, withSettle)
	auth, action, h := r.valid()
	r.broker.FailAfterPlace(errors.New("timeout"))
	_, _ = r.exec.Execute(context.Background(), auth, action)
	r.broker.FailLookup(errors.New("session lost"))
	r.clock.set(nowUnix + 10_000)
	_, err := r.exec.Reconcile(context.Background(), h)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ibkr.ErrNotPlaced, "a failed lookup is not a final not-found")
	rec, err := r.store.Get(context.Background(), h)
	require.NoError(t, err)
	assert.True(t, rec.InFlight())
}

func TestReconcileUnknownCommitment(t *testing.T) {
	r := newRig(t, withSettle)
	_, err := r.exec.Reconcile(context.Background(), chash(0x77))
	require.ErrorIs(t, err, ibkr.ErrNotFound)
}

// mutatingClock changes the caller's buffer the first time it is read, which
// happens while the executor is still working on the bytes it was handed.
type mutatingClock struct {
	*fixedClock
	buf  []byte
	once sync.Once
}

func (c *mutatingClock) Now() time.Time {
	c.once.Do(func() {
		for i := range c.buf {
			c.buf[i] ^= 0xff
		}
	})
	return c.fixedClock.Now()
}

// A writer that changes the caller's buffer while Execute runs must not change
// the order that is verified or placed.
func TestPlacedOrderIsTheVerifiedBytes(t *testing.T) {
	r := newRig(t)
	auth, action, h := r.valid()
	orig := append([]byte(nil), action...)
	mc := &mutatingClock{fixedClock: r.clock, buf: action}
	e, err := ibkr.NewExecutor(r.cfg, r.broker, r.store, mc)
	require.NoError(t, err)

	_, err = e.Execute(context.Background(), auth, action)
	require.NoError(t, err, "the executor works on its own copy")
	require.NotEqual(t, orig, action, "the test must have changed the caller's buffer")
	want, err := ibkrorder.Decode(orig)
	require.NoError(t, err)
	require.Len(t, r.broker.Placed(), 1)
	assert.Equal(t, ibkr.RequestFromOrder(want, ibkr.ClientOrderID(h)), r.broker.Placed()[0])
}

func TestReconcileNeverClosesBeforeTheSettleTime(t *testing.T) {
	for _, st := range []uint64{1, 60} {
		r := newRig(t, func(c *ibkr.ExecutorConfig) { c.SettleS = st })
		auth, action, h := r.valid()
		r.broker.FailBeforePlace(errors.New("refused"))
		_, err := r.exec.Execute(context.Background(), auth, action)
		require.Error(t, err)
		final := nowUnix + 300 + skew + st
		for _, at := range []uint64{nowUnix, nowUnix + 300, final - 1} {
			r.clock.set(at)
			_, err := r.exec.Reconcile(context.Background(), h)
			require.ErrorIsf(t, err, ibkr.ErrOutcomeUnknown, "settle %d at %d", st, at)
			rec, gerr := r.store.Get(context.Background(), h)
			require.NoError(t, gerr)
			require.Truef(t, rec.InFlight(), "settle %d at %d", st, at)
		}
		r.clock.set(final)
		_, err = r.exec.Reconcile(context.Background(), h)
		require.ErrorIs(t, err, ibkr.ErrNotPlaced)
	}
}

func TestMemStoreIgnoresCancelledContextAndPrunes(t *testing.T) {
	s := ibkr.NewMemStore()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h1, h2 := chash(1), chash(2)

	require.NoError(t, s.Begin(ctx, h1, 1000))
	require.NoError(t, s.Begin(ctx, h2, 2000))
	_, err := s.Get(ctx, h1)
	require.NoError(t, err)
	require.NoError(t, s.Finish(ctx, h1, "42"))

	assert.Equal(t, 0, s.Prune(1000+30, 30), "still inside expires + skew")
	assert.Equal(t, 1, s.Prune(1000+30+1, 30))
	_, err = s.Get(context.Background(), h1)
	require.ErrorIs(t, err, ibkr.ErrNotFound)
	_, err = s.Get(context.Background(), h2)
	require.NoError(t, err)
}

// Two distinct valid tokens for one commitment, as a signer that signed before
// a crash and again after it can produce, place one order.
func TestTwoTokensForOneCommitmentPlaceOnce(t *testing.T) {
	r := newRig(t)
	_, action, h := r.valid()
	tok1 := authorize(t, gateKey(7), h, ibkrorder.ActionType, action)
	tok2 := authorize(t, gateKey(7), h, ibkrorder.ActionType, action,
		func(a *commitment.Authorization) { a.Expires += 5 })
	require.NotEqual(t, tok1, tok2)

	first, err := r.exec.Execute(context.Background(), tok1, action)
	require.NoError(t, err)
	second, err := r.exec.Execute(context.Background(), tok2, action)
	require.ErrorIs(t, err, ibkr.ErrSeen)
	assert.Equal(t, first, second)
	assert.Equal(t, 1, r.broker.PlaceCalls())
}
