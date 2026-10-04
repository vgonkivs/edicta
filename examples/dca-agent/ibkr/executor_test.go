package ibkr_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/examples/dca-agent/ibkr"
	"github.com/vgonkivs/edicta/examples/dca-agent/ibkrorder"
	"github.com/vgonkivs/edicta/test/brokerfake"
)

const (
	gateID  = "gate-paper-1"
	account = "DU1234567"
	nowUnix = uint64(1791000060)
	skew    = uint64(30)
)

type fixedClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fixedClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fixedClock) set(u uint64)   { c.mu.Lock(); c.t = time.Unix(int64(u), 0); c.mu.Unlock() }

func gateKey(seed byte) ed25519.PrivateKey {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed
	}
	return ed25519.NewKeyFromSeed(s)
}

func limit(v uint64) *uint64 { return &v }

// validOrder is a 10 share limit buy at 100.00, notional 1000.00.
func validOrder() *ibkrorder.Order {
	return &ibkrorder.Order{
		Account: account, ConID: 756733, Symbol: "SPY", Side: ibkrorder.SideBuy,
		Qty: 10_0000, OrderType: ibkrorder.TypeLimit, LimitPrice: limit(100_00000000),
		Currency: "USD", TIF: ibkrorder.TIFDay,
	}
}

func encode(t *testing.T, o *ibkrorder.Order) []byte {
	t.Helper()
	b, err := ibkrorder.Encode(o)
	require.NoError(t, err)
	return b
}

type authOpt func(*commitment.Authorization)

func chash(b byte) commitment.Hash {
	var h commitment.Hash
	for i := range h {
		h[i] = b
	}
	return h
}

// authorize builds a SignedAuthorization over action under actionType.
func authorize(t *testing.T, key ed25519.PrivateKey, ch commitment.Hash, actionType string, action []byte, opts ...authOpt) []byte {
	t.Helper()
	ah, err := commitment.ActionHash(actionType, action)
	require.NoError(t, err)
	a := commitment.Authorization{
		Version: 0, CommitmentHash: ch[:], ActionHash: ah[:], GateID: gateID,
		Expires: nowUnix + 300, Path: commitment.PathDA,
	}
	for _, o := range opts {
		o(&a)
	}
	canon, err := commitment.EncodeAuthorization(&a)
	require.NoError(t, err)
	sig := ed25519.Sign(key, commitment.AuthorizationSigningMessage(commitment.HashAuthorization(canon)))
	out, err := commitment.EncodeSignedAuthorization(&commitment.SignedAuthorization{Authorization: a, Signature: sig})
	require.NoError(t, err)
	return out
}

type rig struct {
	t      *testing.T
	broker *brokerfake.Broker
	store  ibkr.Store
	clock  *fixedClock
	cfg    ibkr.ExecutorConfig
	exec   *ibkr.Executor
}

func newRig(t *testing.T, mods ...func(*ibkr.ExecutorConfig)) *rig {
	t.Helper()
	r := &rig{t: t, broker: brokerfake.New(), store: ibkr.NewMemStore(), clock: &fixedClock{}}
	r.clock.set(nowUnix)
	r.cfg = ibkr.ExecutorConfig{
		GatePubKey: gateKey(7).Public().(ed25519.PublicKey),
		GateID:     gateID,
		SkewS:      skew,
		SettleS:    settle,
		SignKey:    gateKey(5),
		Check:      ibkr.CheckConfig{Account: account, MaxNotional: 5000_00000000},
	}
	for _, m := range mods {
		m(&r.cfg)
	}
	r.exec = r.restart()
	return r
}

// restart builds a new executor on the same broker and store, as after a crash.
func (r *rig) restart() *ibkr.Executor {
	e, err := ibkr.NewExecutor(r.cfg, r.broker, r.store, r.clock)
	require.NoError(r.t, err)
	r.exec = e
	return e
}

func (r *rig) valid() (auth, action []byte, h commitment.Hash) {
	action = encode(r.t, validOrder())
	h = chash(0x11)
	return authorize(r.t, gateKey(7), h, ibkrorder.ActionType, action), action, h
}

func TestExecuteHappyPath(t *testing.T) {
	r := newRig(t)
	auth, action, h := r.valid()

	ref, err := r.exec.Execute(context.Background(), auth, action)
	require.NoError(t, err)
	assert.NotEmpty(t, ref)

	require.Equal(t, 1, r.broker.PlaceCalls())
	o, err := ibkrorder.Decode(action)
	require.NoError(t, err)
	assert.Equal(t, ibkr.RequestFromOrder(o, ibkr.ClientOrderID(h)), r.broker.Placed()[0])
	assert.Equal(t, ibkr.ClientOrderID(h), r.broker.Placed()[0].ClientOrderID)
}

func TestExecuteRefusals(t *testing.T) {
	good := validOrder()
	good.Symbol = ""
	cases := []struct {
		name string
		mod  func(r *rig) (auth, action []byte)
		want error
	}{
		{"foreign gate key", func(r *rig) ([]byte, []byte) {
			a := encode(t, validOrder())
			return authorize(t, gateKey(9), chash(1), ibkrorder.ActionType, a), a
		}, commitment.ErrSignatureInvalid},
		{"other gate id in the authorization", func(r *rig) ([]byte, []byte) {
			a := encode(t, validOrder())
			return authorize(t, gateKey(7), chash(1), ibkrorder.ActionType, a,
				func(x *commitment.Authorization) { x.GateID = "gate-other" }), a
		}, commitment.ErrScopeMismatch},
		{"executor pinned to another gate id", func(r *rig) ([]byte, []byte) {
			r.cfg.GateID = "gate-other"
			r.restart()
			a, b, _ := r.valid()
			return a, b
		}, commitment.ErrScopeMismatch},
		{"executor pinned to another key", func(r *rig) ([]byte, []byte) {
			r.cfg.GatePubKey = gateKey(9).Public().(ed25519.PublicKey)
			r.restart()
			a, b, _ := r.valid()
			return a, b
		}, commitment.ErrSignatureInvalid},
		{"expired", func(r *rig) ([]byte, []byte) {
			a, b, _ := r.valid()
			r.clock.set(nowUnix + 300)
			return a, b
		}, commitment.ErrExpired},
		{"inside the skew of expiry", func(r *rig) ([]byte, []byte) {
			a, b, _ := r.valid()
			r.clock.set(nowUnix + 300 - skew)
			return a, b
		}, commitment.ErrExpired},
		{"action byte flipped", func(r *rig) ([]byte, []byte) {
			a, b, _ := r.valid()
			b[len(b)-1] ^= 1
			return a, b
		}, commitment.ErrActionMismatch},
		{"action truncated", func(r *rig) ([]byte, []byte) {
			a, b, _ := r.valid()
			return a, b[:len(b)-1]
		}, commitment.ErrActionMismatch},
		{"authorized under another action type", func(r *rig) ([]byte, []byte) {
			b := encode(t, validOrder())
			return authorize(t, gateKey(7), chash(1), "application/json", b), b
		}, commitment.ErrActionMismatch},
		{"authorization for other bytes", func(r *rig) ([]byte, []byte) {
			o := validOrder()
			o.Qty++
			return authorize(t, gateKey(7), chash(1), ibkrorder.ActionType, encode(t, o)), encode(t, validOrder())
		}, commitment.ErrActionMismatch},
		{"garbage authorization", func(r *rig) ([]byte, []byte) {
			return []byte{0xa0}, encode(t, validOrder())
		}, nil},
		{"empty authorization", func(r *rig) ([]byte, []byte) { return nil, encode(t, validOrder()) }, nil},
		{"order for another account", func(r *rig) ([]byte, []byte) {
			o := validOrder()
			o.Account = "DU7654321"
			a := encode(t, o)
			return authorize(t, gateKey(7), chash(1), ibkrorder.ActionType, a), a
		}, ibkr.ErrAccountMismatch},
		{"notional above the operator limit", func(r *rig) ([]byte, []byte) {
			o := validOrder()
			o.Qty = 100_0000
			a := encode(t, o)
			return authorize(t, gateKey(7), chash(1), ibkrorder.ActionType, a), a
		}, ibkr.ErrRiskLimit},
		{"authorized bytes that are not an order", func(r *rig) ([]byte, []byte) {
			a := []byte(`{"symbol":"SPY","qty":10}`)
			return authorize(t, gateKey(7), chash(1), ibkrorder.ActionType, a), a
		}, ibkrorder.ErrMalformed},
		{"authorized market order", func(r *rig) ([]byte, []byte) {
			o := validOrder()
			o.OrderType, o.LimitPrice = ibkrorder.TypeMarket, nil
			a := encode(t, o)
			return authorize(t, gateKey(7), chash(1), ibkrorder.ActionType, a), a
		}, ibkrorder.ErrInvalid},
		{"authorized non-canonical encoding of a valid order", func(r *rig) ([]byte, []byte) {
			c := encode(t, validOrder())
			nc := append([]byte{0xbf}, c[1:]...)
			nc = append(nc, 0xff)
			return authorize(t, gateKey(7), chash(1), ibkrorder.ActionType, nc), nc
		}, ibkrorder.ErrMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			auth, action := c.mod(r)
			ref, err := r.exec.Execute(context.Background(), auth, action)
			require.Error(t, err)
			if c.want != nil {
				assert.ErrorIs(t, err, c.want)
			}
			assert.Empty(t, ref)
			assert.Zero(t, r.broker.PlaceCalls(), "a refused authorization must not reach the broker")
			assert.Zero(t, r.broker.Lookups())
		})
	}
}

func TestRiskLimitDisabledAndExact(t *testing.T) {
	for _, c := range []struct {
		name  string
		limit uint64
		ok    bool
	}{
		{"exactly at the limit", 1000_00000000, true},
		{"one unit below the notional", 1000_00000000 - 1, false},
		{"limit zero disables the check", 0, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t, func(cfg *ibkr.ExecutorConfig) { cfg.Check.MaxNotional = c.limit })
			auth, action, _ := r.valid()
			_, err := r.exec.Execute(context.Background(), auth, action)
			if c.ok {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, ibkr.ErrRiskLimit)
			assert.Zero(t, r.broker.PlaceCalls())
		})
	}
}

func TestExecuteTwiceIsDeduped(t *testing.T) {
	r := newRig(t)
	auth, action, _ := r.valid()
	first, err := r.exec.Execute(context.Background(), auth, action)
	require.NoError(t, err)

	second, err := r.exec.Execute(context.Background(), auth, action)
	require.ErrorIs(t, err, ibkr.ErrSeen)
	assert.Equal(t, first, second, "the repeat reports the order that exists")
	assert.Equal(t, 1, r.broker.PlaceCalls())

	t.Run("a restarted executor on the same store", func(t *testing.T) {
		again, err := r.restart().Execute(context.Background(), auth, action)
		require.ErrorIs(t, err, ibkr.ErrSeen)
		assert.Equal(t, first, again)
		assert.Equal(t, 1, r.broker.PlaceCalls())
	})
	t.Run("another authorization of the same commitment", func(t *testing.T) {
		other := authorize(t, gateKey(7), chash(0x11), ibkrorder.ActionType, action,
			func(a *commitment.Authorization) { a.Expires++ })
		_, err := r.exec.Execute(context.Background(), other, action)
		require.ErrorIs(t, err, ibkr.ErrSeen)
		assert.Equal(t, 1, r.broker.PlaceCalls())
	})
}

func TestConcurrentExecutePlacesOnce(t *testing.T) {
	r := newRig(t)
	auth, action, _ := r.valid()
	var wg sync.WaitGroup
	var mu sync.Mutex
	refs := map[string]int{}
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ref, err := r.exec.Execute(context.Background(), auth, action)
			if err == nil || errors.Is(err, ibkr.ErrSeen) {
				mu.Lock()
				refs[ref]++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, 1, r.broker.PlaceCalls())
	assert.Len(t, r.broker.Placed(), 1)
}

func TestDistinctCommitmentsAreIndependent(t *testing.T) {
	r := newRig(t)
	action := encode(t, validOrder())
	for _, b := range []byte{1, 2, 3} {
		auth := authorize(t, gateKey(7), chash(b), ibkrorder.ActionType, action)
		_, err := r.exec.Execute(context.Background(), auth, action)
		require.NoError(t, err)
	}
	assert.Equal(t, 3, r.broker.PlaceCalls())
}

func TestAmbiguousResultIsResolvedByLookup(t *testing.T) {
	r := newRig(t)
	auth, action, h := r.valid()
	r.broker.FailAfterPlace(errors.New("connection reset"))

	ref, err := r.exec.Execute(context.Background(), auth, action)
	require.ErrorIs(t, err, ibkr.ErrOutcomeUnknown)
	assert.Empty(t, ref)
	require.Equal(t, 1, r.broker.PlaceCalls())

	resolved, err := r.exec.Execute(context.Background(), auth, action)
	require.NoError(t, err, "the retry finds the order by its client id")
	assert.NotEmpty(t, resolved)
	assert.Equal(t, 1, r.broker.PlaceCalls(), "never placed twice")
	assert.GreaterOrEqual(t, r.broker.Lookups(), 1)
	assert.Equal(t, ibkr.ClientOrderID(h), r.broker.Placed()[0].ClientOrderID)

	again, err := r.exec.Execute(context.Background(), auth, action)
	require.ErrorIs(t, err, ibkr.ErrSeen)
	assert.Equal(t, resolved, again)
	assert.Equal(t, 1, r.broker.PlaceCalls())
}

func TestAmbiguousResultWithFailingLookupStaysUnresolved(t *testing.T) {
	r := newRig(t)
	auth, action, _ := r.valid()
	r.broker.FailAfterPlace(errors.New("timeout"))
	_, err := r.exec.Execute(context.Background(), auth, action)
	require.ErrorIs(t, err, ibkr.ErrOutcomeUnknown)

	r.broker.FailLookup(errors.New("session lost"))
	_, err = r.exec.Execute(context.Background(), auth, action)
	require.Error(t, err)
	assert.Equal(t, 1, r.broker.PlaceCalls(), "a failed lookup never turns into a second order")
}

func TestCrashBeforePlaceDoesNotResend(t *testing.T) {
	r := newRig(t)
	auth, action, h := r.valid()
	// The previous process recorded the commitment as in flight and died.
	require.NoError(t, r.store.Begin(context.Background(), h, nowUnix+300))

	_, err := r.restart().Execute(context.Background(), auth, action)
	require.ErrorIs(t, err, ibkr.ErrOutcomeUnknown)
	assert.Zero(t, r.broker.PlaceCalls(), "an in-flight record is never resolved by sending")
	assert.GreaterOrEqual(t, r.broker.Lookups(), 1)
}

// finishFails loses the record of a placed order, as a crash after Place does.
type finishFails struct {
	ibkr.Store
	once sync.Once
	hit  bool
}

func (s *finishFails) Finish(ctx context.Context, h commitment.Hash, id string) error {
	var err error
	s.once.Do(func() { s.hit = true; err = errors.New("process died") })
	if err != nil {
		return err
	}
	return s.Store.Finish(ctx, h, id)
}

func TestCrashAfterPlaceBeforeFinish(t *testing.T) {
	r := newRig(t)
	fs := &finishFails{Store: r.store}
	r.store = fs
	r.restart()
	auth, action, _ := r.valid()

	_, err := r.exec.Execute(context.Background(), auth, action)
	require.Error(t, err)
	require.True(t, fs.hit)
	require.Equal(t, 1, r.broker.PlaceCalls())

	ref, err := r.restart().Execute(context.Background(), auth, action)
	require.NoError(t, err)
	assert.NotEmpty(t, ref)
	assert.Equal(t, 1, r.broker.PlaceCalls(), "resolved by lookup, one order")
}

func TestExecuteHonoursCancelledContext(t *testing.T) {
	r := newRig(t)
	auth, action, _ := r.valid()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := r.exec.Execute(ctx, auth, action)
	require.Error(t, err)
	assert.Zero(t, r.broker.PlaceCalls())
}

func TestNewExecutorRejectsBadConfig(t *testing.T) {
	b, s, c := brokerfake.New(), ibkr.NewMemStore(), &fixedClock{}
	good := ibkr.ExecutorConfig{
		GatePubKey: gateKey(7).Public().(ed25519.PublicKey), GateID: gateID,
		SettleS: settle,
		Check:   ibkr.CheckConfig{Account: account},
	}
	_, err := ibkr.NewExecutor(good, b, s, c)
	require.NoError(t, err)

	for name, f := range map[string]func(*ibkr.ExecutorConfig){
		"no gate key":    func(x *ibkr.ExecutorConfig) { x.GatePubKey = nil },
		"short gate key": func(x *ibkr.ExecutorConfig) { x.GatePubKey = []byte{1, 2, 3} },
		"no gate id":     func(x *ibkr.ExecutorConfig) { x.GateID = "" },
		"no account":     func(x *ibkr.ExecutorConfig) { x.Check.Account = "" },
		"no settle time": func(x *ibkr.ExecutorConfig) { x.SettleS = 0 },
		"skew above 300": func(x *ibkr.ExecutorConfig) { x.SkewS = 301 },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := good
			f(&cfg)
			_, err := ibkr.NewExecutor(cfg, b, s, c)
			require.ErrorIs(t, err, ibkr.ErrInvalidConfig)
		})
	}
	_, err = ibkr.NewExecutor(good, nil, s, c)
	require.Error(t, err, "nil broker")
	_, err = ibkr.NewExecutor(good, b, nil, c)
	require.Error(t, err, "nil store")
	_, err = ibkr.NewExecutor(good, b, s, nil)
	require.Error(t, err, "nil clock")
}

func FuzzExecuteNeverPlacesUnauthorized(f *testing.F) {
	f.Add([]byte{}, []byte{})
	f.Add([]byte{0xa2, 0x01, 0xa0, 0x02, 0x40}, []byte{0xa0})
	f.Fuzz(func(t *testing.T, auth, action []byte) {
		r := newRig(t)
		_, err := r.exec.Execute(context.Background(), auth, action)
		require.Error(t, err)
		require.Zero(t, r.broker.PlaceCalls())
	})
}

func TestRecordRequestIsSignedByTheExecutorKey(t *testing.T) {
	r := newRig(t)
	h := chash(0x21)
	pub, sig, err := r.exec.RecordRequest(h, "order-9")
	require.NoError(t, err)
	assert.Equal(t, gateKey(5).Public().(ed25519.PublicKey), pub)
	require.NoError(t, commitment.VerifyRecordRequest(h, gateID, "order-9", pub, sig))
	assert.Error(t, commitment.VerifyRecordRequest(h, "gate-other", "order-9", pub, sig), "the request names the executor's gate")
	assert.Error(t, commitment.VerifyRecordRequest(h, gateID, "order-8", pub, sig))

	_, _, err = r.exec.RecordRequest(h, "")
	require.Error(t, err, "an empty reference has no request")
	_, _, err = r.exec.RecordRequest(h, strings.Repeat("a", 129))
	require.Error(t, err)
}
