package retention_test

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/retention"
	"github.com/vgonkivs/edicta/retention/memstore"
	. "github.com/vgonkivs/edicta/test/retentionfix"
)

const waitMax = 5 * time.Second

func with(mut func(*retention.Policy)) retention.Policy {
	p := Policy
	mut(&p)
	return p
}

func mustParams(t *testing.T, p retention.Policy, l retention.LatestSource, d retention.AtHeightSource, st retention.Store, clk retention.Clock, opts ...retention.Option) *retention.Params {
	t.Helper()
	pr, err := retention.NewParams(p, l, d, st, clk, opts...)
	require.NoError(t, err)
	return pr
}

func TestFibreRetentionStoreFailure(t *testing.T) {
	failures := map[string]error{
		"write error":   errors.New("disk full"),
		"corrupt store": retention.ErrStoreCorrupt,
	}
	for name, ferr := range failures {
		t.Run(name, func(t *testing.T) {
			fs := Wrap(memstore.New())
			p := mustParams(t, Policy, Ticking("mocha-5", 100, 30, history), nil, fs, NewClock(5000))
			require.NoError(t, p.Start(ctx))
			fs.FailAppend(ferr)

			got, err := p.FibreRetention(ctx, 0)
			require.NoError(t, err, "the latest value does not depend on persisting")
			assert.Equal(t, uint64(100), got)

			got, err = p.FibreRetention(ctx, 100_000)
			require.Error(t, err, "a past height must fail closed")
			assert.Zero(t, got)
		})
	}
}

func TestInvertedSampleRefused(t *testing.T) {
	l := NewLatest("mocha-5", Ok(S(200, 100, 7, 0)))
	st := memstore.New()
	p := mustParams(t, Policy, l, nil, st, NewClock(5000))
	require.Error(t, p.Start(ctx))
	_, have, err := st.Last(ctx)
	require.NoError(t, err)
	assert.False(t, have, "nothing is recorded")

	l2 := NewLatest("mocha-5", Ok(S(100, 100, 7, 0)), Ok(S(300, 250, 7, 0)))
	st2 := memstore.New()
	p2 := mustParams(t, Policy, l2, nil, st2, NewClock(5000))
	require.NoError(t, p2.Start(ctx))
	require.Error(t, p2.Observe(ctx))
	last, _, err := st2.Last(ctx)
	require.NoError(t, err)
	assert.Equal(t, uint64(100), last.LastFrom)
}

func TestChainSwitchMidRunDetected(t *testing.T) {
	st := memstore.New()
	l := Ticking("mocha-5", 100, 30, history)
	clk := NewClock(5000)
	p := mustParams(t, Policy, l, nil, st, clk)
	require.NoError(t, p.Start(ctx))
	before, _, err := st.Last(ctx)
	require.NoError(t, err)

	l.Chain = "mainnet"
	require.ErrorIs(t, p.Observe(ctx), retention.ErrChainMismatch)
	clk.Advance(60)
	_, err = p.FibreRetention(ctx, 100_000)
	require.ErrorIs(t, err, retention.ErrChainMismatch)
	after, _, err := st.Last(ctx)
	require.NoError(t, err)
	assert.Equal(t, before, after, "the foreign sample is not recorded")
}

func TestObserveBeforeStartRefused(t *testing.T) {
	st := memstore.New()
	p := mustParams(t, Policy, Ticking("mocha-5", 100, 30, history), nil, st, NewClock(5000))
	require.Error(t, p.Observe(ctx))
	_, have, err := st.Last(ctx)
	require.NoError(t, err)
	assert.False(t, have)
}

func TestPolicyDefaults(t *testing.T) {
	run := func(t *testing.T, step uint64, advance int64) error {
		clk := NewClock(5000)
		p := mustParams(t, retention.Policy{}, Ticking("mocha-5", 100, step, func(int) uint64 { return 9 }), nil, memstore.New(), clk)
		require.NoError(t, p.Start(ctx))
		clk.Advance(advance)
		require.NoError(t, p.Observe(ctx))
		_, err := p.FibreRetention(ctx, 100+step/2)
		return err
	}
	assert.NoError(t, run(t, 100, 300), "100 blocks and 300 s stay in one segment")
	assert.ErrorIs(t, run(t, 101, 10), retention.ErrNotCovered, "101 blocks split")
	assert.ErrorIs(t, run(t, 50, 301), retention.ErrNotCovered, "301 s split")
}

func TestNewParamsRejectsOutOfRangePolicy(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*retention.Policy)
		ok   bool
	}{
		{"as configured", func(*retention.Policy) {}, true},
		{"zero policy", func(p *retention.Policy) { *p = retention.Policy{} }, true},
		{"unbounded block gap", func(p *retention.Policy) { p.MaxGapBlocks = math.MaxUint64 }, false},
		{"unbounded time gap", func(p *retention.Policy) { p.MaxGapS = math.MaxUint64 }, false},
		{"keep shorter than the governance maximum", func(p *retention.Policy) { p.KeepS = 3600 }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := retention.NewParams(with(tc.mut), NewLatest("c"), nil, memstore.New(), NewClock(1))
			if tc.ok {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
		})
	}
}

func TestStalledScheduledSampleDoesNotBlockCallers(t *testing.T) {
	clk := NewClock(5000)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	l := NewLatest("mocha-5")
	l.Hook = func(_ context.Context, n int) (retention.Sample, error) {
		if n == 1 {
			close(entered)
			<-release
		}
		return S(100+uint64(n), 100+uint64(n), 7, 0), nil
	}
	p := mustParams(t, with(func(p *retention.Policy) { p.MaxSampleAge = 30 }), l, nil, memstore.New(), clk)
	require.NoError(t, p.Start(ctx))
	clk.Advance(100)

	stalled := make(chan error, 1)
	go func() { stalled <- p.Observe(context.Background()) }()
	select {
	case <-entered:
	case <-time.After(waitMax):
		require.FailNow(t, "the scheduled sample never started")
	}

	cctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := p.FibreRetention(cctx, 0); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			require.ErrorIs(t, err, context.DeadlineExceeded)
		}
	case <-time.After(waitMax):
		require.FailNow(t, "a caller stayed blocked behind the stalled sample")
	}

	once.Do(func() { close(release) })
	require.NoError(t, <-stalled)
}

func TestRunTickHasTimeout(t *testing.T) {
	l := NewLatest("mocha-5")
	saw := make(chan bool, 1)
	l.Hook = func(ctx context.Context, n int) (retention.Sample, error) {
		if n == 0 {
			return S(100, 100, 7, 0), nil
		}
		_, ok := ctx.Deadline()
		select {
		case saw <- ok:
		default:
		}
		return retention.Sample{}, errors.New("down")
	}
	pol := with(func(p *retention.Policy) { p.SampleTimeout = 2 * time.Second })
	p := mustParams(t, pol, l, nil, memstore.New(), NewClock(5000))
	require.NoError(t, p.Start(ctx))

	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ran := make(chan error, 1)
	go func() { ran <- p.Run(rctx, time.Millisecond, time.Hour) }()
	select {
	case ok := <-saw:
		assert.True(t, ok, "the scheduled sample runs under a deadline")
	case <-time.After(waitMax):
		require.FailNow(t, "Run never sampled")
	}
	cancel()
	require.ErrorIs(t, <-ran, context.Canceled)
}

func TestLatestReadReusesARecentSample(t *testing.T) {
	pol := with(func(p *retention.Policy) { p.MaxSampleAge = 30 })
	clk := NewClock(5000)
	latest := Ticking("mocha-5", 100, 30, history)
	p := mustParams(t, pol, latest, nil, memstore.New(), clk)
	require.NoError(t, p.Start(ctx))
	require.NoError(t, p.Observe(ctx))
	require.NoError(t, p.Observe(ctx))
	calls := latest.Calls()

	clk.Advance(10)
	got, err := p.FibreRetention(ctx, 0)
	require.NoError(t, err)
	assert.Equal(t, uint64(50), got, "the newest sample's value")
	assert.Equal(t, calls, latest.Calls(), "no new read within the age")

	clk.Advance(30)
	got, err = p.FibreRetention(ctx, 0)
	require.NoError(t, err)
	assert.Equal(t, uint64(7), got, "an older sample is replaced by a fresh read")
	assert.Equal(t, calls+1, latest.Calls())
}

func TestRunPrunesByKeepS(t *testing.T) {
	fs := Wrap(memstore.New())
	require.NoError(t, fs.Bind(ctx, "mocha-5"))
	require.NoError(t, fs.Append(ctx, S(100, 100, 7, 1000), Policy))
	require.NoError(t, fs.Append(ctx, S(5000, 5000, 7, 1500), Policy))
	now := int64(1000 + Policy.KeepS + 200)
	p := mustParams(t, Policy, Ticking("mocha-5", 100_000, 1, func(int) uint64 { return 7 }), nil, fs, NewClock(now))
	require.NoError(t, p.Start(ctx))

	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ran := make(chan error, 1)
	go func() { ran <- p.Run(rctx, time.Millisecond, time.Millisecond) }()
	select {
	case before := <-fs.Pruned:
		assert.Equal(t, uint64(now)-Policy.KeepS, before)
	case <-time.After(waitMax):
		require.FailNow(t, "Run never pruned")
	}
	cancel()
	require.ErrorIs(t, <-ran, context.Canceled)

	old, err := fs.Segment(ctx, 100)
	require.NoError(t, err)
	assert.Empty(t, old)
	kept, err := fs.Segment(ctx, 5000)
	require.NoError(t, err)
	assert.NotEmpty(t, kept)
}

type recHandler struct {
	mu sync.Mutex
	n  int
}

func (h *recHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recHandler) Handle(context.Context, slog.Record) error {
	h.mu.Lock()
	h.n++
	h.mu.Unlock()
	return nil
}
func (h *recHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recHandler) WithGroup(string) slog.Handler      { return h }
func (h *recHandler) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.n
}

func TestModeSwitchesAreLogged(t *testing.T) {
	boot := func(t *testing.T, d retention.AtHeightSource) (*retention.Params, *recHandler) {
		h := &recHandler{}
		p := mustParams(t, Policy, Ticking("mocha-5", 100, 30, history), d, memstore.New(), NewClock(5000), retention.WithLogger(slog.New(h)))
		require.NoError(t, p.Start(ctx))
		require.NoError(t, p.Observe(ctx))
		require.NoError(t, p.Observe(ctx))
		return p, h
	}

	t.Run("startup mode", func(t *testing.T) {
		_, h := boot(t, nil)
		assert.GreaterOrEqual(t, h.count(), 1)
	})

	t.Run("leaving and re-entering observations-only", func(t *testing.T) {
		p, h := boot(t, &Direct{Canary: []bool{true, false, false, true}, At: Const(1)})
		require.False(t, p.ObservationsOnly())
		n := h.count()
		require.GreaterOrEqual(t, n, 1, "startup mode")

		assert.False(t, p.Canary(ctx))
		require.True(t, p.ObservationsOnly())
		assert.Greater(t, h.count(), n, "entering observations-only")
		n = h.count()

		p.Canary(ctx)
		assert.Equal(t, n, h.count(), "no change, no record")

		assert.True(t, p.Canary(ctx))
		require.False(t, p.ObservationsOnly())
		assert.Greater(t, h.count(), n, "leaving observations-only")
	})

	t.Run("a failed paired canary", func(t *testing.T) {
		p, h := boot(t, &Direct{Canary: []bool{true, false}, At: Const(5)})
		n := h.count()
		_, err := p.FibreRetention(ctx, 115)
		require.NoError(t, err)
		require.True(t, p.ObservationsOnly())
		assert.Greater(t, h.count(), n)
	})
}
