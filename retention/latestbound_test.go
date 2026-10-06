package retention_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/retention"
	"github.com/vgonkivs/edicta/retention/memstore"
	. "github.com/vgonkivs/edicta/test/retentionfix"
)

func TestLatestReadNeverServesAForeignChain(t *testing.T) {
	boundStore := func(t *testing.T) *memstore.Store {
		st := memstore.New()
		require.NoError(t, st.Bind(ctx, "mocha-5"))
		return st
	}

	t.Run("start fails and the latest value is not served", func(t *testing.T) {
		st := boundStore(t)
		p := mustParams(t, Policy, Ticking("evil-1", 100, 30, func(int) uint64 { return 999 }), nil, st, NewClock(5000))
		require.ErrorIs(t, p.Start(ctx), retention.ErrChainMismatch)

		v, err := p.FibreRetention(ctx, 0)
		require.ErrorIs(t, err, retention.ErrChainMismatch)
		assert.Zero(t, v)
		_, have, err := st.Last(ctx)
		require.NoError(t, err)
		assert.False(t, have)
	})

	t.Run("a sample taken while unbound is refused", func(t *testing.T) {
		st := memstore.New()
		p := mustParams(t, Policy, Ticking("mocha-5", 100, 30, func(int) uint64 { return 7 }), nil, st, NewClock(5000))
		v, err := p.FibreRetention(ctx, 0)
		require.Error(t, err)
		assert.Zero(t, v)
		require.Error(t, p.Observe(ctx))
		_, have, err := st.Last(ctx)
		require.NoError(t, err)
		assert.False(t, have)
	})

	t.Run("a chain switch after start is refused at height zero", func(t *testing.T) {
		l := Ticking("mocha-5", 100, 30, func(int) uint64 { return 7 })
		clk := NewClock(5000)
		p := mustParams(t, Policy, l, nil, memstore.New(), clk)
		require.NoError(t, p.Start(ctx))
		l.Chain = "evil-1"
		clk.Advance(60)
		v, err := p.FibreRetention(ctx, 0)
		require.ErrorIs(t, err, retention.ErrChainMismatch)
		assert.Zero(t, v)
	})

	t.Run("a bad sample at height zero is an error", func(t *testing.T) {
		l := NewLatest("mocha-5", Ok(S(100, 100, 7, 0)), Ok(S(300, 250, 7, 0)))
		clk := NewClock(5000)
		p := mustParams(t, Policy, l, nil, memstore.New(), clk)
		require.NoError(t, p.Start(ctx))
		clk.Advance(60)
		v, err := p.FibreRetention(ctx, 0)
		require.ErrorIs(t, err, retention.ErrBadSample)
		assert.Zero(t, v)
	})
}

func TestPolicyCaps(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*retention.Policy)
		ok   bool
	}{
		{"defaults", func(p *retention.Policy) { *p = retention.Policy{} }, true},
		{"sample age at the cap", func(p *retention.Policy) { p.MaxSampleAge = 60 }, true},
		{"sample age above the cap", func(p *retention.Policy) { p.MaxSampleAge = 61 }, false},
		{"gap seconds at the cap", func(p *retention.Policy) { p.MaxGapS = 900 }, true},
		{"gap seconds above the cap", func(p *retention.Policy) { p.MaxGapS = 901 }, false},
		{"old gap seconds cap", func(p *retention.Policy) { p.MaxGapS = 3600 }, false},
		{"gap blocks at the cap", func(p *retention.Policy) { p.MaxGapBlocks = 1000 }, true},
		{"gap blocks above the cap", func(p *retention.Policy) { p.MaxGapBlocks = 1001 }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := Policy
			tc.mut(&p)
			_, err := retention.NewParams(p, NewLatest("c"), nil, memstore.New(), NewClock(1))
			if tc.ok {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, retention.ErrBadPolicy)
		})
	}
}
