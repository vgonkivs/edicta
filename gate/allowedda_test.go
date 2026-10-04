package gate_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/registry"
	"github.com/vgonkivs/edicta/test/gatefix"
)

var errNoFibre = errors.New("module fibre not found")

type countingParams struct {
	inner gate.ChainParams
	calls atomic.Int64
	err   error
}

func (p *countingParams) FibreRetention(ctx context.Context, h uint64) (uint64, error) {
	p.calls.Add(1)
	if p.err != nil {
		return 0, p.err
	}
	return p.inner.FibreRetention(ctx, h)
}

func onlyDA(das ...commitment.DA) func(*gate.Config) {
	return func(c *gate.Config) { c.AllowedDA = das }
}

func TestAllowedDAAdmission(t *testing.T) {
	cases := []struct {
		name    string
		allowed []commitment.DA
		fibre   bool
		wantErr error
	}{
		{"empty set allows da 2", nil, false, nil},
		{"empty set allows da 1", nil, true, nil},
		{"both allowed, da 2", []commitment.DA{1, 2}, false, nil},
		{"both allowed, da 1", []commitment.DA{1, 2}, true, nil},
		{"only 2, da 2", []commitment.DA{2}, false, nil},
		{"only 2, da 1", []commitment.DA{2}, true, gate.ErrDANotAllowed},
		{"only 1, da 1", []commitment.DA{1}, true, nil},
		{"only 1, da 2", []commitment.DA{1}, false, gate.ErrDANotAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := gatefix.New(t, gatefix.WithConfig(onlyDA(tc.allowed...)))
			c, blob := gatefix.Template(t), gatefix.Blob(t)
			if tc.fibre {
				c, blob = gatefix.FibreTemplate(t), gatefix.FibreBlob()
			}
			e.StageDA(c, blob)
			b, _ := gatefix.Sign(t, "agent1", c)
			res, err := e.Authorize(b)
			if tc.wantErr != nil {
				e.RequireRejected(c, err, tc.wantErr)
				assert.Empty(t, res.Authorization)
				assert.EqualValues(t, 0, e.DA.Fetches(), "no payload fetch for a refused da")
				return
			}
			require.NoError(t, err)
			assert.NotEmpty(t, res.Authorization)
		})
	}
}

func TestDANotAllowedIsReportedInMetrics(t *testing.T) {
	e := gatefix.New(t, gatefix.WithConfig(onlyDA(2)))
	c := gatefix.FibreTemplate(t)
	e.StageDA(c, gatefix.FibreBlob())
	b, h := gatefix.Sign(t, "agent1", c)
	_, err := e.Authorize(b)
	require.ErrorIs(t, err, gate.ErrDANotAllowed)
	ev := e.Metrics.Events()
	require.Len(t, ev, 1)
	assert.False(t, ev[0].Authorized)
	assert.ErrorIs(t, ev[0].Err, gate.ErrDANotAllowed)
	assert.Equal(t, commitment.DAFibre, ev[0].DA)
	assert.Equal(t, h, ev[0].CommitmentHash)
}

// The da check must not become an oracle for input that is not validly signed.
func TestDANotAllowedComesAfterSignatureCheck(t *testing.T) {
	e := gatefix.New(t, gatefix.WithConfig(onlyDA(2)))
	c := gatefix.FibreTemplate(t)
	e.StageDA(c, gatefix.FibreBlob())
	b, _ := gatefix.SignWith(t, gatefix.Key(t, "agent2"), c)
	_, err := e.Authorize(b)
	require.ErrorIs(t, err, commitment.ErrSignatureInvalid)
	assert.NotErrorIs(t, err, gate.ErrDANotAllowed)
	e.RequireUntouched(c)
}

// A refused da must not consume the nonce: the same nonce is still usable by
// a commitment with an allowed da.
func TestDANotAllowedLeavesNonceFree(t *testing.T) {
	e := gatefix.New(t, gatefix.WithConfig(onlyDA(2)))
	f := gatefix.FibreTemplate(t)
	b, _ := gatefix.Sign(t, "agent1", f)
	_, err := e.Authorize(b)
	require.ErrorIs(t, err, gate.ErrDANotAllowed)
	_, err = e.Entry(f)
	require.ErrorIs(t, err, registry.ErrNotFound)
}

func TestOnlyDA2NeverReadsFibreRetention(t *testing.T) {
	var cp *countingParams
	e := gatefix.New(t,
		gatefix.WithConfig(onlyDA(2)),
		gatefix.WithDeps(func(d *gate.Deps) {
			cp = &countingParams{inner: d.Params, err: errNoFibre}
			d.Params = cp
		}),
	)
	c := gatefix.Template(t)
	e.StageDA(c, gatefix.Blob(t))
	b, _ := gatefix.Sign(t, "agent1", c)
	res, err := e.Authorize(b)
	require.NoError(t, err)
	assert.NotEmpty(t, res.Authorization)

	f := gatefix.Fresh(gatefix.FibreTemplate(t), 9)
	fb, _ := gatefix.Sign(t, "agent1", f)
	_, err = e.Authorize(fb)
	require.ErrorIs(t, err, gate.ErrDANotAllowed)

	assert.EqualValues(t, 0, cp.calls.Load())
}

func TestDA1AllowedStillReadsFibreRetention(t *testing.T) {
	e := gatefix.New(t, gatefix.WithConfig(onlyDA(1, 2)))
	e.Chain.FailLatest(errNoFibre)
	c := gatefix.Template(t)
	e.StageDA(c, gatefix.Blob(t))
	b, _ := gatefix.Sign(t, "agent1", c)
	_, err := e.Authorize(b)
	require.ErrorIs(t, err, gate.ErrChainUnavailable)
}

func TestPreflight(t *testing.T) {
	cases := []struct {
		name    string
		allowed []commitment.DA
		failErr error
		wantErr bool
	}{
		{"default set, fibre present", nil, nil, false},
		{"default set, fibre absent", nil, errNoFibre, true},
		{"da 1 allowed, fibre absent", []commitment.DA{1, 2}, errNoFibre, true},
		{"only 1, fibre absent", []commitment.DA{1}, errNoFibre, true},
		{"only 2, fibre absent", []commitment.DA{2}, errNoFibre, false},
		{"only 2, fibre present", []commitment.DA{2}, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := gatefix.New(t, gatefix.WithConfig(onlyDA(tc.allowed...)))
			e.Chain.FailLatest(tc.failErr)
			err := gate.Preflight(context.Background(), e.Cfg, e.Deps)
			if !tc.wantErr {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, gate.ErrInvalidConfig)
			assert.ErrorIs(t, err, tc.failErr)
		})
	}
}

func TestPreflightWithOnlyDA2DoesNotReadChain(t *testing.T) {
	cp := &countingParams{err: errNoFibre}
	e := gatefix.New(t, gatefix.WithConfig(onlyDA(2)))
	d := e.Deps
	d.Params = cp
	require.NoError(t, gate.Preflight(context.Background(), e.Cfg, d))
	assert.EqualValues(t, 0, cp.calls.Load())
}
