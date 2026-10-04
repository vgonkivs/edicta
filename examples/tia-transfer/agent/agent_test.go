package agent_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/examples/tia-transfer/agent"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankmsg"
	"github.com/vgonkivs/edicta/examples/tia-transfer/pricefeed"
	"github.com/vgonkivs/edicta/examples/tia-transfer/pricetrigger"
)

const (
	now      = int64(1791000060)
	chainID  = "mocha-4"
	hrp      = "celestia"
	sender   = "celestia1qqp0ztywuvn8agqn6znr4k35eda494vv7klwtc"
	upAddr   = "celestia1mzkhlmxtluk4gmet2kja0yv8kxc2n07ml6lld3"
	downAddr = "celestia1nxeu03k3d4gdza0u0vcqtjy7ckc8efghdg3j4c"
	p100     = uint64(100_00000000)
)

var bg = context.Background()

type fixedClock struct{ t time.Time }

func (c *fixedClock) Now() time.Time { return c.t }

type recorder struct {
	got []agent.Decision
	err error
}

func (r *recorder) Act(_ context.Context, d agent.Decision) error {
	r.got = append(r.got, d)
	return r.err
}

func cfg() agent.Config {
	return agent.Config{
		StrategyID: "tia-band-1",
		ChainID:    chainID,
		HRP:        hrp,
		Sender:     sender,
		Up:         pricetrigger.Branch{Name: "up", ToAddress: upAddr, Amount: 1000, Denom: "utia"},
		Down:       pricetrigger.Branch{Name: "down", ToAddress: downAddr, Amount: 2000, Denom: "utia"},
	}
}

func obs(price uint64, at int64) pricefeed.Observation {
	return pricefeed.Observation{
		Source: "fake:tia", AssetID: "celestia", Quote: "USD",
		Price: price, ObservedAt: uint64(at), FetchedAt: uint64(at),
	}
}

type rig struct {
	feed  *pricefeed.Fake
	act   *recorder
	clock *fixedClock
	a     *agent.Agent
	step  int64
}

func newRig(t *testing.T, mod func(*agent.Config)) *rig {
	t.Helper()
	c := cfg()
	if mod != nil {
		mod(&c)
	}
	r := &rig{feed: pricefeed.NewFake(), act: &recorder{}, clock: &fixedClock{t: time.Unix(now, 0)}}
	a, err := agent.New(c, r.feed, r.act, r.clock)
	require.NoError(t, err)
	r.a = a
	return r
}

// poll queues one observation, advances the clock and runs one step.
func (r *rig) poll(t *testing.T, price uint64) (bool, error) {
	t.Helper()
	r.step += 30
	r.clock.t = time.Unix(now+r.step, 0)
	r.feed.Push(obs(price, now+r.step))
	return r.a.Step(bg)
}

func TestTrigger(t *testing.T) {
	tests := []struct {
		name        string
		baseline    uint64
		price       uint64
		thresholdBP uint64
		fired       bool
		direction   uint64
		move        uint64
	}{
		{"unchanged", p100, p100, 100, false, 0, 0},
		{"one bp under the default", p100, 100_99000000, 100, false, 0, 99},
		{"floor keeps 99.5 bp under", p100, 100_99500000, 100, false, 0, 99},
		{"exactly the default up", p100, 101_00000000, 100, true, 1, 100},
		{"exactly the default down", p100, 99_00000000, 100, true, 2, 100},
		{"just under down", p100, 99_01000000, 100, false, 0, 99},
		{"far up", p100, 150_00000000, 100, true, 1, 5000},
		{"lowered threshold fires", p100, 100_50000000, 50, true, 1, 50},
		{"lowered threshold below", p100, 100_49000000, 50, false, 0, 49},
		{"minimum threshold", p100, 100_01000000, 1, true, 1, 1},
		{"maximum threshold up", p100, 200_00000000, 10000, true, 1, 10000},
		{"maximum threshold not reached", p100, 199_99999999, 10000, false, 0, 9999},
		{"zero baseline never fires", 0, p100, 100, false, 0, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir, move, fired := agent.Trigger(tc.baseline, tc.price, tc.thresholdBP)
			assert.Equal(t, tc.fired, fired)
			if tc.fired {
				assert.Equal(t, tc.direction, dir)
				assert.Equal(t, tc.move, move)
			}
		})
	}
}

func TestDefaultThresholdIs100bp(t *testing.T) {
	assert.Equal(t, uint64(100), uint64(agent.DefaultThresholdBP))
}

func TestFirstObservationIsTheBaselineAndActsNever(t *testing.T) {
	r := newRig(t, nil)
	acted, err := r.poll(t, p100)
	require.NoError(t, err)
	assert.False(t, acted)
	assert.Empty(t, r.act.got)
}

func TestNothingHappensWithoutATrigger(t *testing.T) {
	r := newRig(t, nil)
	_, err := r.poll(t, p100)
	require.NoError(t, err)
	for _, p := range []uint64{100_50000000, 99_50000000, 100_99000000, p100} {
		acted, err := r.poll(t, p)
		require.NoError(t, err)
		assert.False(t, acted)
	}
	assert.Empty(t, r.act.got)
}

func TestUpBranchBuildsTheDecision(t *testing.T) {
	r := newRig(t, func(c *agent.Config) { c.Reason = "price left the band" })
	_, err := r.poll(t, p100)
	require.NoError(t, err)
	acted, err := r.poll(t, 101_00000000)
	require.NoError(t, err)
	require.True(t, acted)
	require.Len(t, r.act.got, 1)
	d := r.act.got[0]

	p, err := pricetrigger.Decode(d.Context)
	require.NoError(t, err, "the context is a valid price-trigger body")
	assert.Equal(t, d.Payload, p)
	assert.Equal(t, "tia-band-1", p.StrategyID)
	assert.Equal(t, uint64(100), p.ThresholdBP)
	assert.Equal(t, uint64(1), p.Direction)
	assert.Equal(t, uint64(100), p.MoveBP)
	assert.Equal(t, p100, p.Baseline.Price)
	assert.Equal(t, pricetrigger.Branch{Name: "up", ToAddress: upAddr, Amount: 1000, Denom: "utia"}, p.Branch)
	assert.Equal(t, "price left the band", p.Reason)
	assert.Equal(t, "celestia", p.Asset.AssetID)
	assert.Equal(t, "USD", p.Asset.Quote)
	require.Len(t, p.Observations, 2)
	assert.Equal(t, uint64(101_00000000), p.Observations[0].Price, "newest first")
	assert.Equal(t, p100, p.Observations[1].Price)

	a, m, err := bankaction.CheckExecution(d.Action,
		bankaction.Domain{ChainID: chainID, Denom: "utia", HRP: hrp, Sender: sender}, bankaction.Limits{})
	require.NoError(t, err, "the action is what an executor accepts")
	assert.Equal(t, chainID, a.ChainID)
	assert.Equal(t, bankmsg.MsgSend{From: sender, To: upAddr, Denom: "utia", Amount: 1000}, m)

	assert.Empty(t, pricetrigger.Verify(p, m, uint64(r.clock.t.Unix())), "the agent's own replay checks pass")
}

func TestDownBranchGoesToItsDestinationAndAmount(t *testing.T) {
	r := newRig(t, nil)
	_, err := r.poll(t, p100)
	require.NoError(t, err)
	acted, err := r.poll(t, 98_00000000)
	require.NoError(t, err)
	require.True(t, acted)
	d := r.act.got[0]
	assert.Equal(t, uint64(2), d.Payload.Direction)
	assert.Equal(t, "down", d.Payload.Branch.Name)
	assert.Empty(t, d.Payload.Reason, "reason is optional")
	_, m, err := bankaction.CheckExecution(d.Action,
		bankaction.Domain{ChainID: chainID, Denom: "utia", HRP: hrp, Sender: sender}, bankaction.Limits{})
	require.NoError(t, err)
	assert.Equal(t, downAddr, m.To)
	assert.Equal(t, uint64(2000), m.Amount)
	assert.Empty(t, pricetrigger.Verify(d.Payload, m, uint64(r.clock.t.Unix())))
}

func TestActsOncePerTrigger(t *testing.T) {
	r := newRig(t, nil)
	_, err := r.poll(t, p100)
	require.NoError(t, err)
	acted, err := r.poll(t, 102_00000000)
	require.NoError(t, err)
	require.True(t, acted)

	for range 3 {
		acted, err = r.poll(t, 102_00000000)
		require.NoError(t, err)
		assert.False(t, acted, "the baseline moved to the trigger price")
	}
	require.Len(t, r.act.got, 1)

	acted, err = r.poll(t, 100_90000000)
	require.NoError(t, err)
	assert.True(t, acted, "a new band around the new baseline")
	require.Len(t, r.act.got, 2)
	assert.Equal(t, uint64(102_00000000), r.act.got[1].Payload.Baseline.Price)
	assert.Equal(t, uint64(2), r.act.got[1].Payload.Direction)
}

func TestConfiguredThreshold(t *testing.T) {
	r := newRig(t, func(c *agent.Config) { c.ThresholdBP = 25 })
	_, err := r.poll(t, p100)
	require.NoError(t, err)
	acted, err := r.poll(t, 100_24000000)
	require.NoError(t, err)
	assert.False(t, acted)
	acted, err = r.poll(t, 100_25000000)
	require.NoError(t, err)
	require.True(t, acted)
	assert.Equal(t, uint64(25), r.act.got[0].Payload.ThresholdBP)
}

func TestFeedErrorKeepsTheStateAndActsNever(t *testing.T) {
	r := newRig(t, nil)
	_, err := r.poll(t, p100)
	require.NoError(t, err)

	boom := errors.New("feed down")
	r.feed.PushErr(boom)
	acted, err := r.a.Step(bg)
	require.ErrorIs(t, err, boom)
	assert.False(t, acted)
	assert.Empty(t, r.act.got)

	acted, err = r.poll(t, 101_00000000)
	require.NoError(t, err)
	assert.True(t, acted, "the baseline survived the error")
}

func TestActorErrorIsReturned(t *testing.T) {
	r := newRig(t, nil)
	r.act.err = errors.New("gate refused")
	_, err := r.poll(t, p100)
	require.NoError(t, err)
	_, err = r.poll(t, 101_00000000)
	require.ErrorIs(t, err, r.act.err)
}

func TestObservationsAreCappedAtEightNewestFirst(t *testing.T) {
	r := newRig(t, nil)
	_, err := r.poll(t, p100)
	require.NoError(t, err)
	for i := range 10 {
		acted, err := r.poll(t, p100+uint64(i+1)*1_000000)
		require.NoError(t, err)
		require.False(t, acted)
	}
	acted, err := r.poll(t, 103_00000000)
	require.NoError(t, err)
	require.True(t, acted)
	obs := r.act.got[0].Payload.Observations
	require.Len(t, obs, 8)
	assert.Equal(t, uint64(103_00000000), obs[0].Price)
	for i := 1; i < len(obs); i++ {
		assert.Greater(t, obs[i-1].ObservedAt, obs[i].ObservedAt)
	}
}

func TestNewValidates(t *testing.T) {
	tests := []struct {
		name string
		mod  func(*agent.Config)
	}{
		{"threshold above 10000", func(c *agent.Config) { c.ThresholdBP = 10001 }},
		{"empty strategy id", func(c *agent.Config) { c.StrategyID = "" }},
		{"zero up amount", func(c *agent.Config) { c.Up.Amount = 0 }},
		{"zero down amount", func(c *agent.Config) { c.Down.Amount = 0 }},
		{"empty chain id", func(c *agent.Config) { c.ChainID = "" }},
		{"empty sender", func(c *agent.Config) { c.Sender = "" }},
		{"sending to itself", func(c *agent.Config) { c.Up.ToAddress = sender }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := cfg()
			tc.mod(&c)
			_, err := agent.New(c, pricefeed.NewFake(), &recorder{}, &fixedClock{t: time.Unix(now, 0)})
			require.ErrorIs(t, err, agent.ErrInvalidConfig)
		})
	}
	t.Run("nil dependencies", func(t *testing.T) {
		_, err := agent.New(cfg(), nil, &recorder{}, &fixedClock{})
		require.ErrorIs(t, err, agent.ErrInvalidConfig)
		_, err = agent.New(cfg(), pricefeed.NewFake(), nil, &fixedClock{})
		require.ErrorIs(t, err, agent.ErrInvalidConfig)
		_, err = agent.New(cfg(), pricefeed.NewFake(), &recorder{}, nil)
		require.ErrorIs(t, err, agent.ErrInvalidConfig)
	})
}
