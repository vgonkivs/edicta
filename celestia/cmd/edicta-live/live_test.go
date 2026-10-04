package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/edictaapi"
	"github.com/vgonkivs/edicta/examples/tia-transfer/agent"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankmsg"
	"github.com/vgonkivs/edicta/examples/tia-transfer/pricefeed"
	"github.com/vgonkivs/edicta/examples/tia-transfer/pricetrigger"
	"github.com/vgonkivs/edicta/examples/tia-transfer/transfer"
)

func goodHealth() edictaapi.HealthInfo {
	return edictaapi.HealthInfo{
		Status: 1, ChainID: "test-1", GateID: "gate-1", GatePubKey: bytes.Repeat([]byte{9}, 32),
		RecorderSigner: bytes.Repeat([]byte{5}, 20), Namespace: bytes.Repeat([]byte{3}, 29),
		AllowedDA: []uint64{uint64(commitment.DACelestiaBlob)},
	}
}

func TestCheckHealth(t *testing.T) {
	good := goodHealth()
	p, err := checkHealth(Config{}, good, "test-1")
	require.NoError(t, err)
	assert.False(t, p.keyPinned, "an unpinned key is reported as such")

	p, err = checkHealth(Config{GatePubKey: hex.EncodeToString(good.GatePubKey), GateID: "gate-1",
		Namespace: hex.EncodeToString(good.Namespace)}, good, "test-1")
	require.NoError(t, err)
	assert.True(t, p.keyPinned)

	mut := map[string]func(*edictaapi.HealthInfo){
		"degraded":         func(h *edictaapi.HealthInfo) { h.Status = 2 },
		"other chain":      func(h *edictaapi.HealthInfo) { h.ChainID = "other-1" },
		"no recorder":      func(h *edictaapi.HealthInfo) { h.RecorderSigner, h.Namespace = nil, nil },
		"da 2 not allowed": func(h *edictaapi.HealthInfo) { h.AllowedDA = []uint64{1} },
	}
	for name, f := range mut {
		h := goodHealth()
		f(&h)
		_, err := checkHealth(Config{}, h, "test-1")
		assert.Error(t, err, name)
	}
	_, err = checkHealth(Config{GatePubKey: hex.EncodeToString(bytes.Repeat([]byte{1}, 32))}, good, "test-1")
	assert.Error(t, err, "a different pinned key refuses")
	_, err = checkHealth(Config{GateID: "gate-2"}, good, "test-1")
	assert.Error(t, err, "a different pinned gate id refuses")
	_, err = checkHealth(Config{Namespace: hex.EncodeToString(bytes.Repeat([]byte{4}, 29))}, good, "test-1")
	assert.Error(t, err, "a different pinned namespace refuses")
}

func TestCheckAccountsRefusesRecorderKeyAsExecutor(t *testing.T) {
	raw, err := bankmsg.DecodeAddress(hrp, addr)
	require.NoError(t, err)
	dom := transfer.Domain{ChainID: "test-1", Denom: "utia", HRP: hrp, Sender: addr}
	require.NoError(t, checkAccounts(dom, bytes.Repeat([]byte{5}, 20)))
	err = checkAccounts(dom, raw)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "two different chain accounts")
	assert.Error(t, checkAccounts(transfer.Domain{HRP: hrp, Sender: "bad"}, raw))
}

type fakeActor struct {
	calls int
	err   error
	last  agent.Decision
}

func (f *fakeActor) Act(_ context.Context, d agent.Decision) error {
	f.calls++
	f.last = d
	if f.err != nil {
		return &decisionError{err: f.err}
	}
	return nil
}

func newTestAgent(t *testing.T, feed pricefeed.Feed, act agent.Actor, bp uint64) *agent.Agent {
	t.Helper()
	third := "celestia1nxeu03k3d4gdza0u0vcqtjy7ckc8efghdg3j4c"
	ag, err := agent.New(agent.Config{
		StrategyID: "s", ChainID: "test-1", HRP: hrp, Sender: addr,
		Up:          pricetrigger.Branch{Name: "up", ToAddress: dst, Amount: 1, Denom: "utia"},
		Down:        pricetrigger.Branch{Name: "down", ToAddress: third, Amount: 2, Denom: "utia"},
		ThresholdBP: bp,
	}, feed, act, realClock{})
	require.NoError(t, err)
	return ag
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func push(f *pricefeed.Fake, price uint64) {
	now := uint64(time.Now().Unix())
	f.Push(pricefeed.Observation{Source: "fake", AssetID: "a", Quote: "USD", Price: price, ObservedAt: now, FetchedAt: now})
}

func quiet(string, ...any) {}

func TestLoopStopsAfterMaxDecisions(t *testing.T) {
	f := pricefeed.NewFake()
	push(f, 100_00000000)
	push(f, 100_00000000)
	push(f, 102_00000000) // +200 bp
	act := &fakeActor{}
	ag := newTestAgent(t, f, act, 100)
	cfg := Config{MaxDecisions: 1, PollInterval: time.Millisecond, Timeout: time.Minute, ThresholdBP: 100}
	require.NoError(t, loop(t.Context(), cfg, ag, quiet))
	assert.Equal(t, 1, act.calls)
	assert.EqualValues(t, 1, act.last.Payload.Direction)
	assert.EqualValues(t, 200, act.last.Payload.MoveBP)
	assert.Equal(t, 3, f.Calls(), "the loop stops polling after the decision")
}

func TestLoopThresholdBoundary(t *testing.T) {
	f := pricefeed.NewFake()
	push(f, 100_00000000)
	push(f, 100_99000000) // 99 bp: no
	push(f, 101_00000000) // 100 bp: yes
	act := &fakeActor{}
	cfg := Config{MaxDecisions: 1, PollInterval: time.Millisecond, Timeout: time.Minute, ThresholdBP: 100}
	require.NoError(t, loop(t.Context(), cfg, newTestAgent(t, f, act, 100), quiet))
	assert.Equal(t, 1, act.calls)
	assert.EqualValues(t, 100, act.last.Payload.MoveBP)
}

func TestLoopDecisionFailureEndsTheRun(t *testing.T) {
	f := pricefeed.NewFake()
	push(f, 100_00000000)
	push(f, 90_00000000)
	boom := errors.New("gate refused")
	act := &fakeActor{err: boom}
	cfg := Config{MaxDecisions: 3, PollInterval: time.Millisecond, Timeout: time.Minute, ThresholdBP: 100}
	err := loop(t.Context(), cfg, newTestAgent(t, f, act, 100), quiet)
	require.ErrorIs(t, err, boom)
	assert.Equal(t, 1, act.calls, "a failed decision is never retried")
}

func TestLoopTimeoutWithoutMove(t *testing.T) {
	f := pricefeed.NewFake()
	for i := 0; i < 2000; i++ {
		push(f, 100_00000000)
	}
	act := &fakeActor{}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	cfg := Config{MaxDecisions: 1, PollInterval: 5 * time.Millisecond, Timeout: 100 * time.Millisecond, ThresholdBP: 100}
	err := loop(ctx, cfg, newTestAgent(t, f, act, 100), quiet)
	require.ErrorIs(t, err, ErrNoDecision)
	assert.Zero(t, act.calls)
}

func TestLoopFeedFailuresAreBounded(t *testing.T) {
	f := pricefeed.NewFake() // empty script: every read fails
	cfg := Config{MaxDecisions: 1, PollInterval: time.Millisecond, Timeout: time.Minute, ThresholdBP: 100}
	err := loop(t.Context(), cfg, newTestAgent(t, f, &fakeActor{}, 100), quiet)
	require.ErrorIs(t, err, pricefeed.ErrExhausted)
}

func TestFmtPrice(t *testing.T) {
	assert.Equal(t, "4.12345678", fmtPrice(412345678))
	assert.Equal(t, "0.00000001", fmtPrice(1))
	assert.Equal(t, "100.00000000", fmtPrice(100_00000000))
}

// 007l2: edictad reports its single da in health (AllowedDA has one entry);
// edicta-live refuses when it differs from its own configured Config.DA
// ("blob" | "fibre", assumed field).
func TestCheckHealthDA(t *testing.T) {
	blob, fibre := []uint64{uint64(commitment.DACelestiaBlob)}, []uint64{uint64(commitment.DAFibre)}
	cases := []struct {
		name    string
		cfgDA   string
		healthD []uint64
		ok      bool
	}{
		{"blob matches blob", "blob", blob, true},
		{"fibre matches fibre", "fibre", fibre, true},
		{"blob client, fibre server", "blob", fibre, false},
		{"fibre client, blob server", "fibre", blob, false},
		{"server lists both", "blob", []uint64{1, 2}, false},
		{"server lists none", "blob", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := goodHealth()
			h.AllowedDA = tc.healthD
			_, err := checkHealth(Config{DA: tc.cfgDA}, h, "test-1")
			if tc.ok {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
