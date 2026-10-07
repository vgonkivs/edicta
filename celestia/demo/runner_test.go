package demo

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/edictad"
	"github.com/vgonkivs/edicta/celestia/railtx"
	"github.com/vgonkivs/edicta/examples/tia-transfer/pricefeed"
	"github.com/vgonkivs/edicta/examples/tia-transfer/transfer"
)

type fakeGate struct {
	deps edictad.Deps
	err  error
}

func (g *fakeGate) Start(_ context.Context, _ edictad.Config, d edictad.Deps) (GateHandle, error) {
	g.deps = d
	return nil, g.err
}

type testEnv struct {
	cfg      Config
	deps     Deps
	console  *fakeConsole
	chain    *fakeChain
	funding  *fakeFunding
	gate     *fakeGate
	sub      *fakeSubmitter
	root     *fakeTrustRoot
	screen   *bytes.Buffer
	funderFC railtx.FunderConfig
	verified int
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	e := &testEnv{
		console: &fakeConsole{},
		chain:   &fakeChain{balances: map[string]uint64{}},
		funding: &fakeFunding{},
		gate:    &fakeGate{err: errors.New("test: stop at the gate")},
		sub:     &fakeSubmitter{},
		root:    &fakeTrustRoot{hash: bytes.Repeat([]byte{7}, 32)},
		screen:  &bytes.Buffer{},
	}
	e.cfg = Config{Home: t.TempDir()}.WithDefaults()
	e.deps = Deps{
		Chain: e.chain, Console: e.console, Screen: NewScreen(e.screen, false, false), Gate: e.gate, TrustRoot: e.root,
		NewFunder: func(_ context.Context, fc railtx.FunderConfig) (Funding, Abandoner, error) {
			e.funderFC = fc
			addr, err := fc.Key.Address("celestia")
			if err != nil {
				return nil, nil, err
			}
			e.funding.addr = addr
			e.funding.consent = fc.Consent
			return e.funding, &fakeAbandoner{}, nil
		},
		NewGateDeps: func(context.Context, edictad.Config) (edictad.Deps, func(), error) {
			return edictad.Deps{Submitter: e.sub}, func() {}, nil
		},
		NewRail: func(context.Context, railtx.KeySource) (transfer.Rail, error) {
			return nil, errors.New("test: no rail")
		},
		NewFeed: func() (pricefeed.Feed, error) { return nil, errors.New("test: no feed") },
		Verify: func(context.Context, []string, io.Writer) int {
			e.verified++
			return 4
		},
		Sleep: noSleep,
		Now:   steppingClock(),
	}
	return e
}

func (e *testEnv) runner(t *testing.T) *Runner {
	t.Helper()
	r, err := New(e.cfg, e.deps)
	require.NoError(t, err)
	return r
}

func TestNothingIsBroadcastBeforeTheStartEnter(t *testing.T) {
	e := newTestEnv(t)
	r := e.runner(t)
	out, err := r.Run(context.Background())
	require.Error(t, err, "the fake gate refuses to start")
	assert.Equal(t, ExitInconclusive, out.Code)

	assert.Empty(t, e.console.prompts, "steps up to the gate need no answer")
	assert.Empty(t, e.funding.sends)
	require.ErrorIs(t, r.consent.Check(), railtx.ErrNotStarted)
	require.NotNil(t, e.gate.deps.Submitter, "the gate got a submitter")
	_, err = e.gate.deps.Submitter.Submit(context.Background(), nil, nil)
	require.ErrorIs(t, err, railtx.ErrNotStarted, "the gate's submitter is behind the Consent")
	assert.Zero(t, e.sub.calls)
	assert.True(t, e.funding.closed)
}

func TestFibreDependenciesAreRefused(t *testing.T) {
	e := newTestEnv(t)
	e.deps.NewGateDeps = func(context.Context, edictad.Config) (edictad.Deps, func(), error) {
		return edictad.Deps{Fibre: &edictad.FibreDeps{}}, func() {}, nil
	}
	out, err := e.runner(t).Run(context.Background())
	require.ErrorIs(t, err, ErrFibreRefused)
	assert.Equal(t, ExitUsage, out.Code)
}

// startState puts a Runner where fundAndStart expects it, without a gate.
func (e *testEnv) startState(t *testing.T) *Runner {
	t.Helper()
	r := e.runner(t)
	r.funder = chainKey{addr: testFunder}
	r.recorderKey = chainKey{addr: testRecorder}
	r.executorKey = chainKey{addr: "celestia1executor"}
	r.minGas = big.NewRat(4, 1000)
	e.funding.addr = testFunder
	e.funding.consent = r.consent
	e.funding.log = nil
	r.funding = e.funding
	r.loop = &fundingLoop{
		f: e.funding, ab: &fakeAbandoner{}, chain: e.chain, console: e.console, screen: r.deps.Screen, denom: "utia",
		explore: r.explore, poll: 1, timeout: 1 << 40, sleep: noSleep, now: r.deps.now,
	}
	return r
}

func TestQuitAtTheStartPromptSendsNothing(t *testing.T) {
	e := newTestEnv(t)
	e.chain.balances[testFunder] = 10_000_000
	e.console.enters = []Answer{AnswerQuit}
	r := e.startState(t)
	err := r.fundAndStart(context.Background())
	require.ErrorIs(t, err, ErrOperatorQuit)
	assert.Empty(t, e.funding.sends)
	require.ErrorIs(t, r.consent.Check(), railtx.ErrNotStarted)
	require.Len(t, e.console.prompts, 1)
	assert.Contains(t, e.console.prompts[0], "Enter")
}

func TestOnlyTheStartEnterArmsAndFundingFollowsIt(t *testing.T) {
	e := newTestEnv(t)
	e.chain.balances[testFunder] = 10_000_000
	e.console.enters = []Answer{AnswerContinue}
	r := e.startState(t)
	e.funding.send = []func() ([32]byte, uint64, error){
		func() ([32]byte, uint64, error) {
			assert.NoError(t, r.consent.Check(), "the Consent is armed when the first send is made")
			e.chain.balances[testRecorder] = 1_000_000
			return [32]byte{1}, 1100, nil
		},
		func() ([32]byte, uint64, error) {
			e.chain.balances[r.executorKey.addr] = 1_000_000
			return [32]byte{2}, 1100, nil
		},
	}
	require.NoError(t, r.fundAndStart(context.Background()))
	assert.Len(t, e.funding.sends, 2)
	assert.Len(t, e.console.prompts, 1, "one Enter, no other confirmation")
}

func TestYesOnlyConfirmsTheFundingCap(t *testing.T) {
	// --yes without --max-total-funding is refused.
	require.Error(t, Config{Home: "h", YesFundingCap: true}.WithDefaults().ValidateBasic())

	for _, yes := range []bool{false, true} {
		e := newTestEnv(t)
		e.cfg.MaxTotalFunding, e.cfg.YesFundingCap = 5_000_000, yes
		e.console.enters = []Answer{AnswerQuit}
		r := e.runner(t)
		_, err := r.Run(context.Background())
		require.Error(t, err)
		assert.EqualValues(t, 5_000_000, e.funderFC.MaxTotalAmount, "the raised cap reaches the Funder")
		assert.EqualValues(t, 200_000, e.funderFC.MaxAmount)
		assert.EqualValues(t, 20_000, e.funderFC.MaxFee)
		assert.Equal(t, filepath.Join(e.cfg.Home, "chain", "funding"), filepath.Dir(e.funderFC.PendingPath))
		assert.Contains(t, filepath.Base(e.funderFC.PendingPath), "celestia1")
		if yes {
			assert.Empty(t, e.console.prompts, "--yes skips the cap prompt and nothing else is asked yet")
		} else {
			assert.Len(t, e.console.prompts, 1)
			assert.ErrorIs(t, err, ErrOperatorQuit, "a declined cap confirmation stops the run")
		}
		assert.Empty(t, e.funding.sends)
		require.ErrorIs(t, r.consent.Check(), railtx.ErrNotStarted, "--yes never arms the Consent")
	}
}

// steppingClock moves one second per reading, so loops that wait on time end
// without sleeping.
func steppingClock() func() time.Time {
	t := time.Now()
	return func() time.Time {
		t = t.Add(time.Second)
		return t
	}
}

func TestQueuedEnterNeverArms(t *testing.T) {
	e := newTestEnv(t)
	e.chain.balances[testFunder] = 10_000_000
	e.console.stale = []Answer{AnswerContinue, AnswerContinue}
	e.console.enters = []Answer{AnswerQuit}
	r := e.startState(t)
	err := r.fundAndStart(context.Background())
	require.ErrorIs(t, err, ErrOperatorQuit, "the answer is the one given after the prompt")
	assert.Equal(t, 1, e.console.flushed)
	assert.Empty(t, e.console.stale)
	assert.Empty(t, e.funding.sends)
	require.ErrorIs(t, r.consent.Check(), railtx.ErrNotStarted)
}
