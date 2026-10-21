// SPDX-License-Identifier: Apache-2.0

package signer_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/edenexec"
	"github.com/vgonkivs/edicta/signer"
	"github.com/vgonkivs/edicta/signer/eden"
	"github.com/vgonkivs/edicta/signer/signertest"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// fakeGate answers record requests like the gate: it checks the executor's
// signature and returns a receipt signed with the gate key, once per
// decision.
type fakeGate struct {
	mu       sync.Mutex
	keys     signertest.Keys
	receipts map[commitment.Hash][]byte
	calls    int
	err      error
}

func (g *fakeGate) Record(_ context.Context, envelope []byte, railRef string, pub, sig []byte) ([]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls++
	if g.err != nil {
		return nil, g.err
	}
	env, err := commitment.DecodeSigned(envelope)
	if err != nil {
		return nil, err
	}
	h, err := commitment.HashOf(&env.Commitment)
	if err != nil {
		return nil, err
	}
	if err := commitment.VerifyRecordRequest(h, signertest.GateID, railRef, pub, sig); err != nil {
		return nil, err
	}
	if r, ok := g.receipts[h]; ok {
		return r, nil
	}
	rc := &commitment.Receipt{
		Version: 1, CommitmentHash: h[:], GateID: signertest.GateID, GatePubKey: g.keys.GatePub(),
		RailRef: railRef, RecordedAt: 1_800_000_000, ExecutorPubKey: pub, ExecutorSignature: sig,
	}
	canon, err := commitment.EncodeReceipt(rc)
	if err != nil {
		return nil, err
	}
	gs := ed25519.Sign(g.keys.Gate, commitment.ReceiptSigningMessage(commitment.HashReceipt(canon)))
	out, err := commitment.EncodeSignedReceipt(&commitment.SignedReceipt{Receipt: *rc, Signature: gs})
	if err != nil {
		return nil, err
	}
	if g.receipts == nil {
		g.receipts = map[commitment.Hash][]byte{}
	}
	g.receipts[h] = out
	return out, nil
}

func (g *fakeGate) Calls() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.calls
}

// env is one signer with its fakes.
type env struct {
	t     testing.TB
	keys  signertest.Keys
	clk   *clock
	chain *signertest.Chain
	gate  *fakeGate
	store *signer.BoltStore
	path  string
	cfg   signer.Config
	h     *eden.Handler
	svc   *signer.Service
	opts  envOpts
	// second is the second operator's source in payment mode.
	second *signertest.Chain
}

// envOpts change how the service is built.
type envOpts struct {
	// wrap replaces the handler the service sees.
	wrap func(signer.Handler) signer.Handler
	// payment turns the Payment-Signature on: two explicitly labelled
	// operators at L1, the quote's facilitator allowed, R required.
	payment bool
}

// labelled gives a fake chain an operator label.
type labelled struct {
	*signertest.Chain
	op string
}

func (l labelled) Operator() string { return l.op }

func defaultConfig(k signertest.Keys) signer.Config {
	cfg := signer.Config{
		GateID: signertest.GateID, GatePubKey: k.GatePub(), AgentKeys: [][]byte{k.AgentPub()},
		Caps: signer.Caps{
			MaxValuePerAction: new(big.Int).Mul(big.NewInt(1e18), big.NewInt(1)),
			MaxValuePerHour:   new(big.Int).Mul(big.NewInt(1e18), big.NewInt(10)),
			MaxFeePerHour:     big.NewInt(1e15),
		},
		RetryInterval: 20 * time.Millisecond,
	}
	cfg.ApplyDefaults()
	return cfg
}

func newEnv(t testing.TB, mut ...func(*signer.Config)) *env {
	t.Helper()
	return newEnvOpts(t, envOpts{}, mut...)
}

func newEnvOpts(t testing.TB, o envOpts, mut ...func(*signer.Config)) *env {
	t.Helper()
	k := signertest.NewKeys(t.Name())
	e := &env{
		t: t, keys: k, clk: &clock{t: time.Now().Truncate(time.Second)},
		chain: signertest.NewChain(714), gate: &fakeGate{keys: k},
		path: filepath.Join(t.TempDir(), "signer.db"), opts: o,
	}
	e.chain.Nonce = 7
	if o.payment {
		e.second = signertest.NewChain(714)
		e.second.Host = "second-operator"
	}
	e.cfg = defaultConfig(k)
	for _, m := range mut {
		m(&e.cfg)
	}
	e.open()
	return e
}

// open builds the service on the store file, as a fresh process would.
func (e *env) open() {
	t := e.t
	t.Helper()
	st, err := signer.OpenBoltStore(e.path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	e.store = st

	pins := eden.ChainPins{
		ChainID: 714, Payer: e.keys.PayerAddress(), Facilitators: [][20]byte{signertest.Facilitator},
		MaxRefundDelay: 7200, MaxFeePerGas: big.NewInt(10_000), MaxGas: 300_000, MaxFeePerAction: big.NewInt(3e9),
		Broadcast: eden.BroadcastDirect,
	}
	hcfg := eden.Config{Chains: []eden.ChainPins{pins}, ResendEvery: 20 * time.Millisecond, PaymentSignatureField: eden.FieldOff}
	ccfg := edenexec.Config{MinLevel: edenexec.LevelNodeAttested, PollInterval: 5 * time.Millisecond}
	srcs := []edenexec.Source{e.chain}
	if e.opts.payment {
		hcfg.PaymentSignatureField = eden.FieldPaymentID
		hcfg.Chains[0].Facilitators = append(hcfg.Chains[0].Facilitators, signertest.QuoteFacilitator())
		ccfg.MinLevel = edenexec.LevelMultiSource
		srcs = []edenexec.Source{labelled{e.chain, "own"}, labelled{e.second, "second"}}
	}
	hcfg.ApplyDefaults()
	ccfg.ApplyDefaults()
	checker, err := edenexec.NewChecker(ccfg, srcs, nil)
	require.NoError(t, err)
	h, err := eden.New(hcfg, eden.Deps{
		Chains: map[uint64]eden.Chain{714: e.chain}, Settlers: map[uint64]eden.Settler{714: checker}, Log: quiet,
	})
	require.NoError(t, err)
	wallet, err := signer.NewKeyWallet(e.keys.Payer)
	require.NoError(t, err)
	exec, err := signer.NewEd25519Executor(e.keys.Executor)
	require.NoError(t, err)
	var hd signer.Handler = h
	if e.opts.wrap != nil {
		hd = e.opts.wrap(h)
	}
	svc, err := signer.New(e.cfg, signer.Deps{
		Store: st, Wallets: map[uint64]signer.WalletBackend{714: wallet}, Handlers: []signer.Handler{hd},
		Executor: exec, Recorder: signer.GateRecorder{C: e.gate}, Clock: e.clk, Log: quiet,
	})
	require.NoError(t, err)
	require.NoError(t, svc.Start(context.Background()))
	e.h, e.svc = h, svc
}

func mustWallet(t testing.TB, k signertest.Keys) *signer.KeyWallet {
	t.Helper()
	w, err := signer.NewKeyWallet(k.Payer)
	require.NoError(t, err)
	return w
}

// reopen closes the store and builds a new service on it.
func (e *env) reopen() {
	require.NoError(e.t, e.store.Close())
	e.open()
}

func (e *env) decision(o signertest.DecisionOpts, mut ...func(*signertest.Deposit)) signertest.Decision {
	t := e.t
	t.Helper()
	d := signertest.NewDeposit(e.clk.Now())
	for _, m := range mut {
		m(&d)
	}
	action, err := d.Action()
	require.NoError(t, err)
	dec, err := signertest.NewDecision(e.keys, action, e.clk.Now(), o)
	require.NoError(t, err)
	return dec
}

func request(d signertest.Decision) signer.Request {
	return signer.Request{Envelope: d.Envelope, Action: d.Action, Salt: d.Salt, Authorization: d.Authorization}
}

func (e *env) entry(h commitment.Hash) signer.Entry {
	e.t.Helper()
	got, ok, err := e.store.Get(context.Background(), h)
	require.NoError(e.t, err)
	require.True(e.t, ok)
	return got
}

// waitState runs the worker until the decision reaches want.
func (e *env) waitState(h commitment.Hash, want signer.State) signer.Entry {
	e.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.svc.Run(ctx) }()
	defer func() {
		cancel()
		<-done
	}()
	var got signer.Entry
	require.Eventually(e.t, func() bool {
		got = e.entry(h)
		return got.State == want
	}, 10*time.Second, 10*time.Millisecond)
	return got
}

var errUnavailable = errors.New("gate down")

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))
