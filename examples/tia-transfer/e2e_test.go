package tiatransfer_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/examples/tia-transfer/agent"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankmsg"
	"github.com/vgonkivs/edicta/examples/tia-transfer/pricefeed"
	"github.com/vgonkivs/edicta/examples/tia-transfer/pricetrigger"
	"github.com/vgonkivs/edicta/examples/tia-transfer/transfer"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/gatetest"
	"github.com/vgonkivs/edicta/sdk"
	"github.com/vgonkivs/edicta/sdk/payload"
	"github.com/vgonkivs/edicta/sdk/sdktest"
	"github.com/vgonkivs/edicta/test/gatefix"
	"github.com/vgonkivs/edicta/test/sdkfix"
)

const (
	chainID = "mocha-4"
	hrp     = "celestia"
	denom   = "utia"
	sender  = "celestia1qqp0ztywuvn8agqn6znr4k35eda494vv7klwtc"
	upAddr  = "celestia1mzkhlmxtluk4gmet2kja0yv8kxc2n07ml6lld3"
	downDst = "celestia1nxeu03k3d4gdza0u0vcqtjy7ckc8efghdg3j4c"
	headH   = uint64(5000)
	blockS  = uint64(6)
)

var bg = context.Background()

// stepClock is the gate's clock; waiting moves it, so nothing sleeps.
type stepClock struct{ *gatetest.Clock }

func (c stepClock) After(d time.Duration) <-chan time.Time {
	c.Advance(d)
	ch := make(chan time.Time, 1)
	ch <- c.Now()
	return ch
}

// chain is a fake chain: height follows the clock, the first broadcast tx is
// included one block later.
type chain struct {
	mu         sync.Mutex
	clock      stepClock
	t0         uint64
	signed     [][]byte
	bodies     [][]byte
	broadcasts [][]byte
}

func (c *chain) height() uint64 { return headH + (uint64(c.clock.Now().Unix())-c.t0)/blockS }

func (c *chain) Domain(context.Context) (transfer.Domain, error) {
	return transfer.Domain{ChainID: chainID, Denom: denom, HRP: hrp, Sender: sender}, nil
}

func (c *chain) Head(context.Context) (uint64, uint64, time.Duration, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.height(), uint64(c.clock.Now().Unix()), time.Duration(blockS) * time.Second, nil
}

func (c *chain) Height(context.Context) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.height(), nil
}

func (c *chain) Sign(_ context.Context, body []byte, _ string, _ uint64) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	auth := []byte{0x0a, 0x02, 0x08, byte(len(c.signed) + 1)}
	sig := sha256.Sum256(body)
	raw := append([]byte{0x0a}, binary.AppendUvarint(nil, uint64(len(body)))...)
	raw = append(raw, body...)
	raw = append(raw, 0x12, byte(len(auth)))
	raw = append(raw, auth...)
	raw = append(raw, 0x1a, 0x20)
	raw = append(raw, sig[:]...)
	c.signed = append(c.signed, raw)
	c.bodies = append(c.bodies, append([]byte(nil), body...))
	return raw, nil
}

func (c *chain) Broadcast(_ context.Context, raw []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.broadcasts = append(c.broadcasts, append([]byte(nil), raw...))
	return nil
}

func (c *chain) Status(_ context.Context, h [32]byte) (transfer.TxStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, raw := range c.signed {
		if sha256.Sum256(raw) == h && len(c.broadcasts) > 0 {
			if c.height() > headH {
				return transfer.TxStatus{State: transfer.TxCommitted, Height: headH + 1, NodeHeight: c.height()}, nil
			}
			return transfer.TxStatus{State: transfer.TxPending, NodeHeight: c.height()}, nil
		}
	}
	return transfer.TxStatus{State: transfer.TxUnknown, NodeHeight: c.height()}, nil
}

func (c *chain) counts() (signs, sends int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.signed), len(c.broadcasts)
}

type world struct {
	t       *testing.T
	env     *gatefix.Env
	vec     *sdkfix.Vectors
	builder *sdk.Builder
	verify  *sdktest.InclusionVerifier
	chain   *chain
	exec    *transfer.Executor
	feed    *pricefeed.Fake
	agent   *agent.Agent

	res     *sdk.Result
	gres    gate.Result
	exRes   transfer.Result
	receipt []byte
	acts    int
}

func newWorld(t *testing.T, mod func(*agent.Config)) *world {
	t.Helper()
	env := gatefix.New(t, gatefix.WithScope(commitment.GateScope{
		GateID: gatefix.GateID, ActionTypes: []string{bankaction.ActionType},
	}))
	vec := sdkfix.Load(t)
	pub := sdktest.NewPublisher(commitment.DACelestiaBlob)
	pub.SetBlockTime(gatefix.Now - 1000)
	pub.SetHeight(4_200_000)
	verify := sdktest.NewInclusionVerifier(pub)
	verify.SetIndependent(false) // the same operator's own check
	signer, err := sdk.NewEd25519Signer(gatefix.Key(t, "agent1"))
	require.NoError(t, err)
	cfg := sdk.DefaultConfig()
	cfg.SubmitterTrust = sdk.SubmitterSameOperator
	cfg.AgentID = "dca-agent-1"
	cfg.Scope = commitment.Scope{GateID: gatefix.GateID}
	cfg.Recipients = vec.Recipients(t, "gate-paper-1", "auditor-1")
	b, err := sdk.New(cfg, sdk.Deps{Publisher: pub, Signer: signer, Clock: env.Clock, Chain: env.Chain, Inclusion: verify})
	require.NoError(t, err)

	clock := stepClock{env.Clock}
	ch := &chain{clock: clock, t0: uint64(env.Clock.Now().Unix())}
	ex, err := transfer.NewExecutor(transfer.Config{
		GatePubKey: ed25519.PublicKey(gatefix.Pub(t, "gate1")),
		GateID:     gatefix.GateID,
		SkewS:      30,
		SignKey:    gatefix.ExecutorKey(t, "executor1"),
	}, transfer.Domain{ChainID: chainID, Denom: denom, HRP: hrp, Sender: sender}, ch, transfer.NewMemStore(), clock)
	require.NoError(t, err)

	w := &world{t: t, env: env, vec: vec, builder: b, verify: verify, chain: ch, exec: ex, feed: pricefeed.NewFake()}
	ac := agent.Config{
		StrategyID: "tia-band-1", ChainID: chainID, HRP: hrp, Sender: sender,
		Up:     pricetrigger.Branch{Name: "up", ToAddress: upAddr, Amount: 1000, Denom: denom},
		Down:   pricetrigger.Branch{Name: "down", ToAddress: downDst, Amount: 2000, Denom: denom},
		Reason: "tia moved past the band",
	}
	if mod != nil {
		mod(&ac)
	}
	w.agent, err = agent.New(ac, w.feed, w, clock)
	require.NoError(t, err)
	return w
}

// Act is the demo's act step: commit, authorize, execute, record.
func (w *world) Act(ctx context.Context, d agent.Decision) error {
	w.acts++
	p := sdkfix.ClonePayload(w.vec.Case0(w.t).Payload)
	p.Context = payload.Data{MediaType: pricetrigger.MediaType, Bytes: d.Context}
	p.Action = payload.Action{Type: bankaction.ActionType, Data: d.Action}
	res, err := w.builder.Commit(ctx, p)
	if err != nil {
		return err
	}
	w.env.StageChain(&res.Commitment, res.Published.BlockTime, res.Published.BlockTime)
	w.env.DA.Put(res.Published.Ref, res.Blob)
	w.res = res

	if w.gres, err = w.env.Gate.Authorize(ctx, res.Envelope, res.Action); err != nil {
		return err
	}
	if w.exRes, err = w.exec.Execute(ctx, w.gres.Authorization, res.Action); err != nil {
		return err
	}
	ref := hex.EncodeToString(w.exRes.TxHash[:])
	pub, sig, err := w.exec.RecordRequest(res.CommitmentHash, ref)
	if err != nil {
		return err
	}
	w.receipt, err = w.env.Gate.Record(ctx, res.Envelope, ref, pub, sig)
	return err
}

func (w *world) poll(price uint64) bool {
	w.t.Helper()
	now := uint64(w.env.Clock.Now().Unix())
	w.feed.Push(pricefeed.Observation{
		Source: "fake:tia", AssetID: "celestia", Quote: "USD",
		Price: price, ObservedAt: now - 5, FetchedAt: now - 4,
	})
	acted, err := w.agent.Step(bg)
	require.NoError(w.t, err)
	return acted
}

func TestEndToEndOffline(t *testing.T) {
	w := newWorld(t, nil)
	require.False(t, w.poll(100_00000000), "the first observation is the baseline")
	require.Zero(t, w.acts)
	require.True(t, w.poll(101_00000000))
	res := w.res
	require.NotNil(t, res)
	assert.Equal(t, 1, w.verify.Calls(), "the inclusion check ran before signing")

	signs, sends := w.chain.counts()
	assert.Equal(t, 1, signs)
	assert.Equal(t, 1, sends, "a single broadcast")

	a, err := bankaction.Decode(res.Action)
	require.NoError(t, err)
	th, err := bankaction.CheckBody(a, res.CommitmentHash, w.chain.bodies[0])
	require.NoError(t, err)
	assert.Greater(t, th, headH)
	assert.Contains(t, string(w.chain.bodies[0]), hex.EncodeToString(res.CommitmentHash[:]), "memo = commitment_hash")

	_, execSig, err := w.exec.RecordRequest(res.CommitmentHash, hex.EncodeToString(w.exRes.TxHash[:]))
	require.NoError(t, err)
	require.NotEmpty(t, execSig)
	ref := hex.EncodeToString(w.exRes.TxHash[:])
	assert.Equal(t, hex.EncodeToString(func() []byte { h := sha256.Sum256(w.chain.signed[0]); return h[:] }()), ref, "rail_ref = hash of TxRaw")
	gatefix.CheckReceipt(t, w.receipt, res.CommitmentHash, ref, gatefix.GateID, gatefix.Pub(t, "gate1"), 0)

	t.Run("the published decision replays against the executed transfer", func(t *testing.T) {
		opened, err := sdk.OpenPayload(res.Envelope, res.Blob, w.vec.Key(t, "auditor-1").OpenKey(true))
		require.NoError(t, err)
		assert.Equal(t, pricetrigger.MediaType, opened.Payload.Context.MediaType)
		pt, err := pricetrigger.Decode(opened.Payload.Context.Bytes)
		require.NoError(t, err)
		assert.Equal(t, "tia moved past the band", pt.Reason)
		_, m, err := bankaction.CheckExecution(opened.Payload.Action.Data,
			bankaction.Domain{ChainID: chainID, Denom: denom, HRP: hrp, Sender: sender}, bankaction.Limits{})
		require.NoError(t, err)
		assert.Equal(t, bankmsg.MsgSend{From: sender, To: upAddr, Denom: denom, Amount: 1000}, m)
		assert.Empty(t, pricetrigger.Verify(pt, m, res.Commitment.IssuedAt))
	})
}

func TestReplaysBroadcastOnce(t *testing.T) {
	w := newWorld(t, nil)
	w.poll(100_00000000)
	require.True(t, w.poll(99_00000000))
	res := w.res

	again, err := w.env.Gate.Authorize(bg, res.Envelope, res.Action)
	require.ErrorIs(t, err, gate.ErrNonceUsed)
	assert.Equal(t, w.gres.Authorization, again.Authorization, "the retry returns the stored authorization")

	for range 3 {
		got, err := w.exec.Execute(bg, again.Authorization, res.Action)
		require.ErrorIs(t, err, transfer.ErrSeen)
		assert.Equal(t, w.exRes, got)
	}
	signs, sends := w.chain.counts()
	assert.Equal(t, 1, signs)
	assert.Equal(t, 1, sends)

	t.Run("a second receipt for the same decision is not a second transfer", func(t *testing.T) {
		assert.Equal(t, 1, w.acts)
	})
}

func TestNoTriggerNoCommitment(t *testing.T) {
	w := newWorld(t, nil)
	w.poll(100_00000000)
	assert.False(t, w.poll(100_90000000))
	assert.False(t, w.poll(99_10000000))
	assert.Zero(t, w.acts)
	assert.Zero(t, w.verify.Calls())
	signs, sends := w.chain.counts()
	assert.Zero(t, signs)
	assert.Zero(t, sends)
}

func TestLoweredThresholdAndDownBranch(t *testing.T) {
	w := newWorld(t, func(c *agent.Config) { c.ThresholdBP = 10 })
	w.poll(100_00000000)
	require.True(t, w.poll(99_89000000))
	_, err := bankaction.Decode(w.res.Action)
	require.NoError(t, err)
	opened, err := sdk.OpenPayload(w.res.Envelope, w.res.Blob, w.vec.Key(t, "auditor-1").OpenKey(true))
	require.NoError(t, err)
	pt, err := pricetrigger.Decode(opened.Payload.Context.Bytes)
	require.NoError(t, err)
	assert.Equal(t, uint64(10), pt.ThresholdBP)
	assert.Equal(t, "down", pt.Branch.Name)
	assert.Equal(t, downDst, pt.Branch.ToAddress)
}

func TestTamperedActionIsNeverBroadcast(t *testing.T) {
	w := newWorld(t, nil)
	w.poll(100_00000000)
	require.True(t, w.poll(101_00000000))

	// A second decision is authorized, then its action bytes are swapped for
	// the other branch's: the executor refuses them under the genuine
	// authorization.
	other, err := bankaction.Encode(bankaction.Action{ChainID: chainID, Msg: mustMsg(t, downDst, 2000)})
	require.NoError(t, err)
	_, err = w.exec.Execute(bg, w.gres.Authorization, other)
	require.ErrorIs(t, err, commitment.ErrActionMismatch)
	_, sends := w.chain.counts()
	assert.Equal(t, 1, sends)
}

func mustMsg(t *testing.T, to string, amount uint64) []byte {
	t.Helper()
	b, err := bankmsg.Encode(bankmsg.MsgSend{From: sender, To: to, Denom: denom, Amount: amount}, hrp)
	require.NoError(t, err)
	return b
}
