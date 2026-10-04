package dcaagent_test

import (
	"context"
	"crypto/ed25519"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/examples/dca-agent/dca"
	"github.com/vgonkivs/edicta/examples/dca-agent/ibkr"
	"github.com/vgonkivs/edicta/examples/dca-agent/ibkrorder"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/sdk"
	"github.com/vgonkivs/edicta/sdk/payload"
	"github.com/vgonkivs/edicta/sdk/sdktest"
	"github.com/vgonkivs/edicta/test/brokerfake"
	"github.com/vgonkivs/edicta/test/gatefix"
	"github.com/vgonkivs/edicta/test/sdkfix"
)

const account = "DU1234567"

var bg = context.Background()

type world struct {
	t       *testing.T
	env     *gatefix.Env
	vec     *sdkfix.Vectors
	builder *sdk.Builder
	broker  *brokerfake.Broker
	exec    *ibkr.Executor
}

func newWorld(t *testing.T) *world {
	t.Helper()
	env := gatefix.New(t)
	vec := sdkfix.Load(t)
	pub := sdktest.NewPublisher(commitment.DACelestiaBlob)
	pub.SetBlockTime(gatefix.Now - 1000)
	pub.SetHeight(4_200_000)
	signer, err := sdk.NewEd25519Signer(gatefix.Key(t, "agent1"))
	require.NoError(t, err)
	cfg := sdk.DefaultConfig()
	cfg.AgentID = "dca-agent-1"
	cfg.Scope = commitment.Scope{GateID: gatefix.GateID}
	cfg.Recipients = vec.Recipients(t, "gate-paper-1", "auditor-1")
	b, err := sdk.New(cfg, sdk.Deps{Publisher: pub, Signer: signer, Clock: env.Clock, Chain: env.Chain})
	require.NoError(t, err)

	broker := brokerfake.New()
	ex, err := ibkr.NewExecutor(ibkr.ExecutorConfig{
		GatePubKey: ed25519.PublicKey(gatefix.Pub(t, "gate1")),
		GateID:     gatefix.GateID,
		SkewS:      30,
		SettleS:    60,
		SignKey:    gatefix.ExecutorKey(t, "executor1"),
		Check:      ibkr.CheckConfig{Account: account, MaxNotional: 5000_00000000},
	}, broker, ibkr.NewMemStore(), env.Clock)
	require.NoError(t, err)
	return &world{t: t, env: env, vec: vec, builder: b, broker: broker, exec: ex}
}

// decide is the agent: a DCA context and the IBKR order it leads to.
func (w *world) decide(mod func(*ibkrorder.Order)) *payload.Payload {
	w.t.Helper()
	price := uint64(100_00000000)
	o := &ibkrorder.Order{
		Account: account, ConID: 756733, Symbol: "SPY", Side: ibkrorder.SideBuy, Qty: 10_0000,
		OrderType: ibkrorder.TypeLimit, LimitPrice: &price, Currency: "USD", TIF: ibkrorder.TIFDay,
	}
	if mod != nil {
		mod(o)
	}
	action, err := ibkrorder.Encode(o)
	require.NoError(w.t, err)
	body, err := dca.Encode(&dca.Context{
		StrategyID: "dca-spy-weekly",
		Schedule:   dca.Schedule{PeriodS: 604800, PeriodStart: gatefix.Now - 3600},
		Budget:     dca.Budget{Currency: "USD", PerPeriod: 2000_00000000, Spent: 500_00000000},
		Price:      dca.Price{Source: "ibkr:delayed", ConID: 756733, Price: 99_50000000, ObservedAt: gatefix.Now - 60},
		Order:      dca.Order{Side: ibkrorder.SideBuy, Qty: 10_0000, LimitPrice: price},
	})
	require.NoError(w.t, err)
	p := sdkfix.ClonePayload(w.vec.Case0(w.t).Payload)
	p.Context = payload.Data{MediaType: dca.MediaType, Bytes: body}
	p.Action = payload.Action{Type: ibkrorder.ActionType, Data: action}
	return p
}

// publish signs and stages everything a Recorder would have left behind.
func (w *world) publish(p *payload.Payload) *sdk.Result {
	w.t.Helper()
	res, err := w.builder.Commit(bg, p)
	require.NoError(w.t, err)
	w.env.StageChain(&res.Commitment, res.Published.BlockTime, res.Published.BlockTime)
	w.env.DA.Put(res.Published.Ref, res.Blob)
	return res
}

func TestEndToEnd(t *testing.T) {
	w := newWorld(t)
	p := w.decide(nil)
	res := w.publish(p)
	assert.Equal(t, p.Action.Data, res.Action)

	gres, err := w.env.Gate.Authorize(bg, res.Envelope, res.Action)
	require.NoError(t, err)
	require.NotEmpty(t, gres.Authorization)

	railRef, err := w.exec.Execute(bg, gres.Authorization, res.Action)
	require.NoError(t, err)
	require.NotEmpty(t, railRef)
	require.Equal(t, 1, w.broker.PlaceCalls())

	decoded, err := ibkrorder.Decode(res.Action)
	require.NoError(t, err)
	assert.Equal(t, ibkr.RequestFromOrder(decoded, ibkr.ClientOrderID(res.CommitmentHash)), w.broker.Placed()[0])

	execPub, execSig, err := w.exec.RecordRequest(res.CommitmentHash, railRef)
	require.NoError(t, err, "the executor signs the record request")
	assert.Equal(t, gatefix.ExecutorPub(t, "executor1"), execPub)
	receipt, err := w.env.Gate.Record(bg, res.Envelope, railRef, execPub, execSig)
	require.NoError(t, err)
	gatefix.CheckReceipt(t, receipt, res.CommitmentHash, railRef, gatefix.GateID, gatefix.Pub(t, "gate1"), 0)

	t.Run("the receipt carries the executor claim, checkable without the gate", func(t *testing.T) {
		sr, _, err := commitment.VerifyReceipt(receipt)
		require.NoError(t, err)
		assert.Equal(t, []byte(execPub), sr.Receipt.ExecutorPubKey)
		require.NoError(t, commitment.VerifyRecordRequest(res.CommitmentHash, sr.Receipt.GateID, railRef, sr.Receipt.ExecutorPubKey, sr.Receipt.ExecutorSignature))
	})
	t.Run("a verifier checks the authorization and replays the decision", func(t *testing.T) {
		sa, _, err := commitment.VerifyAuthorization(gres.Authorization, commitment.AuthorizationCheck{
			GatePubKey: gatefix.Pub(t, "gate1"), GateID: gatefix.GateID, ActionType: ibkrorder.ActionType,
			Action: res.Action, Now: uint64(w.env.Clock.Now().Unix()), SkewS: 30,
		})
		require.NoError(t, err)
		assert.Equal(t, res.CommitmentHash[:], sa.Authorization.CommitmentHash)

		opened, err := sdk.OpenPayload(res.Envelope, res.Blob, w.vec.Key(t, "auditor-1").OpenKey(true))
		require.NoError(t, err)
		assert.Equal(t, res.CommitmentHash, opened.CommitmentHash)
		assert.Equal(t, res.Action, opened.Payload.Action.Data)
		assert.Equal(t, dca.MediaType, opened.Payload.Context.MediaType)

		reasoning, err := dca.Decode(opened.Payload.Context.Bytes)
		require.NoError(t, err)
		executed, err := ibkrorder.Decode(opened.Payload.Action.Data)
		require.NoError(t, err)
		require.NoError(t, dca.CheckConsistency(reasoning, executed))
		assert.Equal(t, ibkr.RequestFromOrder(executed, ibkr.ClientOrderID(opened.CommitmentHash)), w.broker.Placed()[0])
	})
}

func TestReplayOfTheEnvelopePlacesOnce(t *testing.T) {
	w := newWorld(t)
	p := w.decide(nil)
	res := w.publish(p)

	gres, err := w.env.Gate.Authorize(bg, res.Envelope, res.Action)
	require.NoError(t, err)
	first, err := w.exec.Execute(bg, gres.Authorization, res.Action)
	require.NoError(t, err)

	again, err := w.env.Gate.Authorize(bg, res.Envelope, res.Action)
	require.ErrorIs(t, err, gate.ErrNonceUsed)
	assert.Equal(t, gres.Authorization, again.Authorization, "the retry returns the stored authorization")

	second, err := w.exec.Execute(bg, again.Authorization, res.Action)
	require.ErrorIs(t, err, ibkr.ErrSeen)
	assert.Equal(t, first, second)
	assert.Equal(t, 1, w.broker.PlaceCalls())
}

func TestTamperedActionGetsNoAuthorization(t *testing.T) {
	w := newWorld(t)
	p := w.decide(nil)
	res := w.publish(p)

	forged := append([]byte(nil), res.Action...)
	forged[len(forged)-1] ^= 1
	gres, err := w.env.Gate.Authorize(bg, res.Envelope, forged)
	require.ErrorIs(t, err, commitment.ErrActionMismatch)
	assert.Empty(t, gres.Authorization)
	assert.Zero(t, w.broker.PlaceCalls())

	t.Run("the executor refuses the tampered bytes under a genuine authorization", func(t *testing.T) {
		good, err := w.env.Gate.Authorize(bg, res.Envelope, res.Action)
		require.NoError(t, err)
		_, err = w.exec.Execute(bg, good.Authorization, forged)
		require.ErrorIs(t, err, commitment.ErrActionMismatch)
		assert.Zero(t, w.broker.PlaceCalls())
	})
}

func TestAuthorizationFromAnotherGateIsRefused(t *testing.T) {
	w := newWorld(t)
	p := w.decide(nil)
	res := w.publish(p)

	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x42
	}
	other, err := gate.NewEd25519Signer(ed25519.NewKeyFromSeed(seed))
	require.NoError(t, err)
	ow := gatefix.New(t, gatefix.WithSigner(other))
	ow.StageChain(&res.Commitment, res.Published.BlockTime, res.Published.BlockTime)
	ow.DA.Put(res.Published.Ref, res.Blob)
	gres, err := ow.Gate.Authorize(bg, res.Envelope, res.Action)
	require.NoError(t, err)

	_, err = w.exec.Execute(bg, gres.Authorization, res.Action)
	require.ErrorIs(t, err, commitment.ErrSignatureInvalid)
	assert.Zero(t, w.broker.PlaceCalls())
}

func TestOrderForAnotherAccountIsAuthorizedButNotExecuted(t *testing.T) {
	w := newWorld(t)
	p := w.decide(func(o *ibkrorder.Order) { o.Account = "DU7654321" })
	res := w.publish(p)
	gres, err := w.env.Gate.Authorize(bg, res.Envelope, res.Action)
	require.NoError(t, err, "the gate does not know accounts")

	_, err = w.exec.Execute(bg, gres.Authorization, res.Action)
	require.ErrorIs(t, err, ibkr.ErrAccountMismatch)
	assert.Zero(t, w.broker.PlaceCalls())
}

func TestInconsistentReasoningIsVisibleToTheVerifierOnly(t *testing.T) {
	w := newWorld(t)
	p := w.decide(nil)
	// The agent states a smaller order than the one it commits to execute.
	reasoning, err := dca.Decode(p.Context.Bytes)
	require.NoError(t, err)
	reasoning.Order.Qty = 1_0000
	p.Context.Bytes, err = dca.Encode(reasoning)
	require.NoError(t, err)
	res := w.publish(p)

	gres, err := w.env.Gate.Authorize(bg, res.Envelope, res.Action)
	require.NoError(t, err, "the gate never evaluates the agent")
	_, err = w.exec.Execute(bg, gres.Authorization, res.Action)
	require.NoError(t, err)

	opened, err := sdk.OpenPayload(res.Envelope, res.Blob, w.vec.Key(t, "auditor-1").OpenKey(true))
	require.NoError(t, err)
	got, err := dca.Decode(opened.Payload.Context.Bytes)
	require.NoError(t, err)
	executed, err := ibkrorder.Decode(opened.Payload.Action.Data)
	require.NoError(t, err)
	assert.ErrorIs(t, dca.CheckConsistency(got, executed), dca.ErrOrderDiffers)
}

func TestReadmeLinksTheProfile(t *testing.T) {
	b, err := os.ReadFile("README.md")
	require.NoError(t, err, "examples/dca-agent/README.md must exist")
	assert.True(t, strings.Contains(string(b), "spec/profiles/dca-agent-v0.md"),
		"the README must link spec/profiles/dca-agent-v0.md")
	_, err = os.Stat("../../spec/profiles/dca-agent-v0.md")
	require.NoError(t, err)
}
