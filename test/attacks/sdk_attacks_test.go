package attacks_test

import (
	"crypto/ed25519"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/sdk"
	"github.com/vgonkivs/edicta/sdk/sdktest"
	"github.com/vgonkivs/edicta/test/gatefix"
	"github.com/vgonkivs/edicta/test/sdkfix"
)

// The gate attack suite again, with envelopes produced by the SDK instead of
// hand-built ones: what the SDK emits must be exactly as hard to abuse.

type sdkRun struct {
	env *gatefix.Env
	res *sdk.Result
	vec *sdkfix.Vectors
}

func sdkArmed(t *testing.T, key string, stage bool, opts ...gatefix.Option) *sdkRun {
	t.Helper()
	env := gatefix.New(t, opts...)
	v := sdkfix.Load(t)
	signer, err := sdk.NewEd25519Signer(gatefix.Key(t, key))
	require.NoError(t, err)
	cfg := sdk.DefaultConfig()
	cfg.AgentID = "dca-agent-1"
	cfg.Scope = commitment.Scope{GateID: gatefix.GateID, Rail: commitment.RailIBKR, Account: gatefix.Account}
	cfg.Recipients = v.Recipients(t, "gate-paper-1", "auditor-1")
	p := sdktest.NewPublisher(commitment.DACelestiaBlob)
	p.SetBlockTime(gatefix.Now - 1000)
	p.SetHeight(4_200_000)
	b, err := sdk.New(cfg, sdk.Deps{Publisher: p, Signer: signer, Clock: env.Clock, Chain: env.Chain})
	require.NoError(t, err)
	res, err := b.Commit(t.Context(), sdkfix.ClonePayload(v.Case0(t).Payload))
	require.NoError(t, err)
	if stage {
		env.StageChain(&res.Commitment, res.Published.BlockTime, res.Published.BlockTime)
		env.DA.Put(res.Published.Ref, res.Blob)
	}
	return &sdkRun{env: env, res: res, vec: v}
}

func TestSDKAttack0Control(t *testing.T) {
	r := sdkArmed(t, "agent1", true)
	_, err := r.env.Admit(r.res.Envelope)
	require.NoError(t, err)
	require.Equal(t, 1, r.env.Exec.Calls())
}

// 2. Amount, recipient or asset outside the committed action: the SDK
// signature covers the action, so any edit of the envelope breaks it.
func TestSDKAttack2ParamsOutsideCommitment(t *testing.T) {
	muts := map[string]func(o *commitment.IBKROrderV0){
		"qty plus one unit": func(o *commitment.IBKROrderV0) { o.Qty++ },
		"other account":     func(o *commitment.IBKROrderV0) { o.Account = "DU7654321" },
		"other asset":       func(o *commitment.IBKROrderV0) { o.ConID++ },
		"other currency":    func(o *commitment.IBKROrderV0) { o.Currency = "EUR" },
		"other side":        func(o *commitment.IBKROrderV0) { o.Side = commitment.SideSell },
		"price plus one":    func(o *commitment.IBKROrderV0) { p := *o.LimitPrice + 1; o.LimitPrice = &p },
	}
	for name, m := range muts {
		t.Run(name, func(t *testing.T) {
			r := sdkArmed(t, "agent1", true)
			s, err := commitment.DecodeSigned(r.res.Envelope)
			require.NoError(t, err)
			m(s.Commitment.Action.IBKROrder)
			b, err := commitment.EncodeSigned(s)
			require.NoError(t, err)
			_, err = r.env.Admit(b)
			require.Error(t, err)
			require.Zero(t, r.env.Exec.Calls())
			r.env.RequireUntouched(&r.res.Commitment)
		})
	}
}

// 3. Expired validity window.
func TestSDKAttack3Expired(t *testing.T) {
	for name, at := range map[string]uint64{
		"expiry minus skew": 0,
		"expiry":            1,
		"a day later":       86400,
	} {
		t.Run(name, func(t *testing.T) {
			r := sdkArmed(t, "agent1", true)
			until := r.res.Validity.ValidUntil
			switch at {
			case 0:
				r.env.Clock.Set(until - 30)
			case 1:
				r.env.Clock.Set(until)
			default:
				r.env.Clock.Set(until + at)
			}
			_, err := r.env.Admit(r.res.Envelope)
			r.env.RequireRejected(&r.res.Commitment, err, commitment.ErrExpired)
		})
	}
}

// 4. Nonce reuse, including concurrent double-spend of one SDK envelope.
func TestSDKAttack4NonceReuse(t *testing.T) {
	t.Run("sequential", func(t *testing.T) {
		r := sdkArmed(t, "agent1", true)
		_, err := r.env.Admit(r.res.Envelope)
		require.NoError(t, err)
		_, err = r.env.Admit(r.res.Envelope)
		require.ErrorIs(t, err, gate.ErrNonceUsed)
		require.Equal(t, 1, r.env.Exec.Calls())
	})
	t.Run("concurrent", func(t *testing.T) {
		r := sdkArmed(t, "agent1", true)
		const n = 32
		var ok, used atomic.Int32
		var start, done sync.WaitGroup
		start.Add(1)
		for range n {
			done.Add(1)
			go func() {
				defer done.Done()
				start.Wait()
				_, err := r.env.Admit(r.res.Envelope)
				switch {
				case err == nil:
					ok.Add(1)
				case assert.ErrorIs(t, err, gate.ErrNonceUsed):
					used.Add(1)
				}
			}()
		}
		start.Done()
		done.Wait()
		assert.EqualValues(t, 1, ok.Load(), "exactly one winner")
		assert.EqualValues(t, n-1, used.Load())
		assert.Equal(t, 1, r.env.Exec.Calls(), "the order is sent once")
	})
	t.Run("two SDK commitments of one decision are two decisions", func(t *testing.T) {
		r := sdkArmed(t, "agent1", true)
		assert.NotEqual(t, r.res.Commitment.Nonce, sdkArmed(t, "agent1", false).res.Commitment.Nonce)
	})
}

// 5. Payload unavailable in Fibre and archive.
func TestSDKAttack5PayloadUnavailable(t *testing.T) {
	r := sdkArmed(t, "agent1", false)
	r.env.StageChain(&r.res.Commitment, r.res.Published.BlockTime, r.res.Published.BlockTime)
	_, err := r.env.Admit(r.res.Envelope)
	r.env.RequireRejected(&r.res.Commitment, err, gate.ErrPayloadUnavailable)
}

// 6. Commitment signed by a different key.
func TestSDKAttack6WrongKey(t *testing.T) {
	t.Run("agent id registered to another key", func(t *testing.T) {
		r := sdkArmed(t, "agent2", true)
		_, err := r.env.Admit(r.res.Envelope)
		r.env.RequireRejected(&r.res.Commitment, err, gate.ErrAgentKeyMismatch)
	})
	t.Run("signature of another key under the right agent key", func(t *testing.T) {
		r := sdkArmed(t, "agent1", true)
		s, err := commitment.DecodeSigned(r.res.Envelope)
		require.NoError(t, err)
		s.Signature = ed25519.Sign(gatefix.Key(t, "agent2"), commitment.SigningMessage(r.res.CommitmentHash))
		b, err := commitment.EncodeSigned(s)
		require.NoError(t, err)
		_, err = r.env.Admit(b)
		r.env.RequireRejected(&r.res.Commitment, err, commitment.ErrSignatureInvalid)
	})
}

// 7. Payload swapped after the fact: the gate and the verifier both see the
// hash mismatch.
func TestSDKAttack7PayloadSwapped(t *testing.T) {
	r := sdkArmed(t, "agent1", false)
	swapped := append([]byte{}, r.res.Blob...)
	swapped[len(swapped)/2] ^= 0xff
	r.env.StageChain(&r.res.Commitment, r.res.Published.BlockTime, r.res.Published.BlockTime)
	r.env.DA.Put(r.res.Published.Ref, swapped)

	_, err := r.env.Admit(r.res.Envelope)
	require.Error(t, err)
	require.Zero(t, r.env.Exec.Calls())

	_, err = sdk.OpenPayload(r.res.Envelope, swapped, r.vec.Key(t, "gate-paper-1").OpenKey(true))
	require.ErrorIs(t, err, commitment.ErrPayloadHashMismatch)

	other := sdkArmed(t, "agent1", false) // another decision, same size class
	_, err = sdk.OpenPayload(r.res.Envelope, other.res.Blob, r.vec.Key(t, "gate-paper-1").OpenKey(true))
	require.Error(t, err)
}

// 8. Cross-domain replay: the same SDK commitment against another gate, rail
// scope or account.
func TestSDKAttack8CrossDomain(t *testing.T) {
	for name, g := range map[string]commitment.GateScope{
		"other gate":    {GateID: "gate-other", Rail: commitment.RailIBKR, Account: gatefix.Account},
		"other account": {GateID: gatefix.GateID, Rail: commitment.RailIBKR, Account: "DU7654321"},
	} {
		t.Run(name, func(t *testing.T) {
			r := sdkArmed(t, "agent1", true, gatefix.WithScope(g))
			_, err := r.env.Admit(r.res.Envelope)
			r.env.RequireRejected(&r.res.Commitment, err, commitment.ErrScopeMismatch)
		})
	}
	t.Run("a chain id cannot be put into an IBKR scope", func(t *testing.T) {
		v := sdkfix.Load(t)
		signer, err := sdk.NewEd25519Signer(gatefix.Key(t, "agent1"))
		require.NoError(t, err)
		chain := "eip155:1"
		cfg := sdk.DefaultConfig()
		cfg.AgentID = "dca-agent-1"
		cfg.Scope = commitment.Scope{GateID: gatefix.GateID, Rail: commitment.RailIBKR, Account: gatefix.Account, ChainID: &chain}
		cfg.Recipients = v.Recipients(t, "gate-paper-1")
		env := gatefix.New(t)
		p := sdktest.NewPublisher(commitment.DACelestiaBlob)
		p.SetBlockTime(gatefix.Now - 1000)
		p.SetHeight(4_200_000)
		b, err := sdk.New(cfg, sdk.Deps{Publisher: p, Signer: signer, Clock: env.Clock, Chain: env.Chain})
		if err == nil {
			_, err = b.Commit(t.Context(), sdkfix.ClonePayload(v.Case0(t).Payload))
		}
		require.Error(t, err)
	})
}
