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
	cfg.Scope = commitment.Scope{GateID: gatefix.GateID}
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

// admit presents the envelope with the exact action bytes the SDK returned.
func (r *sdkRun) admit(envelope []byte) (gate.Result, error) {
	return r.env.AuthorizeWith(envelope, r.res.Action)
}

func TestSDKAttack0Control(t *testing.T) {
	r := sdkArmed(t, "agent1", true)
	res, err := r.admit(r.res.Envelope)
	require.NoError(t, err)
	_, _, err = commitment.VerifyAuthorization(res.Authorization, commitment.AuthorizationCheck{
		GatePubKey: gatefix.Pub(t, "gate1"), GateID: gatefix.GateID, ActionType: r.res.Commitment.Action.Type,
		Action: r.res.Action, Now: gatefix.Now, SkewS: 30,
	})
	require.NoError(t, err, "the Authorization covers the bytes the agent committed to")
}

// 2. Amount, recipient or asset outside the committed action: the SDK
// signature covers the action hash, so an edited envelope breaks it, and other
// action bytes than the committed ones do not match the hash.
func TestSDKAttack2ActionOutsideCommitment(t *testing.T) {
	t.Run("hash edited in the envelope", func(t *testing.T) {
		r := sdkArmed(t, "agent1", true)
		s, err := commitment.DecodeSigned(r.res.Envelope)
		require.NoError(t, err)
		s.Commitment.Action.Hash[0] ^= 1
		b, err := commitment.EncodeSigned(s)
		require.NoError(t, err)
		_, err = r.admit(b)
		r.env.RequireRejected(&r.res.Commitment, err, commitment.ErrSignatureInvalid)
	})
	t.Run("type edited in the envelope", func(t *testing.T) {
		r := sdkArmed(t, "agent1", true, gatefix.WithScope(commitment.GateScope{
			GateID: gatefix.GateID, ActionTypes: []string{gatefix.ActionType, "application/json"},
		}))
		s, err := commitment.DecodeSigned(r.res.Envelope)
		require.NoError(t, err)
		s.Commitment.Action.Type = "application/json"
		b, err := commitment.EncodeSigned(s)
		require.NoError(t, err)
		_, err = r.admit(b)
		r.env.RequireRejected(&r.res.Commitment, err, commitment.ErrSignatureInvalid)
	})
	t.Run("every single byte flip of the committed action", func(t *testing.T) {
		r := sdkArmed(t, "agent1", true)
		for i := range r.res.Action {
			bad := append([]byte(nil), r.res.Action...)
			bad[i] ^= 1
			_, err := r.env.AuthorizeWith(r.res.Envelope, bad)
			r.env.RequireRejected(&r.res.Commitment, err, commitment.ErrActionMismatch)
		}
	})
	t.Run("the template order instead of the committed one", func(t *testing.T) {
		r := sdkArmed(t, "agent1", true)
		_, err := r.env.AuthorizeWith(r.res.Envelope, gatefix.Action(t))
		r.env.RequireRejected(&r.res.Commitment, err, commitment.ErrActionMismatch)
	})
	t.Run("the payload carries the committed bytes", func(t *testing.T) {
		r := sdkArmed(t, "agent1", true)
		o, err := sdk.OpenPayload(r.res.Envelope, r.res.Blob, r.vec.Key(t, "gate-paper-1").OpenKey(true))
		require.NoError(t, err)
		require.Equal(t, r.res.Action, o.Payload.Action.Data)
		require.NoError(t, commitment.CheckAction(&o.Commitment, o.Payload.Action.Data))
	})
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
			_, err := r.admit(r.res.Envelope)
			r.env.RequireRejected(&r.res.Commitment, err, commitment.ErrExpired)
		})
	}
}

// 4. Nonce reuse, including concurrent double-spend of one SDK envelope.
func TestSDKAttack4NonceReuse(t *testing.T) {
	t.Run("sequential", func(t *testing.T) {
		r := sdkArmed(t, "agent1", true)
		_, err := r.admit(r.res.Envelope)
		require.NoError(t, err)
		_, err = r.admit(r.res.Envelope)
		require.ErrorIs(t, err, gate.ErrNonceUsed)
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
				_, err := r.admit(r.res.Envelope)
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
	_, err := r.admit(r.res.Envelope)
	r.env.RequireRejected(&r.res.Commitment, err, gate.ErrPayloadUnavailable)
}

// 6. Commitment signed by a different key.
func TestSDKAttack6WrongKey(t *testing.T) {
	t.Run("agent id registered to another key", func(t *testing.T) {
		r := sdkArmed(t, "agent2", true)
		_, err := r.admit(r.res.Envelope)
		r.env.RequireRejected(&r.res.Commitment, err, gate.ErrAgentKeyMismatch)
	})
	t.Run("signature of another key under the right agent key", func(t *testing.T) {
		r := sdkArmed(t, "agent1", true)
		s, err := commitment.DecodeSigned(r.res.Envelope)
		require.NoError(t, err)
		s.Signature = ed25519.Sign(gatefix.Key(t, "agent2"), commitment.SigningMessage(r.res.CommitmentHash))
		b, err := commitment.EncodeSigned(s)
		require.NoError(t, err)
		_, err = r.admit(b)
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

	_, err := r.admit(r.res.Envelope)
	require.Error(t, err)
	r.env.RequireUntouched(&r.res.Commitment)

	_, err = sdk.OpenPayload(r.res.Envelope, swapped, r.vec.Key(t, "gate-paper-1").OpenKey(true))
	require.ErrorIs(t, err, commitment.ErrPayloadHashMismatch)

	other := sdkArmed(t, "agent1", false) // another decision, same size class
	_, err = sdk.OpenPayload(r.res.Envelope, other.res.Blob, r.vec.Key(t, "gate-paper-1").OpenKey(true))
	require.Error(t, err)
}

// 8. Cross-domain replay: the same SDK commitment against another gate or a
// gate that serves other action types.
func TestSDKAttack8CrossDomain(t *testing.T) {
	for name, tt := range map[string]struct {
		scope commitment.GateScope
		want  error
	}{
		"other gate":        {commitment.GateScope{GateID: "gate-other", ActionTypes: []string{gatefix.ActionType}}, commitment.ErrScopeMismatch},
		"other action type": {commitment.GateScope{GateID: gatefix.GateID, ActionTypes: []string{"application/json"}}, commitment.ErrActionTypeNotAllowed},
	} {
		t.Run(name, func(t *testing.T) {
			r := sdkArmed(t, "agent1", true, gatefix.WithScope(tt.scope))
			_, err := r.admit(r.res.Envelope)
			r.env.RequireRejected(&r.res.Commitment, err, tt.want)
		})
	}
}
