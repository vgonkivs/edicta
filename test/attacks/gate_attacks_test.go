package attacks_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/test/gatefix"
)

// The gate attack suite: each test drives the full gate with fakes and
// requires a rejection with the right sentinel, no executor call and, for the
// stages before the nonce is consumed, an untouched nonce. The entry point is
// still the admit-and-execute path; the authorizer replaces it.

func armed(t *testing.T, opts ...gatefix.Option) (*gatefix.Env, *commitment.Commitment, []byte) {
	t.Helper()
	e := gatefix.New(t, opts...)
	c := gatefix.Template(t)
	e.StageDA(c, gatefix.Blob(t))
	b, _ := gatefix.Sign(t, "agent1", c)
	return e, c, b
}

func TestGateAttack0Control(t *testing.T) {
	e, _, b := armed(t)
	_, err := e.Admit(b)
	require.NoError(t, err, "the honest path must be admitted")
}

// 1. Action without commitment.
func TestGateAttack1ActionWithoutCommitment(t *testing.T) {
	e, c, good := armed(t)
	unsigned, _ := commitment.Encode(c)
	zeroSig, _ := commitment.EncodeSigned(&commitment.SignedCommitment{Commitment: *c, Signature: make([]byte, 64)})
	for name, b := range map[string][]byte{
		"nil":                nil,
		"empty":              {},
		"empty map":          {0xa0},
		"bare action":        {0xa1, 0x01, 0xa0},
		"unsigned":           unsigned,
		"zero signature":     zeroSig,
		"garbage":            []byte("not cbor at all"),
		"truncated envelope": good[:len(good)/2],
	} {
		t.Run(name, func(t *testing.T) {
			_, err := e.Admit(b)
			require.Error(t, err, "gate accepted")
			require.EqualValues(t, 0, e.Exec.Calls(), "executor called")
		})
	}
	_, err := e.Entry(c)
	require.Error(t, err, "a nonce was consumed by rejected input")
}

// 2. Amount, recipient or asset outside the committed action. The core does
// not parse actions: it compares the presented bytes with the committed hash,
// so every field of any format is covered by the same rule.
func TestGateAttack2ActionOutsideCommitment(t *testing.T) {
	const jsonType = "application/json"
	both := gatefix.WithScope(commitment.GateScope{GateID: gatefix.GateID, ActionTypes: []string{gatefix.ActionType, jsonType}})
	committed := []byte(`{"to":"0xA1","asset":"TIA","amount":"100"}`)
	armedJSON := func(t *testing.T) (*gatefix.Env, *commitment.Commitment, []byte) {
		e := gatefix.New(t, both)
		c := gatefix.WithAction(t, gatefix.Template(t), jsonType, committed)
		e.StageDA(c, gatefix.Blob(t))
		b, _ := gatefix.Sign(t, "agent1", c)
		return e, c, b
	}
	t.Run("control", func(t *testing.T) {
		e, _, b := armedJSON(t)
		_, err := e.AdmitWith(b, committed)
		require.NoError(t, err)
	})
	variants := map[string]string{
		"amount raised":         `{"to":"0xA1","asset":"TIA","amount":"101"}`,
		"amount with extra 0":   `{"to":"0xA1","asset":"TIA","amount":"1000"}`,
		"recipient changed":     `{"to":"0xA2","asset":"TIA","amount":"100"}`,
		"asset changed":         `{"to":"0xA1","asset":"ETH","amount":"100"}`,
		"extra field":           `{"to":"0xA1","asset":"TIA","amount":"100","memo":"x"}`,
		"whitespace only":       `{"to": "0xA1","asset":"TIA","amount":"100"}`,
		"field order only":      `{"asset":"TIA","to":"0xA1","amount":"100"}`,
		"a second action added": `{"to":"0xA1","asset":"TIA","amount":"100"}{"to":"0xA2","asset":"TIA","amount":"1"}`,
	}
	for name, changed := range variants {
		t.Run(name, func(t *testing.T) {
			e, c, b := armedJSON(t)
			_, err := e.AdmitWith(b, []byte(changed))
			e.RequireRejected(c, err, commitment.ErrActionMismatch)
		})
	}
	t.Run("every single byte flip of the committed action", func(t *testing.T) {
		e, c, b := armedJSON(t)
		for i := range committed {
			bad := append([]byte(nil), committed...)
			bad[i] ^= 1
			_, err := e.AdmitWith(b, bad)
			e.RequireRejected(c, err, commitment.ErrActionMismatch)
		}
	})
	t.Run("every truncation of the committed action", func(t *testing.T) {
		e, c, b := armedJSON(t)
		for i := 1; i < len(committed); i++ {
			_, err := e.AdmitWith(b, committed[:i])
			e.RequireRejected(c, err, commitment.ErrActionMismatch)
		}
	})
	t.Run("no bytes and too many bytes", func(t *testing.T) {
		e, c, b := armedJSON(t)
		for _, bad := range [][]byte{nil, {}, make([]byte, commitment.MaxActionSize+1)} {
			_, err := e.AdmitWith(b, bad)
			e.RequireRejected(c, err, commitment.ErrActionSize)
		}
	})
	t.Run("the template order against the json commitment", func(t *testing.T) {
		e, c, b := armedJSON(t)
		_, err := e.AdmitWith(b, gatefix.Action(t))
		e.RequireRejected(c, err, commitment.ErrActionMismatch)
	})
	t.Run("committed bytes under a type the gate does not serve", func(t *testing.T) {
		e := gatefix.New(t)
		c := gatefix.WithAction(t, gatefix.Template(t), jsonType, committed)
		e.StageDA(c, gatefix.Blob(t))
		b, _ := gatefix.Sign(t, "agent1", c)
		_, err := e.AdmitWith(b, committed)
		e.RequireRejected(c, err, commitment.ErrActionTypeNotAllowed)
	})
	t.Run("hash rewritten after signing", func(t *testing.T) {
		e, c, _ := armedJSON(t)
		other := []byte(`{"to":"0xBAD","asset":"TIA","amount":"100"}`)
		oh, err := commitment.ActionHash(jsonType, other)
		require.NoError(t, err)
		s, _, _ := commitment.Sign(gatefix.Key(t, "agent1"), c)
		s.Commitment.Action.Hash = oh[:]
		b, _ := commitment.EncodeSigned(s)
		_, err = e.AdmitWith(b, other)
		e.RequireRejected(c, err, commitment.ErrSignatureInvalid)
	})
	t.Run("template action, other bytes", func(t *testing.T) {
		e, c, b := armed(t)
		_, err := e.AdmitWith(b, gatefix.OtherAction(t, 1))
		e.RequireRejected(c, err, commitment.ErrActionMismatch)
	})
}

// 3. Expired validity window.
func TestGateAttack3Expired(t *testing.T) {
	for name, now := range map[string]uint64{
		"expiry minus skew": 1791000900 - 30,
		"expiry":            1791000900,
		"one second after":  1791000901,
		"a year later":      1791000900 + 86400*365,
	} {
		t.Run(name, func(t *testing.T) {
			e, c, b := armed(t, gatefix.WithNow(now))
			_, err := e.Admit(b)
			e.RequireRejected(c, err, commitment.ErrExpired)
		})
	}
	t.Run("expires while the payload is fetched", func(t *testing.T) {
		e, c, b := armed(t)
		e.DA.OnFetch(func() { e.Clock.Advance(time.Hour) })
		_, err := e.Admit(b)
		e.RequireRejected(c, err, commitment.ErrExpired)
	})
	t.Run("validity stretched beyond the maximum", func(t *testing.T) {
		c := gatefix.Template(t)
		c.ValidUntil = c.IssuedAt + 3601
		e := gatefix.New(t)
		e.StageDA(c, gatefix.Blob(t))
		b, _ := gatefix.Sign(t, "agent1", c)
		_, err := e.Admit(b)
		e.RequireRejected(c, err, commitment.ErrTTLTooLong)
	})
	t.Run("valid_until extended after signing", func(t *testing.T) {
		e, c, _ := armed(t)
		s, _, _ := commitment.Sign(gatefix.Key(t, "agent1"), c)
		s.Commitment.ValidUntil += 600
		b, _ := commitment.EncodeSigned(s)
		e.Clock.Set(1791000900)
		_, err := e.Admit(b)
		e.RequireRejected(c, err, commitment.ErrSignatureInvalid)
	})
	t.Run("validity outlasts the retention window: the DA copy is not used", func(t *testing.T) {
		e := gatefix.New(t)
		c := gatefix.Template(t)
		th := c.ValidUntil + 600 - 14400 - 1
		e.StageChain(c, th, th)
		e.DA.Put(c.PayloadRef, gatefix.Blob(t))
		b, _ := gatefix.Sign(t, "agent1", c)
		_, err := e.Admit(b)
		e.RequireRejected(c, err, gate.ErrAnchorTooOld)
		require.EqualValues(t, 0, e.DA.Fetches(), "DA used outside its retention window")
	})
}

// 4. Reused nonce, including concurrent double spend.
func TestGateAttack4ReusedNonce(t *testing.T) {
	t.Run("sequential replay", func(t *testing.T) {
		e, _, b := armed(t)
		_, err := e.Admit(b)
		require.NoError(t, err)
		for i := 0; i < 5; i++ {
			_, err := e.Admit(b)
			require.ErrorIsf(t, err, gate.ErrNonceUsed, "replay %d", i)
		}
		require.EqualValuesf(t, 1, e.Exec.Calls(), "executor calls %d", e.Exec.Calls())
	})
	t.Run("same nonce, different action", func(t *testing.T) {
		e, _, b := armed(t)
		_, err := e.Admit(b)
		require.NoError(t, err)
		c2 := gatefix.Variant(t, gatefix.Template(t), 1)
		e.StageDA(c2, gatefix.Blob(t))
		b2, _ := gatefix.Sign(t, "agent1", c2)
		_, err = e.AdmitWith(b2, gatefix.OtherAction(t, 1))
		require.ErrorIs(t, err, gate.ErrNonceUsed)
		require.EqualValuesf(t, 1, e.Exec.Calls(), "executor calls %d", e.Exec.Calls())
	})
	t.Run("replay after an ambiguous execution", func(t *testing.T) {
		e, _, b := armed(t)
		e.Exec.SetError(errors.New("timeout"))
		_, err := e.Admit(b)
		require.ErrorIs(t, err, gate.ErrExecutionUnknown)
		e.Exec.SetResult(gate.ExecResult{Outcome: gate.OutcomeExecuted, RailRef: "1"})
		_, err = e.Admit(b)
		require.ErrorIs(t, err, gate.ErrNonceUsed)
		require.EqualValuesf(t, 1, e.Exec.Calls(), "executor calls %d", e.Exec.Calls())
	})
	t.Run("concurrent double spend", func(t *testing.T) {
		e, _, b := armed(t)
		const n = 64
		release := make(chan struct{})
		e.Exec.OnExecute(func(context.Context, gate.ExecRequest) { <-release })
		var wg sync.WaitGroup
		var ok atomic.Int32
		losers := make(chan struct{}, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := e.Admit(append([]byte(nil), b...))
				if err == nil {
					ok.Add(1)
					return
				}
				assert.ErrorIs(t, err, gate.ErrNonceUsed)
				losers <- struct{}{}
			}()
		}
		for i := 0; i < n-1; i++ {
			select {
			case <-losers:
			case <-time.After(30 * time.Second):
				close(release)
				require.FailNow(t, "a replay did not return: the nonce check let it through to the executor")
			}
		}
		close(release)
		wg.Wait()
		require.EqualValuesf(t, 1, ok.Load(), "admitted %d, executor calls %d", ok.Load(), e.Exec.Calls())
		require.EqualValuesf(t, 1, e.Exec.Calls(), "admitted %d, executor calls %d", ok.Load(), e.Exec.Calls())
	})
	t.Run("concurrent double spend with a slow executor result", func(t *testing.T) {
		e, _, b := armed(t)
		e.Exec.SetError(errors.New("timeout"))
		var wg sync.WaitGroup
		for i := 0; i < 32; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); _, _ = e.Admit(b) }()
		}
		wg.Wait()
		require.EqualValuesf(t, 1, e.Exec.Calls(), "executor calls %d", e.Exec.Calls())
	})
}

// 5. Payload unavailable in the DA layer and the archive.
func TestGateAttack5PayloadUnavailable(t *testing.T) {
	t.Run("neither source has it", func(t *testing.T) {
		e := gatefix.New(t)
		c := gatefix.Template(t)
		e.StageChain(c, gatefix.BlockTime(c), gatefix.BlockTime(c))
		b, _ := gatefix.Sign(t, "agent1", c)
		_, err := e.Admit(b)
		e.RequireRejected(c, err, gate.ErrPayloadUnavailable)
	})
	t.Run("both sources fail", func(t *testing.T) {
		e, c, b := armed(t)
		e.DA.Fail(errors.New("down"))
		e.Archive.Fail(errors.New("down"))
		_, err := e.Admit(b)
		e.RequireRejected(c, err, gate.ErrPayloadUnavailable)
	})
	t.Run("pruned by the DA layer and the archive lost it", func(t *testing.T) {
		e := gatefix.New(t)
		c := gatefix.Template(t)
		th := c.ValidUntil + 600 - 14400 - 1
		e.StageChain(c, th, th)
		b, _ := gatefix.Sign(t, "agent1", c)
		_, err := e.Admit(b)
		e.RequireRejected(c, err, gate.ErrAnchorTooOld)
		require.ErrorIs(t, err, gate.ErrPayloadUnavailable, "must also match ErrPayloadUnavailable")
	})
	t.Run("no anchor means no commitment was published", func(t *testing.T) {
		e := gatefix.New(t)
		c := gatefix.Template(t)
		e.DA.Put(c.PayloadRef, gatefix.Blob(t))
		b, _ := gatefix.Sign(t, "agent1", c)
		_, err := e.Admit(b)
		e.RequireRejected(c, err, gate.ErrAnchorNotFound)
	})
	t.Run("fibre payload that only the archive has", func(t *testing.T) {
		e := gatefix.New(t)
		c := gatefix.FibreTemplate(t)
		th := c.ValidUntil + 600 - 14400 - 1
		e.StageChain(c, th, th)
		e.Archive.Put(c.PayloadRef, gatefix.FibreBlob())
		b, _ := gatefix.Sign(t, "agent1", c)
		_, err := e.Admit(b)
		e.RequireRejected(c, err, gate.ErrArchiveRecomputeUnsupported)
		require.EqualValues(t, 0, e.Archive.Fetches(), "archive read for a payload that cannot be recomputed")
	})
}

// 6. Commitment signed by a different key.
func TestGateAttack6WrongKey(t *testing.T) {
	t.Run("signed by agent2, claims agent1", func(t *testing.T) {
		e, c, _ := armed(t)
		h, _ := commitment.HashOf(c)
		b, _ := commitment.EncodeSigned(&commitment.SignedCommitment{Commitment: *c,
			Signature: ed25519.Sign(gatefix.Key(t, "agent2"), commitment.SigningMessage(h))})
		_, err := e.Admit(b)
		e.RequireRejected(c, err, commitment.ErrSignatureInvalid)
	})
	t.Run("pubkey swapped after signing", func(t *testing.T) {
		e, c, _ := armed(t)
		s, _, _ := commitment.Sign(gatefix.Key(t, "agent1"), c)
		s.Commitment.AgentPubKey = gatefix.Pub(t, "agent2")
		b, _ := commitment.EncodeSigned(s)
		_, err := e.Admit(b)
		e.RequireRejected(c, err, commitment.ErrSignatureInvalid)
	})
	t.Run("valid signature of a key the allowlist does not bind to the id", func(t *testing.T) {
		e := gatefix.New(t)
		c := gatefix.WithKey(t, gatefix.Template(t), "agent2") // agent_id still says dca-agent-1
		e.StageDA(c, gatefix.Blob(t))
		b, _ := gatefix.Sign(t, "agent2", c)
		_, err := e.Admit(b)
		e.RequireRejected(c, err, gate.ErrAgentKeyMismatch)
	})
	t.Run("unknown agent", func(t *testing.T) {
		e := gatefix.New(t, gatefix.WithAllowlist(map[string][]byte{"other": gatefix.Pub(t, "agent2")}))
		c := gatefix.Template(t)
		e.StageDA(c, gatefix.Blob(t))
		b, _ := gatefix.Sign(t, "agent1", c)
		_, err := e.Admit(b)
		e.RequireRejected(c, err, gate.ErrAgentNotAllowed)
	})
	t.Run("the gate's own receipt key as agent key", func(t *testing.T) {
		e := gatefix.New(t)
		c := gatefix.WithKey(t, gatefix.Template(t), "gate1")
		e.StageDA(c, gatefix.Blob(t))
		b, _ := gatefix.Sign(t, "gate1", c)
		_, err := e.Admit(b)
		e.RequireRejected(c, err, gate.ErrAgentKeyIsGateKey)
	})
	t.Run("small-order key forges any message", func(t *testing.T) {
		e, c, _ := armed(t)
		c = gatefix.Clone(c)
		c.AgentPubKey = append([]byte{1}, make([]byte, 31)...)
		sig := append([]byte{1}, make([]byte, 63)...)
		b, _ := commitment.EncodeSigned(&commitment.SignedCommitment{Commitment: *c, Signature: sig})
		_, err := e.Admit(b)
		e.RequireRejected(c, err, commitment.ErrInvalidPublicKey)
	})
}

// 7. Payload swapped after the fact.
func TestGateAttack7PayloadSwapped(t *testing.T) {
	x := gatefix.Blob(t)
	t.Run("any single flipped byte in the DA copy", func(t *testing.T) {
		for i := range x {
			e, c, b := armed(t)
			bad := append([]byte(nil), x...)
			bad[i] ^= 1
			e.DA.Put(c.PayloadRef, bad)
			_, err := e.Admit(b)
			e.RequireRejected(c, err, commitment.ErrPayloadHashMismatch)
		}
	})
	t.Run("both copies swapped", func(t *testing.T) {
		e, c, b := armed(t)
		e.DA.Put(c.PayloadRef, gatefix.BlobY(t))
		e.Archive.Put(c.PayloadRef, gatefix.BlobY(t))
		_, err := e.Admit(b)
		e.RequireRejected(c, err, commitment.ErrPayloadHashMismatch)
	})
	t.Run("archive copy swapped, DA pruned", func(t *testing.T) {
		e := gatefix.New(t)
		c := gatefix.Template(t)
		th := c.ValidUntil + 600 - 14400 - 1
		e.StageChain(c, th, th)
		e.Archive.Put(c.PayloadRef, gatefix.BlobY(t))
		b, _ := gatefix.Sign(t, "agent1", c)
		_, err := e.Admit(b)
		e.RequireRejected(c, err, commitment.ErrPayloadHashMismatch)
	})
	t.Run("anchor X, sign the hash of Y, archive serves Y", func(t *testing.T) {
		e := gatefix.New(t)
		c := gatefix.Template(t)
		y := gatefix.BlobY(t)
		h := sha(y)
		c.CiphertextHash = h[:]
		th := c.ValidUntil + 600 - 14400 - 1
		e.StageChain(c, th, th)
		e.Archive.Put(c.PayloadRef, y)
		b, _ := gatefix.Sign(t, "agent1", c)
		_, err := e.Admit(b)
		e.RequireRejected(c, err, gate.ErrDACommitmentMismatch)
	})
	t.Run("hash replaced after signing", func(t *testing.T) {
		e, c, _ := armed(t)
		s, _, _ := commitment.Sign(gatefix.Key(t, "agent1"), c)
		s.Commitment.CiphertextHash[0] ^= 1
		b, _ := commitment.EncodeSigned(s)
		_, err := e.Admit(b)
		e.RequireRejected(c, err, commitment.ErrSignatureInvalid)
	})
}

// 8. Cross-domain replay. The core binds the gate id and the action type
// allowlist; account and chain binding is the action format's job.
func TestGateAttack8CrossDomainReplay(t *testing.T) {
	scopes := map[string]struct {
		scope commitment.GateScope
		want  error
	}{
		"other gate":        {commitment.GateScope{GateID: "gate-paper-2", ActionTypes: []string{gatefix.ActionType}}, commitment.ErrScopeMismatch},
		"gate id case":      {commitment.GateScope{GateID: "GATE-PAPER-1", ActionTypes: []string{gatefix.ActionType}}, commitment.ErrScopeMismatch},
		"other action type": {commitment.GateScope{GateID: gatefix.GateID, ActionTypes: []string{"application/json"}}, commitment.ErrActionTypeNotAllowed},
		"no action types":   {commitment.GateScope{GateID: gatefix.GateID}, commitment.ErrActionTypeNotAllowed},
	}
	for name, tt := range scopes {
		t.Run(name, func(t *testing.T) {
			// The envelope was executed on the home gate; a second gate with
			// its own registry must still refuse it.
			home, c, b := armed(t)
			_, err := home.Admit(b)
			require.NoError(t, err)
			other := gatefix.New(t, gatefix.WithScope(tt.scope))
			other.StageDA(c, gatefix.Blob(t))
			_, err = other.Admit(b)
			other.RequireRejected(c, err, tt.want)
		})
	}
	t.Run("same bytes presented as another allowed type", func(t *testing.T) {
		e := gatefix.New(t, gatefix.WithScope(commitment.GateScope{
			GateID: gatefix.GateID, ActionTypes: []string{gatefix.ActionType, "application/octet-stream"},
		}))
		c := gatefix.Template(t)
		c.Action.Type = "application/octet-stream" // hash was computed under the ibkr type
		e.StageDA(c, gatefix.Blob(t))
		b, _ := gatefix.Sign(t, "agent1", c)
		_, err := e.Admit(b)
		e.RequireRejected(c, err, commitment.ErrActionMismatch)
	})
	t.Run("commitment of another gate rewritten to this one", func(t *testing.T) {
		e, c, _ := armed(t)
		other := gatefix.Clone(c)
		other.Scope.GateID = "gate-paper-2"
		s, _, _ := commitment.Sign(gatefix.Key(t, "agent1"), other)
		s.Commitment.Scope.GateID = gatefix.GateID
		b, _ := commitment.EncodeSigned(s)
		_, err := e.Admit(b)
		e.RequireRejected(c, err, commitment.ErrSignatureInvalid)
	})
}

// Replay through a stepped clock: forward step, prune, back step inside one
// admission must not let the executed envelope run again.
func TestGateAttack4ClockStepReplay(t *testing.T) {
	e, _, b := armed(t, gatefix.WithFaultyRegistry())
	_, err := e.Admit(b)
	require.NoError(t, err)

	later := gatefix.Now + 7200
	c2 := gatefix.Times(gatefix.Fresh(gatefix.Template(t), 2), later-10, later+890)
	c2.PayloadRef.Height++
	e.StageDA(c2, gatefix.Blob(t))
	b2, _ := gatefix.Sign(t, "agent1", c2)
	e.Faulty.Before("Get", func() {
		e.Clock.Set(later)
		_, err := e.Admit(b2)
		assert.NoError(t, err)
		_, err = e.Gate.Prune(context.Background())
		assert.NoError(t, err)
		e.Clock.Set(gatefix.Now)
	})
	_, err = e.Admit(b)
	require.ErrorIs(t, err, gate.ErrClockRegression)
	require.Equal(t, 2, e.Exec.Calls())
}
