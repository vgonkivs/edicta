package gate_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/test/gatefix"
)

func strangerKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x5a
	}
	return ed25519.NewKeyFromSeed(seed)
}

func recordWith(e *gatefix.Env, key ed25519.PrivateKey, b []byte, ref string) ([]byte, error) {
	return e.Gate.Record(context.Background(), b, ref, key.Public().(ed25519.PublicKey), gatefix.RecordSig(e.T, key, b, ref))
}

func TestRecordExecutorChecks(t *testing.T) {
	t.Run("the receipt carries the claim and a verifier checks it without the gate", func(t *testing.T) {
		e, _, b, h := authorized(t)
		r, err := e.Record(b, "order-42")
		require.NoError(t, err)
		gatefix.CheckReceipt(t, r, h, "order-42", gatefix.GateID, gatefix.Pub(t, "gate1"), 0)
		sr, _, err := commitment.VerifyReceipt(r)
		require.NoError(t, err)
		assert.Equal(t, []byte(gatefix.ExecutorPub(t, "executor1")), sr.Receipt.ExecutorPubKey)
		assert.Equal(t, gatefix.RecordSig(t, gatefix.ExecutorKey(t, "executor1"), b, "order-42"), sr.Receipt.ExecutorSignature)
	})
	t.Run("a second allowlisted executor may claim for a fresh decision", func(t *testing.T) {
		e, _, b, h := authorized(t)
		r, err := e.RecordAs("executor2", b, "order-43")
		require.NoError(t, err)
		gatefix.CheckReceipt(t, r, h, "order-43", gatefix.GateID, gatefix.Pub(t, "gate1"), 0)
	})
	t.Run("an unknown executor", func(t *testing.T) {
		e, c, b, _ := authorized(t)
		r, err := recordWith(e, strangerKey(), b, "ref-1")
		require.ErrorIs(t, err, gate.ErrExecutorNotAllowed)
		assert.Nil(t, r)
		ent, _ := e.Entry(c)
		assert.Nil(t, ent.Receipt)
	})
	t.Run("the agent key and the gate key are no executors", func(t *testing.T) {
		e, _, b, _ := authorized(t)
		_, err := recordWith(e, gatefix.Key(t, "agent1"), b, "ref-1")
		require.ErrorIs(t, err, gate.ErrExecutorNotAllowed)
		_, err = recordWith(e, gatefix.Key(t, "gate1"), b, "ref-1")
		require.ErrorIs(t, err, gate.ErrExecutorNotAllowed)
	})
	t.Run("an empty executor allowlist records nothing", func(t *testing.T) {
		e, _, b, _ := authorized(t, gatefix.WithConfig(func(c *gate.Config) { c.ExecutorKeys = nil }))
		_, err := e.Record(b, "ref-1")
		require.ErrorIs(t, err, gate.ErrExecutorNotAllowed)
	})
	t.Run("the signature is checked before the allowlist", func(t *testing.T) {
		e, _, b, _ := authorized(t)
		k := strangerKey()
		_, err := e.Gate.Record(context.Background(), b, "ref-1", k.Public().(ed25519.PublicKey), make([]byte, 64))
		require.ErrorIs(t, err, commitment.ErrSignatureInvalid)
		assert.NotErrorIs(t, err, gate.ErrExecutorNotAllowed)
	})
	t.Run("the allowlist is checked before the registry", func(t *testing.T) {
		e, _, b, _ := happy(t) // never authorized
		_, err := recordWith(e, strangerKey(), b, "ref-1")
		require.ErrorIs(t, err, gate.ErrExecutorNotAllowed)
		assert.NotErrorIs(t, err, gate.ErrNotAuthorized)
	})
	t.Run("a known executor before any authorization", func(t *testing.T) {
		e, _, b, _ := happy(t)
		_, err := e.Record(b, "ref-1")
		require.ErrorIs(t, err, gate.ErrNotAuthorized)
	})
}

func TestRecordRefusesAClaimMadeForAnotherGate(t *testing.T) {
	e, c, b, _ := authorized(t)
	k := gatefix.ExecutorKey(t, "executor1")
	sig := gatefix.RecordSigFor(t, k, "gate-paper-2", b, "ref-1")
	r, err := e.Gate.Record(context.Background(), b, "ref-1", k.Public().(ed25519.PublicKey), sig)
	require.ErrorIs(t, err, commitment.ErrSignatureInvalid)
	assert.Nil(t, r)
	ent, _ := e.Entry(c)
	assert.Nil(t, ent.Receipt)
	_, err = e.Record(b, "ref-1")
	require.NoError(t, err, "the request for this gate still works")
}

func TestRecordBadExecutorSignatures(t *testing.T) {
	good := func(e *gatefix.Env, b []byte, ref string) (ed25519.PublicKey, []byte) {
		k := gatefix.ExecutorKey(t, "executor1")
		return k.Public().(ed25519.PublicKey), gatefix.RecordSig(t, k, b, ref)
	}
	cases := map[string]func(e *gatefix.Env, b []byte) (string, ed25519.PublicKey, []byte){
		"flipped bit": func(e *gatefix.Env, b []byte) (string, ed25519.PublicKey, []byte) {
			pub, sig := good(e, b, "ref-1")
			sig[10] ^= 1
			return "ref-1", pub, sig
		},
		"signed for another reference": func(e *gatefix.Env, b []byte) (string, ed25519.PublicKey, []byte) {
			pub, sig := good(e, b, "ref-2")
			return "ref-1", pub, sig
		},
		"signed by another allowlisted key": func(e *gatefix.Env, b []byte) (string, ed25519.PublicKey, []byte) {
			_, sig := good(e, b, "ref-1")
			return "ref-1", gatefix.ExecutorPub(t, "executor2"), sig
		},
		"short signature": func(e *gatefix.Env, b []byte) (string, ed25519.PublicKey, []byte) {
			pub, sig := good(e, b, "ref-1")
			return "ref-1", pub, sig[:63]
		},
		"nil signature": func(e *gatefix.Env, b []byte) (string, ed25519.PublicKey, []byte) {
			pub, _ := good(e, b, "ref-1")
			return "ref-1", pub, nil
		},
		"identity key": func(e *gatefix.Env, b []byte) (string, ed25519.PublicKey, []byte) {
			id := make([]byte, 32)
			id[0] = 1
			return "ref-1", id, make([]byte, 64)
		},
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			e, c, b, _ := authorized(t)
			ref, pub, sig := f(e, b)
			r, err := e.Gate.Record(context.Background(), b, ref, pub, sig)
			require.Error(t, err)
			assert.True(t, errorsIsAny(err, commitment.ErrSignatureInvalid, commitment.ErrInvalidPublicKey, commitment.ErrFieldSize), "%v", err)
			assert.Nil(t, r)
			ent, _ := e.Entry(c)
			assert.Nil(t, ent.Receipt, "a refused request used up the receipt")
			_, err = e.Record(b, "ref-1")
			require.NoError(t, err)
		})
	}
	t.Run("signed for another decision", func(t *testing.T) {
		e, _, b, _ := authorized(t)
		c2 := gatefix.Fresh(gatefix.Template(t), 2)
		b2, _ := gatefix.Sign(t, "agent1", c2)
		k := gatefix.ExecutorKey(t, "executor1")
		_, err := e.Gate.Record(context.Background(), b, "ref-1", k.Public().(ed25519.PublicKey), gatefix.RecordSig(t, k, b2, "ref-1"))
		require.ErrorIs(t, err, commitment.ErrSignatureInvalid)
	})
}

func errorsIsAny(err error, ts ...error) bool {
	for _, t := range ts {
		if errors.Is(err, t) {
			return true
		}
	}
	return false
}

func TestRecordRailRefLimitWithExecutorSignature(t *testing.T) {
	e, _, b, _ := authorized(t)
	k := gatefix.ExecutorKey(t, "executor1")
	_, err := e.Gate.Record(context.Background(), b, strings.Repeat("a", 129), k.Public().(ed25519.PublicKey), make([]byte, 64))
	require.ErrorIs(t, err, commitment.ErrFieldSize)
	_, err = e.Record(b, strings.Repeat("a", 128))
	require.NoError(t, err)
}

func TestOneReceiptPerDecisionAcrossExecutors(t *testing.T) {
	e, c, b, _ := authorized(t)
	first, err := e.RecordAs("executor1", b, "ref-1")
	require.NoError(t, err)

	second, err := e.RecordAs("executor2", b, "ref-other")
	require.ErrorIs(t, err, gate.ErrReceiptExists)
	assert.Equal(t, first, second, "only the stored receipt leaves the gate")
	ent, _ := e.Entry(c)
	assert.Equal(t, first, ent.Receipt)
}

func TestNewChecksExecutorKeyRoles(t *testing.T) {
	ex := [32]byte(gatefix.ExecutorPub(t, "executor1"))
	for name, tc := range map[string]struct {
		keys [][32]byte
		want error
	}{
		"the gate key": {[][32]byte{ex, [32]byte(gatefix.Pub(t, "gate1"))}, commitment.ErrKeyRole},
		"an agent key": {[][32]byte{ex, [32]byte(gatefix.Pub(t, "agent1"))}, commitment.ErrKeyRole},
		"the identity": {[][32]byte{ex, {1}}, commitment.ErrInvalidPublicKey},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := gatefix.TryNew(t, gatefix.WithConfig(func(c *gate.Config) { c.ExecutorKeys = tc.keys }))
			require.ErrorIs(t, err, tc.want)
		})
	}
	t.Run("a key of OtherGateKeys", func(t *testing.T) {
		other := [32]byte(gatefix.ExecutorPub(t, "executor2"))
		_, err := gatefix.TryNew(t, gatefix.WithConfig(func(c *gate.Config) {
			c.OtherGateKeys = [][32]byte{other}
			c.ExecutorKeys = [][32]byte{other}
		}))
		require.ErrorIs(t, err, commitment.ErrKeyRole)
	})
	t.Run("ExecutorKeys is copied", func(t *testing.T) {
		keys := [][32]byte{ex}
		e, _, b, _ := authorized(t, gatefix.WithConfig(func(c *gate.Config) { c.ExecutorKeys = keys }))
		keys[0] = [32]byte{}
		_, err := e.Record(b, "ref-1")
		require.NoError(t, err)
	})
}

// An executor key that is the agent key of the presented commitment is refused
// before the registry is consulted. The commitment need not have been
// authorized, so this is reachable through the public API.
func TestRecordRefusesAnExecutorKeyThatIsTheAgentKey(t *testing.T) {
	e := gatefix.New(t)
	exec := gatefix.ExecutorKey(t, "executor1")
	c := gatefix.Clone(gatefix.Template(t))
	c.AgentPubKey = exec.Public().(ed25519.PublicKey)
	b, _ := gatefix.SignWith(t, exec, c)

	r, err := e.Record(b, "ref-1")
	require.ErrorIs(t, err, commitment.ErrKeyRole)
	assert.NotErrorIs(t, err, gate.ErrNotAuthorized, "the role check comes first")
	assert.Nil(t, r)

	// The same key as executor for a commitment of a real agent is fine.
	e2, _, b2, _ := authorized(t)
	_, err = e2.Record(b2, "ref-1")
	require.NoError(t, err)
}

func TestRecordWithANonDefaultGateID(t *testing.T) {
	const id = "gate-other-9"
	e := gatefix.New(t, gatefix.WithScope(commitment.GateScope{GateID: id, ActionTypes: []string{gatefix.ActionType}}))
	c := gatefix.Clone(gatefix.Template(t))
	c.Scope.GateID = id
	e.StageDA(c, gatefix.Blob(t))
	b, h := gatefix.Sign(t, "agent1", c)
	_, err := e.Authorize(b)
	require.NoError(t, err)

	k := gatefix.ExecutorKey(t, "executor1")
	pub := k.Public().(ed25519.PublicKey)
	_, err = e.Gate.Record(context.Background(), b, "ref-1", pub, gatefix.RecordSigFor(t, k, gatefix.GateID, b, "ref-1"))
	require.ErrorIs(t, err, commitment.ErrSignatureInvalid, "a request for the default gate id")

	r, err := e.Record(b, "ref-1")
	require.NoError(t, err)
	sr, _, err := commitment.VerifyReceipt(r)
	require.NoError(t, err)
	assert.Equal(t, id, sr.Receipt.GateID)
	require.NoError(t, commitment.VerifyRecordRequest(h, id, "ref-1", sr.Receipt.ExecutorPubKey, sr.Receipt.ExecutorSignature))
}
