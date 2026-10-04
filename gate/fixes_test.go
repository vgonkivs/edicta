package gate_test

import (
	"context"
	"crypto/ed25519"
	"log/slog"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/registry"
	"github.com/vgonkivs/edicta/test/gatefix"
)

// signedToken signs an Authorization with the gate key for the given hashes.
func signedToken(t *testing.T, commitmentHash, actionHash []byte, expires uint64) []byte {
	t.Helper()
	a := commitment.Authorization{
		CommitmentHash: commitmentHash, ActionHash: actionHash, GateID: gatefix.GateID,
		Expires: expires, Path: commitment.PathDA,
	}
	canon, err := commitment.EncodeAuthorization(&a)
	require.NoError(t, err)
	sig := ed25519.Sign(gatefix.Key(t, "gate1"), commitment.AuthorizationSigningMessage(commitment.HashAuthorization(canon)))
	out, err := commitment.EncodeSignedAuthorization(&commitment.SignedAuthorization{Authorization: a, Signature: sig})
	require.NoError(t, err)
	return out
}

func seed(t *testing.T, e *gatefix.Env, c *commitment.Commitment, h, entryAction commitment.Hash, token []byte) {
	t.Helper()
	require.NoError(t, e.Reg.Consume(context.Background(), registry.Entry{
		Key: gatefix.KeyOf(c), CommitmentHash: h, ActionHash: entryAction, Path: registry.PathDA,
		AuthorizedAt: gatefix.Now, ValidUntil: c.ValidUntil, Authorization: token,
	}, 0))
}

func TestRetryFollowsTheStoredToken(t *testing.T) {
	t.Run("token signed for other bytes, entry field correct", func(t *testing.T) {
		e, c, b, h := happy(t)
		other := commitment.Hash{9, 9, 9}
		seed(t, e, c, h, commitment.Hash(c.Action.Hash), signedToken(t, h[:], other[:], c.ValidUntil))

		res, err := e.AuthorizeWith(b, gatefix.Action(t))
		require.ErrorIs(t, err, commitment.ErrActionMismatch)
		assert.NotErrorIs(t, err, gate.ErrNonceUsed)
		assert.Empty(t, res.Authorization)
		assert.Len(t, e.Metrics.Mismatches(), 1)
	})
	t.Run("token for another commitment, entry field correct", func(t *testing.T) {
		e, c, b, h := happy(t)
		other := commitment.Hash{7, 7, 7}
		seed(t, e, c, h, commitment.Hash(c.Action.Hash), signedToken(t, other[:], c.Action.Hash, c.ValidUntil))

		res, err := e.AuthorizeWith(b, gatefix.Action(t))
		require.Error(t, err)
		assert.Empty(t, res.Authorization)
	})
	t.Run("entry field wrong, token correct", func(t *testing.T) {
		e, c, b, h := happy(t)
		token := signedToken(t, h[:], c.Action.Hash, c.ValidUntil)
		seed(t, e, c, h, commitment.Hash{1, 2, 3}, token)

		res, err := e.AuthorizeWith(b, gatefix.Action(t))
		require.ErrorIs(t, err, gate.ErrNonceUsed)
		assert.Equal(t, token, res.Authorization, "the signed token is the source of truth")
	})
	t.Run("token correct, other bytes presented", func(t *testing.T) {
		e, c, b, h := happy(t)
		seed(t, e, c, h, commitment.Hash(c.Action.Hash), signedToken(t, h[:], c.Action.Hash, c.ValidUntil))

		res, err := e.AuthorizeWith(b, gatefix.OtherAction(t, 1))
		require.ErrorIs(t, err, commitment.ErrActionMismatch)
		assert.Empty(t, res.Authorization)
	})
}

type tallySigner struct {
	inner gate.Signer
	n     atomic.Int32
}

func (s *tallySigner) PublicKey() ed25519.PublicKey { return s.inner.PublicKey() }
func (s *tallySigner) Sign(ctx context.Context, m []byte) ([]byte, error) {
	s.n.Add(1)
	return s.inner.Sign(ctx, m)
}

// The clock steps back during the payload fetch, within the tolerance but
// before the commitment is valid; the second time check must refuse it.
func TestSecondTimeCheckRefusesAStepBackDuringFetch(t *testing.T) {
	inner, err := gate.NewEd25519Signer(gatefix.Key(t, "gate1"))
	require.NoError(t, err)
	cs := &tallySigner{inner: inner}
	e, c, b, _ := happy(t, gatefix.WithSigner(cs), gatefix.WithConfig(func(g *gate.Config) {
		g.ClockTolerance, g.PruneGrace = 8000, 8001
	}))
	e.DA.OnFetch(func() { e.Clock.Set(c.IssuedAt - e.Cfg.SkewS - 1) })

	res, err := e.AuthorizeWith(b, gatefix.Action(t))
	require.ErrorIs(t, err, commitment.ErrNotYetValid)
	assert.Empty(t, res.Authorization)
	assert.Zero(t, cs.n.Load(), "nothing is signed")
	_, err = e.Entry(c)
	require.ErrorIs(t, err, registry.ErrNotFound)
}

func TestSecondTimeCheckRefusesExpiryDuringFetch(t *testing.T) {
	inner, err := gate.NewEd25519Signer(gatefix.Key(t, "gate1"))
	require.NoError(t, err)
	cs := &tallySigner{inner: inner}
	e, c, b, _ := happy(t, gatefix.WithSigner(cs))
	e.DA.OnFetch(func() { e.Clock.Set(c.ValidUntil + e.Cfg.SkewS + 1) })

	_, err = e.AuthorizeWith(b, gatefix.Action(t))
	require.Error(t, err)
	assert.Zero(t, cs.n.Load())
	_, err = e.Entry(c)
	require.ErrorIs(t, err, registry.ErrNotFound)
}

func TestNewValidatesAndCopiesScope(t *testing.T) {
	typ := gatefix.ActionType
	for name, sc := range map[string]commitment.GateScope{
		"empty gate id":        {GateID: "", ActionTypes: []string{typ}},
		"gate id with a space": {GateID: "gate id", ActionTypes: []string{typ}},
		"gate id too long":     {GateID: string(make([]byte, 65)), ActionTypes: []string{typ}},
		"nil action types":     {GateID: gatefix.GateID},
		"empty action types":   {GateID: gatefix.GateID, ActionTypes: []string{}},
		"upper case type":      {GateID: gatefix.GateID, ActionTypes: []string{"Application/X"}},
		"type without slash":   {GateID: gatefix.GateID, ActionTypes: []string{"json"}},
		"duplicate type":       {GateID: gatefix.GateID, ActionTypes: []string{typ, typ}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := gatefix.TryNew(t, gatefix.WithScope(sc))
			require.ErrorIs(t, err, gate.ErrInvalidConfig)
		})
	}

	t.Run("later writes by the caller have no effect", func(t *testing.T) {
		types := []string{typ}
		e, _, b, _ := happy(t, gatefix.WithScope(commitment.GateScope{GateID: gatefix.GateID, ActionTypes: types}))
		types[0] = "application/json"
		_, err := e.AuthorizeWith(b, gatefix.Action(t))
		require.NoError(t, err)
	})
}

// A stored token whose hashes match but whose signature is not the gate's is
// never handed out; it fails closed like a stored mismatch, with
// commitment.ErrActionMismatch.
func TestRetryRefusesAStoredTokenWithoutTheGateSignature(t *testing.T) {
	foreign := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	resign := func(t *testing.T, tok []byte, key ed25519.PrivateKey) []byte {
		sa, _, err := commitment.DecodeSignedAuthorization(tok)
		require.NoError(t, err)
		canon, err := commitment.EncodeAuthorization(&sa.Authorization)
		require.NoError(t, err)
		sa.Signature = ed25519.Sign(key, commitment.AuthorizationSigningMessage(commitment.HashAuthorization(canon)))
		out, err := commitment.EncodeSignedAuthorization(sa)
		require.NoError(t, err)
		return out
	}
	forge := map[string]func(t *testing.T, tok []byte) []byte{
		"signed by another key": func(t *testing.T, tok []byte) []byte { return resign(t, tok, foreign) },
		"bit-flipped signature": func(t *testing.T, tok []byte) []byte {
			sa, _, err := commitment.DecodeSignedAuthorization(tok)
			require.NoError(t, err)
			sa.Signature[0] ^= 1
			out, err := commitment.EncodeSignedAuthorization(sa)
			require.NoError(t, err)
			return out
		},
		"zero signature": func(t *testing.T, tok []byte) []byte {
			sa, _, err := commitment.DecodeSignedAuthorization(tok)
			require.NoError(t, err)
			sa.Signature = make([]byte, 64)
			out, err := commitment.EncodeSignedAuthorization(sa)
			require.NoError(t, err)
			return out
		},
	}
	for name, f := range forge {
		t.Run(name, func(t *testing.T) {
			e, c, b, h := happy(t)
			tok := f(t, signedToken(t, h[:], c.Action.Hash, c.ValidUntil))
			seed(t, e, c, h, commitment.Hash(c.Action.Hash), tok)

			res, err := e.AuthorizeWith(b, gatefix.Action(t))
			require.ErrorIs(t, err, commitment.ErrActionMismatch)
			assert.NotErrorIs(t, err, gate.ErrNonceUsed)
			assert.Empty(t, res.Authorization)
			assert.NotEmpty(t, e.Logs.Records(slog.LevelError))
			assert.Contains(t, e.Metrics.Mismatches(), h)
		})
	}
}
