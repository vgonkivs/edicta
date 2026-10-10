package demo

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
	"github.com/vgonkivs/edicta/sdk"
)

// saltedGate signs a v1 Authorization over the action hash computed with the
// salt it was handed, as the real gate does.
type saltedGate struct {
	priv    ed25519.PrivateKey
	gateID  string
	expires uint64
	salt    []byte
}

func (g *saltedGate) AuthorizeWithVerdict(_ context.Context, _, action, salt []byte) ([]byte, []byte, error) {
	g.salt = bytes.Clone(salt)
	ah, err := commitment.ActionHash(bankaction.ActionType, salt, action)
	if err != nil {
		return nil, nil, err
	}
	a := commitment.Authorization{
		Version: commitment.Version, CommitmentHash: make([]byte, 32), ActionHash: ah[:], GateID: g.gateID,
		Expires: g.expires, Path: commitment.PathDA, Mode: commitment.ModeStrict,
	}
	canon, err := commitment.EncodeAuthorization(&a)
	if err != nil {
		return nil, nil, err
	}
	sig := ed25519.Sign(g.priv, commitment.AuthorizationSigningMessage(commitment.HashAuthorization(canon)))
	raw, err := commitment.EncodeSignedAuthorization(&commitment.SignedAuthorization{Authorization: a, Signature: sig})
	return raw, nil, err
}

func TestAuthorizeStepChecksTheSaltedAuthorization(t *testing.T) {
	e := newTestEnv(t)
	r := e.runner(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	r.gatePub, r.gateID = pub, "demo-gate"
	g := &saltedGate{priv: priv, gateID: r.gateID, expires: uint64(r.deps.now().Unix()) + 600}

	salt := bytes.Repeat([]byte{5}, commitment.ActionSaltSize)
	d := &decision{res: &sdk.Result{Envelope: []byte{1}, Action: []byte("send"), ActionSalt: salt}}
	require.NoError(t, r.authorizeWith(context.Background(), g, d))
	assert.Equal(t, salt, g.salt, "the gate gets the salt the SDK drew")
	assert.NotEmpty(t, d.authBytes)
	assert.Equal(t, g.expires, d.authExpires)

	// An Authorization for another salt is not the one for this action.
	d2 := &decision{res: &sdk.Result{Envelope: []byte{1}, Action: []byte("send"), ActionSalt: salt}}
	other := &otherSaltGate{saltedGate: g}
	err = r.authorizeWith(context.Background(), other, d2)
	require.ErrorIs(t, err, commitment.ErrActionMismatch)
	assert.Nil(t, d2.authBytes)
}

type otherSaltGate struct{ *saltedGate }

func (g *otherSaltGate) AuthorizeWithVerdict(ctx context.Context, env, action, _ []byte) ([]byte, []byte, error) {
	return g.saltedGate.AuthorizeWithVerdict(ctx, env, action, bytes.Repeat([]byte{6}, commitment.ActionSaltSize))
}
