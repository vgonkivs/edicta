package sdk_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding"
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/sdk"
	"github.com/vgonkivs/edicta/test/gatefix"
	"github.com/vgonkivs/edicta/test/sdkfix"
)

func TestEd25519SignerSignsOnlyTheTaggedHash(t *testing.T) {
	priv := gatefix.Key(t, "agent1")
	s, err := sdk.NewEd25519Signer(priv)
	require.NoError(t, err)
	assert.Equal(t, priv.Public().(ed25519.PublicKey), s.PublicKey())

	var h commitment.Hash
	copy(h[:], bytes.Repeat([]byte{0x42}, 32))
	sig, err := s.SignCommitment(bg, h)
	require.NoError(t, err)
	require.Len(t, sig, ed25519.SignatureSize)
	assert.True(t, ed25519.Verify(s.PublicKey(), commitment.SigningMessage(h), sig))
	assert.False(t, ed25519.Verify(s.PublicKey(), h[:], sig), "not a signature over the bare hash")
	cm, _, err := commitment.Sign(priv, gatefix.Template(t))
	require.NoError(t, err)
	h2, err := commitment.HashOf(&cm.Commitment)
	require.NoError(t, err)
	sig2, err := s.SignCommitment(bg, h2)
	require.NoError(t, err)
	assert.Equal(t, cm.Signature, sig2, "same bytes as the commitment package's own signature")
}

func TestEd25519SignerRejectsBadKeys(t *testing.T) {
	t.Run("short key", func(t *testing.T) {
		s, err := sdk.NewEd25519Signer(make([]byte, 31))
		require.Error(t, err)
		assert.Nil(t, s)
	})
	t.Run("nil key", func(t *testing.T) {
		_, err := sdk.NewEd25519Signer(nil)
		require.Error(t, err)
	})
	for _, k := range sdkRejectKeys(t) {
		t.Run(k.id, func(t *testing.T) {
			priv := make([]byte, ed25519.PrivateKeySize)
			copy(priv[32:], k.pub)
			s, err := sdk.NewEd25519Signer(priv)
			require.ErrorIs(t, err, commitment.ErrInvalidPublicKey)
			assert.Nil(t, s)
		})
	}
}

func TestEd25519SignerNeverPrintsTheKey(t *testing.T) {
	priv := gatefix.Key(t, "agent1")
	s, err := sdk.NewEd25519Signer(priv)
	require.NoError(t, err)
	pubHex := sdkfix.HexOf(priv.Public().(ed25519.PublicKey))
	seedHex := sdkfix.HexOf(priv.Seed())
	privHex := sdkfix.HexOf(priv)

	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("agent", "signer", s)
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("agent", "signer", s)

	outs := []string{
		fmt.Sprint(s), fmt.Sprintf("%v", s), fmt.Sprintf("%+v", s), fmt.Sprintf("%#v", s), fmt.Sprintf("%s", s),
		fmt.Sprintf("%x", s), fmt.Sprintf("%d", s), s.String(), buf.String(),
	}
	for _, out := range outs {
		assert.NotContains(t, out, seedHex)
		assert.NotContains(t, out, privHex)
		assert.NotContains(t, out, string(priv.Seed()))
		assert.NotContains(t, out, string(priv))
	}
	assert.Equal(t, "Ed25519Signer("+pubHex+")", s.String())
	assert.Contains(t, buf.String(), pubHex)

	_, err = json.Marshal(s)
	require.Error(t, err, "no JSON form")
	if tm, ok := any(s).(encoding.TextMarshaler); ok {
		_, err = tm.MarshalText()
		require.Error(t, err, "no text form")
	}
}

func TestEd25519SignerClose(t *testing.T) {
	priv := gatefix.Key(t, "agent1")
	s, err := sdk.NewEd25519Signer(bytes.Clone(priv))
	require.NoError(t, err)
	require.NoError(t, s.Close())
	sig, err := s.SignCommitment(bg, commitment.Hash{})
	require.ErrorIs(t, err, sdk.ErrSignerClosed)
	assert.Nil(t, sig)
	require.NoError(t, s.Close(), "Close is idempotent")
	assert.Equal(t, priv.Public().(ed25519.PublicKey), s.PublicKey(), "the public key stays readable")
}

func TestEd25519SignerCopiesTheKey(t *testing.T) {
	priv := bytes.Clone(gatefix.Key(t, "agent1"))
	s, err := sdk.NewEd25519Signer(priv)
	require.NoError(t, err)
	for i := range priv {
		priv[i] = 0
	}
	sig, err := s.SignCommitment(bg, commitment.Hash{1})
	require.NoError(t, err)
	assert.True(t, ed25519.Verify(s.PublicKey(), commitment.SigningMessage(commitment.Hash{1}), sig))
}
