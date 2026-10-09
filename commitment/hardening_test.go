package commitment_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
)

func TestNilCommitment(t *testing.T) {
	_, _, p := baseCommitment(t)
	rows := []struct {
		name string
		call func() error
		want error
	}{
		{"ValidateStatic", func() error { return commitment.ValidateStatic(nil, p) }, nil},
		{"CheckTime", func() error { return commitment.CheckTime(nil, edgeNow, p) }, commitment.ErrExpired},
		{"CheckScope", func() error { return commitment.CheckScope(nil, commitment.GateScope{}) }, commitment.ErrScopeMismatch},
		{"CheckAction", func() error { return commitment.CheckAction(nil, []byte{1}, testSalt) }, commitment.ErrActionMismatch},
		{"CheckPayload", func() error { return commitment.CheckPayload(nil, []byte("x")) }, commitment.ErrPayloadSizeMismatch},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			var err error
			func() {
				defer func() {
					v := recover()
					require.Nilf(t, v, "panic: %v", v)
				}()
				err = r.call()
			}()
			require.Error(t, err, "nil error")
			if r.want != nil {
				require.ErrorIsf(t, err, r.want, "want %v, got", r.want)
			}
			require.ErrorContains(t, err, "nil commitment")
		})
	}
}

func TestTagLengths(t *testing.T) {
	tags := map[string]string{
		"TagCommitment": commitment.TagCommitment,
		"TagSig":        commitment.TagSig,
		"TagReceipt":    commitment.TagReceipt,
		"TagAction":     commitment.TagAction,
		"TagAuth":       commitment.TagAuthorization,
		"TagAuthSig":    commitment.TagAuthorizationSig,
	}
	for name, v := range tags {
		n := len(v)
		assert.GreaterOrEqualf(t, n, 1, "%s length %d outside 1..255", name, n)
		assert.LessOrEqualf(t, n, 255, "%s length %d outside 1..255", name, n)
	}
}

func TestSignDoesNotAliasCaller(t *testing.T) {
	c, _, _ := baseCommitment(t)
	s, h, err := commitment.Sign(loadKey(t, "agent1"), c)
	require.NoError(t, err)
	wantNonce := bytes.Clone(s.Commitment.Nonce)
	wantKey := bytes.Clone(s.Commitment.AgentPubKey)
	for i := range c.Nonce {
		c.Nonce[i] ^= 0xff
	}
	for i := range c.AgentPubKey {
		c.AgentPubKey[i] ^= 0xff
	}
	require.Equal(t, hex.EncodeToString(wantNonce), hex.EncodeToString(s.Commitment.Nonce), "envelope changed after caller mutation")
	require.Equal(t, hex.EncodeToString(wantKey), hex.EncodeToString(s.Commitment.AgentPubKey), "envelope changed after caller mutation")
	hh, err := commitment.HashOf(&s.Commitment)
	require.NoError(t, err)
	require.Equal(t, h, hh, "envelope no longer matches returned hash")
	err = verifyErr(s)
	require.NoError(t, err, "envelope no longer verifies")
}

func TestNilCommitmentEncoding(t *testing.T) {
	priv := loadKey(t, "agent1")
	rows := []struct {
		name string
		call func() error
	}{
		{"Sign", func() error { _, _, err := commitment.Sign(priv, nil); return err }},
		{"Encode", func() error { _, err := commitment.Encode(nil); return err }},
		{"HashOf", func() error { _, err := commitment.HashOf(nil); return err }},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			defer func() {
				v := recover()
				require.Nilf(t, v, "panic: %v", v)
			}()
			err := r.call()
			require.Error(t, err, "nil error")
			require.ErrorContains(t, err, "nil commitment")
		})
	}
}
