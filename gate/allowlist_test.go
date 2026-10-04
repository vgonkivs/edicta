package gate_test

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/test/gatefix"
)

func TestStaticAllowlist(t *testing.T) {
	a1, a2 := gatefix.Pub(t, "agent1"), gatefix.Pub(t, "agent2")
	al, err := gate.NewStaticAllowlist(map[string][]byte{"dca-agent-1": a1, "dca-agent-2": a2})
	require.NoError(t, err)
	got, err := al.PubKey(context.Background(), "dca-agent-1")
	require.NoErrorf(t, err, "PubKey = %x", got)
	require.Equalf(t, string(a1), string(got[:]), "PubKey = %x, %v", got, err)
	_, err = al.PubKey(context.Background(), "nobody")
	require.ErrorIs(t, err, gate.ErrAgentNotAllowed, "absent id")
	bad := map[string]map[string][]byte{
		"small-order key":      {"a": append([]byte{1}, make([]byte, 31)...)},
		"short key":            {"a": a1[:31]},
		"id with space":        {"a b": a1},
		"empty id":             {"": a1},
		"id of 65 chars":       {strings.Repeat("a", 65): a1},
		"same key under 2 ids": {"a": a1, "b": a1},
	}
	for name, m := range bad {
		_, err := gate.NewStaticAllowlist(m)
		assert.Errorf(t, err, "%s: accepted", name)
	}
	_, err = gate.NewStaticAllowlist(map[string][]byte{"a": append([]byte{1}, make([]byte, 31)...)})
	assert.ErrorIs(t, err, commitment.ErrInvalidPublicKey, "small-order key error")
}

func TestLoadAllowlistJSON(t *testing.T) {
	a1, a2 := hex.EncodeToString(gatefix.Pub(t, "agent1")), hex.EncodeToString(gatefix.Pub(t, "agent2"))
	good := `{"version":0,"agents":[{"agent_id":"dca-agent-1","pubkey":"` + a1 + `"},{"agent_id":"dca-agent-2","pubkey":"` + a2 + `"}]}`
	al, err := gate.LoadAllowlistJSON(strings.NewReader(good))
	require.NoError(t, err)
	k, err := al.PubKey(context.Background(), "dca-agent-2")
	require.NoErrorf(t, err, "%x", k)
	require.Equalf(t, a2, hex.EncodeToString(k[:]), "%x %v", k, err)
	bad := map[string]string{
		"duplicate id":   `{"version":0,"agents":[{"agent_id":"x","pubkey":"` + a1 + `"},{"agent_id":"x","pubkey":"` + a2 + `"}]}`,
		"duplicate key":  `{"version":0,"agents":[{"agent_id":"x","pubkey":"` + a1 + `"},{"agent_id":"y","pubkey":"` + a1 + `"}]}`,
		"bad hex":        `{"version":0,"agents":[{"agent_id":"x","pubkey":"zz"}]}`,
		"short key":      `{"version":0,"agents":[{"agent_id":"x","pubkey":"` + a1[:62] + `"}]}`,
		"small order":    `{"version":0,"agents":[{"agent_id":"x","pubkey":"0100000000000000000000000000000000000000000000000000000000000000"}]}`,
		"unknown field":  `{"version":0,"agents":[],"extra":1}`,
		"wrong version":  `{"version":1,"agents":[]}`,
		"not json":       `{`,
		"trailing value": good + `{}`,
	}
	for name, in := range bad {
		_, err := gate.LoadAllowlistJSON(strings.NewReader(in))
		assert.Errorf(t, err, "%s: accepted", name)
	}
}

func TestEd25519Signer(t *testing.T) {
	priv := gatefix.Key(t, "gate1")
	s, err := gate.NewEd25519Signer(priv)
	require.NoError(t, err)
	require.Equal(t, string(priv.Public().(ed25519.PublicKey)), string(s.PublicKey()), "public key differs")
	sig, err := s.Sign(context.Background(), []byte("m"))
	require.NoError(t, err, "signature does not verify")
	require.Truef(t, ed25519.Verify(s.PublicKey(), []byte("m"), sig), "signature does not verify: %v", err)
	_, err = gate.NewEd25519Signer(priv[:10])
	require.Error(t, err, "accepted a short private key")
	_, err = gate.NewEd25519Signer(nil)
	require.Error(t, err, "accepted a nil key")
}
