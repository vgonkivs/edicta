package attacks_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
)

const (
	dir = "../../spec/vectors/"
	now = uint64(1791000060)
)

func readJSON(t testing.TB, name string, v any) {
	t.Helper()
	path := dir + "v1/" + name
	if name == "keys.json" {
		path = dir + name
	}
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	err = json.Unmarshal(b, v)
	require.NoError(t, err)
}

func key(t testing.TB, name string) ed25519.PrivateKey {
	var kf struct {
		Keys map[string]struct {
			SeedHex string `json:"seed_hex"`
		} `json:"keys"`
	}
	readJSON(t, "keys.json", &kf)
	seed, err := hex.DecodeString(kf.Keys[name].SeedHex)
	require.NoError(t, err)
	return ed25519.NewKeyFromSeed(seed)
}

type env struct {
	c      *commitment.Commitment
	action []byte
	salt   []byte
	gate   commitment.GateScope
	params commitment.Params
}

func setup(t testing.TB) env {
	var vf struct {
		RawParams map[string]string `json:"params"`
		Gate      struct {
			GateID      string   `json:"gate_id"`
			ActionTypes []string `json:"action_types"`
		} `json:"gate"`
		Cases []struct {
			ID        string `json:"id"`
			Hex       string `json:"commitment_cbor_hex"`
			ActionHex string `json:"action_hex"`
			SaltHex   string `json:"action_salt_hex"`
		} `json:"cases"`
	}
	readJSON(t, "valid.json", &vf)
	n := func(s string) uint64 {
		v, err := strconv.ParseUint(s, 10, 64)
		require.NoError(t, err)
		return v
	}
	var e env
	for _, c := range vf.Cases {
		if c.ID == "minimal_lmt" {
			b, _ := hex.DecodeString(c.Hex)
			cm, err := commitment.Decode(b)
			require.NoError(t, err)
			e.c = cm
			e.action, _ = hex.DecodeString(c.ActionHex)
			e.salt, _ = hex.DecodeString(c.SaltHex)
		}
	}
	require.NotNil(t, e.c, "vector minimal_lmt missing")
	e.gate = commitment.GateScope{GateID: vf.Gate.GateID, ActionTypes: vf.Gate.ActionTypes}
	e.params = commitment.Params{FibreRetentionS: n(vf.RawParams["fibre_retention_s"]), BlobRetentionS: n(vf.RawParams["blob_retention_s"]), SkewS: n(vf.RawParams["skew_s"])}
	return e
}

func envelope(t testing.TB, c *commitment.Commitment, priv ed25519.PrivateKey) []byte {
	s, _, err := commitment.Sign(priv, c)
	require.NoError(t, err)
	b, err := commitment.EncodeSigned(s)
	require.NoError(t, err)
	return b
}

func clone(c *commitment.Commitment) *commitment.Commitment {
	d := *c
	d.Action.Hash = append([]byte(nil), c.Action.Hash...)
	return &d
}

func mustReject(t *testing.T, err error, want error) {
	t.Helper()
	require.Error(t, err)
	require.ErrorIs(t, err, want)
}

// gateAdmit is the stateless part of the gate: verify, then match the
// presented action bytes and the vector salt against the committed hash.
func gateAdmit(e env, b []byte, at uint64, action []byte) error {
	return gateAdmitSalt(e, b, at, action, e.salt)
}

func gateAdmitSalt(e env, b []byte, at uint64, action, salt []byte) error {
	s, _, err := commitment.VerifyForGate(b, at, e.gate, e.params)
	if err != nil {
		return err
	}
	return commitment.CheckAction(&s.Commitment, action, salt)
}

func TestAttack1ActionWithoutCommitment(t *testing.T) {
	e := setup(t)
	req := e.action
	for name, b := range map[string][]byte{
		"nil":        nil,
		"empty":      {},
		"empty map":  {0xa0},
		"bare order": {0xa1, 0x01, 0xa0},
		"unsigned":   mustEncode(t, e.c),
		"zero sig":   envelopeWithSig(t, e.c, make([]byte, 64)),
		"garbage":    []byte("not cbor at all"),
	} {
		t.Run(name, func(t *testing.T) {
			err := gateAdmit(e, b, now, req)
			require.Error(t, err, "gate accepted")
		})
	}
}

func mustEncode(t testing.TB, c *commitment.Commitment) []byte {
	b, err := commitment.Encode(c)
	require.NoError(t, err)
	return b
}

func envelopeWithSig(t testing.TB, c *commitment.Commitment, sig []byte) []byte {
	b, err := commitment.EncodeSigned(&commitment.SignedCommitment{Commitment: *c, Signature: sig})
	require.NoError(t, err)
	return b
}

// Amount, recipient and asset live in the action bytes, which the core never
// parses: presenting any other bytes than the committed ones is refused. The
// example is a JSON action; the check is the same for any format.
func TestAttack2ActionOutsideCommitment(t *testing.T) {
	e := setup(t)
	const typ = "application/json"
	e.gate.ActionTypes = []string{typ}
	committed := []byte(`{"to":"0xA1","asset":"TIA","amount":"100"}`)
	h, err := commitment.ActionHash(typ, e.salt, committed)
	require.NoError(t, err)
	c := clone(e.c)
	c.Action = commitment.Action{Type: typ, Hash: h[:]}
	b := envelope(t, c, key(t, "agent1"))
	err = gateAdmit(e, b, now, committed)
	require.NoError(t, err, "control")

	tests := map[string]string{
		"amount raised":           `{"to":"0xA1","asset":"TIA","amount":"101"}`,
		"amount appended digit":   `{"to":"0xA1","asset":"TIA","amount":"1000"}`,
		"recipient changed":       `{"to":"0xA2","asset":"TIA","amount":"100"}`,
		"asset changed":           `{"to":"0xA1","asset":"ETH","amount":"100"}`,
		"extra field":             `{"to":"0xA1","asset":"TIA","amount":"100","memo":"x"}`,
		"same meaning other form": `{"to": "0xA1", "asset": "TIA", "amount": "100"}`,
		"field order changed":     `{"asset":"TIA","to":"0xA1","amount":"100"}`,
	}
	for name, changed := range tests {
		t.Run(name, func(t *testing.T) {
			mustReject(t, gateAdmit(e, b, now, []byte(changed)), commitment.ErrActionMismatch)
		})
	}

	t.Run("every single byte flip", func(t *testing.T) {
		for i := range committed {
			bad := append([]byte(nil), committed...)
			bad[i] ^= 1
			mustReject(t, gateAdmit(e, b, now, bad), commitment.ErrActionMismatch)
		}
	})
	t.Run("every truncation", func(t *testing.T) {
		for i := 1; i < len(committed); i++ {
			mustReject(t, gateAdmit(e, b, now, committed[:i]), commitment.ErrActionMismatch)
		}
	})
	t.Run("size limits", func(t *testing.T) {
		mustReject(t, gateAdmit(e, b, now, nil), commitment.ErrActionSize)
		mustReject(t, gateAdmit(e, b, now, make([]byte, commitment.MaxActionSize+1)), commitment.ErrActionSize)
	})
	t.Run("committed bytes under another type", func(t *testing.T) {
		d := clone(e.c)
		d.Action.Type = "application/octet-stream" // the hash was computed under the json type
		bb := envelope(t, d, key(t, "agent1"))
		e2 := e
		e2.gate.ActionTypes = []string{"application/octet-stream"}
		mustReject(t, gateAdmit(e2, bb, now, committed), commitment.ErrActionMismatch)
	})
	t.Run("rewriting the committed hash after signing", func(t *testing.T) {
		other := []byte(`{"to":"0xBAD","asset":"TIA","amount":"100"}`)
		oh, err := commitment.ActionHash(typ, e.salt, other)
		require.NoError(t, err)
		s, _, err := commitment.Sign(key(t, "agent1"), c)
		require.NoError(t, err)
		s.Commitment.Action.Hash = oh[:]
		bb, err := commitment.EncodeSigned(s)
		require.NoError(t, err)
		mustReject(t, gateAdmit(e, bb, now, other), commitment.ErrSignatureInvalid)
	})
	t.Run("real minimal order against the json commitment", func(t *testing.T) {
		mustReject(t, gateAdmit(e, b, now, setup(t).action), commitment.ErrActionMismatch)
	})
}

func TestAttack3Expired(t *testing.T) {
	e := setup(t)
	b := envelope(t, e.c, key(t, "agent1"))
	req := e.action
	vu := e.c.ValidUntil
	for name, at := range map[string]uint64{
		"now == valid_until - skew": vu - e.params.SkewS,
		"now == valid_until":        vu,
		"now == valid_until + 1":    vu + 1,
		"long after":                vu + 86400*365,
		"max uint64":                ^uint64(0),
	} {
		t.Run(name, func(t *testing.T) { mustReject(t, gateAdmit(e, b, at, req), commitment.ErrExpired) })
	}
	t.Run("ttl stretched beyond MaxTTL", func(t *testing.T) {
		c := clone(e.c)
		c.ValidUntil = c.IssuedAt + 3601
		_, _, err := commitment.VerifyForGate(envelope(t, c, key(t, "agent1")), now, e.gate, e.params)
		mustReject(t, err, commitment.ErrTTLTooLong)
	})
	t.Run("backdating valid_until after signing", func(t *testing.T) {
		s, _, _ := commitment.Sign(key(t, "agent1"), e.c)
		s.Commitment.ValidUntil += 600
		bb, _ := commitment.EncodeSigned(s)
		_, _, err := commitment.VerifyForGate(bb, now, e.gate, e.params)
		mustReject(t, err, commitment.ErrSignatureInvalid)
	})
}

// The nonce registry lives in the gate. At this layer the check is
// pure and must be race-free and give identical results under concurrency;
// the same envelope is presented by many goroutines and yields one hash and
// one `(agent_pubkey, nonce)`.
func TestAttack4ConcurrentSameEnvelopeSameKey(t *testing.T) {
	e := setup(t)
	b := envelope(t, e.c, key(t, "agent1"))
	const n = 64
	var wg sync.WaitGroup
	var bad atomic.Int32
	hashes := make([]commitment.Hash, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, h, err := commitment.VerifyForGate(append([]byte(nil), b...), now, e.gate, e.params)
			if err != nil || s == nil {
				bad.Add(1)
				return
			}
			hashes[i] = h
		}()
	}
	wg.Wait()
	require.EqualValuesf(t, 0, bad.Load(), "%d failures", bad.Load())
	for _, h := range hashes {
		require.EqualValues(t, hashes[0], h, "different hash for one envelope")
	}
	t.Run("same nonce in two commitments gives different hashes", func(t *testing.T) {
		other := append(append([]byte(nil), e.action...), 0)
		ah, err := commitment.ActionHash(e.c.Action.Type, e.salt, other)
		require.NoError(t, err)
		c2 := clone(e.c)
		c2.Action.Hash = ah[:]
		h1, _ := commitment.HashOf(e.c)
		h2, _ := commitment.HashOf(c2)
		require.NotEqual(t, h2, h1, "hash collision")
		require.Equal(t, string(c2.Nonce), string(e.c.Nonce), "setup")
	})
}

func TestAttack5PayloadUnavailable(t *testing.T) {
	e := setup(t)
	for name, blob := range map[string][]byte{"nil": nil, "empty": {}, "short": make([]byte, e.c.PayloadSize-1), "long": make([]byte, e.c.PayloadSize+1)} {
		t.Run(name, func(t *testing.T) {
			mustReject(t, commitment.CheckPayload(e.c, blob), commitment.ErrPayloadSizeMismatch)
		})
	}
}

func TestAttack6WrongKey(t *testing.T) {
	e := setup(t)
	req := e.action
	t.Run("signed by agent2, claims agent1", func(t *testing.T) {
		a2 := key(t, "agent2")
		_, _, err := commitment.Sign(a2, e.c)
		require.ErrorIs(t, err, commitment.ErrInvalidPublicKey, "Sign must refuse mismatched key, got")
		h, err := commitment.HashOf(e.c)
		require.NoError(t, err)
		forged := &commitment.SignedCommitment{Commitment: *e.c, Signature: ed25519.Sign(a2, commitment.SigningMessage(h))}
		b, err := commitment.EncodeSigned(forged)
		require.NoError(t, err)
		mustReject(t, gateAdmit(e, b, now, req), commitment.ErrSignatureInvalid)
	})
	t.Run("pubkey swapped to agent2 after signing", func(t *testing.T) {
		s, _, _ := commitment.Sign(key(t, "agent1"), e.c)
		s.Commitment.AgentPubKey = key(t, "agent2").Public().(ed25519.PublicKey)
		b, _ := commitment.EncodeSigned(s)
		mustReject(t, gateAdmit(e, b, now, req), commitment.ErrSignatureInvalid)
	})
	t.Run("agent2 re-signs with agent2 pubkey: valid, binding is the allowlist", func(t *testing.T) {
		c := clone(e.c)
		c.AgentPubKey = key(t, "agent2").Public().(ed25519.PublicKey)
		s, _, err := commitment.VerifyForGate(envelope(t, c, key(t, "agent2")), now, e.gate, e.params)
		require.NoError(t, err)
		require.NotEqual(t, string(e.c.AgentPubKey), string(s.Commitment.AgentPubKey), "setup")
	})
}

func TestAttack7PayloadSwapped(t *testing.T) {
	e := setup(t)
	var pf struct {
		Cases []struct {
			BlobHex     string `json:"blob_hex"`
			PayloadSize string `json:"payload_size"`
			HashHex     string `json:"ciphertext_hash_hex"`
		} `json:"cases"`
	}
	readJSON(t, "payload.json", &pf)
	blob, _ := hex.DecodeString(pf.Cases[0].BlobHex)
	size, _ := strconv.ParseUint(pf.Cases[0].PayloadSize, 10, 64)
	h, _ := hex.DecodeString(pf.Cases[0].HashHex)
	c := clone(e.c)
	c.PayloadSize, c.CiphertextHash = size, h
	err := commitment.CheckPayload(c, blob)
	require.NoError(t, err, "control")
	for i := range blob {
		bad := append([]byte(nil), blob...)
		bad[i] ^= 1
		mustReject(t, commitment.CheckPayload(c, bad), commitment.ErrPayloadHashMismatch)
	}
	swapped := append([]byte(nil), blob...)
	for i := range swapped {
		swapped[i] = ^swapped[i]
	}
	mustReject(t, commitment.CheckPayload(c, swapped), commitment.ErrPayloadHashMismatch)

	t.Run("commitment hash replaced after signing", func(t *testing.T) {
		s, _, _ := commitment.Sign(key(t, "agent1"), c)
		s.Commitment.CiphertextHash[0] ^= 1
		b, _ := commitment.EncodeSigned(s)
		_, _, err := commitment.VerifyForGate(b, now, e.gate, e.params)
		mustReject(t, err, commitment.ErrSignatureInvalid)
	})
}

// Domain binding in the core is the gate id and the action type allowlist.
// Account and chain binding is the action format's job and is attacked at the
// executor (see the executor attacks).
func TestAttack8CrossDomainReplay(t *testing.T) {
	e := setup(t)
	b := envelope(t, e.c, key(t, "agent1"))
	req := e.action
	tests := map[string]struct {
		mutate func(g *commitment.GateScope)
		want   error
	}{
		"other gate":          {func(g *commitment.GateScope) { g.GateID = "gate-paper-2" }, commitment.ErrScopeMismatch},
		"other action type":   {func(g *commitment.GateScope) { g.ActionTypes = []string{"application/json"} }, commitment.ErrActionTypeNotAllowed},
		"no action types":     {func(g *commitment.GateScope) { g.ActionTypes = nil }, commitment.ErrActionTypeNotAllowed},
		"type is a prefix":    {func(g *commitment.GateScope) { g.ActionTypes = []string{e.c.Action.Type[:len(e.c.Action.Type)-1]} }, commitment.ErrActionTypeNotAllowed},
		"type has a suffix":   {func(g *commitment.GateScope) { g.ActionTypes = []string{e.c.Action.Type + "x"} }, commitment.ErrActionTypeNotAllowed},
		"other gate and type": {func(g *commitment.GateScope) { g.GateID = "gate-paper-2"; g.ActionTypes = nil }, commitment.ErrScopeMismatch},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			e2 := e
			e2.gate.ActionTypes = append([]string(nil), e.gate.ActionTypes...)
			tt.mutate(&e2.gate)
			mustReject(t, gateAdmit(e2, b, now, req), tt.want)
		})
	}
	t.Run("same bytes presented as another action type", func(t *testing.T) {
		c := clone(e.c)
		c.Action.Type = "application/json"
		bb := envelope(t, c, key(t, "agent1"))
		e2 := e
		e2.gate.ActionTypes = []string{"application/json"}
		mustReject(t, gateAdmit(e2, bb, now, req), commitment.ErrActionMismatch)
	})
	t.Run("rewriting scope after signing", func(t *testing.T) {
		s, _, _ := commitment.Sign(key(t, "agent1"), e.c)
		s.Commitment.Scope.GateID = "gate-paper-2"
		bb, _ := commitment.EncodeSigned(s)
		e2 := e
		e2.gate.GateID = "gate-paper-2"
		mustReject(t, gateAdmit(e2, bb, now, req), commitment.ErrSignatureInvalid)
	})
	t.Run("receipt-tag signature is not a commitment signature", func(t *testing.T) {
		h, _ := commitment.HashOf(e.c)
		msg := append([]byte{byte(len(commitment.TagReceipt))}, commitment.TagReceipt...)
		msg = append(msg, h[:]...)
		bb := envelopeWithSig(t, e.c, ed25519.Sign(key(t, "agent1"), msg))
		mustReject(t, gateAdmit(e, bb, now, req), commitment.ErrSignatureInvalid)
	})
	t.Run("authorization-tag signature is not a commitment signature", func(t *testing.T) {
		h, _ := commitment.HashOf(e.c)
		bb := envelopeWithSig(t, e.c, ed25519.Sign(key(t, "agent1"), commitment.AuthorizationSigningMessage(h)))
		mustReject(t, gateAdmit(e, bb, now, req), commitment.ErrSignatureInvalid)
	})
}

// Small-order agent_pubkey: A = identity, R = identity, S = 0 verifies for any
// message under a bare Ed25519 library (the public key check).
func TestAttack9SmallOrderKeyForgery(t *testing.T) {
	e := setup(t)
	for name, pub := range map[string]string{
		"identity":           "0100000000000000000000000000000000000000000000000000000000000000",
		"identity non-canon": "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"order2":             "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	} {
		t.Run(name, func(t *testing.T) {
			c := clone(e.c)
			c.AgentPubKey, _ = hex.DecodeString(pub)
			sig := append([]byte{1}, make([]byte, 63)...)
			b, err := commitment.EncodeSigned(&commitment.SignedCommitment{Commitment: *c, Signature: sig})
			require.NoError(t, err)
			_, _, err = commitment.VerifyForGate(b, now, e.gate, e.params)
			mustReject(t, err, commitment.ErrInvalidPublicKey)
		})
	}
}
