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

	"github.com/vgonkivs/prior/commitment"
)

const (
	dir = "../../spec/vectors/v0/"
	now = uint64(1791000060)
)

func readJSON(t testing.TB, name string, v any) {
	t.Helper()
	b, err := os.ReadFile(dir + name)
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
	gate   commitment.GateScope
	params commitment.Params
}

func setup(t testing.TB) env {
	var vf struct {
		RawParams map[string]string `json:"params"`
		Gate      struct {
			GateID  string `json:"gate_id"`
			Rail    string `json:"rail"`
			Account string `json:"account"`
		} `json:"gate"`
		Cases []struct {
			ID  string `json:"id"`
			Hex string `json:"commitment_cbor_hex"`
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
		}
	}
	require.NotNil(t, e.c, "vector minimal_lmt missing")
	e.gate = commitment.GateScope{GateID: vf.Gate.GateID, Rail: commitment.Rail(n(vf.Gate.Rail)), Account: vf.Gate.Account}
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
	o := *c.Action.IBKROrder
	d.Action.IBKROrder = &o
	return &d
}

func mustReject(t *testing.T, err error, want error) {
	t.Helper()
	require.Error(t, err)
	require.ErrorIs(t, err, want)
}

// gateAdmit is the stateless part of the gate: verify, then match the order.
func gateAdmit(e env, b []byte, at uint64, req commitment.IBKROrderV0) error {
	s, _, err := commitment.VerifyForGate(b, at, e.gate, e.params)
	if err != nil {
		return err
	}
	return commitment.CheckAction(&s.Commitment, req)
}

func TestAttack1ActionWithoutCommitment(t *testing.T) {
	e := setup(t)
	req := *e.c.Action.IBKROrder
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

func TestAttack2ParamsOutsideCommitment(t *testing.T) {
	e := setup(t)
	b := envelope(t, e.c, key(t, "agent1"))
	good := *e.c.Action.IBKROrder
	err := gateAdmit(e, b, now, good)
	require.NoError(t, err, "control")
	tests := map[string]func(o *commitment.IBKROrderV0){
		"qty plus 1 unit": func(o *commitment.IBKROrderV0) { o.Qty++ },
		"qty doubled":     func(o *commitment.IBKROrderV0) { o.Qty *= 2 },
		"qty smaller":     func(o *commitment.IBKROrderV0) { o.Qty-- },
		"price plus 1":    func(o *commitment.IBKROrderV0) { o.LimitPrice = ptr(*o.LimitPrice + 1) },
		"price minus 1":   func(o *commitment.IBKROrderV0) { o.LimitPrice = ptr(*o.LimitPrice - 1) },
		"no limit price":  func(o *commitment.IBKROrderV0) { o.LimitPrice = nil },
		"market order":    func(o *commitment.IBKROrderV0) { o.OrderType = commitment.OrderMarket; o.LimitPrice = nil },
		"other account":   func(o *commitment.IBKROrderV0) { o.Account = "DU7654321" },
		"other conid":     func(o *commitment.IBKROrderV0) { o.ConID++ },
		"other currency":  func(o *commitment.IBKROrderV0) { o.Currency = "EUR" },
		"other side":      func(o *commitment.IBKROrderV0) { o.Side = commitment.SideSell },
		"other tif":       func(o *commitment.IBKROrderV0) { o.TIF++ },
	}
	for name, m := range tests {
		t.Run(name, func(t *testing.T) {
			req := good
			m(&req)
			mustReject(t, gateAdmit(e, b, now, req), commitment.ErrActionMismatch)
		})
	}

	t.Run("committed notional above max_notional", func(t *testing.T) {
		c := clone(e.c)
		c.Constraints.MaxNotional = 190_500_000_000 - 1
		bb := envelope(t, c, key(t, "agent1"))
		_, _, err := commitment.VerifyForGate(bb, now, e.gate, e.params)
		mustReject(t, err, commitment.ErrNotionalExceeded)
	})
	t.Run("committed price breaks price_bound", func(t *testing.T) {
		c := clone(e.c)
		c.Action.IBKROrder.Side = commitment.SideBuy
		c.Constraints.PriceBound = ptr(*c.Action.IBKROrder.LimitPrice - 1)
		_, _, err := commitment.VerifyForGate(envelope(t, c, key(t, "agent1")), now, e.gate, e.params)
		mustReject(t, err, commitment.ErrPriceBound)
	})
	t.Run("account differs from scope account", func(t *testing.T) {
		c := clone(e.c)
		c.Action.IBKROrder.Account = "DU7654321"
		_, _, err := commitment.VerifyForGate(envelope(t, c, key(t, "agent1")), now, e.gate, e.params)
		mustReject(t, err, commitment.ErrAccountMismatch)
	})
}

func ptr[T any](v T) *T { return &v }

func TestAttack3Expired(t *testing.T) {
	e := setup(t)
	b := envelope(t, e.c, key(t, "agent1"))
	req := *e.c.Action.IBKROrder
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
	t.Run("deadline before valid_until", func(t *testing.T) {
		c := clone(e.c)
		c.Constraints.Deadline = ptr(c.IssuedAt + 100)
		bb := envelope(t, c, key(t, "agent1"))
		mustReject(t, gateAdmit(e, bb, c.IssuedAt+100, req), commitment.ErrExpired)
	})
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
		c2 := clone(e.c)
		c2.Action.IBKROrder.Qty++
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
	req := *e.c.Action.IBKROrder
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

func TestAttack8CrossDomainReplay(t *testing.T) {
	e := setup(t)
	b := envelope(t, e.c, key(t, "agent1"))
	req := *e.c.Action.IBKROrder
	chain := "celestia-1"
	tests := map[string]func(g *commitment.GateScope){
		"other gate":    func(g *commitment.GateScope) { g.GateID = "gate-paper-2" },
		"other rail":    func(g *commitment.GateScope) { g.Rail = 2 },
		"other account": func(g *commitment.GateScope) { g.Account = "DU7654321" },
		"chain gate":    func(g *commitment.GateScope) { g.ChainID = &chain },
	}
	for name, m := range tests {
		t.Run(name, func(t *testing.T) {
			e2 := e
			m(&e2.gate)
			mustReject(t, gateAdmit(e2, b, now, req), commitment.ErrScopeMismatch)
		})
	}
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
