package commitment_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"math"
	"math/big"
	"testing"

	"github.com/vgonkivs/prior/commitment"
)

const edgeNow = uint64(1791000060)

func signedEnv(t *testing.T, mutate func(c *commitment.Commitment)) []byte {
	t.Helper()
	c, _, _ := baseCommitment(t)
	if mutate != nil {
		mutate(c)
	}
	s, _, err := commitment.Sign(loadKey(t, "agent1"), c)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	b, err := commitment.EncodeSigned(s)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return b
}

func edgeGate(t *testing.T) (commitment.GateScope, commitment.Params) {
	_, g, p := baseCommitment(t)
	return g, p
}

func TestEdgeSignatureMalleability(t *testing.T) {
	c, _, _ := baseCommitment(t)
	priv := loadKey(t, "agent1")
	s, _, err := commitment.Sign(priv, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := commitment.Verify(s); err != nil {
		t.Fatalf("baseline: %v", err)
	}

	l, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	rev := func(b []byte) []byte {
		o := make([]byte, len(b))
		for i := range b {
			o[len(b)-1-i] = b[i]
		}
		return o
	}
	sv := new(big.Int).SetBytes(rev(s.Signature[32:]))
	sv.Add(sv, l)
	sb := rev(sv.FillBytes(make([]byte, 32)))
	mal := &commitment.SignedCommitment{Commitment: s.Commitment, Signature: append(append([]byte{}, s.Signature[:32]...), sb...)}
	if _, err := commitment.Verify(mal); err == nil {
		t.Fatal("S+L accepted")
	}

	sigLen := func(n int) *commitment.SignedCommitment {
		return &commitment.SignedCommitment{Commitment: s.Commitment, Signature: make([]byte, n)}
	}
	for _, n := range []int{0, 63, 65} {
		assertSentinel(t, verifyErr(sigLen(n)), "ErrSignatureInvalid")
	}
}

func verifyErr(s *commitment.SignedCommitment) error {
	_, err := commitment.Verify(s)
	return err
}

func TestEdgeEnvelopeExtraData(t *testing.T) {
	good := signedEnv(t, nil)
	g, p := edgeGate(t)
	if _, _, err := commitment.VerifyForGate(good, edgeNow, g, p); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	s, _ := commitment.DecodeSigned(good)
	sigBytes := s.Signature
	i := bytes.Index(good, sigBytes)
	if i < 0 {
		t.Fatal("signature not found in envelope")
	}

	tests := []struct {
		name string
		env  []byte
		want string
	}{
		{"trailing byte", append(append([]byte{}, good...), 0), "ErrTrailingData"},
		{"trailing second envelope", append(append([]byte{}, good...), good...), "ErrTrailingData"},
		{"extra envelope key 3", append(append([]byte{}, good...), 0), ""},
		{"empty", nil, "ErrMalformed"},
		{"truncated", good[:len(good)-1], "ErrMalformed"},
	}
	// envelope map header a2 -> a3 plus extra key 3 -> 0 (unsigned data)
	ext := append([]byte{0xa3}, good[1:]...)
	ext = append(ext, 0x03, 0x00)
	tests[2] = struct {
		name string
		env  []byte
		want string
	}{"extra envelope key 3", ext, "ErrUnknownKey"}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := commitment.VerifyForGate(tt.env, edgeNow, g, p)
			if tt.name == "empty" || tt.name == "truncated" {
				if err == nil || !matchesAnySentinel(err) {
					t.Fatalf("want a sentinel error, got %v", err)
				}
				return
			}
			assertSentinel(t, err, tt.want)
		})
	}
}

func TestEdgeCrossDomainSignatures(t *testing.T) {
	c, _, _ := baseCommitment(t)
	priv := loadKey(t, "agent1")
	canon, err := commitment.Encode(c)
	if err != nil {
		t.Fatal(err)
	}
	tag := func(name string, parts ...[]byte) []byte {
		out := append([]byte{byte(len(name))}, name...)
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	hashUnder := func(name string) []byte {
		h := sha256.Sum256(tag(name, canon))
		return h[:]
	}
	h := commitment.HashCanonical(canon)

	tests := []struct {
		name string
		msg  []byte
	}{
		{"receipt tag over hash", tag(commitment.TagReceipt, h[:])},
		{"commitment tag over hash", tag(commitment.TagCommitment, h[:])},
		{"sig tag over receipt-tagged hash", tag(commitment.TagSig, hashUnder(commitment.TagReceipt))},
		{"sig tag over sig-tagged hash", tag(commitment.TagSig, hashUnder(commitment.TagSig))},
		{"bare hash", h[:]},
		{"sig tag over canonical cbor", tag(commitment.TagSig, canon)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &commitment.SignedCommitment{Commitment: *c, Signature: ed25519.Sign(priv, tt.msg)}
			assertSentinel(t, verifyErr(s), "ErrSignatureInvalid")
		})
	}
	if commitment.HashCanonical(canon) == commitment.Hash(sha256.Sum256(canon)) {
		t.Fatal("hash lacks domain tag")
	}
	good := &commitment.SignedCommitment{Commitment: *c, Signature: ed25519.Sign(priv, commitment.SigningMessage(h))}
	if err := verifyErr(good); err != nil {
		t.Fatalf("control: %v", err)
	}
}

func TestEdgeForeignGateRailAccount(t *testing.T) {
	env := signedEnv(t, nil)
	g, p := edgeGate(t)
	chain := "celestia-1"
	tests := []struct {
		name   string
		mutate func(g *commitment.GateScope)
	}{
		{"other gate id", func(g *commitment.GateScope) { g.GateID = "gate-paper-2" }},
		{"gate id prefix", func(g *commitment.GateScope) { g.GateID = g.GateID[:len(g.GateID)-1] }},
		{"gate id case", func(g *commitment.GateScope) { g.GateID = "GATE-PAPER-1" }},
		{"other rail", func(g *commitment.GateScope) { g.Rail = 2 }},
		{"zero rail", func(g *commitment.GateScope) { g.Rail = 0 }},
		{"other account", func(g *commitment.GateScope) { g.Account = "DU7654321" }},
		{"empty account", func(g *commitment.GateScope) { g.Account = "" }},
		{"gate has chain id", func(g *commitment.GateScope) { g.ChainID = &chain }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gg := g
			tt.mutate(&gg)
			_, _, err := commitment.VerifyForGate(env, edgeNow, gg, p)
			assertSentinel(t, err, "ErrScopeMismatch")
		})
	}
	t.Run("commitment has chain id", func(t *testing.T) {
		withChain := signedEnv(t, func(c *commitment.Commitment) { c.Scope.ChainID = &chain })
		_, _, err := commitment.VerifyForGate(withChain, edgeNow, g, p)
		assertSentinel(t, err, "ErrChainIDRule")
	})
}

func TestEdgeTimeBoundaries(t *testing.T) {
	g, p := edgeGate(t)
	const issued = uint64(1791000000)
	run := func(t *testing.T, issuedAt, validUntil uint64, now uint64, want string) {
		env := signedEnv(t, func(c *commitment.Commitment) { c.IssuedAt, c.ValidUntil = issuedAt, validUntil })
		_, _, err := commitment.VerifyForGate(env, now, g, p)
		if want == "" {
			if err != nil {
				t.Fatalf("unexpected: %v", err)
			}
			return
		}
		assertSentinel(t, err, want)
	}
	tests := []struct {
		name         string
		iss, vu, now uint64
		want         string
	}{
		{"ttl exactly MaxTTL", issued, issued + 3600, issued, ""},
		{"ttl MaxTTL+1", issued, issued + 3601, issued, "ErrTTLTooLong"},
		{"ttl 1", issued, issued + 1, issued - 30, ""},
		{"valid_until == issued_at", issued, issued, issued, "ErrTimeOrder"},
		{"valid_until < issued_at", issued, issued - 1, issued, "ErrTimeOrder"},
		{"now+skew == valid_until", issued, issued + 900, issued + 870, "ErrExpired"},
		{"now+skew == valid_until-1", issued, issued + 900, issued + 869, ""},
		{"issued_at == now+skew", issued, issued + 900, issued - 30, ""},
		{"issued_at == now+skew+1", issued, issued + 900, issued - 31, "ErrNotYetValid"},
		{"now = 0", issued, issued + 900, 0, "ErrNotYetValid"},
		{"now = max uint64", issued, issued + 900, math.MaxUint64, "ErrExpired"},
		{"now = max uint64 - 10 (skew carry)", issued, issued + 900, math.MaxUint64 - 10, "ErrExpired"},
		{"issued_at zero", 0, 900, 100, "ErrZeroValue"},
		{"valid_until 2^63", issued, 1 << 63, issued, "ErrIntRange"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { run(t, tt.iss, tt.vu, tt.now, tt.want) })
	}

	t.Run("deadline equals issued_at", func(t *testing.T) {
		env := signedEnv(t, func(c *commitment.Commitment) { c.Constraints.Deadline = ptr(issued) })
		_, _, err := commitment.VerifyForGate(env, issued, g, p)
		assertSentinel(t, err, "ErrDeadlineRange")
	})
	t.Run("deadline one past valid_until", func(t *testing.T) {
		env := signedEnv(t, func(c *commitment.Commitment) { c.Constraints.Deadline = ptr(issued + 901) })
		_, _, err := commitment.VerifyForGate(env, issued, g, p)
		assertSentinel(t, err, "ErrDeadlineRange")
	})
	t.Run("deadline wins over valid_until", func(t *testing.T) {
		env := signedEnv(t, func(c *commitment.Commitment) { c.Constraints.Deadline = ptr(issued + 100) })
		_, _, err := commitment.VerifyForGate(env, issued+70, g, p)
		assertSentinel(t, err, "ErrExpired")
	})
}

func TestEdgeMaxTTLRetention(t *testing.T) {
	for _, tc := range []struct {
		ret, want uint64
	}{{1, 0}, {3, 0}, {4, 1}, {7, 1}, {599, 149}, {14400, 3600}, {14401, 3600}, {math.MaxInt64, 3600}} {
		p := commitment.Params{FibreRetentionS: tc.ret, BlobRetentionS: tc.ret}
		for _, da := range []commitment.DA{commitment.DAFibre, commitment.DACelestiaBlob} {
			if got := p.MaxTTL(da); got != tc.want {
				t.Errorf("ret %d da %d: MaxTTL %d, want %d", tc.ret, da, got, tc.want)
			}
		}
	}
	p := commitment.DefaultParams()
	for _, da := range []commitment.DA{0, 3, math.MaxUint64} {
		if p.MaxTTL(da) != 0 {
			t.Errorf("da %d: MaxTTL not 0", da)
		}
	}
}

func TestEdgeNotionalBoundaries(t *testing.T) {
	g, p := edgeGate(t)
	_ = g
	// qty 10.0000 x price 190.50000000 = 1905.00000000 = 190_500_000_000 units
	const exact = uint64(190_500_000_000)
	tests := []struct {
		name   string
		mutate func(c *commitment.Commitment)
		want   string
	}{
		{"max_notional exact", func(c *commitment.Commitment) { c.Constraints.MaxNotional = exact }, ""},
		{"max_notional minus 1 unit", func(c *commitment.Commitment) { c.Constraints.MaxNotional = exact - 1 }, "ErrNotionalExceeded"},
		{"qty plus 1 unit", func(c *commitment.Commitment) {
			c.Constraints.MaxNotional = exact
			c.Action.IBKROrder.Qty++
		}, "ErrNotionalExceeded"},
		{"price plus 1 unit", func(c *commitment.Commitment) {
			c.Constraints.MaxNotional = exact
			c.Action.IBKROrder.LimitPrice = ptr(*c.Action.IBKROrder.LimitPrice + 1)
		}, "ErrNotionalExceeded"},
		{"fractional notional rounds up against agent", func(c *commitment.Commitment) {
			c.Action.IBKROrder.Qty = 1
			c.Action.IBKROrder.LimitPrice = ptr(uint64(10_001))
			c.Constraints.MaxNotional = 1
		}, "ErrNotionalExceeded"},
		{"qty*price exactly 10^4 x max_notional", func(c *commitment.Commitment) {
			c.Action.IBKROrder.Qty = 1
			c.Action.IBKROrder.LimitPrice = ptr(uint64(10_000))
			c.Constraints.MaxNotional = 1
		}, ""},
		{"2^63-1 qty and price, max_notional 2^63-1 (128-bit)", func(c *commitment.Commitment) {
			c.Action.IBKROrder.Qty = math.MaxInt64
			c.Action.IBKROrder.LimitPrice = ptr(uint64(math.MaxInt64))
			c.Constraints.MaxNotional = math.MaxInt64
		}, "ErrNotionalExceeded"},
		{"qty 2^63", func(c *commitment.Commitment) { c.Action.IBKROrder.Qty = 1 << 63 }, "ErrIntRange"},
		{"qty max uint64", func(c *commitment.Commitment) { c.Action.IBKROrder.Qty = math.MaxUint64 }, "ErrIntRange"},
		{"limit_price max uint64", func(c *commitment.Commitment) { c.Action.IBKROrder.LimitPrice = ptr(uint64(math.MaxUint64)) }, "ErrIntRange"},
		{"max_notional max uint64", func(c *commitment.Commitment) { c.Constraints.MaxNotional = math.MaxUint64 }, "ErrIntRange"},
		{"height max uint64", func(c *commitment.Commitment) { c.PayloadRef.Height = math.MaxUint64 }, "ErrIntRange"},
		{"qty 0", func(c *commitment.Commitment) { c.Action.IBKROrder.Qty = 0 }, "ErrZeroValue"},
		{"max_notional 0", func(c *commitment.Commitment) { c.Constraints.MaxNotional = 0 }, "ErrZeroValue"},
		{"limit_price 0", func(c *commitment.Commitment) { c.Action.IBKROrder.LimitPrice = ptr(uint64(0)) }, "ErrZeroValue"},
		{"payload_size 2^27", func(c *commitment.Commitment) { c.PayloadSize = commitment.MaxPayloadSize }, ""},
		{"payload_size 2^27+1", func(c *commitment.Commitment) { c.PayloadSize = commitment.MaxPayloadSize + 1 }, "ErrPayloadTooLarge"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _, _ := baseCommitment(t)
			tt.mutate(c)
			err := commitment.ValidateStatic(c, p)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("unexpected: %v", err)
				}
				return
			}
			assertSentinel(t, err, tt.want)
		})
	}
}

func TestEdgeUint64WireRoundTrip(t *testing.T) {
	c, _, _ := baseCommitment(t)
	c.PayloadSize = math.MaxUint64
	c.Constraints.MaxNotional = math.MaxUint64
	b, err := commitment.Encode(c)
	if err != nil {
		t.Fatal(err)
	}
	d, err := commitment.Decode(b)
	if err != nil {
		t.Fatalf("decode of 2^64-1 must succeed at stage D: %v", err)
	}
	if d.PayloadSize != math.MaxUint64 || d.Constraints.MaxNotional != math.MaxUint64 {
		t.Fatal("uint64 lost")
	}
	_, p := edgeGate(t)
	assertSentinel(t, commitment.ValidateStatic(d, p), "ErrIntRange")
}

func TestEdgeSizeLimits(t *testing.T) {
	over := func(n int) []byte { return bytes.Repeat([]byte{0xa0}, n) }
	if _, err := commitment.DecodeSigned(over(commitment.MaxSignedSize + 1)); !isErr(err, "ErrTooLarge") {
		t.Fatalf("envelope limit+1: %v", err)
	}
	if _, err := commitment.DecodeSigned(over(commitment.MaxSignedSize)); err == nil || isErr(err, "ErrTooLarge") {
		t.Fatalf("envelope at limit must pass the size gate and fail later: %v", err)
	}
	if _, err := commitment.Decode(over(commitment.MaxCommitmentSize + 1)); !isErr(err, "ErrTooLarge") {
		t.Fatalf("commitment limit+1: %v", err)
	}
	if _, err := commitment.Decode(over(commitment.MaxCommitmentSize)); err == nil || isErr(err, "ErrTooLarge") {
		t.Fatalf("commitment at limit: %v", err)
	}

	// Inner commitment of 2049 bytes inside an envelope under 2176: a
	// map of 16 entries whose values are padded by a long byte string.
	pad := func(n int) []byte {
		b := []byte{0xa2, 0x01, 0xa1, 0x01, 0x59, byte(n >> 8), byte(n)}
		b = append(b, make([]byte, n)...)
		b = append(b, 0x02, 0x58, 0x40)
		return append(b, make([]byte, 64)...)
	}
	// 0xa1 map(1){1: bstr(n)} is 1+1+3+n = n+5 bytes
	if _, err := commitment.DecodeSigned(pad(commitment.MaxCommitmentSize - 5 + 1)); !isErr(err, "ErrTooLarge") {
		t.Fatalf("inner commitment 2049 bytes: %v", err)
	}
	if _, err := commitment.DecodeSigned(pad(commitment.MaxCommitmentSize - 5)); err == nil || isErr(err, "ErrTooLarge") {
		t.Fatalf("inner commitment 2048 bytes: %v", err)
	}
}

func isErr(err error, name string) bool {
	return err != nil && errorsIs(err, name)
}

func TestEdgeNestingDepth(t *testing.T) {
	// depth 5 map inside envelope key 1
	deep := []byte{0xa1, 0x01, 0xa1, 0x01, 0xa1, 0x01, 0xa1, 0x01, 0xa1, 0x01, 0x00}
	if _, err := commitment.DecodeSigned(deep); !isErr(err, "ErrNestingTooDeep") {
		t.Fatalf("depth 5: %v", err)
	}
	var many []byte
	for i := 0; i < 2000; i++ {
		many = append(many, 0xa1, 0x01)
	}
	many = append(many, 0)
	if _, err := commitment.DecodeSigned(many); err == nil {
		t.Fatal("2000-deep nesting accepted")
	}
	if _, err := commitment.DecodeSigned(many[:2176]); err == nil {
		t.Fatal("deep nesting at size limit accepted")
	}
	if _, err := commitment.Decode(deep[:9:9]); err == nil {
		t.Fatal("bare commitment depth 4 within a commitment must fail (depth 2 base)")
	}
}

// Documents impl-notes behaviour for hand-built inputs.
func TestEdgeImplNotesAmbiguities(t *testing.T) {
	c, _, p := baseCommitment(t)

	t.Run("Sign with mismatched key fails", func(t *testing.T) {
		s, _, err := commitment.Sign(loadKey(t, "agent2"), c)
		if err == nil || s != nil {
			t.Fatalf("Sign accepted mismatched key: %v", err)
		}
		if !errors.Is(err, commitment.ErrInvalidPublicKey) {
			t.Fatalf("want ErrInvalidPublicKey, got %v", err)
		}
	})
	t.Run("Sign rejects short private key", func(t *testing.T) {
		if _, _, err := commitment.Sign(ed25519.PrivateKey(make([]byte, 31)), c); err == nil {
			t.Fatal("accepted")
		}
		if _, _, err := commitment.Sign(nil, c); err == nil {
			t.Fatal("accepted nil key")
		}
	})
	t.Run("nil order", func(t *testing.T) {
		d := *c
		d.Action.IBKROrder = nil
		assertSentinel(t, commitment.ValidateStatic(&d, p), "ErrUnsupportedActionKind")
		assertSentinel(t, verifyErr(&commitment.SignedCommitment{Commitment: d, Signature: make([]byte, 64)}), "ErrSignatureInvalid")
		assertSentinel(t, commitment.CheckAction(&d, commitment.IBKROrderV0{}), "ErrActionMismatch")
		if _, err := commitment.Encode(&d); err == nil {
			t.Fatal("encode of nil order succeeded")
		}
	})
	t.Run("nil envelope", func(t *testing.T) {
		assertSentinel(t, verifyErr(nil), "ErrSignatureInvalid")
	})
	t.Run("unknown kind", func(t *testing.T) {
		d := *c
		d.Action.Kind = "ibkr.order.v1"
		assertSentinel(t, commitment.ValidateStatic(&d, p), "ErrUnsupportedActionKind")
	})
	t.Run("encode does not validate", func(t *testing.T) {
		d := *c
		d.Version = 7
		if _, err := commitment.Encode(&d); err != nil {
			t.Fatalf("Encode validates: %v", err)
		}
	})
	t.Run("nil byte slices encode as empty strings", func(t *testing.T) {
		d := *c
		d.Nonce = nil
		b1, err := commitment.Encode(&d)
		if err != nil {
			t.Fatal(err)
		}
		d.Nonce = []byte{}
		b2, _ := commitment.Encode(&d)
		if !bytes.Equal(b1, b2) {
			t.Fatal("nil and empty differ")
		}
		_, err = commitment.Decode(b1)
		assertSentinel(t, err, "ErrFieldSize")
	})
	t.Run("symbol ignored by CheckAction", func(t *testing.T) {
		req := *c.Action.IBKROrder
		req.Symbol = ptr("OTHER")
		if err := commitment.CheckAction(c, req); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("CheckAction limit_price presence", func(t *testing.T) {
		req := *c.Action.IBKROrder
		req.LimitPrice = nil
		assertSentinel(t, commitment.CheckAction(c, req), "ErrActionMismatch")
	})
	t.Run("Verify hashes the struct, DecodeSigned guarantees bytes equal", func(t *testing.T) {
		env := signedEnv(t, nil)
		s, err := commitment.DecodeSigned(env)
		if err != nil {
			t.Fatal(err)
		}
		again, _ := commitment.EncodeSigned(s)
		if !bytes.Equal(env, again) {
			t.Fatal("not canonical")
		}
	})
}

func errorsIs(err error, name string) bool { return errors.Is(err, sentinels[name]) }
