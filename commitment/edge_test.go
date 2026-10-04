package commitment_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
)

const edgeNow = uint64(1791000060)

func signedEnv(t *testing.T, mutate func(c *commitment.Commitment)) []byte {
	t.Helper()
	c, _, _ := baseCommitment(t)
	if mutate != nil {
		mutate(c)
	}
	s, _, err := commitment.Sign(loadKey(t, "agent1"), c)
	require.NoError(t, err, "sign")
	b, err := commitment.EncodeSigned(s)
	require.NoError(t, err, "encode")
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
	require.NoError(t, err)
	_, err = commitment.Verify(s)
	require.NoError(t, err, "baseline")

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
	_, err = commitment.Verify(mal)
	require.Error(t, err, "S+L accepted")

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
	_, _, err := commitment.VerifyForGate(good, edgeNow, g, p)
	require.NoError(t, err, "baseline")
	s, _ := commitment.DecodeSigned(good)
	sigBytes := s.Signature
	i := bytes.Index(good, sigBytes)
	require.GreaterOrEqual(t, i, 0, "signature not found in envelope")

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
				require.Error(t, err)
				require.True(t, matchesAnySentinel(err))
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
	require.NoError(t, err)
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
	require.NotEqual(t, commitment.Hash(sha256.Sum256(canon)), commitment.HashCanonical(canon), "hash lacks domain tag")
	good := &commitment.SignedCommitment{Commitment: *c, Signature: ed25519.Sign(priv, commitment.SigningMessage(h))}
	err = verifyErr(good)
	require.NoError(t, err, "control")
}

func TestEdgeForeignGateAndActionType(t *testing.T) {
	env := signedEnv(t, nil)
	g, p := edgeGate(t)
	tests := []struct {
		name   string
		mutate func(g *commitment.GateScope)
		want   string
	}{
		{"other gate id", func(g *commitment.GateScope) { g.GateID = "gate-paper-2" }, "ErrScopeMismatch"},
		{"gate id prefix", func(g *commitment.GateScope) { g.GateID = g.GateID[:len(g.GateID)-1] }, "ErrScopeMismatch"},
		{"gate id case", func(g *commitment.GateScope) { g.GateID = "GATE-PAPER-1" }, "ErrScopeMismatch"},
		{"empty gate id", func(g *commitment.GateScope) { g.GateID = "" }, "ErrScopeMismatch"},
		{"other action type", func(g *commitment.GateScope) { g.ActionTypes = []string{"application/json"} }, "ErrActionTypeNotAllowed"},
		{"no action types", func(g *commitment.GateScope) { g.ActionTypes = nil }, "ErrActionTypeNotAllowed"},
		{"action type with suffix", func(g *commitment.GateScope) {
			g.ActionTypes = []string{"application/vnd.edicta.ibkr.order.v0+cbor2"}
		}, "ErrActionTypeNotAllowed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gg := g
			tt.mutate(&gg)
			_, _, err := commitment.VerifyForGate(env, edgeNow, gg, p)
			assertSentinel(t, err, tt.want)
		})
	}
}

func TestEdgeTimeBoundaries(t *testing.T) {
	g, p := edgeGate(t)
	const issued = uint64(1791000000)
	run := func(t *testing.T, issuedAt, validUntil uint64, now uint64, want string) {
		env := signedEnv(t, func(c *commitment.Commitment) { c.IssuedAt, c.ValidUntil = issuedAt, validUntil })
		_, _, err := commitment.VerifyForGate(env, now, g, p)
		if want == "" {
			require.NoError(t, err)
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
}

func TestEdgeMaxTTLRetention(t *testing.T) {
	for _, tc := range []struct {
		ret, want uint64
	}{{1, 0}, {3, 0}, {4, 1}, {7, 1}, {599, 149}, {14400, 3600}, {14401, 3600}, {math.MaxInt64, 3600}} {
		p := commitment.Params{FibreRetentionS: tc.ret, BlobRetentionS: tc.ret}
		for _, da := range []commitment.DA{commitment.DAFibre, commitment.DACelestiaBlob} {
			got := p.MaxTTL(da)
			assert.Equal(t, tc.want, got)
		}
	}
	p := commitment.DefaultParams()
	for _, da := range []commitment.DA{0, 3, math.MaxUint64} {
		assert.EqualValuesf(t, 0, p.MaxTTL(da), "da %d: MaxTTL not 0", da)
	}
}

func TestEdgeStaticIntegerBoundaries(t *testing.T) {
	_, p := edgeGate(t)
	tests := []struct {
		name   string
		mutate func(c *commitment.Commitment)
		want   string
	}{
		{"height max uint64", func(c *commitment.Commitment) { c.PayloadRef.Height = math.MaxUint64 }, "ErrIntRange"},
		{"height 2^63-1", func(c *commitment.Commitment) { c.PayloadRef.Height = math.MaxInt64 }, ""},
		{"height 0", func(c *commitment.Commitment) { c.PayloadRef.Height = 0 }, "ErrZeroValue"},
		{"issued_at max uint64", func(c *commitment.Commitment) { c.IssuedAt = math.MaxUint64 }, "ErrIntRange"},
		{"payload_size max uint64", func(c *commitment.Commitment) { c.PayloadSize = math.MaxUint64 }, "ErrIntRange"},
		{"payload_size 2^27", func(c *commitment.Commitment) { c.PayloadSize = commitment.MaxPayloadSize }, ""},
		{"payload_size 2^27+1", func(c *commitment.Commitment) { c.PayloadSize = commitment.MaxPayloadSize + 1 }, "ErrPayloadTooLarge"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _, _ := baseCommitment(t)
			tt.mutate(c)
			err := commitment.ValidateStatic(c, p)
			if tt.want == "" {
				require.NoError(t, err)
				return
			}
			assertSentinel(t, err, tt.want)
		})
	}
}

func TestEdgeUint64WireRoundTrip(t *testing.T) {
	c, _, _ := baseCommitment(t)
	c.PayloadSize = math.MaxUint64
	b, err := commitment.Encode(c)
	require.NoError(t, err)
	d, err := commitment.Decode(b)
	require.NoError(t, err, "decode of 2^64-1 must succeed at stage D")
	require.Equal(t, uint64(math.MaxUint64), d.PayloadSize, "uint64 lost")
	_, p := edgeGate(t)
	assertSentinel(t, commitment.ValidateStatic(d, p), "ErrIntRange")
}

func TestEdgeSizeLimits(t *testing.T) {
	over := func(n int) []byte { return bytes.Repeat([]byte{0xa0}, n) }
	_, err := commitment.DecodeSigned(over(commitment.MaxSignedSize + 1))
	require.Truef(t, isErr(err, "ErrTooLarge"), "envelope limit+1: %v", err)
	_, err = commitment.DecodeSigned(over(commitment.MaxSignedSize))
	require.Errorf(t, err, "envelope at limit must pass the size gate and fail later: %v", err)
	require.Falsef(t, isErr(err, "ErrTooLarge"), "envelope at limit must pass the size gate and fail later: %v", err)
	_, err = commitment.Decode(over(commitment.MaxCommitmentSize + 1))
	require.Truef(t, isErr(err, "ErrTooLarge"), "commitment limit+1: %v", err)
	_, err = commitment.Decode(over(commitment.MaxCommitmentSize))
	require.Errorf(t, err, "commitment at limit: %v", err)
	require.Falsef(t, isErr(err, "ErrTooLarge"), "commitment at limit: %v", err)

	// Inner commitment of 2049 bytes inside an envelope under 2176: a
	// map of 16 entries whose values are padded by a long byte string.
	pad := func(n int) []byte {
		b := []byte{0xa2, 0x01, 0xa1, 0x01, 0x59, byte(n >> 8), byte(n)}
		b = append(b, make([]byte, n)...)
		b = append(b, 0x02, 0x58, 0x40)
		return append(b, make([]byte, 64)...)
	}
	// 0xa1 map(1){1: bstr(n)} is 1+1+3+n = n+5 bytes
	_, err = commitment.DecodeSigned(pad(commitment.MaxCommitmentSize - 5 + 1))
	require.Truef(t, isErr(err, "ErrTooLarge"), "inner commitment 2049 bytes: %v", err)
	_, err = commitment.DecodeSigned(pad(commitment.MaxCommitmentSize - 5))
	require.Errorf(t, err, "inner commitment 2048 bytes: %v", err)
	require.Falsef(t, isErr(err, "ErrTooLarge"), "inner commitment 2048 bytes: %v", err)
}

func isErr(err error, name string) bool {
	return err != nil && errorsIs(err, name)
}

func TestEdgeNestingDepth(t *testing.T) {
	// depth 5 map inside envelope key 1
	deep := []byte{0xa1, 0x01, 0xa1, 0x01, 0xa1, 0x01, 0xa1, 0x01, 0xa1, 0x01, 0x00}
	_, err := commitment.DecodeSigned(deep)
	require.Truef(t, isErr(err, "ErrNestingTooDeep"), "depth 5: %v", err)
	var many []byte
	for i := 0; i < 2000; i++ {
		many = append(many, 0xa1, 0x01)
	}
	many = append(many, 0)
	_, err = commitment.DecodeSigned(many)
	require.Error(t, err, "2000-deep nesting accepted")
	_, err = commitment.DecodeSigned(many[:2176])
	require.Error(t, err, "deep nesting at size limit accepted")
	_, err = commitment.Decode(deep[:9:9])
	require.Error(t, err, "bare commitment depth 4 within a commitment must fail (depth 2 base)")
}

// Documents impl-notes behaviour for hand-built inputs.
func TestEdgeImplNotesAmbiguities(t *testing.T) {
	c, _, _ := baseCommitment(t)

	t.Run("Sign with mismatched key fails", func(t *testing.T) {
		s, _, err := commitment.Sign(loadKey(t, "agent2"), c)
		require.Errorf(t, err, "Sign accepted mismatched key: %v", err)
		require.Nilf(t, s, "Sign accepted mismatched key: %v", err)
		require.ErrorIs(t, err, commitment.ErrInvalidPublicKey, "want ErrInvalidPublicKey, got")
	})
	t.Run("Sign rejects short private key", func(t *testing.T) {
		_, _, err := commitment.Sign(ed25519.PrivateKey(make([]byte, 31)), c)
		require.Error(t, err, "accepted")
		_, _, err = commitment.Sign(nil, c)
		require.Error(t, err, "accepted nil key")
	})
	t.Run("nil commitment in CheckAction", func(t *testing.T) {
		assertSentinel(t, commitment.CheckAction(nil, []byte{1}), "ErrActionMismatch")
	})
	t.Run("nil envelope", func(t *testing.T) {
		assertSentinel(t, verifyErr(nil), "ErrSignatureInvalid")
	})
	t.Run("encode does not interpret the action type", func(t *testing.T) {
		d := *c
		d.Action.Type = "not a media type"
		_, err := commitment.Encode(&d)
		require.NoError(t, err, "Encode validates the action type")
	})
	t.Run("encode does not validate", func(t *testing.T) {
		d := *c
		d.Version = 7
		_, err := commitment.Encode(&d)
		require.NoError(t, err, "Encode validates")
	})
	t.Run("nil byte slices encode as empty strings", func(t *testing.T) {
		d := *c
		d.Nonce = nil
		b1, err := commitment.Encode(&d)
		require.NoError(t, err)
		d.Nonce = []byte{}
		b2, _ := commitment.Encode(&d)
		require.Equal(t, hex.EncodeToString(b2), hex.EncodeToString(b1), "nil and empty differ")
		_, err = commitment.Decode(b1)
		assertSentinel(t, err, "ErrFieldSize")
	})
	t.Run("Verify hashes the struct, DecodeSigned guarantees bytes equal", func(t *testing.T) {
		env := signedEnv(t, nil)
		s, err := commitment.DecodeSigned(env)
		require.NoError(t, err)
		again, _ := commitment.EncodeSigned(s)
		require.Equal(t, hex.EncodeToString(again), hex.EncodeToString(env), "not canonical")
	})
}

func errorsIs(err error, name string) bool { return errors.Is(err, sentinels[name]) }
