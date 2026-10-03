package commitment_test

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/prior/commitment"
)

// Every encoding below must be rejected as a public key before any signature work.
var badPublicKeys = []struct{ name, hex string }{
	{"identity", "0100000000000000000000000000000000000000000000000000000000000000"},
	{"order2", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
	{"order4 a", "0000000000000000000000000000000000000000000000000000000000000080"},
	{"order4 b", "0000000000000000000000000000000000000000000000000000000000000000"},
	{"order8 a", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"},
	{"order8 b", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"},
	{"order8 c", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"},
	{"order8 d", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"},
	{"identity x=0 sign bit", "0100000000000000000000000000000000000000000000000000000000000080"},
	{"order2 x=0 sign bit", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
	{"order4 y=p", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
	{"order4 y=p sign", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
	{"identity y=p+1", "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
	{"identity y=p+1 sign", "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
	{"y=p+3 non-canonical", "f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
	{"y=2 not on curve", "0200000000000000000000000000000000000000000000000000000000000000"},
}

func pubkeyCase(t *testing.T, pub, sig []byte) *commitment.SignedCommitment {
	c, _, _ := baseCommitment(t)
	c.AgentPubKey = pub
	return &commitment.SignedCommitment{Commitment: *c, Signature: sig}
}

func identityForgerySig() []byte {
	return append([]byte{1}, make([]byte, 63)...)
}

// Regression: with A = identity, R = identity, S = 0 the
// verification equation holds for every message.
func TestSmallOrderPublicKeyRejected(t *testing.T) {
	g, p := edgeGate(t)
	sigs := []struct {
		name string
		sig  []byte
	}{
		{"identity R, S=0", identityForgerySig()},
		{"all zero", make([]byte, 64)},
		{"garbage", bytes.Repeat([]byte{0xa5}, 64)},
	}
	for _, k := range badPublicKeys {
		for _, sg := range sigs {
			t.Run(k.name+"/"+sg.name, func(t *testing.T) {
				s := pubkeyCase(t, mustHex(t, k.hex), sg.sig)
				assertSentinel(t, verifyErr(s), "ErrInvalidPublicKey")

				b, err := commitment.EncodeSigned(s)
				require.NoError(t, err, "EncodeSigned")
				_, _, err = commitment.VerifyForGate(b, edgeNow, g, p)
				assertSentinel(t, err, "ErrInvalidPublicKey")
			})
		}
	}
}

// Mixed-order keys pass the public key check; they then fail on the
// signature, not on the key.
func TestMixedOrderPublicKeyPassesG0(t *testing.T) {
	for name, h := range map[string]string{
		"agent1 + order2": "16a567fe7d4ef5482ab4012c369bf8c5f11e8d0c2559dcda50fde59708f8aee5",
		"agent1 + order8": "9158312a9a8d6e3b34c891d6d61444f8b8211c5117ebad15bdb0bd68b07e0245",
	} {
		t.Run(name, func(t *testing.T) {
			s := pubkeyCase(t, mustHex(t, h), identityForgerySig())
			assertSentinel(t, verifyErr(s), "ErrSignatureInvalid")
		})
	}
}

// Small-order R under a valid A is not restricted by the public key check.
func TestSmallOrderRWithValidKeyIsSignatureError(t *testing.T) {
	c, _, _ := baseCommitment(t)
	s := &commitment.SignedCommitment{Commitment: *c, Signature: identityForgerySig()}
	assertSentinel(t, verifyErr(s), "ErrSignatureInvalid")
}

func TestHonestKeysPassG0(t *testing.T) {
	for _, name := range []string{"agent1", "agent2"} {
		c, _, _ := baseCommitment(t)
		priv := loadKey(t, name)
		c.AgentPubKey = []byte(priv.Public().(ed25519.PublicKey))
		s, _, err := commitment.Sign(priv, c)
		require.NoErrorf(t, err, "%s", name)
		err = verifyErr(s)
		require.NoErrorf(t, err, "%s", name)
	}
}

func TestStageOrderAroundG0(t *testing.T) {
	g, p := edgeGate(t)
	identity := mustHex(t, badPublicKeys[0].hex)
	env := func(mutate func(c *commitment.Commitment)) []byte {
		c, _, _ := baseCommitment(t)
		c.AgentPubKey = identity
		if mutate != nil {
			mutate(c)
		}
		b, err := commitment.EncodeSigned(&commitment.SignedCommitment{Commitment: *c, Signature: identityForgerySig()})
		require.NoError(t, err)
		return b
	}
	tests := []struct {
		name string
		env  []byte
		now  uint64
		g    commitment.GateScope
		want string
	}{
		{"decode before G0", append(env(nil), 0), edgeNow, g, "ErrTrailingData"},
		{"static before G0", env(func(c *commitment.Commitment) { c.Action.IBKROrder.Qty = 0 }), edgeNow, g, "ErrZeroValue"},
		{"G0 before time", env(nil), 1791009999, g, "ErrInvalidPublicKey"},
		{"G0 before not-yet-valid", env(nil), 1, g, "ErrInvalidPublicKey"},
		{"G0 before scope", env(nil), edgeNow, commitment.GateScope{GateID: "other", Rail: g.Rail, Account: g.Account}, "ErrInvalidPublicKey"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := commitment.VerifyForGate(tt.env, tt.now, tt.g, p)
			assertSentinel(t, err, tt.want)
		})
	}
}
