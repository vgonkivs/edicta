package principalsig_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/principalsig"
)

func TestMessageIsTheMandateSigTag(t *testing.T) {
	require.Equal(t, policy.TagMandateSig, principalsig.TagMandateSig)
	var h [32]byte
	m := principalsig.Message(h)
	assert.Len(t, m, 61)
	assert.Equal(t, byte(0x1c), m[0])
}

func TestBech32KnownAddresses(t *testing.T) {
	pk := secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{7}, 32)).PubKey().SerializeCompressed()
	for _, hrp := range []string{"celestia", "cosmos", "a", "0123456789abcdef"} {
		addr, err := principalsig.CosmosAddress(pk, hrp)
		require.NoError(t, err)
		got, raw, err := principalsig.ParseCosmosAddress(addr)
		require.NoError(t, err)
		assert.Equal(t, hrp, got)
		assert.Len(t, raw, 20)
	}
	addr, err := principalsig.CosmosAddress(pk, "celestia")
	require.NoError(t, err)
	for i := len("celestia1"); i < len(addr); i++ {
		b := []byte(addr)
		if b[i] == 'q' {
			b[i] = 'p'
		} else {
			b[i] = 'q'
		}
		_, _, err := principalsig.ParseCosmosAddress(string(b))
		require.ErrorIs(t, err, principalsig.ErrPrincipal, "position %d", i)
	}
	// BIP-173 valid string whose data part is 20 bytes.
	hrp, raw, err := principalsig.ParseCosmosAddress("abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw")
	require.NoError(t, err)
	assert.Equal(t, "abcdef", hrp)
	assert.Equal(t, "00443214c74254b635cf84653a56d7c675be77df", hex.EncodeToString(raw[:]))
	_, _, err = principalsig.ParseCosmosAddress("ABCDEF1QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LMQQQXW")
	require.NoError(t, err, "an all upper-case bech32 string is valid")
	for _, s := range []string{
		"a12uel5l", // valid bech32 with empty data: not an address
		"abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxx",
		"abcdef1Qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
		"celestia1",
		"1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
	} {
		_, _, err := principalsig.ParseCosmosAddress(s)
		require.ErrorIs(t, err, principalsig.ErrPrincipal, s)
	}
}

func TestCheckPrincipalPerScheme(t *testing.T) {
	ed, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	comp := secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{3}, 32)).PubKey().SerializeCompressed()
	require.NoError(t, principalsig.CheckPrincipal(principalsig.Ed25519, ed))
	require.NoError(t, principalsig.CheckPrincipal(principalsig.CosmosADR036, comp))
	require.NoError(t, principalsig.CheckPrincipal(principalsig.EIP712, make([]byte, 20)))
	require.ErrorIs(t, principalsig.CheckPrincipal(principalsig.CosmosADR036, ed), principalsig.ErrPrincipal)
	require.ErrorIs(t, principalsig.CheckPrincipal(principalsig.Ed25519, comp), principalsig.ErrPrincipal)
	require.ErrorIs(t, principalsig.CheckPrincipal(principalsig.EIP712, comp), principalsig.ErrPrincipal)
	require.ErrorIs(t, principalsig.CheckPrincipal(principalsig.Scheme(4), comp), principalsig.ErrScheme)
	require.ErrorIs(t, principalsig.Verify(principalsig.Scheme(0), ed, "", principalsig.EIP712Message{}, nil, nil), principalsig.ErrScheme)
}

// rawMandate returns a valid mandate whose principal is the raw secp256k1 key
// under the scheme.
func rawMandate(t *testing.T, scheme principalsig.Scheme, sk []byte) (*policy.Mandate, principalsig.Signer) {
	t.Helper()
	hrp := ""
	if scheme == principalsig.CosmosADR036 {
		hrp = "celestia"
	}
	s, err := principalsig.NewSecp256k1Signer(scheme, sk, hrp)
	require.NoError(t, err)
	agent, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	m := &policy.Mandate{
		Format: 1, Principal: s.Principal(), GateID: "gate-test", Agents: [][]byte{agent},
		NotBefore: 1, NotAfter: 2_000_000_000, MandateID: bytes.Repeat([]byte{9}, 16), Version: 3,
		Assets:  []policy.AssetRule{{Asset: "test:<a&b>", Scale: 2, PerActionMax: []byte{100}}},
		SigType: uint64(scheme), PrincipalHRP: hrp,
	}
	return m, s
}

func TestVerifyMandateWithRawSecp256k1(t *testing.T) {
	sk := sha256.Sum256([]byte("raw secp256k1 principal"))
	for _, scheme := range []principalsig.Scheme{principalsig.CosmosADR036, principalsig.EIP712} {
		t.Run(scheme.String(), func(t *testing.T) {
			m, s := rawMandate(t, scheme, sk[:])
			signed, h, err := policy.SignMandateWith(s, m)
			require.NoError(t, err)
			sm, h2, err := policy.VerifyMandate(signed)
			require.NoError(t, err)
			assert.Equal(t, h, h2)
			assert.Equal(t, uint64(scheme), sm.Mandate.SigType)
			assert.Len(t, sm.Signature, principalsig.SignatureSize(scheme))

			bad := bytes.Clone(signed)
			bad[len(bad)-2] ^= 1
			_, _, err = policy.VerifyMandate(bad)
			require.ErrorIs(t, err, policy.ErrMandateSignature)

			// Same key, other mandate: the signature does not carry over.
			m2 := *m
			m2.Version++
			other, _, err := policy.SignMandateWith(s, &m2)
			require.NoError(t, err)
			sm2, _, err := policy.DecodeSignedMandate(other)
			require.NoError(t, err)
			sm2.Signature = sm.Signature
			_, _, err = policy.VerifyMandate(reencode(t, sm2))
			require.ErrorIs(t, err, policy.ErrMandateSignature)
		})
	}
}

func reencode(t *testing.T, sm *policy.SignedMandate) []byte {
	t.Helper()
	b, err := policy.EncodeSignedMandate(sm)
	require.NoError(t, err)
	return b
}

func TestSignMandateWithRefusesAnotherSchemeOrKey(t *testing.T) {
	sk := sha256.Sum256([]byte("k1"))
	m, _ := rawMandate(t, principalsig.EIP712, sk[:])
	cosmos, err := principalsig.NewSecp256k1Signer(principalsig.CosmosADR036, sk[:], "celestia")
	require.NoError(t, err)
	_, _, err = policy.SignMandateWith(cosmos, m)
	require.ErrorIs(t, err, policy.ErrMandateSignature)
	other := sha256.Sum256([]byte("k2"))
	eth, err := principalsig.NewSecp256k1Signer(principalsig.EIP712, other[:], "")
	require.NoError(t, err)
	_, _, err = policy.SignMandateWith(eth, m)
	require.ErrorIs(t, err, policy.ErrMandateSignature)
}

func TestSecpSignerRefusesBadKeys(t *testing.T) {
	n := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
		0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41}
	for _, sk := range [][]byte{nil, make([]byte, 32), n, make([]byte, 31)} {
		_, err := principalsig.NewSecp256k1Signer(principalsig.EIP712, sk, "")
		require.Error(t, err)
	}
	ok := bytes.Repeat([]byte{1}, 32)
	_, err := principalsig.NewSecp256k1Signer(principalsig.CosmosADR036, ok, "Celestia")
	require.ErrorIs(t, err, principalsig.ErrPrincipal)
	_, err = principalsig.NewSecp256k1Signer(principalsig.Ed25519, ok, "")
	require.ErrorIs(t, err, principalsig.ErrScheme)
}

func TestADR036VerifyRefusesTextWithoutTheHashLine(t *testing.T) {
	sk := sha256.Sum256([]byte("adr"))
	m, s := rawMandate(t, principalsig.CosmosADR036, sk[:])
	_, h, err := policy.SignMandateWith(s, m)
	require.NoError(t, err)
	f := policy.SignedFields(m, h)
	d := policy.SignedText(m, h)
	sig, err := s.Sign(f, d)
	require.NoError(t, err)
	require.NoError(t, principalsig.Verify(principalsig.CosmosADR036, m.Principal, "celestia", f, d, sig))
	require.ErrorIs(t, principalsig.Verify(principalsig.CosmosADR036, m.Principal, "cosmos", f, d, sig), principalsig.ErrSignature)
	_, err = s.Sign(f, []byte(policy.Render(m)))
	require.Error(t, err)
	f2 := f
	f2.MandateHash[0] ^= 1
	require.ErrorIs(t, principalsig.Verify(principalsig.CosmosADR036, m.Principal, "celestia", f2, d, sig), principalsig.ErrSignature)
}

func TestEIP712VerifyRefusesOtherEncodings(t *testing.T) {
	sk := sha256.Sum256([]byte("eth"))
	m, s := rawMandate(t, principalsig.EIP712, sk[:])
	_, h, err := policy.SignMandateWith(s, m)
	require.NoError(t, err)
	f := policy.SignedFields(m, h)
	sig, err := s.Sign(f, nil)
	require.NoError(t, err)
	require.NoError(t, principalsig.Verify(principalsig.EIP712, m.Principal, "", f, nil, sig))

	for _, v := range []byte{0, 1, 29, 31, 32} {
		bad := bytes.Clone(sig)
		bad[64] = v
		require.ErrorIs(t, principalsig.Verify(principalsig.EIP712, m.Principal, "", f, nil, bad), principalsig.ErrSignature, "v=%d", v)
	}
	// n - s with v flipped recovers the same key; refused as high s.
	var sc secp256k1.ModNScalar
	sc.SetByteSlice(sig[32:64])
	sc.Negate()
	high := bytes.Clone(sig)
	sb := sc.Bytes()
	copy(high[32:64], sb[:])
	high[64] ^= 1
	require.ErrorIs(t, principalsig.Verify(principalsig.EIP712, m.Principal, "", f, nil, high), principalsig.ErrSignature)
	for _, fld := range []func(*principalsig.EIP712Message){
		func(x *principalsig.EIP712Message) { x.Version++ },
		func(x *principalsig.EIP712Message) { x.GateID += "x" },
		func(x *principalsig.EIP712Message) { x.MandateID[15] ^= 1 },
	} {
		g := f
		fld(&g)
		require.ErrorIs(t, principalsig.Verify(principalsig.EIP712, m.Principal, "", g, nil, sig), principalsig.ErrSignature)
	}
}

func TestEd25519VerifyRefusesNonCanonicalS(t *testing.T) {
	pub, sk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	var h [32]byte
	sig := ed25519.Sign(sk, principalsig.Message(h))
	require.NoError(t, principalsig.Verify(principalsig.Ed25519, pub, "", principalsig.EIP712Message{MandateHash: h}, nil, sig))
	bad := bytes.Clone(sig)
	bad[63] |= 0xf0
	require.ErrorIs(t, principalsig.Verify(principalsig.Ed25519, pub, "", principalsig.EIP712Message{MandateHash: h}, nil, bad), principalsig.ErrSignature)
}
