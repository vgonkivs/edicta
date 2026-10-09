package principalsig_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/principalsig"
)

type vecKey struct {
	Seed       string `json:"seed_hex"`
	Compressed string `json:"public_key_compressed_hex"`
	EthAddress string `json:"eth_address_hex"`
}

type vecReject struct {
	ID         string `json:"id"`
	Signed     string `json:"signed_mandate_hex"`
	Want       string `json:"expect_error"`
	SignedData string `json:"signed_data"`
	SignedDoc  string `json:"signed_signdoc"`
	Digest     string `json:"signed_digest_hex"`
}

func load(t *testing.T, name string, c any) (map[string]vecKey, []vecReject) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "spec", "vectors", "principal", name))
	require.NoError(t, err)
	var f struct {
		Keys   map[string]vecKey `json:"keys"`
		Case   json.RawMessage   `json:"case"`
		Reject []vecReject       `json:"reject"`
	}
	require.NoError(t, json.Unmarshal(b, &f))
	require.NoError(t, json.Unmarshal(f.Case, c))
	require.NotEmpty(t, f.Reject)
	return f.Keys, f.Reject
}

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func decode(t *testing.T, signedHex string) (*policy.SignedMandate, [32]byte) {
	t.Helper()
	sm, h, err := policy.DecodeSignedMandate(unhex(t, signedHex))
	require.NoError(t, err)
	return sm, h
}

// checkRejects runs every reject through policy.VerifyMandate and, when the
// mandate decodes, through principalsig.Verify directly.
func checkRejects(t *testing.T, rejects []vecReject) {
	for _, r := range rejects {
		t.Run(r.ID, func(t *testing.T) {
			_, _, err := policy.VerifyMandate(unhex(t, r.Signed))
			switch r.Want {
			case "ErrMandateSignature":
				require.ErrorIs(t, err, policy.ErrMandateSignature)
				sm, h, derr := policy.DecodeSignedMandate(unhex(t, r.Signed))
				require.NoError(t, derr)
				m := &sm.Mandate
				s, serr := m.Scheme()
				require.NoError(t, serr)
				err = principalsig.Verify(s, m.Principal, m.PrincipalHRP, policy.SignedFields(m, h), policy.SignedText(m, h), sm.Signature)
				require.ErrorIs(t, err, principalsig.ErrSignature)
			case "ErrMandateInvalid":
				require.ErrorIs(t, err, policy.ErrMandateInvalid)
			default:
				require.Failf(t, "unknown expectation", "%q", r.Want)
			}
		})
	}
}

func TestEd25519Vectors(t *testing.T) {
	var c struct {
		Principal  string `json:"principal_hex"`
		Hash       string `json:"mandate_hash_hex"`
		Message    string `json:"signed_message_hex"`
		Signature  string `json:"signature_hex"`
		Signed     string `json:"signed_mandate_hex"`
		CounterKey string `json:"counter_key_hex"`
	}
	keys, rejects := load(t, "ed25519.json", &c)
	sm, h := decode(t, c.Signed)
	m := &sm.Mandate
	assert.Equal(t, c.Hash, hex.EncodeToString(h[:]))
	assert.Equal(t, c.Message, hex.EncodeToString(principalsig.Message(h)))
	assert.Equal(t, c.Principal, hex.EncodeToString(m.Principal))

	signer := principalsig.NewEd25519Signer(ed25519.NewKeyFromSeed(unhex(t, keys["p1"].Seed)))
	assert.Equal(t, m.Principal, signer.Principal())
	sig, err := signer.Sign(policy.SignedFields(m, h), nil)
	require.NoError(t, err)
	assert.Equal(t, c.Signature, hex.EncodeToString(sig))
	require.NoError(t, principalsig.Verify(principalsig.Ed25519, m.Principal, "", policy.SignedFields(m, h), nil, sig))
	ck := m.CounterKey()
	assert.Equal(t, c.CounterKey, hex.EncodeToString(ck[:]))
	checkRejects(t, rejects)
}

func TestADR036Vectors(t *testing.T) {
	var c struct {
		Principal  string `json:"principal_hex"`
		HRP        string `json:"hrp"`
		Address    string `json:"address"`
		Hash       string `json:"mandate_hash_hex"`
		Rendered   string `json:"rendered_text"`
		SignDoc    string `json:"signdoc"`
		Digest     string `json:"digest_hex"`
		Signature  string `json:"signature_hex"`
		Signed     string `json:"signed_mandate_hex"`
		CounterKey string `json:"counter_key_hex"`
	}
	keys, rejects := load(t, "adr036.json", &c)
	sm, h := decode(t, c.Signed)
	m := &sm.Mandate
	require.Equal(t, policy.SigTypeADR036, m.SigType)
	assert.Equal(t, c.Hash, hex.EncodeToString(h[:]))
	assert.Equal(t, c.Principal, hex.EncodeToString(m.Principal))
	assert.Equal(t, c.HRP, m.PrincipalHRP)

	addr, err := principalsig.CosmosAddress(m.Principal, m.PrincipalHRP)
	require.NoError(t, err)
	assert.Equal(t, c.Address, addr)
	assert.Equal(t, keys["p1_secp"].Compressed, c.Principal)

	d := principalsig.ADR036Data([]byte(policy.Render(m)), h)
	assert.Equal(t, c.Rendered, string(d))
	assert.Equal(t, c.Rendered, string(policy.SignedText(m, h)))
	doc, err := principalsig.ADR036SignDoc(m.Principal, m.PrincipalHRP, d)
	require.NoError(t, err)
	assert.Equal(t, c.SignDoc, string(doc))
	digest := sha256.Sum256(doc)
	assert.Equal(t, c.Digest, hex.EncodeToString(digest[:]))

	signer, err := principalsig.NewSecp256k1Signer(principalsig.CosmosADR036, unhex(t, keys["p1_secp"].Seed), c.HRP)
	require.NoError(t, err)
	assert.Equal(t, m.Principal, signer.Principal())
	sig, err := signer.Sign(policy.SignedFields(m, h), d)
	require.NoError(t, err)
	assert.Equal(t, c.Signature, hex.EncodeToString(sig))
	require.NoError(t, principalsig.Verify(principalsig.CosmosADR036, m.Principal, m.PrincipalHRP, policy.SignedFields(m, h), d, sig))
	ck := m.CounterKey()
	assert.Equal(t, c.CounterKey, hex.EncodeToString(ck[:]))

	for _, r := range rejects {
		if r.SignedData != "" {
			assert.NotEqual(t, c.Rendered, r.SignedData, r.ID)
		}
		if r.SignedDoc != "" {
			assert.NotEqual(t, c.SignDoc, r.SignedDoc, r.ID)
		}
	}
	checkRejects(t, rejects)
}

func TestADR036TextDiffersByOneByte(t *testing.T) {
	var c struct {
		Rendered string `json:"rendered_text"`
	}
	_, rejects := load(t, "adr036.json", &c)
	for _, r := range rejects {
		if r.ID != "text_differs_one_byte" {
			continue
		}
		require.Len(t, r.SignedData, len(c.Rendered))
		diff := 0
		for i := range c.Rendered {
			if c.Rendered[i] != r.SignedData[i] {
				diff++
			}
		}
		require.Equal(t, 1, diff)
		_, _, err := policy.VerifyMandate(unhex(t, r.Signed))
		require.ErrorIs(t, err, policy.ErrMandateSignature)
		return
	}
	require.Fail(t, "reject text_differs_one_byte missing")
}

func TestEIP712Vectors(t *testing.T) {
	var c struct {
		Address    string          `json:"address"`
		Hash       string          `json:"mandate_hash_hex"`
		TypedData  json.RawMessage `json:"typed_data"`
		Domain     string          `json:"domain_separator_hex"`
		TypeHash   string          `json:"type_hash_hex"`
		HashStruct string          `json:"hash_struct_hex"`
		Digest     string          `json:"digest_hex"`
		Signature  string          `json:"signature_hex"`
		Signed     string          `json:"signed_mandate_hex"`
		CounterKey string          `json:"counter_key_hex"`
	}
	keys, rejects := load(t, "eip712.json", &c)
	sm, h := decode(t, c.Signed)
	m := &sm.Mandate
	require.Equal(t, policy.SigTypeEIP712, m.SigType)
	assert.Equal(t, c.Hash, hex.EncodeToString(h[:]))
	assert.Equal(t, c.Address, "0x"+hex.EncodeToString(m.Principal))

	cosmos, err := principalsig.NewSecp256k1Signer(principalsig.CosmosADR036, unhex(t, keys["p1_secp"].Seed), "celestia")
	require.NoError(t, err)
	addr, err := principalsig.EthereumAddress(cosmos.Principal())
	require.NoError(t, err)
	assert.Equal(t, keys["p1_secp"].EthAddress, hex.EncodeToString(addr[:]))

	f := policy.SignedFields(m, h)
	td, err := principalsig.EIP712TypedDataJSON(f)
	require.NoError(t, err)
	assert.JSONEq(t, string(c.TypedData), string(td))
	ds, th, hs, dg := principalsig.EIP712DomainSeparator(), principalsig.EIP712TypeHash(), principalsig.EIP712HashStruct(f), principalsig.EIP712Digest(f)
	assert.Equal(t, c.Domain, hex.EncodeToString(ds[:]))
	assert.Equal(t, c.TypeHash, hex.EncodeToString(th[:]))
	assert.Equal(t, c.HashStruct, hex.EncodeToString(hs[:]))
	assert.Equal(t, c.Digest, hex.EncodeToString(dg[:]))

	signer, err := principalsig.NewSecp256k1Signer(principalsig.EIP712, unhex(t, keys["p1_secp"].Seed), "")
	require.NoError(t, err)
	assert.Equal(t, m.Principal, signer.Principal())
	sig, err := signer.Sign(f, nil)
	require.NoError(t, err)
	assert.Equal(t, c.Signature, hex.EncodeToString(sig))
	require.NoError(t, principalsig.Verify(principalsig.EIP712, m.Principal, "", f, nil, sig))
	ck := m.CounterKey()
	assert.Equal(t, c.CounterKey, hex.EncodeToString(ck[:]))

	for _, r := range rejects {
		if r.Digest != "" {
			assert.NotEqual(t, c.Digest, r.Digest, r.ID)
		}
	}
	checkRejects(t, rejects)
}
