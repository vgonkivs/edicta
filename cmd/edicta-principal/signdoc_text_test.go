package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/principalsig"
)

type adr036Case struct {
	Cbor    string `json:"mandate_cbor_hex"`
	Hash    string `json:"mandate_hash_hex"`
	D       string `json:"rendered_text"`
	SignDoc string `json:"signdoc"`
}

func adr036Vectors(t *testing.T) (map[string]adr036Case, string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "spec", "vectors", "principal", "adr036.json"))
	require.NoError(t, err)
	var f struct {
		Keys map[string]struct {
			Seed string `json:"seed_hex"`
		} `json:"keys"`
		Case        adr036Case `json:"case"`
		CasePrivate adr036Case `json:"case_private"`
	}
	require.NoError(t, json.Unmarshal(b, &f))
	return map[string]adr036Case{"case": f.Case, "case_private": f.CasePrivate}, f.Keys["p1_secp"].Seed
}

func signDocData(t *testing.T, signdoc string) string {
	t.Helper()
	var doc struct {
		Msgs []struct {
			Value struct {
				Data string `json:"data"`
			} `json:"value"`
		} `json:"msgs"`
	}
	require.NoError(t, json.Unmarshal([]byte(signdoc), &doc))
	require.Len(t, doc.Msgs, 1)
	d, err := base64.StdEncoding.DecodeString(doc.Msgs[0].Value.Data)
	require.NoError(t, err)
	return string(d)
}

func TestSignDocTextIsD(t *testing.T) {
	cases, _ := adr036Vectors(t)
	for id, c := range cases {
		t.Run(id, func(t *testing.T) {
			code, out, errOut := call("signdoc", "--text", "--mandate", file(t, "m", c.Cbor))
			require.Equal(t, exitOK, code, errOut)
			assert.Equal(t, signDocData(t, c.SignDoc), out)
			assert.Equal(t, c.D, out)
			assert.True(t, strings.HasSuffix(out, "\n\nmandate hash: "+c.Hash), "D ends in the hash line, no LF after it")

			code, out, errOut = call("signdoc", "--mandate", file(t, "m", c.Cbor))
			require.Equal(t, exitOK, code, errOut)
			assert.Equal(t, c.SignDoc+"\n", out)
		})
	}
}

func TestSignDocTextRoundTrip(t *testing.T) {
	cases, seed := adr036Vectors(t)
	sk, err := hex.DecodeString(seed)
	require.NoError(t, err)
	for id, c := range cases {
		t.Run(id, func(t *testing.T) {
			mf := file(t, "m", c.Cbor)
			code, text, errOut := call("signdoc", "--text", "--mandate", mf)
			require.Equal(t, exitOK, code, errOut)

			raw, err := hex.DecodeString(c.Cbor)
			require.NoError(t, err)
			m, h, err := policy.DecodeMandate(raw)
			require.NoError(t, err)
			s, err := principalsig.NewSecp256k1Signer(principalsig.CosmosADR036, sk, m.PrincipalHRP)
			require.NoError(t, err)
			sig, err := s.Sign(policy.SignedFields(m, h), []byte(text))
			require.NoError(t, err)

			signed := filepath.Join(t.TempDir(), "signed.cbor")
			code, _, errOut = call("sign", "--mandate", mf, "--scheme", "cosmos",
				"--signature", base64.StdEncoding.EncodeToString(sig), "--out", signed)
			require.Equal(t, exitOK, code, errOut)
			code, out, errOut := call("verify", "--signed", signed)
			require.Equal(t, exitOK, code, errOut)
			assert.Contains(t, out, "valid\nmandate hash: "+c.Hash+"\n")
		})
	}
}

func TestTextOnlyForSignDoc(t *testing.T) {
	cases, _ := adr036Vectors(t)
	mf := file(t, "m", cases["case"].Cbor)
	code, _, _ := call("render", "--text", "--mandate", mf)
	assert.Equal(t, exitUsage, code)
	code, _, _ = call("typed-data", "--text", "--mandate", mf)
	assert.Equal(t, exitUsage, code)
}
