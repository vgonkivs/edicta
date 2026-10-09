package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mandateCase struct {
	ID        string `json:"id"`
	Signer    string `json:"signer"`
	Cbor      string `json:"mandate_cbor_hex"`
	Hash      string `json:"mandate_hash_hex"`
	Signature string `json:"signature_hex"`
	Signed    string `json:"signed_mandate_hex"`
	SignDoc   string `json:"signdoc"`
}

func vectors(t *testing.T) (map[string]mandateCase, map[string]string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "spec", "vectors", "policy", "mandate.json"))
	require.NoError(t, err)
	var f struct {
		Keys map[string]struct {
			Seed string `json:"seed_hex"`
		} `json:"keys"`
		Cases []mandateCase `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(b, &f))
	cases := map[string]mandateCase{}
	for _, c := range f.Cases {
		cases[c.ID] = c
	}
	seeds := map[string]string{}
	for k, v := range f.Keys {
		seeds[k] = v.Seed
	}
	return cases, seeds
}

func file(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	return p
}

func call(args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func renderText(t *testing.T, id string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "spec", "vectors", "policy", "render.json"))
	require.NoError(t, err)
	var f struct {
		Cases []struct {
			Ref  string `json:"mandate_ref"`
			Text string `json:"text"`
		} `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(b, &f))
	for _, c := range f.Cases {
		if c.Ref == id {
			return c.Text
		}
	}
	require.Failf(t, "no render case", id)
	return ""
}

func TestSignVerifyPublishPerScheme(t *testing.T) {
	cases, seeds := vectors(t)
	for id, scheme := range map[string]string{"m_full": "ed25519", "m_adr036": "cosmos", "m_eip712": "eth"} {
		t.Run(id, func(t *testing.T) {
			c := cases[id]
			mf := file(t, "mandate.hex", c.Cbor)
			code, out, _ := call("render", "--mandate", mf)
			require.Equal(t, exitOK, code)
			assert.Equal(t, renderText(t, id), out)

			key := file(t, "key.hex", seeds[c.Signer]+"\n")
			outFile := filepath.Join(t.TempDir(), "signed.cbor")
			code, _, errOut := call("sign", "--mandate", mf, "--scheme", scheme, "--key", key, "--out", outFile)
			require.Equal(t, exitOK, code, errOut)
			signed, err := os.ReadFile(outFile)
			require.NoError(t, err)
			assert.Equal(t, c.Signed, hex.EncodeToString(signed))

			sig, err := hex.DecodeString(c.Signature)
			require.NoError(t, err)
			for _, s := range []string{"0x" + c.Signature, base64.StdEncoding.EncodeToString(sig)} {
				code, out, errOut = call("sign", "--mandate", mf, "--scheme", scheme, "--signature", s)
				require.Equal(t, exitOK, code, errOut)
				assert.Equal(t, c.Signed+"\n", out)
			}

			code, out, _ = call("verify", "--signed", outFile)
			require.Equal(t, exitOK, code)
			assert.Contains(t, out, "mandate hash: "+c.Hash)

			dir := t.TempDir()
			code, out, errOut = call("publish", "--signed", outFile, "--archive", dir)
			require.Equal(t, exitOK, code, errOut)
			assert.Contains(t, out, "written")
			code, out, _ = call("publish", "--signed", outFile, "--archive", dir)
			require.Equal(t, exitOK, code)
			assert.Contains(t, out, "already present")
		})
	}
}

func TestWalletPayloads(t *testing.T) {
	cases, _ := vectors(t)
	code, out, errOut := call("signdoc", "--mandate", file(t, "m", cases["m_adr036"].Cbor))
	require.Equal(t, exitOK, code, errOut)
	assert.Equal(t, cases["m_adr036"].SignDoc+"\n", out)

	code, out, errOut = call("typed-data", "--mandate", file(t, "m", cases["m_eip712"].Signed))
	require.Equal(t, exitOK, code, errOut)
	assert.Contains(t, out, `"mandateHash":"0x`+cases["m_eip712"].Hash+`"`)
	assert.Contains(t, out, `"name":"Edicta Mandate"`)

	code, _, _ = call("typed-data", "--mandate", file(t, "m", cases["m_adr036"].Cbor))
	assert.Equal(t, exitUsage, code)
	code, _, _ = call("signdoc", "--mandate", file(t, "m", cases["m_full"].Cbor))
	assert.Equal(t, exitUsage, code)
}

func TestRefusals(t *testing.T) {
	cases, seeds := vectors(t)
	c := cases["m_eip712"]
	mf := file(t, "m", c.Cbor)
	code, _, _ := call("sign", "--mandate", mf, "--scheme", "cosmos", "--key", file(t, "k", seeds["p1_secp"]))
	assert.Equal(t, exitUsage, code, "scheme differs from the mandate's")
	code, _, _ = call("sign", "--mandate", mf, "--scheme", "eth")
	assert.Equal(t, exitUsage, code, "neither key nor signature")
	code, _, _ = call("sign", "--mandate", mf, "--scheme", "eth", "--key", file(t, "k", seeds["p2_secp"]))
	assert.Equal(t, exitInvalid, code, "key of another principal")

	bad := []byte(c.Signature)
	bad[0] ^= 1
	code, _, _ = call("sign", "--mandate", mf, "--scheme", "eth", "--signature", string(bad))
	assert.Equal(t, exitInvalid, code, "wallet signature that does not verify")

	signed := []byte(c.Signed)
	signed[len(signed)-3] ^= 1
	code, _, _ = call("verify", "--signed", file(t, "s", string(signed)))
	assert.Equal(t, exitInvalid, code)
	code, _, _ = call("publish", "--signed", file(t, "s", string(signed)), "--archive", t.TempDir())
	assert.Equal(t, exitInvalid, code)

	for _, args := range [][]string{{}, {"bogus"}, {"render"}, {"render", "--mandate", mf, "extra"}, {"publish", "--signed", mf}} {
		code, _, errOut := call(args...)
		assert.Equal(t, exitUsage, code, strings.Join(args, " "))
		assert.Contains(t, errOut, "usage")
	}
}

func TestPrivateMandateAndAddressBook(t *testing.T) {
	cases, seeds := vectors(t)
	c := cases["m_full"]
	bob := strings.Repeat("09", 32)
	alice := strings.Repeat("0a", 32)
	mallory := strings.Repeat("0b", 32)

	priv := filepath.Join(t.TempDir(), "private.cbor")
	code, _, errOut := call("private", "--mandate", file(t, "m.hex", c.Cbor),
		"--auditor", "Bob:"+bob, "--auditor", "Alice:"+alice, "--new-id", "--out", priv)
	require.Equal(t, exitOK, code, errOut)

	again := filepath.Join(t.TempDir(), "again.cbor")
	code, _, errOut = call("private", "--mandate", file(t, "m.hex", c.Cbor), "--auditor", "Bob:"+bob, "--new-id", "--out", again)
	require.Equal(t, exitOK, code, errOut)
	a, err := os.ReadFile(priv)
	require.NoError(t, err)
	b, err := os.ReadFile(again)
	require.NoError(t, err)
	assert.NotEqual(t, a, b, "mandate_id and state_salt are drawn fresh")

	book := filepath.Join(t.TempDir(), "book.json")
	code, out, errOut := call("render", "--mandate", priv, "--book", book)
	require.Equal(t, exitOK, code, errOut)
	assert.Contains(t, out, `Auditor "Bob" (label not verified) - key fingerprint: `)
	assert.Contains(t, out, "Labels are not verified")
	assert.Contains(t, errOut, `auditor label "Bob" is new`)

	key := file(t, "key.hex", seeds[c.Signer]+"\n")
	code, _, errOut = call("sign", "--mandate", priv, "--scheme", "ed25519", "--key", key, "--book", book)
	require.Equal(t, exitOK, code, errOut)
	assert.Contains(t, errOut, "counters of this mandate start at zero")
	_, err = os.Stat(book)
	require.NoError(t, err, "sign records the labels")

	swapped := filepath.Join(t.TempDir(), "swapped.cbor")
	code, _, errOut = call("private", "--mandate", file(t, "m.hex", c.Cbor),
		"--auditor", "Bob:"+mallory, "--auditor", "Alice:"+alice, "--new-id", "--out", swapped)
	require.Equal(t, exitOK, code, errOut)
	code, _, errOut = call("sign", "--mandate", swapped, "--scheme", "ed25519", "--key", key, "--book", book)
	assert.Equal(t, exitInvalid, code)
	assert.Contains(t, errOut, `WARNING: auditor label "Bob" maps to another key`)
	code, _, errOut = call("sign", "--mandate", swapped, "--scheme", "ed25519", "--key", key, "--book", book, "--accept-new-key")
	require.Equal(t, exitOK, code, errOut)

	signed := filepath.Join(t.TempDir(), "signed.cbor")
	code, _, errOut = call("sign", "--mandate", priv, "--scheme", "ed25519", "--key", key, "--out", signed, "--book", book, "--accept-new-key")
	require.Equal(t, exitOK, code, errOut)
	code, _, errOut = call("publish", "--signed", signed, "--archive", t.TempDir())
	assert.Equal(t, exitInvalid, code, "a private mandate is never published in clear")
	assert.Contains(t, errOut, "private mandate")
}

func TestSignWarnsOnModeSwitch(t *testing.T) {
	cases, seeds := vectors(t)
	c := cases["m_full"]
	key := file(t, "key.hex", seeds[c.Signer]+"\n")
	public := filepath.Join(t.TempDir(), "public.cbor")
	code, _, errOut := call("sign", "--mandate", file(t, "m.hex", c.Cbor), "--scheme", "ed25519", "--key", key, "--out", public)
	require.Equal(t, exitOK, code, errOut)

	code, _, errOut = call("sign", "--mandate", file(t, "m.hex", c.Cbor), "--scheme", "ed25519", "--key", key, "--replaces", public)
	require.Equal(t, exitOK, code, errOut)
	assert.NotContains(t, errOut, "start at zero", "same mandate_id, same mode")

	priv := filepath.Join(t.TempDir(), "private.cbor")
	code, _, errOut = call("private", "--mandate", file(t, "m.hex", c.Cbor), "--auditor", "Bob:"+strings.Repeat("09", 32), "--out", priv)
	require.Equal(t, exitOK, code, errOut)
	code, _, errOut = call("sign", "--mandate", priv, "--scheme", "ed25519", "--key", key, "--replaces", public)
	require.Equal(t, exitOK, code, errOut)
	assert.Contains(t, errOut, "switches between public and private mode")
}
