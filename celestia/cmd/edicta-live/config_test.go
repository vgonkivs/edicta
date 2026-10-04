package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/secret"
	"github.com/vgonkivs/edicta/edictaapi"
)

func goodArgs() []string {
	pub := hex.EncodeToString(bytes.Repeat([]byte{9}, 32))
	return []string{
		"--api-url", "http://127.0.0.1:8080",
		"--bridge-addr", "bridge.example.invalid:26658", "--bridge-tls",
		"--grpc-addr", "consensus.example.invalid:9090", "--grpc-tls",
		"--agent-id", "agent-1", "--agent-key-file", "/nonexistent/agent.key",
		"--recipient", "auditor=" + pubHex(),
		"--up-addr", "celestia1up", "--up-amount", "1000",
		"--down-addr", "celestia1down", "--down-amount", "2000",
		"--executor-keyring-dir", "/nonexistent/kr", "--executor-key", "sender",
		"--executor-passphrase-file", "/nonexistent/pass",
		"--executor-ed25519-file", "/nonexistent/exec.key",
		"--gate-pubkey", pub,
	}
}

func pubHex() string {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(k.PublicKey().Bytes())
}

func parse(t *testing.T, extra ...string) (Config, error) {
	t.Helper()
	var sink bytes.Buffer
	return parseFlags(append(goodArgs(), extra...), &sink)
}

func TestParseFlagsDefaults(t *testing.T) {
	c, err := parse(t)
	require.NoError(t, err)
	assert.EqualValues(t, 100, c.ThresholdBP, "live threshold is 100 bp")
	assert.Equal(t, 1, c.MaxDecisions)
	assert.Equal(t, "self", c.Inclusion)
	assert.Equal(t, "coingecko", c.PriceSource)
	assert.False(t, c.DryRun)
	assert.Len(t, c.Recipients, 1)
}

func TestParseFlagsOverrides(t *testing.T) {
	c, err := parse(t, "--threshold-bp", "5", "--max-decisions", "3", "--dry-run", "--timeout", "5m",
		"--price-source", "kraken", "--kraken-pair", "TIAUSD")
	require.NoError(t, err)
	assert.EqualValues(t, 5, c.ThresholdBP)
	assert.Equal(t, 3, c.MaxDecisions)
	assert.True(t, c.DryRun)
	assert.Equal(t, 5*time.Minute, c.Timeout)
	assert.Equal(t, "kraken", c.PriceSource)
}

func TestParseFlagsRefusals(t *testing.T) {
	// Later flags win in the flag package, so an extra flag overrides a good one.
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"bad api url", []string{"--api-url", "ftp://x"}, "--api-url"},
		{"relative api url", []string{"--api-url", "localhost:8080"}, "--api-url"},
		{"token over http to a remote host", []string{"--api-url", "http://edictad.example.invalid:8080", "--api-token-file", "/t"}, "plain HTTP"},
		{"bridge token over plain http", []string{"--bridge-tls=false", "--bridge-token-file", "/t"}, "--bridge-tls"},
		{"grpc token over plain grpc", []string{"--grpc-tls=false", "--grpc-token-file", "/t"}, "--grpc-tls"},
		{"no bridge", []string{"--bridge-addr", ""}, "--bridge-addr"},
		{"no grpc", []string{"--grpc-addr", ""}, "--grpc-addr"},
		{"bad gate key", []string{"--gate-pubkey", "zz"}, "--gate-pubkey"},
		{"bad namespace", []string{"--namespace", "abcd"}, "--namespace"},
		{"threshold zero", []string{"--threshold-bp", "0"}, "--threshold-bp"},
		{"threshold too big", []string{"--threshold-bp", "10001"}, "--threshold-bp"},
		{"zero decisions", []string{"--max-decisions", "0"}, "--max-decisions"},
		{"fast poll", []string{"--poll-interval", "10ms"}, "--poll-interval"},
		{"zero timeout", []string{"--timeout", "0s"}, "--timeout"},
		{"unknown inclusion", []string{"--inclusion", "trust-me"}, "--inclusion"},
		{"light without primary", []string{"--inclusion", "light"}, "--rpc-primary"},
		{"light without witness", []string{"--inclusion", "light", "--rpc-primary", "https://a.invalid"}, "--rpc-witness"},
		{"light without trust", []string{"--inclusion", "light", "--rpc-primary", "https://a.invalid", "--rpc-witness", "https://b.invalid"}, "--trust-height"},
		{"crosscheck with one", []string{"--inclusion", "crosscheck", "--crosscheck-bridge", "a:1"}, "two"},
		{"unknown price source", []string{"--price-source", "oracle"}, "--price-source"},
		{"lower-case quote", []string{"--quote", "usd"}, "--quote"},
		{"bad price url", []string{"--price-base-url", "nope"}, "--price-base-url"},
		{"zero amount", []string{"--up-amount", "0"}, "amount"},
		{"no destination", []string{"--down-addr", ""}, "--down-addr"},
		{"no keyring dir", []string{"--executor-keyring-dir", ""}, "--executor-keyring-dir"},
		{"both passphrase sources", []string{"--executor-passphrase-prompt"}, "exactly one"},
		{"fee above max", []string{"--fee", "10", "--max-fee", "5"}, "--max-fee"},
		{"zero gas", []string{"--gas-limit", "0"}, "--gas-limit"},
		{"bad agent id", []string{"--agent-id", "a b"}, "--agent-id"},
		{"bad recipient", []string{"--recipient", "kid=00"}, "--recipient"},
		{"stray argument", []string{"extra"}, "unexpected"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parse(t, tc.args...)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrConfig)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestParseFlagsNoPassphraseSource(t *testing.T) {
	args := goodArgs()
	for i, a := range args {
		if a == "--executor-passphrase-file" {
			args = append(args[:i], args[i+2:]...)
			break
		}
	}
	_, err := parseFlags(args, &bytes.Buffer{})
	require.ErrorIs(t, err, ErrConfig)
	assert.Contains(t, err.Error(), "exactly one")
}

func TestDryRunNeedsNoRecordKey(t *testing.T) {
	args := goodArgs()
	for i, a := range args {
		if a == "--executor-ed25519-file" {
			args = append(args[:i], args[i+2:]...)
			break
		}
	}
	_, err := parseFlags(args, &bytes.Buffer{})
	require.ErrorIs(t, err, ErrConfig)
	assert.Contains(t, err.Error(), "--executor-ed25519-file")
	_, err = parseFlags(append(args, "--dry-run"), &bytes.Buffer{})
	require.NoError(t, err)
}

func TestLightAndCrosscheckConfig(t *testing.T) {
	hash := hex.EncodeToString(bytes.Repeat([]byte{1}, 32))
	_, err := parse(t, "--inclusion", "light", "--rpc-primary", "https://a.invalid", "--rpc-witness", "https://b.invalid,https://c.invalid",
		"--trust-height", "10", "--trust-hash", hash)
	require.NoError(t, err)
	_, err = parse(t, "--inclusion", "light", "--rpc-primary", "https://a.invalid", "--rpc-witness", "https://b.invalid",
		"--trust-height", "10", "--trust-hash", "abcd")
	require.ErrorIs(t, err, ErrConfig)
	_, err = parse(t, "--inclusion", "crosscheck", "--crosscheck-bridge", "a.invalid:1", "--crosscheck-bridge", "b.invalid:1", "--crosscheck-tls")
	require.NoError(t, err)
}

func TestNoSecretValueInErrors(t *testing.T) {
	_, err := parse(t, "--gate-pubkey", "SECRETVALUE")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "SECRETVALUE")
}

func TestParseRecipient(t *testing.T) {
	r, err := parseRecipient("kid-1=" + pubHex())
	require.NoError(t, err)
	assert.Equal(t, []byte("kid-1"), r.KID)
	for _, bad := range []string{"", "nokey", "=" + pubHex(), "k=zz", "k=" + strings.Repeat("00", 31), strings.Repeat("k", 33) + "=" + pubHex()} {
		_, err := parseRecipient(bad)
		assert.Error(t, err, bad)
	}
}

func TestReadSeed(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "k")
	require.NoError(t, os.WriteFile(good, bytes.Repeat([]byte{7}, 32), 0o600))
	k, err := readSeed(good, "agent")
	require.NoError(t, err)
	assert.Len(t, k, 64)

	wide := filepath.Join(dir, "wide")
	require.NoError(t, os.WriteFile(wide, bytes.Repeat([]byte{7}, 32), 0o644))
	_, err = readSeed(wide, "agent")
	assert.ErrorIs(t, err, secret.ErrPermissions)

	short := filepath.Join(dir, "short")
	require.NoError(t, os.WriteFile(short, []byte("abc"), 0o600))
	_, err = readSeed(short, "agent")
	assert.Error(t, err)
	_, err = readSeed(filepath.Join(dir, "none"), "agent")
	assert.Error(t, err)
}

func TestPublishSignerNeverPrints(t *testing.T) {
	_, priv := mustKey(t)
	s := newPublishSigner("agent-1", priv)
	for _, out := range []string{
		strings.Join([]string{s.String(), s.GoString()}, " "),
		sprint("%v %+v %#v %s %x", s, s, s, s, s),
	} {
		assert.NotContains(t, out, hex.EncodeToString(priv))
		assert.NotContains(t, out, string(priv))
	}
	sig, err := s.SignPublish(t.Context(), []byte("m"))
	require.NoError(t, err)
	assert.Len(t, sig, 64)
	var _ edictaapi.PublishSigner = s
}

func TestGenRecipientNeverOverwrites(t *testing.T) {
	p := filepath.Join(t.TempDir(), "r.key")
	r, err := genRecipient(p)
	require.NoError(t, err)
	assert.NotNil(t, r.PublicKey)
	fi, err := os.Stat(p)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
	_, err = genRecipient(p)
	assert.Error(t, err, "an existing file is never replaced")
}

func TestErrConfigIsSentinel(t *testing.T) {
	assert.True(t, errors.Is(cfgErr("x"), ErrConfig))
}

func TestPubkeyCommand(t *testing.T) {
	p := filepath.Join(t.TempDir(), "seed")
	seed := bytes.Repeat([]byte{7}, 32)
	require.NoError(t, os.WriteFile(p, seed, 0o600))
	var out bytes.Buffer
	require.NoError(t, execute(t.Context(), []string{"pubkey", p}, &out, &bytes.Buffer{}, os.Stdin))
	want := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	assert.Equal(t, hex.EncodeToString(want)+"\n", out.String())
	assert.NotContains(t, out.String(), hex.EncodeToString(seed))
	assert.Error(t, execute(t.Context(), []string{"pubkey"}, &out, &bytes.Buffer{}, os.Stdin))
	assert.Error(t, execute(t.Context(), []string{"pubkey", filepath.Join(t.TempDir(), "none")}, &out, &bytes.Buffer{}, os.Stdin))
}
