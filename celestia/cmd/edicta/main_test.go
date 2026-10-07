package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/archive/httparchive"
	"github.com/vgonkivs/edicta/celestia/test/fibrefix"
	"github.com/vgonkivs/edicta/celestia/verifycli"
)

const (
	exitValid         = 0
	exitInvalid       = 1
	exitUnchecked     = 2
	exitNotAuthorized = 3
	exitUsage         = 4
)

func edicta(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := run(args, &out)
	return code, out.String()
}

func TestNoSubcommandIsAUsageError(t *testing.T) {
	code, out := edicta(t)
	assert.Equal(t, exitUsage, code)
	for _, sub := range []string{"verify", "replay"} {
		assert.Contains(t, out, sub, "the usage names the subcommand")
	}
}

func TestUnknownSubcommandIsAUsageError(t *testing.T) {
	for _, sub := range []string{"frobnicate", "VERIFY", "--verify", "-"} {
		code, out := edicta(t, sub)
		assert.Equal(t, exitUsage, code, "%q: %s", sub, out)
		assert.NotEmpty(t, out)
	}
}

func TestVerifyUsageErrorsAreUsageErrors(t *testing.T) {
	h := hex.EncodeToString(make([]byte, 32))
	key := hex.EncodeToString(make([]byte, 32))
	tests := [][]string{
		{"verify"},
		{"verify", h},
		{"verify", h, "--gate-key", key},
		{"verify", "zz", "--gate-key", key, "--archive", t.TempDir()},
		{"verify", h, "--gate-key", "00", "--archive", t.TempDir()},
		{"verify", h, "--gate-key", key, "--archive", "/nonexistent/archive"},
		{"verify", h, "--gate-key", key, "--archive-url", "ftp://x"},
		{"verify", h, "--gate-key", key, "--archive", t.TempDir(), "--archive-url", "http://127.0.0.1:1"},
		{"replay"},
		{"replay", h, "--gate-key", key},
	}
	for _, args := range tests {
		code, out := edicta(t, args...)
		assert.Equal(t, exitUsage, code, "%v: %s", args, out)
		assert.NotEmpty(t, out)

		want := verifycli.Run(context.Background(), args, &bytes.Buffer{})
		assert.Equal(t, want, code, "the same exit code as the library entry point")
	}
}

func TestVerifyUsageErrorIsJSONWithTheFlag(t *testing.T) {
	code, out := edicta(t, "verify", "--json")
	assert.Equal(t, exitUsage, code)
	var e map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &e), out)
	assert.NotEmpty(t, e["error"])
}

func TestUnknownFlagGivesNoVerdict(t *testing.T) {
	code, out := edicta(t, "verify", "--no-such-flag")
	assert.Equal(t, exitUsage, code)
	assert.NotContains(t, out, "verdict")
}

// A live Fibre decision, verified through the real anchor verifier.
func TestVerifyAndReplayEndToEnd(t *testing.T) {
	l := fibrefix.LoadLive(t)
	d := l.WriteDecision(t, l.Evidence(t))
	trusted := l.TrustedFile(t, nil)
	h := hex.EncodeToString(d.Hash[:])

	t.Run("hash first, as documented", func(t *testing.T) {
		code, out := edicta(t, "verify", h, "--gate-key", d.GateKeyHex, "--archive", d.Dir, "--trusted", trusted)
		require.Equal(t, exitValid, code, out)
		assert.Contains(t, out, "verdict: valid")
		assert.Contains(t, out, "[ok] header_trust")
	})
	t.Run("flags first, as edicta-verify took them", func(t *testing.T) {
		code, out := edicta(t, "verify", "--gate-key", d.GateKeyHex, "--archive", d.Dir, "--trusted", trusted, h)
		require.Equal(t, exitValid, code, out)
	})
	t.Run("json", func(t *testing.T) {
		code, out := edicta(t, "verify", h, "--gate-key", d.GateKeyHex, "--archive", d.Dir, "--trusted", trusted, "--json")
		require.Equal(t, exitValid, code, out)
		var rep map[string]any
		require.NoError(t, json.Unmarshal([]byte(out), &rep))
		assert.Equal(t, "valid", rep["verdict"])
		assert.NotContains(t, rep, "execution", "no execution check was asked for")
	})
	t.Run("replay", func(t *testing.T) {
		code, out := edicta(t, "replay", h, "--gate-key", d.GateKeyHex, "--archive", d.Dir, "--trusted", trusted, "--json")
		require.Equal(t, exitValid, code, out)
		var rep map[string]any
		require.NoError(t, json.Unmarshal([]byte(out), &rep))
		assert.Contains(t, rep, "retention_replay")
	})
	t.Run("no trusted header is unchecked", func(t *testing.T) {
		code, out := edicta(t, "verify", h, "--gate-key", d.GateKeyHex, "--archive", d.Dir)
		assert.Equal(t, exitUnchecked, code, out)
	})
	t.Run("another decision has no record, so it is inconclusive", func(t *testing.T) {
		other := bytes.Clone(d.Hash[:])
		other[0] ^= 1
		code, out := edicta(t, "verify", hex.EncodeToString(other), "--gate-key", d.GateKeyHex, "--archive", d.Dir, "--trusted", trusted)
		assert.Equal(t, exitUnchecked, code, out)
	})
	t.Run("the same archive over HTTP", func(t *testing.T) {
		ro, err := fsarchive.OpenReadOnly(d.Dir, fibrefix.Committers(t))
		require.NoError(t, err)
		srv := httptest.NewServer(httparchive.NewHandler(ro))
		t.Cleanup(srv.Close)
		code, out := edicta(t, "verify", h, "--gate-key", d.GateKeyHex, "--archive-url", srv.URL, "--trusted", trusted)
		require.Equal(t, exitValid, code, out)
		assert.Contains(t, out, "verdict: valid")
	})
	t.Run("a withheld Authorization over HTTP is not authorized", func(t *testing.T) {
		ro, err := fsarchive.OpenReadOnly(d.Dir, fibrefix.Committers(t))
		require.NoError(t, err)
		inner := httparchive.NewHandler(ro)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/authorization/"+h {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			inner.ServeHTTP(w, r)
		}))
		t.Cleanup(srv.Close)
		code, out := edicta(t, "verify", h, "--gate-key", d.GateKeyHex, "--archive-url", srv.URL, "--trusted", trusted)
		assert.Equal(t, exitNotAuthorized, code, out)
	})
	t.Run("an archive that faults gives no verdict", func(t *testing.T) {
		ro, err := fsarchive.OpenReadOnly(d.Dir, fibrefix.Committers(t))
		require.NoError(t, err)
		inner := httparchive.NewHandler(ro)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/decision/"+h {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			inner.ServeHTTP(w, r)
		}))
		t.Cleanup(srv.Close)
		code, out := edicta(t, "verify", h, "--gate-key", d.GateKeyHex, "--archive-url", srv.URL, "--trusted", trusted)
		assert.Equal(t, exitUsage, code, out)
		assert.NotContains(t, out, "verdict:")
	})
}
