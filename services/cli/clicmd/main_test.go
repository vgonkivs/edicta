package clicmd

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/config"
	"github.com/vgonkivs/edicta/engine/archive/fsarchive"
	"github.com/vgonkivs/edicta/engine/archive/httparchive"
	"github.com/vgonkivs/edicta/plugins/celestia/celestiatest/fibrefix"
	"github.com/vgonkivs/edicta/services/cli/verifycli"
)

const (
	exitValid         = 0
	exitInvalid       = 1
	exitUnchecked     = 2
	exitNotAuthorized = 3
	exitUsage         = 4
)

// edicta runs one subcommand as the edicta command line routes it.
func edicta(t *testing.T, args ...string) (int, string) {
	t.Helper()
	if os.Getenv(config.EnvHome) == "" {
		t.Setenv(config.EnvHome, t.TempDir())
	}
	require.NotEmpty(t, args)
	var out bytes.Buffer
	var code int
	switch args[0] {
	case "init":
		code = Init(args[1:], &out)
	case "doctor":
		code = Doctor(args[1:], &out)
	case "commit":
		code = Commit(args[1:], strings.NewReader(""), &out)
	case "agent":
		code = Agent(args[1:], &out)
	default:
		code = Verify(args, &out)
	}
	return code, out.String()
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
	for _, line := range strings.Split(out, "\n") {
		assert.False(t, strings.HasPrefix(strings.TrimSpace(line), "verdict:"), "no verdict line: %q", line)
	}
	var doc map[string]any
	if json.Unmarshal([]byte(out), &doc) == nil {
		assert.NotContains(t, doc, "verdict", "no JSON report either")
	}
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
