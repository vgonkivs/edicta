package demo

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTrustRootHostCollisionIsRefused(t *testing.T) {
	p, err := LoadPreset("mocha")
	require.NoError(t, err)
	require.NoError(t, p.ValidateBasic())
	require.NoError(t, p.CheckTrustRootHost(), "the default Celenium host is its own")

	for _, api := range []string{
		"https://rpc-mocha.pops.one/v1/block/{height}",
		"https://RPC-MOCHA.POPS.ONE./v1/block/{height}",
		"http://rpc-mocha.pops.one:26657/block/{height}",
		"https://rpc-1.testnet.celestia.nodes.guru/x/{height}",
		"https://grpc-mocha.pops.one/x/{height}",
		"https://public-endpoint.celestia-mocha.quiknode.pro/{height}",
	} {
		q := p.Apply(PresetOverrides{TrustRootAPI: api})
		require.ErrorIs(t, q.CheckTrustRootHost(), ErrTrustRootNotIndependent, api)
		_, err := New(Config{Home: "h", Overrides: PresetOverrides{TrustRootAPI: api}}, Deps{})
		require.ErrorIs(t, err, ErrTrustRootNotIndependent, api)
		assert.Equal(t, ExitUsage, ExitCodeOf(err))
	}
}

func celeniumServer(t *testing.T, height uint64, hash string, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		fmt.Fprintf(w, `{"height":%d,"hash":%q}`, height, hash)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestCeleniumTrustRoot(t *testing.T) {
	good := hex.EncodeToString(make([]byte, 32))
	for name, tc := range map[string]struct {
		height uint64
		hash   string
		status int
		ok     bool
	}{
		"ok":            {100, good, 200, true},
		"other height":  {101, good, 200, false},
		"short hash":    {100, "abcd", 200, false},
		"not hex":       {100, "zz" + good[2:], 200, false},
		"server error":  {100, good, 500, false},
		"not found yet": {100, good, 404, false},
	} {
		t.Run(name, func(t *testing.T) {
			srv := celeniumServer(t, tc.height, tc.hash, tc.status)
			tr, err := NewCeleniumTrustRoot(srv.URL+"/block/{height}", "https://x/{height}", "Celenium", srv.Client())
			require.NoError(t, err)
			h, err := tr.HeaderHash(context.Background(), 100)
			if tc.ok {
				require.NoError(t, err)
				assert.Len(t, h, 32)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestNoFallbackToADataRPCWhenTheTrustRootFails(t *testing.T) {
	e := newTestEnv(t)
	e.root.err = errors.New("celenium is down")
	e.console.lines = []string{"q"}
	r := e.startState(t)
	e.chain.balances = map[string]uint64{}
	_, err := r.trustRoot(context.Background(), 50)
	require.ErrorIs(t, err, ErrTrustRootUnavailable)
	assert.Equal(t, ExitInconclusive, ExitCodeOf(err))
	assert.Equal(t, 0, e.verified, "the verifier is never asked to find a root itself")
	require.Len(t, e.console.prompts, 1)
	assert.Contains(t, e.console.prompts[0], "HEIGHT:HASH")
	assert.Greater(t, e.root.calls, 0)

	// A line typed by the operator is taken once it is well formed and high enough.
	e = newTestEnv(t)
	e.root.err = errors.New("celenium is down")
	hash := hex.EncodeToString(make([]byte, 32))
	e.console.lines = []string{"nonsense", "10:" + hash, "60:" + hash}
	r = e.startState(t)
	root, err := r.trustRoot(context.Background(), 50)
	require.NoError(t, err)
	assert.EqualValues(t, 60, root.Height)
	assert.Equal(t, "manual input", root.Source)
}

func TestTrustedHeaderOverride(t *testing.T) {
	hash := hex.EncodeToString(make([]byte, 32))
	e := newTestEnv(t)
	e.cfg.TrustedHeader = "100:" + hash
	r := e.startState(t)
	root, err := r.trustRoot(context.Background(), 50)
	require.NoError(t, err)
	assert.EqualValues(t, 100, root.Height)
	assert.Equal(t, "--trusted-header", root.Source)
	assert.Zero(t, e.root.calls, "the explorer is never asked when the user supplied a header")

	e = newTestEnv(t)
	e.cfg.TrustedHeader = "40:" + hash
	e.console.lines = []string{"q"}
	r = e.startState(t)
	_, err = r.trustRoot(context.Background(), 50)
	require.ErrorIs(t, err, ErrTrustRootUnavailable)
	assert.Zero(t, e.root.calls, "a header that is too low is never silently replaced by the explorer")
}

func TestConfigValidation(t *testing.T) {
	hash := hex.EncodeToString(make([]byte, 32))
	base := Config{Home: "h"}.WithDefaults()
	require.NoError(t, base.ValidateBasic())
	for _, bad := range []string{"", "x", "0:" + hash, "5:abcd", "-1:" + hash} {
		c := base
		c.TrustedHeader = bad
		if bad != "" {
			require.ErrorIs(t, c.ValidateBasic(), ErrConfig, bad)
		}
	}
	c := base
	c.Funder.KeyName = "k"
	require.ErrorIs(t, c.ValidateBasic(), ErrConfig)
}
