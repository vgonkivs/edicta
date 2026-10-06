package node

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/celestiaorg/celestia-app/v10/fibre/state"
	"github.com/celestiaorg/celestia-node/api/client"
)

func TestNewSigningRefusesTokenWithoutTransportBeforeAnyClient(t *testing.T) {
	for _, tc := range []struct {
		name string
		b    BridgeConfig
		g    GRPCConfig
	}{
		{"grpc token", BridgeConfig{Addr: "http://127.0.0.1:26658"}, GRPCConfig{Addr: "127.0.0.1:9090", Token: "t"}},
		{"bridge token", BridgeConfig{Addr: "http://127.0.0.1:26658", Token: "t"}, GRPCConfig{Addr: "127.0.0.1:9090"}},
		{"grpc token remote", BridgeConfig{Addr: "http://bn.invalid:26658"}, GRPCConfig{Addr: "grpc.invalid:9090", Token: "t"}},
		{"bridge token remote", BridgeConfig{Addr: "http://bn.invalid:26658", Token: "t"}, GRPCConfig{Addr: "grpc.invalid:9090"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			oldNew := newClientFn
			t.Cleanup(func() { newClientFn = oldNew })
			newClientFn = func(context.Context, client.Config, keyring.Keyring) (*client.Client, error) {
				called = true
				return nil, nil
			}
			c, _, _, err := NewSigning(tctx(t), tc.b, tc.g, keyring.NewInMemory(nil), "k", "mocha-4")
			require.Error(t, err)
			assert.Nil(t, c)
			assert.False(t, called, "newClientFn must not run")
		})
	}
}

func TestNewReadOnlyAndFibreBridgeRefuseBridgeTokenWithoutTransport(t *testing.T) {
	b := BridgeConfig{Addr: "http://127.0.0.1:26658", Token: "t"}
	_, _, err := NewReadOnly(tctx(t), b)
	require.Error(t, err)
	_, err = NewFibreBridge(tctx(t), b, BridgeLimits{})
	require.Error(t, err)
}

var loopbackCases = []struct {
	addr     string
	loopback bool
}{
	{"127.0.0.1", true},
	{"127.0.0.1:9090", true},
	{"127.5.5.5:1", true},
	{"::1", true},
	{"[::1]:9090", true},
	{"localhost", false},
	{"localhost:26658", false},
	{"http://127.0.0.1:26658", true},
	{"http://localhost:26658", false},
	{"http://[::1]:26658", true},
	{"example.com", false},
	{"example.com:9090", false},
	{"10.0.0.1:9090", false},
	{"0.0.0.0:9090", false},
	{"http://bn.invalid:26658", false},
	{"localhost.example.com:9090", false},
	{"127.0.0.1.example.com:9090", false},
	{"http://127.0.0.1:1@evil.example", false},
	{"http://localhost:x@evil.example/", false},
	{"dns://127.0.0.1:1@evil.example/x", false},
	{"127.0.0.1:1@evil.example", false},
	{"127.0.0.1:x", false},
	{"dns:///127.0.0.1:9090", false},
	{"unix:/tmp/x.sock", false},
	{"", false},
}

func TestLoopbackAddr(t *testing.T) {
	for _, tc := range loopbackCases {
		t.Run(tc.addr, func(t *testing.T) { assert.Equal(t, tc.loopback, LoopbackAddr(tc.addr)) })
	}
}

func TestInsecureTokenOptInOnlyForLoopback(t *testing.T) {
	for _, tc := range loopbackCases {
		if tc.addr == "" {
			continue
		}
		t.Run(tc.addr, func(t *testing.T) {
			g := GRPCConfig{Addr: tc.addr, Token: "t", AllowInsecureToken: true}
			b := BridgeConfig{Addr: tc.addr, Token: "t", AllowInsecureToken: true}
			if tc.loopback {
				require.NoError(t, g.ValidateBasic())
				require.NoError(t, b.ValidateBasic())
				return
			}
			require.Error(t, g.ValidateBasic())
			require.Error(t, b.ValidateBasic())
			_, err := DialGRPC(g)
			require.Error(t, err)
			_, err = NewFibreBridge(tctx(t), b, BridgeLimits{})
			require.Error(t, err)
			_, _, err = NewReadOnly(tctx(t), b)
			require.Error(t, err)
		})
	}
}

func TestTokenOverTLSNeedsNoOptIn(t *testing.T) {
	require.NoError(t, GRPCConfig{Addr: "example.com:9090", Token: "t", TLS: true}.ValidateBasic())
	require.NoError(t, BridgeConfig{Addr: "example.com:26658", Token: "t", TLS: true}.ValidateBasic())
	require.NoError(t, BridgeConfig{Addr: "example.com:26658"}.ValidateBasic())
}

var (
	autoFundOn = regexp.MustCompile(`AutoFund\s*(=|:)\s*true`)
	depositUse = regexp.MustCompile(`\.Deposit\(`)
)

// The Recorder never moves funds: escrow is funded by the operator.
func TestNoAutoFundOrDepositInProductionCode(t *testing.T) {
	root := ".."
	require.NoError(t, filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		require.NoError(t, err)
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		src, rerr := os.ReadFile(p)
		require.NoError(t, rerr)
		if strings.HasPrefix(filepath.ToSlash(p), "../node/") {
			assert.False(t, autoFundOn.Match(src), "%s enables AutoFund", p)
		}
		assert.False(t, depositUse.Match(src), "%s calls Deposit", p)
		return nil
	}))
}

func TestBridgeSchemeTLSDisagreementRefusedBeforeAnyClient(t *testing.T) {
	for _, tc := range []struct {
		name string
		b    BridgeConfig
	}{
		{"http with tls", BridgeConfig{Addr: "http://bn.invalid:26658", TLS: true}},
		{"https without tls", BridgeConfig{Addr: "https://bn.invalid:26658"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			oldNew, oldDial := newClientFn, dialStateClient
			t.Cleanup(func() { newClientFn, dialStateClient = oldNew, oldDial })
			newClientFn = func(context.Context, client.Config, keyring.Keyring) (*client.Client, error) {
				called = true
				return nil, nil
			}
			dialStateClient = func(GRPCConfig) (state.Client, error) {
				called = true
				return nil, nil
			}
			_, _, err := NewReadOnly(tctx(t), tc.b)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "disagrees")
			_, _, _, err = NewSigning(tctx(t), tc.b, GRPCConfig{Addr: "127.0.0.1:9090"}, keyring.NewInMemory(nil), "k", "mocha-4")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "disagrees")
			assert.False(t, called, "no client or dial")
		})
	}
}

func TestNewSigningPassesTheNormalisedBridgeURL(t *testing.T) {
	for _, tc := range []struct {
		name, addr string
		tls        bool
		want       string
	}{
		{"bare plain", "bn.invalid:26658", false, "http://bn.invalid:26658"},
		{"bare tls", "bn.invalid:26658", true, "https://bn.invalid:26658"},
		{"url kept", "http://bn.invalid:26658", false, "http://bn.invalid:26658"},
		{"bare ipv6", "::1", false, "http://[::1]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got client.Config
			oldNew := newClientFn
			t.Cleanup(func() { newClientFn = oldNew })
			newClientFn = func(_ context.Context, cfg client.Config, _ keyring.Keyring) (*client.Client, error) {
				got = cfg
				return nil, errors.New("stop")
			}
			_, _, _, err := NewSigning(tctx(t), BridgeConfig{Addr: tc.addr, TLS: tc.tls}, GRPCConfig{Addr: "127.0.0.1:9090"},
				keyring.NewInMemory(nil), "k", "mocha-4")
			require.Error(t, err)
			assert.Equal(t, tc.want, got.ReadConfig.BridgeDAAddr)
		})
	}
}

func TestNewFibreDirectValidatesItsConfigBeforeAnyDial(t *testing.T) {
	dialed := false
	old := dialStateClient
	t.Cleanup(func() { dialStateClient = old })
	dialStateClient = func(GRPCConfig) (state.Client, error) {
		dialed = true
		return &atomicStop{}, nil
	}
	for _, g := range []GRPCConfig{
		{Addr: "grpc.invalid:9090", Token: "t"},
		{Addr: "grpc.invalid:9090", Token: "t", AllowInsecureToken: true},
		{},
	} {
		d, err := NewFibreDirect(tctx(t), g)
		require.Error(t, err)
		assert.Nil(t, d)
	}
	assert.False(t, dialed)
}

func TestBridgeURLBracketsBareIPv6(t *testing.T) {
	for _, tc := range []struct {
		addr, want string
		bad        bool
	}{
		{"::1", "http://[::1]", false},
		{"[::1]:26658", "http://[::1]:26658", false},
		{"http://[::1]:26658", "http://[::1]:26658", false},
		{"::1:26658", "", true},
	} {
		t.Run(tc.addr, func(t *testing.T) {
			got, err := BridgeURL(tc.addr, false)
			if tc.bad {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
