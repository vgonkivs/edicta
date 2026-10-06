package node

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
	{"localhost", true},
	{"localhost:26658", true},
	{"http://127.0.0.1:26658", true},
	{"http://localhost:26658", true},
	{"http://[::1]:26658", true},
	{"example.com", false},
	{"example.com:9090", false},
	{"10.0.0.1:9090", false},
	{"0.0.0.0:9090", false},
	{"http://bn.invalid:26658", false},
	{"localhost.example.com:9090", false},
	{"127.0.0.1.example.com:9090", false},
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
