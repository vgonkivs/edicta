package node

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"unicode"

	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/celestiaorg/celestia-node/api/client"
	nodefibre "github.com/celestiaorg/celestia-node/nodebuilder/fibre"
)

func fibreSignIn(t *testing.T, b BridgeConfig, g GRPCConfig) (FibreSubmitter, error) {
	t.Helper()
	c, _, s, err := NewFibreSigning(tctx(t), b, g, keyring.NewInMemory(nil), "k", "mocha-4")
	if err == nil {
		t.Cleanup(func() { _ = c.Close() })
	} else {
		assert.Nil(t, c)
		assert.Nil(t, s)
	}
	return s, err
}

func TestNewFibreSigningRefusesTokenWithoutTransportBeforeAnyClient(t *testing.T) {
	for _, tc := range []struct {
		name string
		b    BridgeConfig
		g    GRPCConfig
	}{
		{"grpc token", BridgeConfig{Addr: "http://127.0.0.1:26658"}, GRPCConfig{Addr: "127.0.0.1:9090", Token: "t"}},
		{"bridge token", BridgeConfig{Addr: "http://127.0.0.1:26658", Token: "t"}, GRPCConfig{Addr: "127.0.0.1:9090"}},
		{"grpc token remote", BridgeConfig{Addr: "http://bn.invalid:26658"}, GRPCConfig{Addr: "grpc.invalid:9090", Token: "t"}},
		{"bridge token remote", BridgeConfig{Addr: "http://bn.invalid:26658", Token: "t"}, GRPCConfig{Addr: "grpc.invalid:9090"}},
		{"bridge scheme disagrees with tls", BridgeConfig{Addr: "http://bn.invalid:26658", TLS: true}, GRPCConfig{Addr: "127.0.0.1:9090"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			oldNew := newClientFn
			t.Cleanup(func() { newClientFn = oldNew })
			newClientFn = func(context.Context, client.Config, keyring.Keyring) (*client.Client, error) {
				called = true
				return nil, nil
			}
			_, err := fibreSignIn(t, tc.b, tc.g)
			require.Error(t, err)
			assert.False(t, called, "no client may be built")
		})
	}
}

func TestNewFibreSigningDisablesAutoFundAndReportsTheDialledEndpoint(t *testing.T) {
	var closes atomic.Int32
	s := installSigningSeams(t, func() (*client.Client, error) {
		c := fakeClient(t, true, &closes, nil)
		c.Fibre = struct{ nodefibre.Module }{}
		return c, nil
	})
	g := GRPCConfig{Addr: "127.0.0.1:9090"}
	sub, err := fibreSignIn(t, BridgeConfig{Addr: "http://bn.invalid:26658"}, g)
	require.NoError(t, err)
	require.NotNil(t, s.got.SubmitConfig.Fibre)
	assert.False(t, s.got.SubmitConfig.Fibre.Escrow.AutoFund)
	assert.Equal(t, g.Addr, sub.Endpoint(), "the address that was dialled, not a caller's string")
	assert.Equal(t, g.Addr, s.got.SubmitConfig.CoreGRPCConfig.Addr)
}

func TestNewFibreSigningWithoutAFibreSideClosesTheClient(t *testing.T) {
	var closes atomic.Int32
	installSigningSeams(t, func() (*client.Client, error) { return fakeClient(t, true, &closes, nil), nil })
	_, err := fibreSignIn(t, BridgeConfig{Addr: "http://bn.invalid:26658"}, GRPCConfig{Addr: "127.0.0.1:9090"})
	require.Error(t, err)
	assert.EqualValues(t, 1, closes.Load())
}

// No exported symbol of the package hands a library client out or takes one
// in, and none names a funds call: a caller cannot reach the Fibre module,
// whose Deposit and Withdraw move escrow, or skip the validated dial.
func TestExportedSurfaceNeverExposesTheLibraryClientOrFundsCalls(t *testing.T) {
	fset := token.NewFileSet()
	require.NoError(t, filepath.WalkDir(".", func(p string, d fs.DirEntry, err error) error {
		require.NoError(t, err)
		if d.IsDir() && p != "." {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, p, nil, 0)
		require.NoError(t, perr)
		exported := func(n string) bool { return n != "" && unicode.IsUpper(rune(n[0])) }
		isClient := func(n ast.Node) bool {
			found := false
			ast.Inspect(n, func(x ast.Node) bool {
				if se, ok := x.(*ast.SelectorExpr); ok {
					if id, ok := se.X.(*ast.Ident); ok && id.Name == "client" && se.Sel.Name == "Client" {
						found = true
					}
				}
				return !found
			})
			return found
		}
		funds := []string{"Deposit", "Withdraw"}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if !exported(d.Name.Name) {
					continue
				}
				if d.Recv != nil && len(d.Recv.List) == 1 {
					rt := d.Recv.List[0].Type
					if st, ok := rt.(*ast.StarExpr); ok {
						rt = st.X
					}
					if id, ok := rt.(*ast.Ident); ok && !exported(id.Name) {
						continue
					}
				}
				assert.NotContains(t, funds, d.Name.Name, "%s: %s", p, d.Name.Name)
				assert.False(t, isClient(d.Type), "%s: exported func %s takes or returns the library client", p, d.Name.Name)
			case *ast.GenDecl:
				for _, sp := range d.Specs {
					ts, ok := sp.(*ast.TypeSpec)
					if !ok || !exported(ts.Name.Name) {
						continue
					}
					assert.False(t, isClient(ts.Type), "%s: exported type %s holds the library client", p, ts.Name.Name)
					if it, ok := ts.Type.(*ast.InterfaceType); ok {
						for _, m := range it.Methods.List {
							for _, n := range m.Names {
								assert.NotContains(t, funds, n.Name, "%s: %s.%s", p, ts.Name.Name, n.Name)
							}
						}
					}
				}
			}
		}
		return nil
	}))
}
