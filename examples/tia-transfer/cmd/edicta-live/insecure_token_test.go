package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every node.BridgeConfig and node.GRPCConfig literal built here must set
// AllowInsecureToken from loopbackAddr of the very address it carries.
func TestConfigBuildersTieInsecureTokenToLoopback(t *testing.T) {
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	fset := token.NewFileSet()
	seen := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, rerr := os.ReadFile(f)
		require.NoError(t, rerr)
		file, perr := parser.ParseFile(fset, f, src, 0)
		require.NoError(t, perr)
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			sel, ok := lit.Type.(*ast.SelectorExpr)
			if !ok || types.ExprString(sel.X) != "node" || (sel.Sel.Name != "BridgeConfig" && sel.Sel.Name != "GRPCConfig") {
				return true
			}
			seen++
			where := fset.Position(lit.Pos()).String()
			var addr, allow ast.Expr
			for _, e := range lit.Elts {
				kv, ok := e.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				switch types.ExprString(kv.Key) {
				case "Addr":
					addr = kv.Value
				case "AllowInsecureToken":
					allow = kv.Value
				}
			}
			if !assert.NotNil(t, addr, where) || !assert.NotNil(t, allow, "%s: AllowInsecureToken not set", where) {
				return true
			}
			call, ok := allow.(*ast.CallExpr)
			if !assert.True(t, ok, "%s: AllowInsecureToken is not loopbackAddr(...)", where) {
				return true
			}
			assert.Equal(t, "loopbackAddr", types.ExprString(call.Fun), where)
			if assert.Len(t, call.Args, 1, where) {
				assert.Equal(t, types.ExprString(addr), types.ExprString(call.Args[0]), "%s: checks another address", where)
			}
			return true
		})
	}
	assert.Positive(t, seen, "no config literal found; the guard is stale")
}
