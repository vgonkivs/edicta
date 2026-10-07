package demo

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/railtx"
	"github.com/vgonkivs/edicta/examples/tia-transfer/transfer"
)

type countingRail struct {
	transfer.Rail
	broadcasts int
}

func (r *countingRail) Broadcast(context.Context, []byte) error { r.broadcasts++; return nil }

func TestGuardsRefuseUntilArmed(t *testing.T) {
	var c railtx.Consent
	sub := &fakeSubmitter{}
	gs := GuardSubmitter(sub, &c)
	_, err := gs.Submit(context.Background(), nil, nil)
	require.ErrorIs(t, err, railtx.ErrNotStarted)

	inner := &countingRail{}
	exec, rogue := GuardRail(inner, &c), GuardRailOnce(inner, &c)
	require.ErrorIs(t, exec.Broadcast(context.Background(), []byte{1}), railtx.ErrNotStarted)
	require.ErrorIs(t, rogue.Broadcast(context.Background(), []byte{1}), railtx.ErrNotStarted)
	assert.Zero(t, sub.calls+inner.broadcasts, "nothing is broadcast before the Consent is armed")

	c.Arm()
	_, err = gs.Submit(context.Background(), nil, nil)
	require.NoError(t, err)
	require.NoError(t, exec.Broadcast(context.Background(), []byte{1}))
	require.NoError(t, rogue.Broadcast(context.Background(), []byte{1}))
	require.ErrorIs(t, rogue.Broadcast(context.Background(), []byte{1}), ErrRailLocked, "the rogue rail allows one broadcast")

	exec.Lock()
	require.ErrorIs(t, exec.Broadcast(context.Background(), []byte{1}), ErrRailLocked)
	assert.Equal(t, 2, inner.broadcasts)
}

// callSites finds the functions that contain a call to a method named name.
func callSites(t *testing.T, name string) []string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	var out []string
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		require.NoError(t, err)
		for _, d := range af.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == name {
						out = append(out, f+":"+fn.Name.Name)
					}
				}
				return true
			})
		}
	}
	return out
}

func TestSingleCallSites(t *testing.T) {
	assert.Equal(t, []string{"setup.go:fundAndStart"}, callSites(t, "Arm"), "only the start Enter arms the Consent")
	assert.Equal(t, []string{"funding.go:offerAbandon"}, callSites(t, "Abandon"))
	assert.Equal(t, []string{"funding.go:offerBinding"}, callSites(t, "AbandonBinding"))
	assert.ElementsMatch(t, []string{"consent.go:Broadcast", "attempts.go:rogueSend"}, callSites(t, "Broadcast"), "the guards are the only broadcast paths")
	assert.Equal(t, []string{"funding.go:ensure"}, callSites(t, "Send"), "funding sends only in the funding loop")
}
