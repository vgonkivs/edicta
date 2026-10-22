package sdk_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/engine/gate"
	"github.com/vgonkivs/edicta/internal/testkit"
)

// The SDK ships inside agent binaries and must not pull the gate in. The
// shared share-commitment package exists so that it does not have to.
func TestSDKDoesNotImportTheGate(t *testing.T) {
	gatePath := reflect.TypeOf(gate.Result{}).PkgPath()
	require.Equal(t, "gate", testkit.ImportPackage(t, gatePath).Name)
	for _, dir := range []string{".", "blob", "payload"} {
		fset := token.NewFileSet()
		pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
			return !strings.HasSuffix(fi.Name(), "_test.go")
		}, parser.ImportsOnly)
		require.NoError(t, err)
		require.NotEmpty(t, pkgs, dir)
		for _, p := range pkgs {
			for name, f := range p.Files {
				for _, imp := range f.Imports {
					path := strings.Trim(imp.Path.Value, `"`)
					inGate := path == gatePath || strings.HasPrefix(path, gatePath+"/")
					assert.Falsef(t, inGate, "%s imports %s", filepath.Join(dir, filepath.Base(name)), path)
					assert.NotContainsf(t, path, "celestia-core", "%s imports %s", name, path)
					assert.NotContainsf(t, path, "cometbft", "%s imports %s", name, path)
				}
			}
		}
	}
}
