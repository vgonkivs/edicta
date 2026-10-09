package commitment_test

import (
	"go/build"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const module = "github.com/vgonkivs/edicta"

// The commitment format must stay independent of principal signature
// schemes and their secp256k1 dependencies: walk every module-local import
// of commitment and refuse principalsig, go-ethereum and cosmos-sdk.
func TestCommitmentDoesNotImportPrincipalsig(t *testing.T) {
	root, err := filepath.Abs("..")
	require.NoError(t, err)
	seen := map[string]bool{}
	var walk func(path string)
	walk = func(path string) {
		if seen[path] {
			return
		}
		seen[path] = true
		dir := filepath.Join(root, strings.TrimPrefix(strings.TrimPrefix(path, module), "/"))
		pkg, err := build.ImportDir(dir, 0)
		require.NoError(t, err, path)
		for _, imp := range pkg.Imports {
			require.NotEqual(t, module+"/principalsig", imp, "imported by %s", path)
			require.NotContains(t, imp, "go-ethereum", "imported by %s", path)
			require.NotContains(t, imp, "cosmos-sdk", "imported by %s", path)
			require.NotContains(t, imp, "decred", "imported by %s", path)
			if strings.HasPrefix(imp, module+"/") {
				walk(imp)
			}
		}
	}
	walk(module + "/commitment")
	require.True(t, seen[module+"/commitment"])
}
