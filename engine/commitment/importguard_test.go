package commitment_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/engine/commitment"
	"github.com/vgonkivs/edicta/engine/principalsig"
	"github.com/vgonkivs/edicta/internal/testkit"
)

// The commitment format must stay independent of principal signature
// schemes and their secp256k1 dependencies: walk every module-local import
// of commitment and refuse principalsig, go-ethereum and cosmos-sdk.
func TestCommitmentDoesNotImportPrincipalsig(t *testing.T) {
	module := testkit.ModulePath(t)
	principalsigPath := reflect.TypeOf(principalsig.Scheme(0)).PkgPath()
	require.Equal(t, "principalsig", testkit.ImportPackage(t, principalsigPath).Name)
	commitmentPath := reflect.TypeOf(commitment.Authorization{}).PkgPath()
	seen := map[string]bool{}
	var walk func(path string)
	walk = func(path string) {
		if seen[path] {
			return
		}
		seen[path] = true
		for _, imp := range testkit.ImportPackage(t, path).Imports {
			require.NotEqual(t, principalsigPath, imp, "imported by %s", path)
			require.NotContains(t, imp, "go-ethereum", "imported by %s", path)
			require.NotContains(t, imp, "cosmos-sdk", "imported by %s", path)
			require.NotContains(t, imp, "decred", "imported by %s", path)
			if strings.HasPrefix(imp, module+"/") {
				walk(imp)
			}
		}
	}
	walk(commitmentPath)
	require.True(t, seen[commitmentPath])
}
