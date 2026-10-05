package importguard_test

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const forbidden = "github.com/celestiaorg/celestia-app"

func TestRootModuleDoesNotImportCelestiaApp(t *testing.T) {
	cmd := exec.Command("go", "list", "-deps", "./...")
	cmd.Dir = "../.."
	cmd.Env = append(cmd.Environ(), "GOFLAGS=-mod=mod", "GOWORK=off")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))

	var bad []string
	for _, pkg := range strings.Fields(string(out)) {
		if strings.HasPrefix(pkg, forbidden) {
			bad = append(bad, pkg)
		}
	}
	require.Empty(t, bad, "root module must not depend on celestia-app")
}
