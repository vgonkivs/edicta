package importguard_test

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const forbidden = "github.com/celestiaorg/celestia-app"

func goOut(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command("go", args...)
	cmd.Dir = "../.."
	cmd.Env = append(cmd.Environ(), "GOFLAGS=-mod=readonly", "GOWORK=off")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	return string(out)
}

func TestRootModuleDoesNotImportCelestiaApp(t *testing.T) {
	var bad []string
	for _, pkg := range strings.Fields(goOut(t, "list", "-deps", "-test", "./...")) {
		if strings.HasPrefix(pkg, forbidden) {
			bad = append(bad, pkg)
		}
	}
	require.Empty(t, bad, "root module must not depend on celestia-app")
}

func TestRootModuleGraphHasNoCelestiaApp(t *testing.T) {
	var bad []string
	for _, line := range strings.Split(goOut(t, "list", "-m", "all"), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), forbidden) {
			bad = append(bad, line)
		}
	}
	require.Empty(t, bad, "root module graph must not contain celestia-app")
}
