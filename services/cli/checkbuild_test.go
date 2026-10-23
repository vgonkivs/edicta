// SPDX-License-Identifier: Apache-2.0

package cli_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// The edicta binary links the Fibre client, which refuses to run when the
// module's build graph differs from the pinned one; a missing or drifted
// replace in this go.mod shows up here instead of at the command's start.
func TestFibreCommitCheckBuildInCLI(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary")
	}
	bin := filepath.Join(t.TempDir(), "fibrecheck")
	build := exec.Command("go", "build", "-mod=readonly", "-o", bin, "./testdata/fibrecheck")
	build.Env = append(os.Environ(), "GOFLAGS=", "GOPROXY=off", "GOWORK=off")
	out, err := build.CombinedOutput()
	require.NoError(t, err, string(out))

	out, err = exec.Command(bin).CombinedOutput()
	require.NoError(t, err, string(out))
	require.Contains(t, string(out), "checkbuild=<nil>")
}
