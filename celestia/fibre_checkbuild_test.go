package celestia_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vgonkivs/edicta/fibre/fibrecommit"
)

func TestFibreCommitCheckBuildInCelestia(t *testing.T) {
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

func TestFibreCommitSelfTest(t *testing.T) {
	require.NoError(t, fibrecommit.SelfTest())
}
