package fibrecommit

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// buildInfoOf builds the checkbuild program for the target and returns the
// module data embedded in the binary, without running it.
func buildInfoOf(t *testing.T, goos, goarch, cgo string) *debug.BuildInfo {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "checkbuild")
	build := exec.Command("go", "build", "-mod=readonly", "-o", bin, "./fibrecommit/testdata/checkbuild")
	build.Dir = ".."
	build.Env = append(os.Environ(),
		"GOFLAGS=", "GOPROXY=off", "GOWORK=off",
		"GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED="+cgo)
	out, err := build.CombinedOutput()
	require.NoError(t, err, string(out))

	raw, err := exec.Command("go", "version", "-m", bin).Output()
	require.NoError(t, err)
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	require.Greater(t, len(lines), 2)
	goVer := strings.TrimSpace(strings.TrimPrefix(lines[0], bin+":"))
	var body []string
	for _, l := range lines[1:] {
		body = append(body, strings.TrimPrefix(l, "\t"))
	}
	bi, err := debug.ParseBuildInfo("go\t" + goVer + "\n" + strings.Join(body, "\n") + "\n")
	require.NoError(t, err)
	return bi
}

func TestCheckBuildInfoCrossBuilt(t *testing.T) {
	if testing.Short() {
		t.Skip("cross-builds binaries")
	}
	targets := []struct{ name, goos, goarch, cgo string }{
		{"linux/amd64 nocgo", "linux", "amd64", "0"},
		{"linux/arm64 nocgo", "linux", "arm64", "0"},
	}
	for _, tc := range targets {
		t.Run(tc.name, func(t *testing.T) {
			bi := buildInfoOf(t, tc.goos, tc.goarch, tc.cgo)
			require.NoError(t, checkBuildInfo(bi))
		})
	}
}

func TestGenpinsMatchesPinsGen(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the platform matrix")
	}
	orig, err := os.ReadFile("pins_gen.go")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.WriteFile("pins_gen.go", orig, 0o644) })

	for range 2 {
		gen := exec.Command("go", "run", "./internal/genpins")
		gen.Env = append(os.Environ(), "GOFLAGS=", "GOPROXY=off", "GOWORK=off")
		out, err := gen.CombinedOutput()
		require.NoError(t, err, string(out))

		got, err := os.ReadFile("pins_gen.go")
		require.NoError(t, err)
		require.Equal(t, string(orig), string(got))
	}
}
