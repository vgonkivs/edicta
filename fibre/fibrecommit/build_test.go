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

func TestSelfTest(t *testing.T) {
	require.NoError(t, SelfTest())
}

func TestCheckBuildInBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary")
	}
	bin := filepath.Join(t.TempDir(), "checkbuild")
	build := exec.Command("go", "build", "-o", bin, "./fibrecommit/testdata/checkbuild")
	build.Dir = ".."
	build.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOPROXY=off", "GOWORK=off")
	out, err := build.CombinedOutput()
	require.NoError(t, err, string(out))

	out, err = exec.Command(bin).CombinedOutput()
	require.NoError(t, err, string(out))
	require.Contains(t, string(out), "selftest=<nil>")
	require.Contains(t, string(out), "checkbuild=<nil>")
}

// goModBuildInfo derives the build info a correct build carries: the pinned
// app version and every non-local replace from fibre/go.mod.
func goModBuildInfo(t *testing.T) *debug.BuildInfo {
	t.Helper()
	b, err := os.ReadFile("../go.mod")
	require.NoError(t, err)

	bi := &debug.BuildInfo{Deps: []*debug.Module{{Path: appModule, Version: PinnedAppVersion}}}
	inBlock := false
	for _, line := range strings.Split(string(b), "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		switch {
		case line == "replace (":
			inBlock = true
			continue
		case inBlock && line == ")":
			inBlock = false
			continue
		case strings.HasPrefix(line, "replace "):
			line = strings.TrimPrefix(line, "replace ")
		case !inBlock:
			continue
		}
		old, target, ok := strings.Cut(line, "=>")
		if !ok {
			continue
		}
		f := strings.Fields(target)
		if len(f) != 2 {
			continue
		}
		bi.Deps = append(bi.Deps, &debug.Module{
			Path:    strings.TrimSpace(old),
			Version: "v0.0.0",
			Replace: &debug.Module{Path: f[0], Version: f[1]},
		})
	}
	return bi
}

func TestCheckBuildInfo(t *testing.T) {
	t.Run("derived from go.mod", func(t *testing.T) {
		bi := goModBuildInfo(t)
		require.Greater(t, len(bi.Deps), len(pinnedReplaces)/2)
		require.NoError(t, checkBuildInfo(bi))
	})
	t.Run("nil", func(t *testing.T) {
		require.Error(t, checkBuildInfo(nil))
	})
	t.Run("app version drift", func(t *testing.T) {
		bi := goModBuildInfo(t)
		bi.Deps[0].Version = "v10.4.1-mocha"
		require.Error(t, checkBuildInfo(bi))
	})
	t.Run("app missing", func(t *testing.T) {
		bi := goModBuildInfo(t)
		bi.Deps = bi.Deps[1:]
		require.Error(t, checkBuildInfo(bi))
	})
	t.Run("replace target changed", func(t *testing.T) {
		bi := goModBuildInfo(t)
		bi.Deps[1].Replace.Version = "v0.0.0-doctored"
		require.Error(t, checkBuildInfo(bi))
	})
	t.Run("replace dropped", func(t *testing.T) {
		bi := goModBuildInfo(t)
		bi.Deps[1].Replace = nil
		require.Error(t, checkBuildInfo(bi))
	})
}
