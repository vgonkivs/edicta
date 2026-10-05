package fibrecommit

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
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

// goModReplaces returns the non-local replaces of fibre/go.mod as
// old path -> "target@version". golang.org/x/mod is in the module graph only
// at a version whose source is not in go.sum or the offline cache, so the file
// is parsed by hand.
func goModReplaces(t *testing.T) map[string]string {
	t.Helper()
	b, err := os.ReadFile("../go.mod")
	require.NoError(t, err)

	out := map[string]string{}
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
		out[strings.TrimSpace(old)] = f[0] + "@" + f[1]
	}
	return out
}

func TestPinnedReplacesEqualGoMod(t *testing.T) {
	assert.Equal(t, goModReplaces(t), pinnedReplaces)
}

// pinnedBuildInfo is the build info a correct build carries. A replaced
// module appears under its original path with the pinned module data on the
// replacement.
func pinnedBuildInfo(t *testing.T) *debug.BuildInfo {
	t.Helper()
	require.NotEmpty(t, pinnedModules)
	bi := &debug.BuildInfo{}
	hasApp := false
	for _, m := range pinnedModules {
		if m.path == appModule {
			hasApp = true
		}
		d := &debug.Module{Path: m.path, Version: m.version, Sum: m.sum}
		if m.replacePath != "" {
			d = &debug.Module{
				Path:    m.path,
				Version: "v0.0.0",
				Replace: &debug.Module{Path: m.replacePath, Version: m.version, Sum: m.sum},
			}
		}
		bi.Deps = append(bi.Deps, d)
	}
	require.True(t, hasApp, "pinned modules must include celestia-app")
	return bi
}

func findDep(t *testing.T, bi *debug.BuildInfo, keep func(*debug.Module) bool) *debug.Module {
	t.Helper()
	for _, d := range bi.Deps {
		if keep(d) {
			return d
		}
	}
	require.FailNow(t, "no matching dependency in the pinned build info")
	return nil
}

func TestCheckBuildInfo(t *testing.T) {
	app := func(d *debug.Module) bool { return d.Path == appModule }
	replaced := func(d *debug.Module) bool { return d.Replace != nil }
	plain := func(d *debug.Module) bool {
		return d.Path != appModule && d.Replace == nil
	}

	tests := []struct {
		name   string
		mutate func(t *testing.T, bi *debug.BuildInfo) *debug.BuildInfo
		ok     bool
	}{
		{"pinned", func(_ *testing.T, bi *debug.BuildInfo) *debug.BuildInfo { return bi }, true},
		{"nil", func(*testing.T, *debug.BuildInfo) *debug.BuildInfo { return nil }, false},
		{"app version drift", func(t *testing.T, bi *debug.BuildInfo) *debug.BuildInfo {
			findDep(t, bi, app).Version = "v10.4.1-mocha"
			return bi
		}, false},
		{"app missing", func(t *testing.T, bi *debug.BuildInfo) *debug.BuildInfo {
			a := findDep(t, bi, app)
			var deps []*debug.Module
			for _, d := range bi.Deps {
				if d != a {
					deps = append(deps, d)
				}
			}
			bi.Deps = deps
			return bi
		}, false},
		{"app sum differs", func(t *testing.T, bi *debug.BuildInfo) *debug.BuildInfo {
			findDep(t, bi, app).Sum = "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
			return bi
		}, false},
		{"app sum missing", func(t *testing.T, bi *debug.BuildInfo) *debug.BuildInfo {
			findDep(t, bi, app).Sum = ""
			return bi
		}, false},
		{"app replaced", func(t *testing.T, bi *debug.BuildInfo) *debug.BuildInfo {
			a := findDep(t, bi, app)
			a.Replace = &debug.Module{Path: "example.com/fork", Version: "v1.0.0", Sum: "h1:x"}
			return bi
		}, false},
		{"replace target version changed", func(t *testing.T, bi *debug.BuildInfo) *debug.BuildInfo {
			findDep(t, bi, replaced).Replace.Version = "v0.0.0-doctored"
			return bi
		}, false},
		{"replace target path changed", func(t *testing.T, bi *debug.BuildInfo) *debug.BuildInfo {
			findDep(t, bi, replaced).Replace.Path = "example.com/fork"
			return bi
		}, false},
		{"replace target sum differs", func(t *testing.T, bi *debug.BuildInfo) *debug.BuildInfo {
			findDep(t, bi, replaced).Replace.Sum = "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
			return bi
		}, false},
		{"replace target sum missing", func(t *testing.T, bi *debug.BuildInfo) *debug.BuildInfo {
			findDep(t, bi, replaced).Replace.Sum = ""
			return bi
		}, false},
		{"replace dropped", func(t *testing.T, bi *debug.BuildInfo) *debug.BuildInfo {
			findDep(t, bi, replaced).Replace = nil
			return bi
		}, false},
		{"upstream dependency version differs", func(t *testing.T, bi *debug.BuildInfo) *debug.BuildInfo {
			findDep(t, bi, plain).Version = "v0.0.1-doctored"
			return bi
		}, false},
		{"upstream dependency sum differs", func(t *testing.T, bi *debug.BuildInfo) *debug.BuildInfo {
			findDep(t, bi, plain).Sum = "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
			return bi
		}, false},
		{"upstream dependency sum missing", func(t *testing.T, bi *debug.BuildInfo) *debug.BuildInfo {
			findDep(t, bi, plain).Sum = ""
			return bi
		}, false},
		{"upstream dependency unpinned replace", func(t *testing.T, bi *debug.BuildInfo) *debug.BuildInfo {
			d := findDep(t, bi, plain)
			d.Replace = &debug.Module{Path: "example.com/fork", Version: "v1.0.0", Sum: "h1:x"}
			return bi
		}, false},
		{"pinned replaced module absent", func(t *testing.T, bi *debug.BuildInfo) *debug.BuildInfo {
			r := findDep(t, bi, replaced)
			var deps []*debug.Module
			for _, d := range bi.Deps {
				if d != r {
					deps = append(deps, d)
				}
			}
			bi.Deps = deps
			return bi
		}, false},
		{"pinned upstream dependency absent", func(t *testing.T, bi *debug.BuildInfo) *debug.BuildInfo {
			p := findDep(t, bi, plain)
			var deps []*debug.Module
			for _, d := range bi.Deps {
				if d != p {
					deps = append(deps, d)
				}
			}
			bi.Deps = deps
			return bi
		}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkBuildInfo(tc.mutate(t, pinnedBuildInfo(t)))
			if tc.ok {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
		})
	}
}

func TestPinnedModulesWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, m := range pinnedModules {
		seen[m.path] = true
		assert.NotEmpty(t, m.version, m.path)
		assert.True(t, strings.HasPrefix(m.sum, "h1:"), m.path)
	}
	assert.True(t, seen[appModule])
}
