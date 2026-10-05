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
	build := exec.Command("go", "build", "-mod=readonly", "-o", bin, "./fibrecommit/testdata/checkbuild")
	build.Dir = ".."
	build.Env = append(os.Environ(), "GOFLAGS=", "GOPROXY=off", "GOWORK=off")
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

const (
	linkedPlain    = "github.com/example/linked"
	linkedReplaced = "github.com/gogo/protobuf"
	badSum         = "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
)

// pinnedBuildInfo is the build info a correct build carries: the strict
// modules as pinned, plus one plain and one correctly replaced linked module.
// A replaced module appears under its original path with the pinned module
// data on the replacement.
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

	target, ok := pinnedReplaces[linkedReplaced]
	require.True(t, ok)
	path, version, _ := strings.Cut(target, "@")
	bi.Deps = append(bi.Deps,
		&debug.Module{Path: linkedPlain, Version: "v1.2.3", Sum: "h1:linked"},
		&debug.Module{Path: linkedReplaced, Version: "v1.3.2", Replace: &debug.Module{Path: path, Version: version, Sum: "h1:r"}},
	)
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

func without(bi *debug.BuildInfo, path string) *debug.BuildInfo {
	var deps []*debug.Module
	for _, d := range bi.Deps {
		if d.Path != path {
			deps = append(deps, d)
		}
	}
	bi.Deps = deps
	return bi
}

func TestCheckBuildInfo(t *testing.T) {
	byPath := func(p string) func(*debug.Module) bool {
		return func(d *debug.Module) bool { return d.Path == p }
	}
	strictReplaced := func(d *debug.Module) bool {
		for _, m := range pinnedModules {
			if m.path == d.Path && m.replacePath != "" {
				return true
			}
		}
		return false
	}
	strictPlain := func(d *debug.Module) bool {
		for _, m := range pinnedModules {
			if m.path == d.Path && m.path != appModule && m.replacePath == "" {
				return true
			}
		}
		return false
	}
	// eff returns the module whose version and sum are pinned.
	eff := func(d *debug.Module) *debug.Module {
		if d.Replace != nil {
			return d.Replace
		}
		return d
	}
	bad := &debug.Module{Path: "example.com/fork", Version: "v1.0.0", Sum: "h1:x"}

	type mut func(t *testing.T, bi *debug.BuildInfo) *debug.BuildInfo
	pick := func(keep func(*debug.Module) bool, f func(d *debug.Module)) mut {
		return func(t *testing.T, bi *debug.BuildInfo) *debug.BuildInfo {
			f(findDep(t, bi, keep))
			return bi
		}
	}
	drop := func(keep func(*debug.Module) bool) mut {
		return func(t *testing.T, bi *debug.BuildInfo) *debug.BuildInfo {
			return without(bi, findDep(t, bi, keep).Path)
		}
	}

	tests := []struct {
		name   string
		mutate mut
		ok     bool
	}{
		{"pinned", func(_ *testing.T, bi *debug.BuildInfo) *debug.BuildInfo { return bi }, true},
		{"nil", func(*testing.T, *debug.BuildInfo) *debug.BuildInfo { return nil }, false},

		{"app version drift", pick(byPath(appModule), func(d *debug.Module) { d.Version = "v10.4.1-mocha" }), false},
		{"app missing", drop(byPath(appModule)), false},
		{"app sum differs", pick(byPath(appModule), func(d *debug.Module) { d.Sum = badSum }), false},
		{"app sum missing", pick(byPath(appModule), func(d *debug.Module) { d.Sum = "" }), false},
		{"app replaced", pick(byPath(appModule), func(d *debug.Module) { d.Replace = bad }), false},

		{"strict replaced version drift", pick(strictReplaced, func(d *debug.Module) { d.Replace.Version = "v0.0.0-doctored" }), false},
		{"strict replaced path changed", pick(strictReplaced, func(d *debug.Module) { d.Replace.Path = "example.com/fork" }), false},
		{"strict replaced sum differs", pick(strictReplaced, func(d *debug.Module) { d.Replace.Sum = badSum }), false},
		{"strict replaced sum missing", pick(strictReplaced, func(d *debug.Module) { d.Replace.Sum = "" }), false},
		{"strict replaced dropped", pick(strictReplaced, func(d *debug.Module) { d.Replace = nil }), false},
		{"strict replaced absent", drop(strictReplaced), false},

		{"strict version drift", pick(strictPlain, func(d *debug.Module) { eff(d).Version = "v0.0.1-doctored" }), false},
		{"strict sum differs", pick(strictPlain, func(d *debug.Module) { eff(d).Sum = badSum }), false},
		{"strict sum missing", pick(strictPlain, func(d *debug.Module) { eff(d).Sum = "" }), false},
		{"strict unpinned replace", pick(strictPlain, func(d *debug.Module) { d.Replace = bad }), false},
		{"strict absent", drop(strictPlain), false},

		{"linked version differs", pick(byPath(linkedPlain), func(d *debug.Module) { d.Version = "v9.9.9" }), true},
		{"linked sum differs", pick(byPath(linkedPlain), func(d *debug.Module) { d.Sum = badSum }), true},
		{"linked absent", drop(byPath(linkedPlain)), true},
		{"linked pinned replace absent", drop(byPath(linkedReplaced)), true},
		{"linked unpinned replace", pick(byPath(linkedPlain), func(d *debug.Module) { d.Replace = bad }), false},
		{"linked pinned module wrong replace path", pick(byPath(linkedReplaced), func(d *debug.Module) { d.Replace.Path = "example.com/fork" }), false},
		{"linked pinned module wrong replace version", pick(byPath(linkedReplaced), func(d *debug.Module) { d.Replace.Version = "v0.0.0-doctored" }), false},
		{"linked pinned module not replaced", pick(byPath(linkedReplaced), func(d *debug.Module) { d.Replace = nil }), false},
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
