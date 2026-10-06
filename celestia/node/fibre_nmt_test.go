package node

import (
	"os"
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func nmtDep(version string, replace *debug.Module) *debug.BuildInfo {
	return &debug.BuildInfo{Deps: []*debug.Module{
		{Path: "github.com/other/mod", Version: "v1.0.0"},
		{Path: NMTModule, Version: version, Replace: replace},
	}}
}

func TestCheckNMTBuildInfo(t *testing.T) {
	cases := []struct {
		name string
		bi   *debug.BuildInfo
		ok   bool
	}{
		{"the pinned version", nmtDep("v0.24.5", nil), true},
		{"one version older", nmtDep("v0.24.4", nil), false},
		{"before the completeness check", nmtDep("v0.24.2", nil), false},
		{"a newer version", nmtDep("v0.24.6", nil), false},
		{"a pseudo version", nmtDep("v0.24.6-0.20260101000000-abcdef123456", nil), false},
		{"replaced by another module", nmtDep("v0.24.5", &debug.Module{Path: "github.com/fork/nmt", Version: "v0.24.5"}), false},
		{"replaced by a local path", nmtDep("v0.24.5", &debug.Module{Path: "../nmt"}), false},
		{"not linked", &debug.BuildInfo{Deps: []*debug.Module{{Path: "github.com/other/mod", Version: "v1.0.0"}}}, false},
		{"nil dependency entry", &debug.BuildInfo{Deps: []*debug.Module{nil}}, false},
		{"no dependencies", &debug.BuildInfo{}, false},
		{"no build info", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkNMTBuildInfo(tc.bi)
			if tc.ok {
				require.NoError(t, err)
				return
			}
			assert.Error(t, err)
		})
	}
}

// A test binary carries no module list, so the real check cannot run here;
// the pin is compared with the module file instead.
func TestNMTPinMatchesGoMod(t *testing.T) {
	mod, err := os.ReadFile("../go.mod")
	require.NoError(t, err)
	assert.Contains(t, string(mod), NMTModule+" "+NMTVersion)
	assert.NotContains(t, string(mod), "replace "+NMTModule)
	assert.Error(t, CheckNMTBuild(), "no build info in a test binary must fail closed")
}
