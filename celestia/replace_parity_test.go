package celestia_test

import (
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/internal/testkit"
)

func replaceSet(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)

	var set []string
	inBlock := false
	for _, line := range strings.Split(string(b), "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		switch {
		case line == "":
		case inBlock && line == ")":
			inBlock = false
		case line == "replace (":
			inBlock = true
		case inBlock:
			set = append(set, line)
		case strings.HasPrefix(line, "replace "):
			set = append(set, strings.TrimSpace(strings.TrimPrefix(line, "replace ")))
		}
	}

	var out []string
	for _, r := range set {
		_, target, ok := strings.Cut(r, "=>")
		require.True(t, ok, "malformed replace %q", r)
		target = strings.TrimSpace(target)
		if strings.HasPrefix(target, ".") || strings.HasPrefix(target, "/") {
			continue
		}
		out = append(out, strings.Join(strings.Fields(r), " "))
	}
	sort.Strings(out)
	return out
}

// heavyModules are the modules, relative to the repository root, that link
// celestia-node or celestia-app and so need the fork replace block.
var heavyModules = []string{"celestia", "examples"}

func TestReplaceSetParityAcrossHeavyModules(t *testing.T) {
	cel := replaceSet(t, "go.mod")
	require.NotEmpty(t, cel)
	for _, m := range heavyModules {
		got := replaceSet(t, testkit.RepoPath(t, m+"/go.mod"))
		require.Equal(t, cel, got, "%s/go.mod and celestia/go.mod must carry identical non-local replaces", m)
	}
}
