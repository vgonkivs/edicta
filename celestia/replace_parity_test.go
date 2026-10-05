package celestia_test

import (
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
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

func TestReplaceSetParityWithFibreModule(t *testing.T) {
	cel := replaceSet(t, "go.mod")
	fib := replaceSet(t, "../fibre/go.mod")
	require.NotEmpty(t, cel)
	require.Equal(t, cel, fib, "fibre/go.mod and celestia/go.mod must carry identical non-local replaces")
}
