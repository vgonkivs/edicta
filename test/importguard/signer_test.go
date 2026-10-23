// SPDX-License-Identifier: Apache-2.0

package importguard_test

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/internal/testkit"
)

// heavyPrefixes are the module paths a light binary must not link. The
// signer holds the payer key, so its process stays free of the Celestia node
// and chain stacks and their dependency graphs.
var heavyPrefixes = []string{
	"github.com/celestiaorg/celestia-node",
	"github.com/celestiaorg/celestia-app",
	"github.com/cosmos/cosmos-sdk",
	"github.com/cometbft/cometbft",
}

func goOutIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("go", args...)
	cmd.Dir = filepath.Join(testkit.RepoRoot(t), filepath.FromSlash(dir))
	cmd.Env = append(cmd.Environ(), "GOFLAGS=-mod=readonly", "GOWORK=off")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "go %s in %s: %s", strings.Join(args, " "), dir, out)
	return string(out)
}

// heavyLines returns the lines of go list output whose first field is a
// module or package under one of prefixes.
func heavyLines(out string, prefixes ...string) []string {
	var hit []string
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		for _, p := range prefixes {
			if strings.HasPrefix(fields[0], p) {
				hit = append(hit, line)
				break
			}
		}
	}
	return hit
}

func TestSignerModuleIsLight(t *testing.T) {
	for _, args := range [][]string{
		{"list", "-m", "all"},
		{"list", "-deps", "-test", "./..."},
		{"list", "-deps", "-test", "-tags", "edictadev", "./..."},
	} {
		assert.Emptyf(t, heavyLines(goOutIn(t, "services/signer", args...), heavyPrefixes...),
			"services/signer must stay light: go %s", strings.Join(args, " "))
	}
}

// The guard is only as good as its prefixes: each must name a module the
// heavy celestia module actually links, or a typo would pass silently.
func TestHeavyPrefixesNameLinkedModules(t *testing.T) {
	out := goOutIn(t, "plugins/celestia", "list", "-m", "all")
	for _, p := range heavyPrefixes {
		assert.NotEmptyf(t, heavyLines(out, p), "%s is not in the celestia module graph", p)
	}
}
