// SPDX-License-Identifier: Apache-2.0

package doclinks

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/internal/testkit"
)

// repoTree lists the files in the git index, so that build output, local
// leftovers and the internal journal never make a stale path resolve. A new
// file counts once it is added.
func repoTree(t *testing.T, repo string) Tree {
	t.Helper()
	cmd := exec.Command("git", "-C", repo, "ls-files", "-z", "--cached")
	out, err := cmd.Output()
	require.NoError(t, err, "git ls-files")
	var files []string
	for _, f := range bytes.Split(out, []byte{0}) {
		if len(f) == 0 {
			continue
		}
		// A file deleted in the working tree but still in the index is gone.
		if _, err := os.Lstat(filepath.Join(repo, string(f))); err != nil {
			continue
		}
		files = append(files, string(f))
	}
	return NewTree(files)
}

func TestPublishedDocs(t *testing.T) {
	repo := testkit.RepoRoot(t)
	tree := repoTree(t, repo)
	docs := Published(tree)
	for _, must := range []string{"README.md", "ARCHITECTURE.md", Changelog, CodeLocations, "docs/README.md", "services/gate/README.md"} {
		require.Contains(t, docs, must)
	}
	for _, d := range docs {
		require.Falsef(t, strings.HasPrefix(d, "spec/"), "%s: the frozen specification is not checked", d)
		b, err := os.ReadFile(filepath.Join(repo, filepath.FromSlash(d)))
		require.NoError(t, err)
		for _, p := range Check(tree, d, string(b)) {
			t.Error(p)
		}
	}
}

var fixture = NewTree([]string{
	"README.md",
	"CHANGELOG.md",
	"docs/guide.md",
	"docs/code-locations.md",
	"engine/gate/gate.go",
	"plugins/celestia/go.mod",
	"plugins/celestia/node/node.go",
	"services/cli/go.mod",
	"services/cli/cmd/edicta/main.go",
	"examples/tia-transfer/README.md",
	"examples/tia-transfer/cmd/edicta-live/main.go",
	"cmd/edicta-principal/main.go",
})

func msgs(ps []Problem) []string {
	var out []string
	for _, p := range ps {
		out = append(out, p.String())
	}
	return out
}

func TestCheckAcceptsResolvingReferences(t *testing.T) {
	doc := strings.Join([]string{
		"See [the guide](guide.md), [top](../README.md#flow), [root](/engine/gate/) and [web](https://example.org/x).",
		"Paths: `engine/gate`, `engine/gate/gate.go`, `./engine/gate/...`, `engine/gate.Verify`, `plugins/celestia/node/`.",
		"Imports: `github.com/vgonkivs/edicta/engine/gate`, `github.com/vgonkivs/edicta/cmd/edicta-principal@v1.2.0`, `github.com/vgonkivs/edicta`.",
		"Not paths: `archive/`, `edicta/v1/action`, `/v1/health`, `~/edicta-live/x`, `celestia/tia-transfer/v1`, `a b/c`, `docs/<file>.md`.",
		"```sh",
		"go -C services/cli run ./cmd/edicta verify --no-config",
		"go -C plugins/celestia test ./...   # all of it",
		"```",
		"[ref]: guide.md",
	}, "\n")
	assert.Empty(t, msgs(Check(fixture, "docs/guide.md", doc)))

	local := "Run `cmd/edicta-live` from here, or see [the code](cmd/edicta-live/main.go)."
	assert.Empty(t, msgs(Check(fixture, "examples/tia-transfer/README.md", local)))
}

func TestCheckRefusesStaleReferences(t *testing.T) {
	for _, tc := range []struct{ line, want string }{
		{"[x](missing.md)", `link "missing.md"`},
		{"[x](../../outside.md)", `link "../../outside.md"`},
		{"![img](img/none.png)", `link "img/none.png"`},
		{"`engine/nogate`", "path `engine/nogate`"},
		{"`celestia/railverify`", "path `celestia/railverify`"},
		{"`gate/registry`", "path `gate/registry`"},
		{"`guide/operator.md`", "path `guide/operator.md`"},
		{"`engine/gate.Verify.x`", "path `engine/gate.Verify.x`"},
		{"`archive/fsarchive`", "path `archive/fsarchive`"},
		{"`github.com/vgonkivs/edicta/gate`", "import path `github.com/vgonkivs/edicta/gate`"},
		{"`go -C celestia run ./cmd/edictad`", "go -C celestia: celestia is not a module directory"},
		{"`go -C services/cli run ./cmd/edicta-verify`", "./cmd/edicta-verify does not exist in services/cli"},
		{"run edicta demo now", `names "edicta demo"`},
		{"edictad -config x.toml", `names "edictad -config"`},
		{"bin in celestia/bin/", `names "celestia/bin"`},
		{"build edicta-devinit", `names "edicta-devinit"`},
	} {
		got := msgs(Check(fixture, "docs/guide.md", tc.line))
		require.NotEmpty(t, got, tc.line)
		assert.Contains(t, strings.Join(got, "\n"), tc.want, tc.line)
	}

	fenced := "text\n```sh\ngo -C examples run ./tia-transfer/cmd/edicta-live\n```\n"
	got := msgs(Check(fixture, "docs/guide.md", fenced))
	assert.Equal(t, []string{"docs/guide.md:3: go -C examples: examples is not a module directory"}, got, "lines are numbered from 1 inside fences too")
}

// The map names old paths in its first column only; the changelog is
// checked in its latest section only, and both may name removed commands.
func TestCheckExemptions(t *testing.T) {
	cl := strings.Join([]string{
		"| Old | New |",
		"|---|---|",
		"| `celestia/node` | `plugins/celestia/node` |",
		"| `edicta-verify` | `edicta verify --no-config` |",
		"| `go -C celestia run ./cmd/edictad` | `go -C services/cli run ./cmd/edicta gate serve` |",
		"| `celestia/inclusion` | `plugins/celestia/chain/inclusion` |",
	}, "\n")
	got := msgs(Check(fixture, CodeLocations, cl))
	assert.Equal(t, []string{"docs/code-locations.md:6: path `plugins/celestia/chain/inclusion` is not in the repository"}, got)

	log := strings.Join([]string{
		"# Changelog",
		"",
		"## v2",
		"Removed edicta demo; see `engine/gate` and [x](missing.md).",
		"",
		"## v1",
		"Old `gate/fast.go` and [y](gone.md).",
	}, "\n")
	got = msgs(Check(fixture, Changelog, log))
	assert.Equal(t, []string{`CHANGELOG.md:4: link "missing.md" does not resolve to a file or directory`}, got)
}
