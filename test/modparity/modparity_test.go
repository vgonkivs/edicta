// SPDX-License-Identifier: Apache-2.0

// Package modparity_test checks the replace directives of the repository's Go
// modules. Replaces apply only in the main module, so every module that
// links celestia-node or celestia-app must carry the same fork replace block,
// or its binaries build against other code than the pinned one.
package modparity_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/internal/testkit"
)

// heavyModules are the module directories, relative to the repository root,
// that link celestia-node or celestia-app and so need the fork replace
// block. The test fails when this list and the go.mod files disagree.
var heavyModules = []string{"examples", "plugins/celestia", "services/cli", "services/gate"}

// heavyRequires are the requirements that make a module heavy, directly or
// through the in-repo module that wraps them.
var heavyRequires = []string{
	"github.com/celestiaorg/celestia-node",
	"github.com/celestiaorg/celestia-app/",
	"github.com/vgonkivs/edicta/plugins/celestia",
}

type gomod struct {
	requires []string
	// forks are the replaces whose target is a module version, not a
	// directory of this repository, normalized and sorted.
	forks []string
}

func parse(t *testing.T, path string) gomod {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)

	var m gomod
	block := ""
	for _, line := range strings.Split(string(b), "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		switch {
		case line == "":
			continue
		case block != "" && line == ")":
			block = ""
			continue
		case line == "require (" || line == "replace (":
			block = strings.TrimSuffix(line, " (")
			continue
		}
		kind := block
		if kind == "" {
			k, rest, ok := strings.Cut(line, " ")
			if !ok || (k != "require" && k != "replace") {
				continue
			}
			kind, line = k, strings.TrimSpace(rest)
		}
		switch kind {
		case "require":
			m.requires = append(m.requires, strings.Fields(line)[0])
		case "replace":
			_, target, ok := strings.Cut(line, "=>")
			require.Truef(t, ok, "%s: malformed replace %q", path, line)
			target = strings.TrimSpace(target)
			if strings.HasPrefix(target, ".") || strings.HasPrefix(target, "/") {
				continue
			}
			m.forks = append(m.forks, strings.Join(strings.Fields(line), " "))
		}
	}
	sort.Strings(m.forks)
	return m
}

func (m gomod) heavy() bool {
	for _, r := range m.requires {
		for _, h := range heavyRequires {
			if r == h || (strings.HasSuffix(h, "/") && strings.HasPrefix(r, h)) {
				return true
			}
		}
	}
	return false
}

// modules returns every go.mod of the code, keyed by its directory relative
// to the repository root. The vector generators are independent of the
// code on purpose and pin their own graphs.
func modules(t *testing.T, root string) map[string]gomod {
	t.Helper()
	out := map[string]gomod{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if p != root && (strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") ||
				name == "testdata" || name == "node_modules" || name == "journal" || name == "spec") {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != "go.mod" {
			return nil
		}
		rel, err := filepath.Rel(root, filepath.Dir(p))
		if err != nil {
			return err
		}
		out[filepath.ToSlash(rel)] = parse(t, p)
		return nil
	})
	require.NoError(t, err)
	return out
}

func TestReplaceSetParityAcrossHeavyModules(t *testing.T) {
	mods := modules(t, testkit.RepoRoot(t))
	require.Contains(t, mods, ".")

	var heavy []string
	for dir, m := range mods {
		if m.heavy() {
			heavy = append(heavy, dir)
		}
	}
	assert.ElementsMatch(t, heavyModules, heavy, "heavyModules must list exactly the modules that link celestia-node or celestia-app")

	want := mods[heavyModules[0]].forks
	require.NotEmpty(t, want, "%s/go.mod carries no fork replace", heavyModules[0])
	for _, dir := range heavyModules[1:] {
		m, ok := mods[dir]
		if !assert.Truef(t, ok, "%s/go.mod not found", dir) {
			continue
		}
		assert.Equal(t, want, m.forks, "%s/go.mod and %s/go.mod must carry identical non-local replaces", dir, heavyModules[0])
	}
	for dir, m := range mods {
		if !m.heavy() {
			assert.Emptyf(t, m.forks, "%s/go.mod is light and must carry no fork replace", dir)
		}
	}
}

// releaseModules build shipped binaries. They must declare the same go and
// toolchain lines, so that no binary is built with an older standard library
// than the others just because its module sits in another directory.
var releaseModules = []string{".", "examples", "plugins/celestia", "services/cli", "services/gate", "services/signer"}

// goLines returns the go and toolchain directives of a go.mod; an absent
// toolchain directive is the empty string.
func goLines(t *testing.T, path string) (goVer, toolchain string) {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		switch f[0] {
		case "go":
			goVer = f[1]
		case "toolchain":
			toolchain = f[1]
		}
	}
	require.NotEmptyf(t, goVer, "%s has no go directive", path)
	return goVer, toolchain
}

func TestGoAndToolchainLinesMatchAcrossReleaseModules(t *testing.T) {
	root := testkit.RepoRoot(t)
	wantGo, wantTC := goLines(t, filepath.Join(root, releaseModules[0], "go.mod"))
	for _, dir := range releaseModules[1:] {
		g, tc := goLines(t, filepath.Join(root, dir, "go.mod"))
		assert.Equalf(t, wantGo, g, "%s/go.mod go line differs from %s/go.mod", dir, releaseModules[0])
		assert.Equalf(t, wantTC, tc, "%s/go.mod toolchain line differs from %s/go.mod", dir, releaseModules[0])
	}
}
