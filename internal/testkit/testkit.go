// SPDX-License-Identifier: Apache-2.0

// Package testkit locates repository files for tests from any package
// directory and any module of the repository, so that moving a package
// never breaks the paths its tests read. It is for tests only.
package testkit

import (
	"bufio"
	"go/build"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type marker struct{}

// rootModule is the root module path, derived from this package's own
// import path so that it never has to be spelled out.
var rootModule = strings.TrimSuffix(reflect.TypeOf(marker{}).PkgPath(), "/internal/testkit")

// RepoRoot returns the repository root: the nearest ancestor of the working
// directory that holds spec/vectors/MANIFEST.sha256 or the root module's
// go.mod.
func RepoRoot(tb testing.TB) string {
	tb.Helper()
	dir, err := os.Getwd()
	require.NoError(tb, err)
	for {
		if isFile(filepath.Join(dir, "spec", "vectors", "MANIFEST.sha256")) {
			return dir
		}
		if p, ok := modulePath(filepath.Join(dir, "go.mod")); ok && p == rootModule {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			require.FailNow(tb, "testkit: repository root not found above the working directory")
			return ""
		}
		dir = parent
	}
}

// RepoPath joins slash-separated elements onto the repository root.
func RepoPath(tb testing.TB, elem ...string) string {
	tb.Helper()
	return join(RepoRoot(tb), elem)
}

// SpecPath joins slash-separated elements onto the spec directory.
func SpecPath(tb testing.TB, elem ...string) string {
	tb.Helper()
	return join(filepath.Join(RepoRoot(tb), "spec"), elem)
}

// ModuleRoot returns the directory of the nearest go.mod at or above the
// working directory.
func ModuleRoot(tb testing.TB) string {
	tb.Helper()
	dir, _ := nearestModule(tb)
	return dir
}

// ModulePath returns the module path declared by the nearest go.mod at or
// above the working directory.
func ModulePath(tb testing.TB) string {
	tb.Helper()
	_, path := nearestModule(tb)
	return path
}

func nearestModule(tb testing.TB) (string, string) {
	tb.Helper()
	dir, err := os.Getwd()
	require.NoError(tb, err)
	for {
		gomod := filepath.Join(dir, "go.mod")
		if isFile(gomod) {
			path, ok := modulePath(gomod)
			require.Truef(tb, ok, "%s has no module directive", gomod)
			return dir, path
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			require.FailNow(tb, "testkit: no go.mod above the working directory")
			return "", ""
		}
		dir = parent
	}
}

func join(base string, elem []string) string {
	parts := make([]string, 0, len(elem)+1)
	parts = append(parts, base)
	for _, e := range elem {
		parts = append(parts, filepath.FromSlash(e))
	}
	return filepath.Join(parts...)
}

func isFile(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

func modulePath(gomod string) (string, bool) {
	f, err := os.Open(gomod)
	if err != nil {
		return "", false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if rest, ok := strings.CutPrefix(line, "module"); ok && rest != "" && (rest[0] == ' ' || rest[0] == '\t') {
			return strings.Trim(strings.TrimSpace(rest), `"`), true
		}
	}
	return "", false
}

// ImportPackage resolves an import path of the module that holds the working
// directory to its directory and parses it, failing the test unless a Go
// package lives there. Import guards call it on the paths they forbid, so
// that a package moved to a new path fails the guard instead of leaving it
// to check a path nothing can import.
func ImportPackage(tb testing.TB, importPath string) *build.Package {
	tb.Helper()
	root, mod := nearestModule(tb)
	rel, ok := strings.CutPrefix(importPath, mod)
	require.Truef(tb, ok && (rel == "" || rel[0] == '/'), "%s is not a package of module %s", importPath, mod)
	pkg, err := build.ImportDir(join(root, []string{strings.TrimPrefix(rel, "/")}), 0)
	require.NoErrorf(tb, err, "%s does not resolve to a package", importPath)
	return pkg
}
