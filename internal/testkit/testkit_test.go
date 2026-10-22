// SPDX-License-Identifier: Apache-2.0

package testkit_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/internal/testkit"
)

func TestRepoRootHoldsTheManifest(t *testing.T) {
	root := testkit.RepoRoot(t)
	assert.FileExists(t, filepath.Join(root, "spec", "vectors", "MANIFEST.sha256"))
	assert.FileExists(t, filepath.Join(root, "go.mod"))

	wd, err := os.Getwd()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(root, "internal", "testkit"), wd)
}

func TestPathsJoinSlashSeparatedElements(t *testing.T) {
	root := testkit.RepoRoot(t)
	for _, tc := range []struct {
		name string
		got  string
		want string
	}{
		{"spec file", testkit.SpecPath(t, "vectors/MANIFEST.sha256"), filepath.Join(root, "spec", "vectors", "MANIFEST.sha256")},
		{"spec elems", testkit.SpecPath(t, "vectors", "keys.json"), filepath.Join(root, "spec", "vectors", "keys.json")},
		{"repo file", testkit.RepoPath(t, "go.mod"), filepath.Join(root, "go.mod")},
		{"repo root", testkit.RepoPath(t), root},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.got)
			_, err := os.Stat(tc.got)
			assert.NoError(t, err)
		})
	}
}

func TestModuleRootIsTheRootModuleHere(t *testing.T) {
	assert.Equal(t, testkit.RepoRoot(t), testkit.ModuleRoot(t))
	assert.Equal(t, "github.com/vgonkivs/edicta", testkit.ModulePath(t))
}
