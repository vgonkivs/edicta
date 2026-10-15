package execcapture

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func recordSyncs(t *testing.T, root string) *[]string {
	t.Helper()
	var got []string
	orig := syncDir
	syncDir = func(dir string) error {
		rel, err := filepath.Rel(root, dir)
		require.NoError(t, err)
		got = append(got, filepath.ToSlash(rel))
		return orig(dir)
	}
	t.Cleanup(func() { syncDir = orig })
	return &got
}

// The archived marker is durable before the capture is dropped: after a
// crash the reference reads as captured, so it is not tracked again and
// given up as lost once the node prunes it.
func TestMarkArchivedSyncsTheMarkerFirst(t *testing.T) {
	root := t.TempDir()
	d, err := OpenDir(root)
	require.NoError(t, err)
	syncs := recordSyncs(t, root)
	ref := strings.Repeat("ab", 32)
	b := Block{ChainID: "test-chain", Height: 7, Header: []byte{1}, NextHeader: []byte{2},
		Namespaces: []NamespaceProof{{Namespace: []byte{3}}}, Txs: []Tx{{RailRef: ref}}}
	require.NoError(t, d.PutBlock(context.Background(), b))
	assert.Equal(t, []string{"blocks", "blocks/test-chain", "refs"}, *syncs, "a new chain directory is synced into blocks/")

	*syncs = nil
	require.NoError(t, d.MarkArchived(context.Background(), "test-chain", 7, ref))
	assert.Equal(t, []string{"archived", "blocks/test-chain", "refs"}, *syncs)
	done, err := d.Captured(context.Background(), ref)
	require.NoError(t, err)
	assert.True(t, done)
}

func TestQuarantineRenameIsSynced(t *testing.T) {
	root := t.TempDir()
	d, err := OpenDir(root)
	require.NoError(t, err)
	ref := strings.Repeat("cd", 32)
	require.NoError(t, d.writeFile(filepath.Join(root, "pending", ref+".json"), []byte("{")))
	syncs := recordSyncs(t, root)
	_, err = d.ListPending(context.Background())
	require.Error(t, err)
	assert.True(t, slices.Contains(*syncs, "quarantine") && slices.Contains(*syncs, "pending"), "%v", *syncs)
}
