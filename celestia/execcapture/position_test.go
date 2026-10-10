package execcapture_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/celestiaorg/go-square/v4/share"
	blobtx "github.com/celestiaorg/go-square/v4/tx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/execcapture"
	"github.com/vgonkivs/edicta/celestia/railverify"
)

// addBlobTx appends a blob tx, which the block lists after its ordinary txs.
func (f *fakeChain) addBlobTx(t *testing.T, height uint64, code uint32) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	b, err := share.NewV0Blob(share.MustNewV0Namespace(bytes.Repeat([]byte{7}, 10)), bytes.Repeat([]byte{0xbb}, 700))
	require.NoError(t, err)
	tx, err := blobtx.MarshalBlobTx([]byte{byte(height), 0xcc, byte(len(f.txs[height]))}, b)
	require.NoError(t, err)
	f.txs[height] = append(f.txs[height], tx)
	f.results[height] = append(f.results[height], railverify.TxResult{Code: code, GasWanted: 100, GasUsed: 70})
}

func capturedBlock(t *testing.T, r *rig, ref string, height uint64) execcapture.Block {
	t.Helper()
	_, err := r.cap.Track(t.Context(), ref, hashA, false)
	require.NoError(t, err)
	r.cap.Pass(t.Context())
	done, err := r.store.Captured(t.Context(), ref)
	require.NoError(t, err)
	require.True(t, done, r.logs.String())
	b, err := r.store.Block(t.Context(), chainID, height)
	require.NoError(t, err)
	return b
}

// The capture stores header H_exec and complete proofs of the transaction
// namespaces against its data_hash, from which the index is derived: the
// ordinary txs come first in block order, then the blob txs, and the unit
// counts add up to the block's results.
func TestCapturePositionFromNamespaceProofsOrdinaryTxsBeforeBlobTxs(t *testing.T) {
	r := newRig(t)
	refs := r.chain.block(800, 4, func(i int) uint32 { return uint32(i) })
	r.chain.addBlobTx(t, 800, 0)
	r.chain.addBlobTx(t, 800, 9)
	r.chain.setHead(801)

	b := capturedBlock(t, r, refs[2], 800)
	require.NotEmpty(t, b.Header)
	require.Len(t, b.Namespaces, 3, "TX_NS, PFB_NS and the share that closes them")
	assert.Equal(t, share.TxNamespace.Bytes(), b.Namespaces[0].Namespace)
	assert.Equal(t, share.PayForBlobNamespace.Bytes(), b.Namespaces[1].Namespace)
	assert.Zero(t, b.Namespaces[0].Start)
	require.Len(t, b.Txs, 1)
	tx := b.Txs[0]
	assert.EqualValues(t, 2, tx.Index)
	assert.EqualValues(t, 2, tx.Result.Code)
	assert.EqualValues(t, 6, tx.Proof.Total)
	require.NoError(t, execcapture.VerifyTx(b, tx))

	t.Run("another index does not verify", func(t *testing.T) {
		bad := tx
		bad.Index, bad.Proof.Index = 1, 1
		require.ErrorIs(t, execcapture.VerifyTx(b, bad), execcapture.ErrUnproven)
	})
	t.Run("a missing namespace proof does not verify", func(t *testing.T) {
		bad := b
		bad.Namespaces = []execcapture.NamespaceProof{b.Namespaces[0], b.Namespaces[2]}
		require.ErrorIs(t, execcapture.VerifyTx(bad, tx), execcapture.ErrUnproven)
		bad.Namespaces = b.Namespaces[:2]
		require.ErrorIs(t, execcapture.VerifyTx(bad, tx), execcapture.ErrUnproven, "without the closing share the namespaces are not shown complete")
	})
	t.Run("a tampered proof does not verify", func(t *testing.T) {
		bad := b
		bad.Namespaces = append([]execcapture.NamespaceProof(nil), b.Namespaces...)
		p := bytes.Clone(bad.Namespaces[0].Proof)
		p[len(p)/2] ^= 1
		bad.Namespaces[0].Proof = p
		require.Error(t, execcapture.VerifyTx(bad, tx))
	})
	t.Run("another header does not verify", func(t *testing.T) {
		bad := b
		bad.Header = bytes.Clone(b.Header)
		bad.Header[len(bad.Header)-1] ^= 1
		require.Error(t, execcapture.VerifyTx(bad, tx))
	})
}

func TestCaptureRefusesTxsThatDoNotRebuildDataHash(t *testing.T) {
	r := newRig(t)
	refs := r.chain.block(600, 3, func(int) uint32 { return 0 })
	r.chain.setHead(601)
	r.chain.swapServed = 600
	_, err := r.cap.Capture(t.Context(), refs[0], 600)
	require.ErrorIs(t, err, execcapture.ErrUnproven)
	assert.Contains(t, err.Error(), "data_hash")
}

func TestCaptureNeedsThePinnedAppVersion(t *testing.T) {
	r := newRig(t)
	refs := r.chain.block(600, 1, func(int) uint32 { return 0 })
	r.chain.app[600] = 11
	r.chain.setHead(601)
	_, err := r.cap.Capture(t.Context(), refs[0], 600)
	require.ErrorIs(t, err, execcapture.ErrUnproven)
	assert.Contains(t, err.Error(), "app version")
}

func TestCaptureRefusesAHeaderTheNextOneDoesNotFollow(t *testing.T) {
	r := newRig(t)
	refs := r.chain.block(600, 1, func(int) uint32 { return 0 })
	r.chain.unlinked = 601
	r.chain.setHead(601)
	_, err := r.cap.Capture(t.Context(), refs[0], 600)
	require.ErrorIs(t, err, execcapture.ErrUnproven)
}

func TestCaptureRefusesATxTwiceInItsBlock(t *testing.T) {
	r := newRig(t)
	refs := r.chain.block(600, 2, func(int) uint32 { return 0 })
	r.chain.mu.Lock()
	r.chain.txs[600] = append(r.chain.txs[600], r.chain.txs[600][1])
	r.chain.results[600] = append(r.chain.results[600], r.chain.results[600][1])
	r.chain.mu.Unlock()
	r.chain.setHead(601)
	_, err := r.cap.Capture(t.Context(), refs[1], 600)
	require.ErrorIs(t, err, execcapture.ErrUnproven)
}

// A node answer that conflicts with the stored block keeps the reference
// pending and is logged once at error level.
func TestCaptureConflictKeepsPendingAndAlertsOnce(t *testing.T) {
	r := newRig(t)
	refs := r.chain.block(600, 2, func(int) uint32 { return 0 })
	r.chain.setHead(601)
	capturedBlock(t, r, refs[0], 600)

	r.chain.mu.Lock()
	r.chain.results[600][1].GasUsed++
	r.chain.mu.Unlock()
	_, err := r.cap.Track(t.Context(), refs[1], hashA, false)
	require.NoError(t, err)
	r.cap.Pass(t.Context())
	r.cap.Pass(t.Context())
	pend, err := r.store.ListPending(t.Context())
	require.NoError(t, err)
	require.Len(t, pend, 1)
	assert.Equal(t, 1, strings.Count(r.logs.String(), "conflicts with the capture already stored"))
	assert.Contains(t, r.logs.String(), "level=ERROR")
}
