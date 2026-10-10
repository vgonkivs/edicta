package gatechain_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	libshare "github.com/celestiaorg/go-square/v4/share"
	squaretx "github.com/celestiaorg/go-square/v4/tx"

	"github.com/vgonkivs/edicta/celestia/gatechain"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
)

func TestBlobIntentBindingEdges(t *testing.T) {
	ref, msg := blobRef(t)
	hs := blobHeaders{head: 102, at: map[uint64]time.Time{100: time.Unix(1_790_997_000, 0)}}
	v, err := gatechain.NewBlobIntents(hs)
	require.NoError(t, err)

	otherNS := bytes.Clone(ref.Namespace)
	otherNS[len(otherNS)-1] ^= 1
	wrongNS := *msg
	wrongNS.Namespaces = [][]byte{otherNS, otherNS}

	ns, err := libshare.NewNamespaceFromBytes(ref.Namespace)
	require.NoError(t, err)
	bl, err := libshare.NewV1Blob(ns, []byte("blob"), ref.Signer)
	require.NoError(t, err)
	wrapped, err := squaretx.MarshalBlobTx(pfbTx(t, 0, true, msg), bl)
	require.NoError(t, err)

	for name, tx := range map[string][]byte{
		"another namespace":  pfbTx(t, 0, true, &wrongNS),
		"timeout below h0":   pfbTx(t, 99, true, msg),
		"a BlobTx, not a tx": wrapped,
		"no message":         pfbTx(t, 0, true),
		"empty":              {},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := v.VerifyIntent(t.Context(), ref, &gate.AnchorIntent{DA: commitment.DACelestiaBlob, Tx: tx}, 4)
			require.ErrorIs(t, err, gate.ErrAnchorIntentInvalid)
		})
	}

	t.Run("timeout one above h0", func(t *testing.T) {
		f, err := v.VerifyIntent(t.Context(), ref, &gate.AnchorIntent{DA: commitment.DACelestiaBlob, Tx: pfbTx(t, 101, true, msg)}, 4)
		require.NoError(t, err)
		assert.EqualValues(t, 101, f.TimeoutHeight)
	})
	t.Run("a da = 1 reference", func(t *testing.T) {
		r := ref
		r.DA = commitment.DAFibre
		_, err := v.VerifyIntent(t.Context(), r, &gate.AnchorIntent{DA: commitment.DACelestiaBlob, Tx: pfbTx(t, 0, true, msg)}, 4)
		require.ErrorIs(t, err, gate.ErrAnchorIntentInvalid)
	})
	t.Run("head below h0", func(t *testing.T) {
		low := blobHeaders{head: 99, at: hs.at}
		lv, err := gatechain.NewBlobIntents(low)
		require.NoError(t, err)
		_, err = lv.VerifyIntent(t.Context(), ref, &gate.AnchorIntent{DA: commitment.DACelestiaBlob, Tx: pfbTx(t, 0, true, msg)}, 4)
		require.ErrorIs(t, err, gate.ErrChainUnavailable)
	})
}

func TestBroadcasterNodeAnswers(t *testing.T) {
	ref, msg := blobRef(t)
	rec := &gate.AnchorIntent{DA: commitment.DACelestiaBlob, Namespace: ref.Namespace, Signer: ref.Signer, Tx: pfbTx(t, 0, true, msg)}
	n := &fakeNode{}
	b, err := gatechain.NewBroadcaster(n)
	require.NoError(t, err)

	st, err := b.Lookup(t.Context(), rec)
	require.NoError(t, err)
	assert.Equal(t, gate.TxStatus{}, st, "an unknown tx is not included")

	n.status = node.TxStatus{Found: true, Height: 7, Code: 11}
	st, err = b.Lookup(t.Context(), rec)
	require.NoError(t, err)
	assert.Equal(t, gate.TxStatus{Included: true, Height: 7, Code: 11}, st, "a failed inclusion keeps its code")

	for name, nerr := range map[string]error{"sequence": node.ErrSequenceMismatch, "mempool full": node.ErrMempoolFull} {
		n.sendFn = func([]byte) error { return nerr }
		require.ErrorIs(t, b.Broadcast(t.Context(), commitment.DAFibre, rec, nil), gate.ErrAnchorIntentRejected, name)
	}

	bad := *rec
	bad.Namespace = []byte{1, 2}
	n.sendFn = nil
	sent := len(n.sent)
	require.ErrorIs(t, b.Broadcast(t.Context(), commitment.DACelestiaBlob, &bad, []byte("blob")), gate.ErrAnchorIntentRejected)
	assert.Len(t, n.sent, sent, "a BlobTx that cannot be built is never sent")
}

func FuzzCheckPFB(f *testing.F) {
	ref, msg := blobRef(f)
	f.Add(pfbTx(f, 0, true, msg))
	f.Add(pfbTx(f, 150, true, msg, msg))
	f.Add(pfbTx(f, 0, false, msg))
	f.Add([]byte{})
	f.Add([]byte{0x0a, 0x00})
	f.Fuzz(func(t *testing.T, tx []byte) {
		timeout, err := gatechain.CheckPFB(tx, ref)
		if err != nil {
			require.ErrorIs(t, err, gate.ErrAnchorIntentInvalid)
			assert.Zero(t, timeout)
			return
		}
		assert.True(t, timeout == 0 || timeout > ref.Height, "an accepted timeout_height is above h0")
	})
}
