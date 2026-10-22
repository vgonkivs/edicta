// SPDX-License-Identifier: Apache-2.0

package absence

import (
	"bytes"
	"testing"

	"github.com/celestiaorg/go-square/v4/inclusion"
	libshare "github.com/celestiaorg/go-square/v4/share"
	"github.com/cometbft/cometbft/crypto/merkle"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/engine/commitment"
)

// Shares handed out as views of one buffer, as a zero-copy decoder would,
// give the same outcome on every read and stay unchanged: go-square writes
// continuation data into the first share's slice.
func TestBlobsParseTwiceFromOneBuffer(t *testing.T) {
	ns := libshare.MustNewV0Namespace(bytes.Repeat([]byte{0x42}, libshare.NamespaceVersionZeroIDSize))
	signer := bytes.Repeat([]byte{7}, libshare.SignerSize)
	b, err := libshare.NewV1Blob(ns, bytes.Repeat([]byte{0xab}, 3000), signer)
	require.NoError(t, err)
	com, err := inclusion.CreateCommitment(b, merkle.HashFromByteSlices, SubtreeRootThreshold)
	require.NoError(t, err)
	split, err := b.ToShares()
	require.NoError(t, err)
	require.Greater(t, len(split), 1)

	var buf []byte
	for i := range split {
		buf = append(buf, split[i].ToBytes()...)
	}
	want := bytes.Clone(buf)
	views := make([]libshare.Share, len(split))
	for i := range views {
		s, err := libshare.NewShare(buf[i*libshare.ShareSize : (i+1)*libshare.ShareSize])
		require.NoError(t, err)
		views[i] = s
	}
	q := Query{DA: commitment.DACelestiaBlob, Namespace: ns.Bytes(), Commitment: com, Signer: signer}

	first := blobs(7, q, []int{0}, views)
	assert.Equal(t, Present, first.Result)
	assert.Equal(t, want, buf, "the caller's buffer is unchanged")
	second := blobs(7, q, []int{0}, views)
	assert.Equal(t, first, second)
}
