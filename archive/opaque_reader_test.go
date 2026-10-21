// SPDX-License-Identifier: Apache-2.0

package archive_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/test/archivefix"
)

// A decision record whose envelope has a da the reader does not define is
// read with payload_ref opaque and keyed by the hash of its commitment bytes.
func TestArchiveReaderOpaqueUndefinedDA(t *testing.T) {
	for _, c := range archivefix.ReaderCases(t) {
		t.Run(c.ID, func(t *testing.T) {
			raw := c.Record(t)
			rec, err := archive.DecodeAt(c.Path, raw)
			require.NoError(t, err)
			path, err := archive.KeyPath(rec)
			require.NoError(t, err)
			assert.Equal(t, c.Path, path)
			again, err := archive.Encode(rec)
			require.NoError(t, err)
			assert.Equal(t, raw, again)
		})
	}
}

// The opaque reading covers payload_ref only: a trailing byte or a changed
// field outside it is still refused.
func TestArchiveReaderOpaqueStaysStrictOutside(t *testing.T) {
	c := archivefix.ReaderCases(t)[0]
	raw := c.Record(t)

	_, err := archive.DecodeAt(c.Path, append(append([]byte(nil), raw...), 0))
	require.Error(t, err)

	// Version 1 -> 2 inside the commitment map (a2 01 ac 01 01 ...).
	bad := append([]byte(nil), raw...)
	i := indexOf(bad, []byte{0xa2, 0x01, 0xac, 0x01, 0x01})
	require.GreaterOrEqual(t, i, 0)
	bad[i+4] = 0x02
	_, err = archive.DecodeAt(c.Path, bad)
	require.Error(t, err)
}

func indexOf(b, sub []byte) int {
	for i := 0; i+len(sub) <= len(b); i++ {
		if string(b[i:i+len(sub)]) == string(sub) {
			return i
		}
	}
	return -1
}
