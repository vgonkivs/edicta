// SPDX-License-Identifier: Apache-2.0

package archive_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/engine/archive"
	"github.com/vgonkivs/edicta/engine/commitment"
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
// version outside it is still refused (the strict cause wins where the
// payload_ref itself fails the strict decode). The two cases
// that pass strict decoding anyway are not the fallback; the other two are.
func TestArchiveReaderOpaqueStaysStrictOutside(t *testing.T) {
	for _, c := range archivefix.ReaderCases(t) {
		t.Run(c.ID, func(t *testing.T) {
			raw := c.Record(t)

			_, err := archive.DecodeAt(c.Path, append(append([]byte(nil), raw...), 0))
			require.ErrorIs(t, err, commitment.ErrTrailingData)

			// Version 1 -> 2 inside the commitment map (a2 01 ac 01 01 ...).
			bad := append([]byte(nil), raw...)
			i := indexOf(bad, []byte{0xa2, 0x01, 0xac, 0x01, 0x01})
			require.GreaterOrEqual(t, i, 0)
			bad[i+4] = 0x02
			_, err = archive.DecodeAt(c.Path, bad)
			want := error(commitment.ErrUnsupportedVersion)
			if c.Cause != "" {
				want = archivefix.Causes[c.Cause]
			}
			require.ErrorIs(t, err, want)
		})
	}
}

// The fallback is what admits the two cases the strict decode refuses; the
// other two never reach it.
func TestArchiveReaderFallbackCases(t *testing.T) {
	for _, c := range archivefix.ReaderCases(t) {
		t.Run(c.ID, func(t *testing.T) {
			rec, err := archive.DecodeAt(c.Path, c.Record(t))
			require.NoError(t, err)
			_, err = commitment.DecodeSigned(rec.(*archive.DecisionRecord).Envelope)
			if c.Cause == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, archivefix.Causes[c.Cause])
		})
	}
}

func indexOf(b, sub []byte) int {
	for i := 0; i+len(sub) <= len(b); i++ {
		if string(b[i:i+len(sub)]) == string(sub) {
			return i
		}
	}
	return -1
}
