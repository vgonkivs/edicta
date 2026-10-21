// SPDX-License-Identifier: Apache-2.0

package fsarchive_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/test/archivefix"
)

// The store reads a decision whose envelope has an undefined da, so the
// verifier can report it as unchecked instead of corrupt. Under another key
// the same bytes stay corrupt.
func TestDecisionWithUndefinedDAIsReadable(t *testing.T) {
	fx := archivefix.Load(t)
	for _, c := range archivefix.ReaderCases(t) {
		t.Run(c.ID, func(t *testing.T) {
			s, dir := open(t, fx)
			raw := c.Record(t)
			plant(t, dir, c.Path, raw)
			d, err := s.Decision(bg, c.Hash(t))
			require.NoError(t, err)
			assert.NotEmpty(t, d.Envelope)

			other := c.Hash(t)
			other[0] ^= 1
			plant(t, dir, archive.HashPath(archive.KindDecision, commitment.Hash(other)), raw)
			_, err = s.Decision(bg, commitment.Hash(other))
			require.ErrorIs(t, err, archive.ErrCorrupt)
		})
	}
}
