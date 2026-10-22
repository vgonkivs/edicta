// SPDX-License-Identifier: Apache-2.0

package httparchive_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/engine/archive"
	"github.com/vgonkivs/edicta/engine/commitment"
	"github.com/vgonkivs/edicta/test/archivefix"
)

// The client reads a decision whose envelope has an undefined da.
func TestDecisionWithUndefinedDAIsReadable(t *testing.T) {
	for _, c := range archivefix.ReaderCases(t) {
		t.Run(c.ID, func(t *testing.T) {
			w := newWorld(t)
			p := filepath.Join(w.dir, filepath.FromSlash(c.Path))
			require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
			require.NoError(t, os.WriteFile(p, c.Record(t), 0o644))
			cl, _ := w.client(t, nil)
			d, err := cl.Decision(bg, commitment.Hash(c.Hash(t)))
			require.NoError(t, err)
			assert.NotEmpty(t, d.Envelope)

			other := c.Hash(t)
			other[0] ^= 1
			p = filepath.Join(w.dir, filepath.FromSlash(archive.HashPath(archive.KindDecision, commitment.Hash(other))))
			require.NoError(t, os.WriteFile(p, c.Record(t), 0o644))
			_, err = cl.Decision(bg, commitment.Hash(other))
			require.ErrorIs(t, err, archive.ErrCorrupt)
		})
	}
}
