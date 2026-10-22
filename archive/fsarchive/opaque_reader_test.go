// SPDX-License-Identifier: Apache-2.0

package fsarchive_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/engine/commitment"
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

// Put writes a public decision with an undefined da under the hash of its
// commitment bytes, and a private one needs the action hash that only a
// strict decode gives: the opaque-only envelopes are refused there.
func TestPutDecisionWithUndefinedDA(t *testing.T) {
	fx := archivefix.Load(t)
	opaqueOnly := map[string]bool{"reader_da_5_key_7": true, "reader_da_4_signer_19": true}
	for _, c := range archivefix.ReaderCases(t) {
		t.Run(c.ID, func(t *testing.T) {
			s, _ := open(t, fx)
			rec, err := archive.DecodeAt(c.Path, c.Record(t))
			require.NoError(t, err)
			d := rec.(*archive.DecisionRecord)

			out, err := s.Put(bg, d)
			require.NoError(t, err)
			assert.Equal(t, archive.Written, out)
			got, err := s.Decision(bg, c.Hash(t))
			require.NoError(t, err)
			assert.Equal(t, d.Envelope, got.Envelope)

			priv := *d
			priv.Form = archive.FormPrivate
			priv.Action, priv.ActionSalt = nil, nil
			s2, _ := open(t, fx)
			_, err = s2.Put(bg, &priv)
			require.Error(t, err)
			if opaqueOnly[c.ID] {
				require.ErrorIs(t, err, archive.ErrUndefinedDA)
			} else {
				require.ErrorIs(t, err, archive.ErrNotFound)
			}
		})
	}
}
