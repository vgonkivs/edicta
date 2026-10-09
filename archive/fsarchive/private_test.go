package fsarchive_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/test/archivefix"
)

// v1Record decodes a record of spec/vectors/v1/archive.json by case id.
func v1Record(t *testing.T, id string) archive.Record {
	raw, err := os.ReadFile("../../spec/vectors/v1/archive.json")
	require.NoError(t, err)
	var d struct {
		Cases []struct {
			ID  string `json:"id"`
			Hex string `json:"record_cbor_hex"`
		} `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(raw, &d))
	for _, c := range d.Cases {
		if c.ID == id {
			b, err := hex.DecodeString(c.Hex)
			require.NoError(t, err)
			rec, err := archive.Decode(b)
			require.NoError(t, err)
			return rec
		}
	}
	require.FailNow(t, "no case "+id)
	return nil
}

// A private decision record needs its kind 15 action record first; the
// action record's identity is its key, so a second envelope of the same
// action is a no-op.
func TestPrivateDecisionNeedsItsActionRecord(t *testing.T) {
	s, _ := open(t, archivefix.Load(t))
	dec := v1Record(t, "decision_private_fibre").(*archive.DecisionRecord)
	act := v1Record(t, "private_action_fibre").(*archive.PrivateBlobRecord)
	_, err := s.Put(t.Context(), dec)
	require.ErrorIs(t, err, archive.ErrNotFound)

	out, err := s.Put(t.Context(), act)
	require.NoError(t, err)
	assert.Equal(t, archive.Written, out)
	other := *act
	other.Envelope = append([]byte(nil), act.Envelope...)
	other.Envelope[len(other.Envelope)-1] ^= 1
	out, err = s.Put(t.Context(), &other)
	require.NoError(t, err)
	assert.Equal(t, archive.Unchanged, out, "the first write stays")

	out, err = s.Put(t.Context(), dec)
	require.NoError(t, err)
	assert.Equal(t, archive.Written, out)

	got, err := s.PrivateBlob(t.Context(), policy.PrivateAction, commitment.Hash(act.Hash))
	require.NoError(t, err)
	assert.Equal(t, act, got)
	_, err = s.PrivateBlob(t.Context(), policy.PrivateBucket, commitment.Hash(act.Hash))
	require.ErrorIs(t, err, archive.ErrNotFound)
	_, err = s.PrivateBlob(t.Context(), 9, commitment.Hash(act.Hash))
	require.ErrorIs(t, err, archive.ErrNotFound)
}
