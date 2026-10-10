package verifier

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
)

// revealRun is the run of the reveal_public_execution_pass vector up to the
// reveal, with the given payload salt as if the payload had been opened.
func revealRun(t *testing.T, payloadSalt []byte) *run {
	t.Helper()
	raw, err := os.ReadFile("../spec/vectors/v1/verify.json")
	require.NoError(t, err)
	var d struct {
		Records map[string]struct {
			CBORHex string `json:"record_cbor_hex"`
		} `json:"records"`
		Cases []struct {
			ID       string `json:"id"`
			Decision string `json:"decision"`
			Reveal   string `json:"reveal"`
			Checker  *struct {
				Action string `json:"tx_action_hex"`
			} `json:"checker"`
		} `json:"action_cases"`
	}
	require.NoError(t, json.Unmarshal(raw, &d))
	for _, c := range d.Cases {
		if c.ID != "reveal_public_execution_pass" {
			continue
		}
		files := map[string][]byte{}
		var recs []archive.Record
		for _, name := range []string{c.Decision, c.Reveal} {
			b := unhex(t, d.Records[name].CBORHex)
			rec, err := archive.Decode(b)
			require.NoError(t, err)
			p, err := archive.KeyPath(rec)
			require.NoError(t, err)
			files[p] = b
			recs = append(recs, rec)
		}
		dec := recs[0].(*archive.DecisionRecord)
		s, err := commitment.DecodeSigned(dec.Envelope)
		require.NoError(t, err)
		h, err := commitment.HashOf(&s.Commitment)
		require.NoError(t, err)
		sr, _, err := commitment.DecodeSignedReceipt(recs[1].(*archive.RevealRecord).SignedReceipt)
		require.NoError(t, err)

		cfg := Config{
			Params:   commitment.Params{FibreRetentionS: 14400, BlobRetentionS: 14400, SkewS: 30},
			GateKeys: []ed25519.PublicKey{sr.Receipt.GatePubKey},
		}
		r := &run{v: &Verifier{cfg: cfg, archive: pathArchive{files: files}}, h: h, ctx: t.Context(), payloadSalt: payloadSalt}
		require.True(t, r.envelope(dec))
		require.NoError(t, r.checkAction(dec))
		action, err := hex.DecodeString(c.Checker.Action)
		require.NoError(t, err)
		require.NoError(t, r.reveal(revealChecker{public: true, action: action}))
		return r
	}
	require.FailNow(t, "no reveal_public_execution_pass case")
	return nil
}

// A revealed salt is held to the salt of an opened payload too: a
// difference makes the revealed copy suspect, not the agent.
func TestRevealedSaltIsComparedWithThePayloadSalt(t *testing.T) {
	r := revealRun(t, nil)
	got, ok := r.rep.Check(CheckAction)
	require.True(t, ok)
	require.Equal(t, StatusPass, got.Status)
	salt := append([]byte(nil), r.salt...)

	r = revealRun(t, salt)
	got, _ = r.rep.Check(CheckAction)
	assert.Equal(t, StatusPass, got.Status, "the same salt")
	assert.Equal(t, ActionSourceReveal, r.rep.ActionSource)

	other := append([]byte(nil), salt...)
	other[0] ^= 1
	r = revealRun(t, other)
	got, _ = r.rep.Check(CheckAction)
	assert.Equal(t, StatusUnchecked, got.Status)
	assert.Equal(t, ReasonSourceCorrupt, got.Reason)
	assert.Equal(t, []string{archive.HashPath(archive.KindReveal, r.h)}, got.Sources)
	assert.Nil(t, r.action)
	assert.Empty(t, r.rep.ActionSource)
}
