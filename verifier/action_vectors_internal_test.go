package verifier

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
)

type actionVectors struct {
	Records map[string]struct {
		CBORHex string `json:"record_cbor_hex"`
	} `json:"records"`
	Cases []struct {
		ID            string `json:"id"`
		Decision      string `json:"decision"`
		PrivateRecord string `json:"private_record"`
		AuditorKey    string `json:"auditor_key"`
		Reveal        string `json:"reveal"`
		PayloadSalt   string `json:"payload_salt_hex"`
		PayloadO8     string `json:"payload_o8"`
		Expect        struct {
			Decision struct {
				Status string `json:"status"`
				Reason string `json:"reason"`
			} `json:"decision"`
			Action *struct {
				Status       string `json:"status"`
				Reason       string `json:"reason"`
				ActionSource string `json:"action_source"`
			} `json:"action"`
		} `json:"expect"`
	} `json:"action_cases"`
}

// TestActionVectors runs the decision and action rules of the action cases
// that need neither an auditor key nor a reveal: the public form, the
// private form without a key, the corrupt record, and O8 before the salt
// comparison.
func TestActionVectors(t *testing.T) {
	raw, err := os.ReadFile("../spec/vectors/v1/verify.json")
	require.NoError(t, err)
	var d actionVectors
	require.NoError(t, json.Unmarshal(raw, &d))
	ran := 0
	for _, c := range d.Cases {
		// The auditor-key, reveal and kind 15 lookup paths belong to private
		// mode, which this verifier does not read yet.
		if c.AuditorKey != "" || c.Reveal != "" ||
			c.Expect.Action != nil && c.Expect.Action.Reason == string(ReasonDecisionUnavailable) {
			continue
		}
		ran++
		t.Run(c.ID, func(t *testing.T) {
			rec, ok := d.Records[c.Decision]
			require.True(t, ok, c.Decision)
			b, err := hex.DecodeString(rec.CBORHex)
			require.NoError(t, err)
			decoded, err := archive.Decode(b)
			if c.Expect.Decision.Status == string(StatusUnchecked) {
				require.ErrorIs(t, err, archive.ErrCorrupt, "a record that does not decode is a bad copy")
				assert.Equal(t, string(ReasonSourceCorrupt), c.Expect.Decision.Reason)
				return
			}
			require.NoError(t, err)
			dec := decoded.(*archive.DecisionRecord)
			s, err := commitment.DecodeSigned(dec.Envelope)
			require.NoError(t, err)
			h, err := commitment.HashOf(&s.Commitment)
			require.NoError(t, err)

			v := &Verifier{cfg: Config{Params: commitment.Params{FibreRetentionS: 14400, BlobRetentionS: 14400, SkewS: 30}}}
			r := &run{v: v, h: h}
			require.True(t, r.envelope(dec))
			r.checkAction(dec)
			if c.PayloadSalt != "" && c.PayloadO8 != "fail" {
				salt, err := hex.DecodeString(c.PayloadSalt)
				require.NoError(t, err)
				r.compareSalt(salt)
			}
			got, ok := r.rep.Check(CheckAction)
			require.True(t, ok)
			want := c.Expect.Action
			require.NotNil(t, want)
			assert.Equal(t, Status(want.Status), got.Status, "%v", got.Err)
			assert.Equal(t, Reason(want.Reason), got.Reason)
			assert.Equal(t, ActionSource(want.ActionSource), r.rep.ActionSource)
		})
	}
	require.GreaterOrEqual(t, ran, 6)
}
