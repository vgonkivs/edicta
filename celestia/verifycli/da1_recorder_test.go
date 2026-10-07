package verifycli

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/test/fibreworld"
	"github.com/vgonkivs/edicta/commitment"
)

// The evidence the da = 1 Recorder archived is accepted by the verifier as it
// is: nothing between the Recorder and edicta-verify repairs or reshapes it.
func TestDA1EvidenceArchivedByTheRecorderVerifies(t *testing.T) {
	w := fibreworld.New(t)
	pub, err := w.Rec.Publish(context.Background(), w.Live.Payload)
	require.NoError(t, err)
	assert.Equal(t, w.Live.Height, pub.Ref.Height)

	ev, err := w.St.Evidence(context.Background(), commitment.DAFibre, w.Live.Ref.Commitment)
	require.NoError(t, err)
	s := &da1{live: w.Live, d: w.Live.WriteDecision(t, ev)}
	trusted := w.Live.TrustedFile(t, nil)

	code, out := exec(t, s.args("verify", "--trusted", trusted))
	require.Equal(t, exitValid, code, out)
	for _, line := range []string{"[ok] anchor", "[ok] header_trust", "[ok] payload", "verdict: valid"} {
		assert.Contains(t, out, line)
	}
	assert.Contains(t, out, "anchor proof form: 1, earlier candidates: 0")
	assert.NotContains(t, out, "[FAIL]")
	assert.NotContains(t, out, "[unchecked]")

	code, out = exec(t, s.args("replay", "--json", "--trusted", trusted))
	require.Equal(t, exitValid, code, out)
}
