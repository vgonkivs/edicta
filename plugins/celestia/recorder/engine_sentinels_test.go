// SPDX-License-Identifier: Apache-2.0

package recorder_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/engine/recorder"
	edrec "github.com/vgonkivs/edicta/plugins/celestia/recorder"
)

var (
	_ recorder.Recorder = (*edrec.Recorder)(nil)
	_ recorder.Recorder = (*edrec.FibreRecorder)(nil)
)

// Clients match the API's recorder.ErrX codes and the daemon maps them from
// the engine's sentinels, so the Celestia Recorder must return those very
// values under its own exported names, with unchanged texts.
func TestSentinelsAreTheEngineSentinels(t *testing.T) {
	for _, tc := range []struct {
		name   string
		engine error
		impl   error
		text   string
	}{
		{"ErrTooLarge", recorder.ErrTooLarge, edrec.ErrTooLarge, "recorder: blob above MaxBlobBytes"},
		{"ErrSignerMismatch", recorder.ErrSignerMismatch, edrec.ErrSignerMismatch, "recorder: anchored blob has another signer or share version"},
		{"ErrNotVisible", recorder.ErrNotVisible, edrec.ErrNotVisible, "recorder: anchor not visible on the read node in time"},
		{"ErrOutcomeUnknown", recorder.ErrOutcomeUnknown, edrec.ErrOutcomeUnknown, "recorder: submit outcome unknown"},
		{"ErrNodeUnavailable", recorder.ErrNodeUnavailable, edrec.ErrNodeUnavailable, "recorder: node unavailable"},
		{"ErrTooManyPending", recorder.ErrTooManyPending, edrec.ErrTooManyPending, "recorder: too many blobs with an unresolved outcome"},
		{"ErrArchiveUnavailable", recorder.ErrArchiveUnavailable, edrec.ErrArchiveUnavailable, "recorder: archive unavailable"},
		{"ErrEscrowInsufficient", recorder.ErrEscrowInsufficient, edrec.ErrEscrowInsufficient, "recorder: escrow balance too low for this upload"},
		{"ErrSubmitMismatch", recorder.ErrSubmitMismatch, edrec.ErrSubmitMismatch, "recorder: node returned another blob id than computed"},
		{"ErrAnchorRejected", recorder.ErrAnchorRejected, edrec.ErrAnchorRejected, "recorder: anchor on chain fails the certificate rule"},
		{"ErrClockSkew", recorder.ErrClockSkew, edrec.ErrClockSkew, "recorder: local clock skewed against the chain"},
		{"ErrIntentStale", recorder.ErrIntentStale, edrec.ErrIntentStale, "recorder: anchor tx signed for a stale account sequence; publish a new blob"},
		{"ErrAnchorTxRejected", recorder.ErrAnchorTxRejected, edrec.ErrAnchorTxRejected, "recorder: the node refused the anchor tx"},
		{"ErrAnchorExpired", recorder.ErrAnchorExpired, edrec.ErrAnchorExpired, "recorder: the anchor did not land in its window"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NotNil(t, tc.engine)
			assert.Same(t, tc.engine, tc.impl)
			require.ErrorIs(t, tc.impl, tc.engine)
			require.ErrorIs(t, tc.engine, tc.impl)
			assert.EqualError(t, tc.engine, tc.text)
		})
	}
}

func TestEngineSentinelsStayDistinct(t *testing.T) {
	all := []error{
		recorder.ErrTooLarge, recorder.ErrSignerMismatch, recorder.ErrNotVisible, recorder.ErrOutcomeUnknown,
		recorder.ErrNodeUnavailable, recorder.ErrTooManyPending, recorder.ErrArchiveUnavailable,
		recorder.ErrEscrowInsufficient, recorder.ErrSubmitMismatch, recorder.ErrAnchorRejected,
		recorder.ErrClockSkew, recorder.ErrIntentStale, recorder.ErrAnchorTxRejected, recorder.ErrAnchorExpired,
	}
	for i, a := range all {
		for j, b := range all {
			if i != j {
				assert.NotErrorIs(t, a, b)
			}
		}
	}
}
