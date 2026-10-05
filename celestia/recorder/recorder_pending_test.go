package recorder_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/recorder"
)

// Uses recorder.Config.MaxPending int (cap on unresolved
// entries, zero = default) and recorder.ErrTooManyPending, returned wrapped by
// Publish for a NEW blob at the cap; a blob that already has an entry is not
// refused with it.

func TestPendingIsBounded(t *testing.T) {
	ch := newChain()
	sub := newLanding(ch)
	sub.Err, sub.NoLand = errBoom, true
	c := cfg()
	c.MaxPending = 3
	rec := mk(t, c, sub, ch)
	for i := 0; i < 3; i++ {
		_, err := rec.Publish(bg, []byte{byte(i), 0xaa})
		require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	}
	_, err := rec.Publish(bg, []byte{9, 0xaa})
	require.ErrorIs(t, err, recorder.ErrTooManyPending, "a clear error, not silent growth")
	assert.NotErrorIs(t, err, recorder.ErrOutcomeUnknown)
	assert.Equal(t, 3, sub.Calls, "the refused blob was not submitted")

	_, err = rec.Publish(bg, []byte{0, 0xaa})
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown, "an existing entry is not refused for the cap")
	assert.NotErrorIs(t, err, recorder.ErrTooManyPending)
}
