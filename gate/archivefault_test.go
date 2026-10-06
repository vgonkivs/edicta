package gate_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/test/gatefix"
)

// A fault of the archive (an unreadable or damaged record) says nothing about
// the payload: it is a retryable archive error, not the availability verdict.
func TestArchiveFaultIsNotAnAvailabilityVerdict(t *testing.T) {
	fault := fmt.Errorf("%w: %w", gate.ErrArchiveUnavailable, errors.New("record damaged"))

	t.Run("window holds, DA has no blob", func(t *testing.T) {
		e, c, b, _ := blobEnv(t)
		e.Archive.Fail(fault)
		_, err := e.Authorize(b)
		require.ErrorIs(t, err, gate.ErrArchiveUnavailable)
		assert.NotErrorIs(t, err, gate.ErrPayloadUnavailable)
		e.RequireUntouched(c)

		e.Archive.Fail(nil)
		e.Archive.Put(c.PayloadRef, gatefix.Blob(t))
		_, err = e.Authorize(b)
		require.NoError(t, err, "the same request succeeds once the archive is back")
	})
	t.Run("window failed, archive only", func(t *testing.T) {
		e := gatefix.New(t)
		c := gatefix.Template(t)
		routeArchive(e, c)
		b, _ := gatefix.Sign(t, "agent1", c)
		e.Archive.Fail(fault)
		_, err := e.Authorize(b)
		require.ErrorIs(t, err, gate.ErrArchiveUnavailable)
		assert.NotErrorIs(t, err, gate.ErrPayloadUnavailable)
		assert.NotErrorIs(t, err, gate.ErrAnchorTooOld)
		e.RequireUntouched(c)
	})
	t.Run("a plain miss is still the verdict", func(t *testing.T) {
		e, c, b, _ := blobEnv(t)
		_, err := e.Authorize(b)
		e.RequireRejected(c, err, gate.ErrPayloadUnavailable)
		assert.NotErrorIs(t, err, gate.ErrArchiveUnavailable)
	})
}
