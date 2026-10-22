package httparchive_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/engine/archive"
	"github.com/vgonkivs/edicta/engine/archive/httparchive"
	"github.com/vgonkivs/edicta/engine/commitment"
	"github.com/vgonkivs/edicta/test/archivefix"
	"github.com/vgonkivs/edicta/test/execresultfix"
)

func TestExecutionResultOverHTTP(t *testing.T) {
	f := execresultfix.Load(t)
	w := newWorld(t, fullSet...)
	r, other := f.Records[0], f.Records[1]
	_, err := w.store.Put(bg, r.Build(t))
	require.NoError(t, err)
	ref := execresultfix.Hex(t, r.Key.RailRef)

	c, srv := w.client(t, nil)
	got, err := c.ExecutionResult(bg, r.Key.ChainID, ref)
	require.NoError(t, err)
	assert.Equal(t, r.Build(t), got)
	assert.Equal(t, []string{"GET /" + r.Path}, srv.paths())

	_, err = c.ExecutionResult(bg, other.Key.ChainID, execresultfix.Hex(t, other.Key.RailRef))
	require.ErrorIs(t, err, archive.ErrNotFound)
	_, err = c.ExecutionResult(bg, "..", ref)
	require.ErrorIs(t, err, archive.ErrNotFound)
}

func TestExecutionResultAnswersOverHTTP(t *testing.T) {
	f := execresultfix.Load(t)
	w := newWorld(t, fullSet...)
	r, other := f.Records[0], f.Records[1]
	ref := execresultfix.Hex(t, r.Key.RailRef)
	key := "/" + r.Path

	for name, tc := range map[string]struct {
		answer func(http.ResponseWriter)
		want   error
	}{
		// A server of an older revision does not know the path.
		"old server 404":  {status(http.StatusNotFound), archive.ErrNotFound},
		"fault":           {status(http.StatusInternalServerError), httparchive.ErrFault},
		"another key":     {body(execresultfix.Hex(t, other.CBORHex)), archive.ErrCorrupt},
		"strict decoding": {body(execresultfix.Hex(t, f.Reject[0].CBORHex)), archive.ErrCorrupt},
		"above the cap":   {zeros(1<<25 + 1), httparchive.ErrTooLarge},
	} {
		t.Run(name, func(t *testing.T) {
			c, _ := w.client(t, override(map[string]func(http.ResponseWriter){key: tc.answer}))
			_, err := c.ExecutionResult(bg, r.Key.ChainID, ref)
			require.ErrorIs(t, err, tc.want)
		})
	}
}

func TestExecutionResultReaderPathsOverHTTP(t *testing.T) {
	f := execresultfix.Load(t)
	w := newWorld(t, fullSet...)
	r := f.Records[0]
	var h commitment.Hash
	h[0] = 0x42
	var other []byte
	for _, c := range archivefix.Load(t).Cases {
		if c.CBOR != nil {
			other = c.CBOR
			break
		}
	}
	require.NotNil(t, other)

	c, _ := w.client(t, override(map[string]func(http.ResponseWriter){
		"/" + archive.HashPath(archive.KindDecision, h): body(execresultfix.Hex(t, r.CBORHex)),
		"/" + r.Path: body(other),
	}))
	_, err := c.Decision(bg, h)
	require.ErrorIs(t, err, archive.ErrCorrupt)
	require.ErrorIs(t, err, commitment.ErrInvalidEnum)
	_, err = c.ExecutionResult(bg, r.Key.ChainID, execresultfix.Hex(t, r.Key.RailRef))
	require.ErrorIs(t, err, archive.ErrCorrupt)
	require.ErrorIs(t, err, commitment.ErrInvalidEnum)
}

// An archive that answers 403 for a missing key is a fault, never absent.
func TestExecutionResult403IsAFault(t *testing.T) {
	r := execresultfix.Load(t).Records[0]
	w := newWorld(t, fullSet...)
	c, _ := w.client(t, override(map[string]func(http.ResponseWriter){"/" + r.Path: status(http.StatusForbidden)}))
	_, err := c.ExecutionResult(bg, r.Key.ChainID, execresultfix.Hex(t, r.Key.RailRef))
	require.ErrorIs(t, err, httparchive.ErrFault)
	require.NotErrorIs(t, err, archive.ErrNotFound)
}
