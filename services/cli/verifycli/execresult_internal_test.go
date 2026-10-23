package verifycli

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/engine/archive"
	"github.com/vgonkivs/edicta/engine/archive/fsarchive"
	"github.com/vgonkivs/edicta/engine/verifier"
	"github.com/vgonkivs/edicta/test/execresultfix"
)

// The online mode wraps the archive; the archived execution results must
// still reach the verifier through it.
func TestRecordingReaderServesExecutionResults(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := fsarchive.Open(dir, nil)
	require.NoError(t, err)
	r := execresultfix.Load(t).Records[0]
	_, err = st.Put(ctx, r.Build(t))
	require.NoError(t, err)

	var rd verifier.Reader = newRecordingReader(st)
	er, ok := rd.(archive.ExecResultReader)
	require.True(t, ok)
	got, err := er.ExecutionResult(ctx, r.Key.ChainID, execresultfix.Hex(t, r.Key.RailRef))
	require.NoError(t, err)
	assert.Equal(t, r.Build(t), got)

	// A wrapped reader without them reads as an archive without the record.
	plain := newRecordingReader(struct{ verifier.Reader }{st})
	_, err = plain.ExecutionResult(ctx, r.Key.ChainID, execresultfix.Hex(t, r.Key.RailRef))
	require.ErrorIs(t, err, archive.ErrNotFound)
}
