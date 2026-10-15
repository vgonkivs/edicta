package edictad

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/celestia/execcapture"
	"github.com/vgonkivs/edicta/test/execresultfix"
)

// Every sweep pass first moves the capture store into the archive.
func TestCaptureSweepMovesCapturesIntoTheArchive(t *testing.T) {
	f := execresultfix.Load(t)
	m := f.Migration[0]
	require.Equal(t, "written", m.Expect[0].Result)

	st, err := execcapture.OpenDir(t.TempDir())
	require.NoError(t, err)
	var b execcapture.Block
	require.NoError(t, json.Unmarshal(m.Capture, &b))
	require.NoError(t, st.PutBlock(context.Background(), b))
	arch, err := fsarchive.Open(t.TempDir(), nil)
	require.NoError(t, err)
	c, err := execcapture.New(execcapture.Config{ChainID: b.ChainID, PruneWindowBlocks: 1000}, idleChain{}, st,
		slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), execcapture.WithArchive(arch))
	require.NoError(t, err)

	sw := &captureSweep{lister: listOnce{}, cap: c, log: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), timeout: time.Second}
	sw.pass(t.Context())

	for _, want := range m.Expect {
		rec, err := arch.ExecutionResult(context.Background(), b.ChainID, execresultfix.Hex(t, want.RailRef))
		require.NoError(t, err)
		got, err := archive.Encode(rec)
		require.NoError(t, err)
		assert.Equal(t, execresultfix.Hex(t, want.CBORHex), got)
	}
	blocks, err := st.Blocks(context.Background())
	require.NoError(t, err)
	assert.Empty(t, blocks)
}

type capturesN struct{ overdue, conflicts uint64 }

func (c capturesN) Overdue() uint64   { return c.overdue }
func (c capturesN) Conflicts() uint64 { return c.conflicts }

func TestHealthDegradedWhileACaptureIsKeptOutOfTheArchive(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	h := &health{clock: fixedClock{now}, log: slog.Default(), lastOK: true, lastAt: now}
	h.captures = capturesN{conflicts: 1}
	info, err := h.Health(t.Context())
	require.NoError(t, err)
	assert.EqualValues(t, 2, info.Status)

	h.captures = capturesN{}
	info, err = h.Health(t.Context())
	require.NoError(t, err)
	assert.EqualValues(t, 1, info.Status)
}
