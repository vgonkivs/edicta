package fsarchive_test

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/test/archivefix"
)

// syncLog records the path of every fsync the store reports through the hook.
type syncLog struct {
	mu    sync.Mutex
	paths []string
}

func (l *syncLog) hook(path string) {
	l.mu.Lock()
	l.paths = append(l.paths, path)
	l.mu.Unlock()
}

func (l *syncLog) count(path string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, p := range l.paths {
		if p == path {
			n++
		}
	}
	return n
}

func TestPutOnAnExistingKeyFsyncsTheRecord(t *testing.T) {
	fx := archivefix.Load(t)
	var l syncLog
	s, dir := open(t, fx, fsarchive.WithSyncHook(l.hook))
	c := fx.Cases["payload_da2_minimal_lmt"]
	final := filepath.Join(dir, filepath.FromSlash(c.Key))

	out, err := s.Put(bg, c.Record)
	require.NoError(t, err)
	require.Equal(t, archive.Written, out)
	afterWrite := l.count(final)

	// The earlier writer may have died between the link and its fsync, so the
	// identical write must sync the file again before it reports success.
	out, err = s.Put(bg, c.Record)
	require.NoError(t, err)
	assert.Equal(t, archive.Unchanged, out)
	assert.Greater(t, l.count(final), afterWrite, "an identical Put syncs the existing record")
}

// A damaged record is reported, never replaced by a Put of the same key.
func TestPutOverACorruptRecordIsAnErrorAndKeepsTheBytes(t *testing.T) {
	fx := archivefix.Load(t)
	s, dir := open(t, fx)
	c := fx.Cases["payload_da2_minimal_lmt"]
	plant(t, dir, c.Key, []byte("garbage"))

	_, err := s.Put(bg, c.Record)
	require.ErrorIs(t, err, archive.ErrCorrupt)
	got, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(c.Key)))
	require.NoError(t, err)
	assert.Equal(t, []byte("garbage"), got)
}

func TestStreamGateSourceRequiresAPayloadStreamer(t *testing.T) {
	fx := archivefix.Load(t)
	s, _ := open(t, fx)

	src, err := archive.NewStreamGateSource(s)
	require.NoError(t, err)
	assert.NotNil(t, src)

	_, err = archive.NewStreamGateSource(plainStore{Store: s})
	require.ErrorIs(t, err, archive.ErrNoStreamer)
	_, err = archive.NewStreamGateSource(nil)
	require.ErrorIs(t, err, archive.ErrNoStreamer)
}

// plainStore hides PayloadReader.
type plainStore struct{ archive.Store }

// A record that is present but damaged is an archive fault, which the gate
// answers with a retryable error. It must never read as a missing blob (the
// ErrPayloadUnavailable verdict and its rejection marker).
func TestStreamGateSourceCorruptRecordIsOperational(t *testing.T) {
	fx := archivefix.Load(t)
	c := fx.Cases["payload_da2_minimal_lmt"]
	p := c.Record.(*archive.PayloadRecord)
	damage := map[string]func(good []byte) []byte{
		"not a record":     func([]byte) []byte { return []byte("garbage") },
		"truncated":        func(g []byte) []byte { return g[:len(g)-3] },
		"another key":      func([]byte) []byte { return fx.Cases["payload_da2_256k"].CBOR },
		"empty":            func([]byte) []byte { return []byte{} },
		"trailing garbage": func(g []byte) []byte { return append(append([]byte(nil), g...), 0xff) },
	}
	for name, f := range damage {
		t.Run(name, func(t *testing.T) {
			s, dir := open(t, fx)
			plant(t, dir, c.Key, f(c.CBOR))
			src, err := archive.NewStreamGateSource(s)
			require.NoError(t, err)

			_, err = src.Fetch(bg, refOf(p), 1<<20)
			require.Error(t, err)
			assert.ErrorIs(t, err, gate.ErrArchiveUnavailable)
			assert.ErrorIs(t, err, archive.ErrCorrupt, "the cause stays visible")
			assert.NotErrorIs(t, err, gate.ErrBlobNotFound)
			assert.NotErrorIs(t, err, gate.ErrPayloadUnavailable)
		})
	}
}

func TestStreamGateSourceMissingRecordIsBlobNotFound(t *testing.T) {
	fx := archivefix.Load(t)
	s, _ := open(t, fx)
	src, err := archive.NewStreamGateSource(s)
	require.NoError(t, err)
	p := fx.Cases["payload_da2_minimal_lmt"].Record.(*archive.PayloadRecord)
	_, err = src.Fetch(bg, refOf(p), 1<<20)
	require.ErrorIs(t, err, gate.ErrBlobNotFound)
	assert.NotErrorIs(t, err, gate.ErrArchiveUnavailable)
}
