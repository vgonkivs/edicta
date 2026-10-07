package edictad

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/registry"
)

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

// memStore is an archive whose Put and Authorization are scripted.
type memStore struct {
	archive.Store
	mu      sync.Mutex
	puts    []archive.Record
	putErr  error
	authErr error
	block   chan struct{}
}

func (m *memStore) Put(_ context.Context, r archive.Record) (archive.Outcome, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.puts = append(m.puts, r)
	if m.putErr != nil {
		return 0, m.putErr
	}
	return archive.Written, nil
}

func (m *memStore) Authorization(ctx context.Context, _ commitment.Hash) (*archive.AuthorizationRecord, error) {
	if m.block != nil {
		select {
		case <-m.block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if m.authErr != nil {
		return nil, m.authErr
	}
	return nil, archive.ErrNotFound
}

func (m *memStore) putCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.puts)
}

func (m *memStore) putAuthFor(h commitment.Hash) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.puts {
		if a, ok := r.(*archive.AuthorizationRecord); ok && string(a.SignedAuthorization) == string(h[:]) {
			return true
		}
	}
	return false
}

type memLister struct {
	entries []registry.Entry
	calls   atomic.Int32
}

func (l *memLister) List(_ context.Context, after *registry.Key, _ int) ([]registry.Entry, error) {
	l.calls.Add(1)
	if after != nil {
		return nil, nil
	}
	return l.entries, nil
}

func entryOf(b byte) registry.Entry {
	var h commitment.Hash
	h[0] = b
	return registry.Entry{CommitmentHash: h, Authorization: h[:], AuthorizedAt: 1}
}

func marker(b byte) archive.Record {
	var h commitment.Hash
	h[0] = b
	return &archive.RejectionRecord{CommitmentHash: h, Error: "ErrExpired", GateID: "g", RejectedAt: 1}
}

func newSweeper(st archive.Store, l registry.Lister) *sweeper {
	return &sweeper{lister: l, io: newArchiveIO(st), q: &retryQueue{}, log: discard, timeout: time.Second}
}

func TestFullQueueMakesTheNextTickScanTheRegistry(t *testing.T) {
	st := &memStore{}
	e := entryOf(7)
	l := &memLister{entries: []registry.Entry{e}}
	sw := newSweeper(st, l)

	for i := range maxRetryQueue {
		require.True(t, sw.q.add(marker(byte(i))))
	}
	require.False(t, sw.q.add(marker(9)), "the record over the bound is dropped")

	tick := make(chan time.Time)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); sw.loop(ctx, tick, time.Hour, false) }()
	tick <- time.Time{}
	tick <- time.Time{}
	cancel()
	<-done

	assert.Positive(t, l.calls.Load(), "the registry was scanned")
	assert.True(t, st.putAuthFor(e.CommitmentHash), "what the queue lost is repaired from the registry")
	assert.False(t, sw.q.takeDropped(), "the flag is cleared by the scan")
}

func TestQueueWithoutADropDoesNotScanTheRegistry(t *testing.T) {
	st := &memStore{}
	l := &memLister{entries: []registry.Entry{entryOf(7)}}
	sw := newSweeper(st, l)
	require.True(t, sw.q.add(marker(1)))

	tick := make(chan time.Time)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); sw.loop(ctx, tick, time.Hour, false) }()
	tick <- time.Time{}
	tick <- time.Time{}
	cancel()
	<-done

	assert.Zero(t, l.calls.Load())
	assert.Equal(t, 1, st.putCount())
}

func TestPermanentErrorsAreNotRequeued(t *testing.T) {
	cases := []struct {
		name string
		err  error
		perm bool
	}{
		{"corrupt record", fmt.Errorf("put: %w", archive.ErrCorrupt), true},
		{"encode error", fmt.Errorf("encode: %w", commitment.ErrFieldSize), true},
		{"malformed", fmt.Errorf("encode: %w", commitment.ErrMalformed), true},
		{"archive down", errors.New("archive down"), false},
		{"timeout", context.DeadlineExceeded, false},
	}
	for _, tc := range cases {
		t.Run("writer "+tc.name, func(t *testing.T) {
			st := &memStore{putErr: tc.err}
			sw := newSweeper(st, &memLister{})
			w := &writer{io: sw.io, q: sw.q, log: discard, timeout: time.Second}
			w.write(context.Background(), marker(1))
			if tc.perm {
				assert.Zero(t, sw.q.len())
			} else {
				assert.Equal(t, 1, sw.q.len())
			}
		})
		t.Run("sweeper "+tc.name, func(t *testing.T) {
			st := &memStore{putErr: tc.err}
			sw := newSweeper(st, &memLister{})
			require.True(t, sw.q.add(marker(1)))
			res := sw.run(context.Background(), false)
			if tc.perm {
				assert.Zero(t, sw.q.len())
				assert.Equal(t, 1, res.stats.permanent)
				assert.Zero(t, res.stats.failed)
			} else {
				assert.Equal(t, 1, sw.q.len())
				assert.Equal(t, 1, res.stats.failed)
			}
		})
	}
}

func TestPermanentErrorIsLoggedOnceWithTheCommitmentHash(t *testing.T) {
	var buf lockedBuf
	log := slog.New(slog.NewTextHandler(&buf, nil))
	sw := newSweeper(&memStore{putErr: archive.ErrCorrupt}, &memLister{})
	sw.log = log
	w := &writer{io: sw.io, q: sw.q, log: log, timeout: time.Second}
	r := marker(1).(*archive.RejectionRecord)
	w.write(context.Background(), r)
	assert.Contains(t, buf.String(), fmt.Sprintf("commitment_hash=%x", r.CommitmentHash[:]))
	assert.Equal(t, 1, countLines(buf.String()))
}

type lockedBuf struct {
	mu sync.Mutex
	b  []byte
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.b = append(l.b, p...)
	return len(p), nil
}

func (l *lockedBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return string(l.b) }

func countLines(s string) int {
	n := 0
	for _, c := range s {
		if c == '\n' {
			n++
		}
	}
	return n
}

func TestHungArchiveEndsTheBoundedSweepAndTheLoopContinuesAtOnce(t *testing.T) {
	st := &memStore{block: make(chan struct{})}
	l := &memLister{entries: []registry.Entry{entryOf(1), entryOf(2)}}
	sw := newSweeper(st, l)
	sw.timeout = time.Hour

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	res := sw.run(ctx, true)
	assert.Less(t, time.Since(start), 5*time.Second, "the pass ends at its budget, not at the archive")
	assert.True(t, res.incomplete || res.scanFailed, "the pass reports that work is left")

	// The loop takes the unfinished pass on at once, without waiting for a tick.
	st2 := &memStore{}
	l2 := &memLister{entries: []registry.Entry{entryOf(3)}}
	sw2 := newSweeper(st2, l2)
	lctx, lcancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); sw2.loop(lctx, make(chan time.Time), time.Hour, true) }()
	require.Eventually(t, func() bool { return st2.putAuthFor(entryOf(3).CommitmentHash) }, 10*time.Second, time.Millisecond)
	lcancel()
	<-done
}

type okDownloader struct{ calls atomic.Int32 }

func (d *okDownloader) Download(context.Context, [33]byte, uint64, uint64) ([]byte, error) {
	d.calls.Add(1)
	return []byte("x"), nil
}

func TestBridgeFallbackIsOffUntilTheProbePasses(t *testing.T) {
	var n atomic.Int32
	fb := &okDownloader{}
	f := &FibreDeps{
		Fallback: fb,
		BridgeCompat: func(context.Context) error {
			if n.Add(1) < 3 {
				return errors.New("not yet")
			}
			return nil
		},
	}
	cfg := Config{}
	cfg.Fibre.BridgeFallback = true
	d, probe := bridgeFallback(cfg, f, discard)
	require.NotNil(t, d)
	require.NotNil(t, probe)

	_, err := d.Download(context.Background(), [33]byte{}, 1, 1)
	require.ErrorIs(t, err, node.ErrNotFound, "off before the probe ran")
	assert.Zero(t, fb.calls.Load())

	probe(context.Background())
	assert.EqualValues(t, 3, n.Load(), "the probe repeats until it passes")
	_, err = d.Download(context.Background(), [33]byte{}, 1, 1)
	require.NoError(t, err)
	assert.EqualValues(t, 1, fb.calls.Load())
}

func TestBridgeFallbackProbeStopsWithItsContext(t *testing.T) {
	f := &FibreDeps{Fallback: &okDownloader{}, BridgeCompat: func(context.Context) error { return errors.New("no") }}
	cfg := Config{}
	cfg.Fibre.BridgeFallback = true
	cfg.Fibre.CanaryEveryS = 3600
	d, probe := bridgeFallback(cfg, f, discard)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); probe(ctx) }()
	cancel()
	<-done
	_, err := d.Download(context.Background(), [33]byte{}, 1, 1)
	require.ErrorIs(t, err, node.ErrNotFound)
}

func TestBridgeFallbackNeedsAProbe(t *testing.T) {
	cfg := Config{}
	d, p := bridgeFallback(cfg, &FibreDeps{Fallback: &okDownloader{}}, discard)
	assert.Nil(t, d)
	assert.Nil(t, p)
	cfg.Fibre.BridgeFallback = true
	d, p = bridgeFallback(cfg, &FibreDeps{Fallback: &okDownloader{}}, discard)
	assert.Nil(t, d)
	assert.Nil(t, p)
}

func TestMarkerNamesAreVerdictsOfTheArchive(t *testing.T) {
	seen := map[string]bool{}
	for _, v := range verdicts {
		assert.Truef(t, archive.IsVerdict(v.name), "%s is a marker the archive refuses", v.name)
		assert.Falsef(t, seen[v.name], "%s is listed twice", v.name)
		seen[v.name] = true
		got, ok := markerName(fmt.Errorf("wrapped: %w", v.err))
		assert.Truef(t, ok, "%s", v.name)
		if v.name != "ErrAnchorTooOld" {
			assert.Equal(t, v.name, got)
		}
		_, err := archive.RejectionPath(commitment.Hash{}, v.name)
		assert.NoError(t, err)
	}
	got, _ := markerName(gate.ErrAnchorTooOld)
	assert.Equal(t, "ErrAnchorTooOld", got, "the more specific verdict wins over the one it wraps")
	for _, op := range operational {
		_, ok := markerName(op)
		assert.Falsef(t, ok, "%v leaves no marker", op)
	}
	assert.False(t, archive.IsVerdict("ErrSomethingElse"))
}
