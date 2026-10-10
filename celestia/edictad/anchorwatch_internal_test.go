package edictad

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate/registry"
	"github.com/vgonkivs/edicta/test/gatefix"
)

// watchStore serves decision records and evidence for the anchor watch.
type watchStore struct {
	archive.Store
	mu        sync.Mutex
	decisions map[commitment.Hash][]byte
	evidence  map[string]bool
	fail      error
}

func (s *watchStore) Decision(_ context.Context, h commitment.Hash) (*archive.DecisionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return nil, s.fail
	}
	env, ok := s.decisions[h]
	if !ok {
		return nil, archive.ErrNotFound
	}
	return &archive.DecisionRecord{Envelope: env}, nil
}

func (s *watchStore) Evidence(_ context.Context, _ commitment.DA, c []byte) (*archive.EvidenceRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.evidence[string(c)] {
		return &archive.EvidenceRecord{}, nil
	}
	return nil, archive.ErrNotFound
}

// alerts counts anchor_missing lines.
type alerts struct {
	mu sync.Mutex
	n  int
}

func (a *alerts) Enabled(context.Context, slog.Level) bool { return true }
func (a *alerts) Handle(_ context.Context, r slog.Record) error {
	if strings.Contains(r.Message, "anchor_missing") {
		a.mu.Lock()
		a.n++
		a.mu.Unlock()
	}
	return nil
}
func (a *alerts) WithAttrs([]slog.Attr) slog.Handler { return a }
func (a *alerts) WithGroup(string) slog.Handler      { return a }
func (a *alerts) count() int                         { a.mu.Lock(); defer a.mu.Unlock(); return a.n }

type watchFx struct {
	st   *watchStore
	reg  *memLister
	head atomic.Uint64
	al   *alerts
	w    *anchorWatch
}

func newWatchFx(t *testing.T) *watchFx {
	f := &watchFx{st: &watchStore{decisions: map[commitment.Hash][]byte{}, evidence: map[string]bool{}}, reg: &memLister{}, al: &alerts{}}
	f.w = &anchorWatch{lister: f.reg, io: newArchiveIO(f.st), log: slog.New(f.al), timeout: timeoutForTests,
		head: func(context.Context) (uint64, error) { return f.head.Load(), nil }}
	return f
}

const timeoutForTests = 5 * time.Second

// add registers an Authorization of mode for a fresh decision and returns
// its payload commitment.
func (f *watchFx) add(t *testing.T, tag byte, mode, deadline uint64) []byte {
	t.Helper()
	c := gatefix.Fresh(gatefix.Template(t), tag)
	c.PayloadRef.Commitment = bytes.Repeat([]byte{tag}, 32)
	env, h := gatefix.Sign(t, "agent1", c)
	f.st.decisions[h] = env
	a := commitment.Authorization{
		Version: 1, CommitmentHash: h[:], ActionHash: bytes.Repeat([]byte{1}, 32), GateID: "gate1", Expires: 10,
		Path: commitment.PathDA, Mode: mode, AnchorDeadline: deadline,
	}
	raw, err := commitment.EncodeSignedAuthorization(&commitment.SignedAuthorization{Authorization: a, Signature: make([]byte, 64)})
	require.NoError(t, err)
	f.reg.entries = append(f.reg.entries, registry.Entry{Key: registry.Key{Nonce: [16]byte{tag}}, CommitmentHash: h, Authorization: raw})
	return c.PayloadRef.Commitment
}

func TestAnchorWatchAlertsOncePerMissedDeadline(t *testing.T) {
	f := newWatchFx(t)
	f.add(t, 1, commitment.ModeFast, 100)
	landed := f.add(t, 2, commitment.ModeFast, 100)
	f.st.evidence[string(landed)] = true
	f.add(t, 3, commitment.ModeStrict, 0)
	f.add(t, 4, commitment.ModeFast, 500)

	f.head.Store(100 + anchorMissingGrace)
	f.w.pass(context.Background())
	assert.Zero(t, f.al.count(), "within the grace after the deadline")

	f.head.Store(100 + anchorMissingGrace + 1)
	f.w.pass(context.Background())
	assert.Equal(t, 1, f.al.count(), "the entry without evidence, not the landed, strict or open ones")
	f.head.Store(200)
	f.w.pass(context.Background())
	f.w.pass(context.Background())
	assert.Equal(t, 1, f.al.count(), "exactly once")

	f.head.Store(600)
	f.w.pass(context.Background())
	assert.Equal(t, 2, f.al.count(), "the later deadline once it passes")
}

func TestAnchorWatchRetriesWhatItCouldNotRead(t *testing.T) {
	f := newWatchFx(t)
	f.add(t, 1, commitment.ModeFast, 100)
	f.st.fail = errBoomWatch
	f.head.Store(200)
	f.w.pass(context.Background())
	assert.Zero(t, f.al.count(), "an archive error is not a missing anchor")
	f.st.fail = nil
	f.head.Store(300)
	f.w.pass(context.Background())
	assert.Equal(t, 1, f.al.count(), "decided on the next pass")
}

var errBoomWatch = assert.AnError

func TestAnchorWatchMissingDecisionIsRetriedNotAlerted(t *testing.T) {
	f := newWatchFx(t)
	f.add(t, 1, commitment.ModeFast, 100)
	h := f.reg.entries[0].CommitmentHash
	f.st.mu.Lock()
	env := f.st.decisions[h]
	delete(f.st.decisions, h)
	f.st.mu.Unlock()

	f.head.Store(200)
	f.w.pass(context.Background())
	assert.Zero(t, f.al.count(), "no decision record yet is not a missing anchor")

	f.st.mu.Lock()
	f.st.decisions[h] = env
	f.st.mu.Unlock()
	f.head.Store(201)
	f.w.pass(context.Background())
	assert.Equal(t, 1, f.al.count(), "decided once the record is there")
}

func TestAnchorWatchEvidenceThatArrivesInTheGraceIsNotAlerted(t *testing.T) {
	f := newWatchFx(t)
	c := f.add(t, 1, commitment.ModeFast, 100)
	f.head.Store(100 + anchorMissingGrace)
	f.w.pass(context.Background())
	f.st.mu.Lock()
	f.st.evidence[string(c)] = true
	f.st.mu.Unlock()
	f.head.Store(300)
	f.w.pass(context.Background())
	assert.Zero(t, f.al.count())
}

// The alert is at-least-once: a restarted watch alerts an old entry again.
func TestAnchorWatchAlertsAgainAfterARestart(t *testing.T) {
	f := newWatchFx(t)
	f.add(t, 1, commitment.ModeFast, 100)
	f.head.Store(200)
	f.w.pass(context.Background())
	require.Equal(t, 1, f.al.count())
	f.w = &anchorWatch{lister: f.reg, io: f.w.io, log: f.w.log, timeout: timeoutForTests, head: f.w.head}
	f.w.pass(context.Background())
	assert.Equal(t, 2, f.al.count())
}

type failingLister struct{ err error }

func (l failingLister) List(context.Context, *registry.Key, int) ([]registry.Entry, error) {
	return nil, l.err
}

func TestAnchorWatchUnreadableRegistryOrHeadAlertsNothing(t *testing.T) {
	f := newWatchFx(t)
	f.add(t, 1, commitment.ModeFast, 100)
	f.head.Store(200)

	f.w.lister = failingLister{assert.AnError}
	f.w.pass(context.Background())
	assert.Zero(t, f.al.count())
	assert.Zero(t, f.w.lastHead, "an incomplete pass moves no watermark")

	f.w.lister = f.reg
	f.w.head = func(context.Context) (uint64, error) { return 0, assert.AnError }
	f.w.pass(context.Background())
	assert.Zero(t, f.al.count())

	f.w.head = func(context.Context) (uint64, error) { return f.head.Load(), nil }
	f.w.pass(context.Background())
	assert.Equal(t, 1, f.al.count())
}
