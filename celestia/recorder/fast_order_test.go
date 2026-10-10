package recorder_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/recorder"
	"github.com/vgonkivs/edicta/commitment"
)

// crashMode says how a write of one kind fails: before it is stored, or after
// it is durable while the caller still sees an error, as a process killed
// right after the write.
type crashMode int

const (
	crashNone crashMode = iota
	crashBefore
	crashAfter
)

var errCrash = errors.New("process killed")

// stepStore logs every write and every broadcast in one ordered event list
// and injects a crash at a chosen kind.
type stepStore struct {
	*fsarchive.Store
	mu     sync.Mutex
	crash  map[archive.Kind]crashMode
	events []string
	puts   map[archive.Kind]int
}

func newStepStore(s *fsarchive.Store) *stepStore {
	return &stepStore{Store: s, crash: map[archive.Kind]crashMode{}, puts: map[archive.Kind]int{}}
}

func (s *stepStore) note(ev string) {
	s.mu.Lock()
	s.events = append(s.events, ev)
	s.mu.Unlock()
}

func (s *stepStore) log() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.events...)
}

func (s *stepStore) count(k archive.Kind) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.puts[k]
}

func (s *stepStore) Put(ctx context.Context, r archive.Record) (archive.Outcome, error) {
	s.mu.Lock()
	mode := s.crash[r.Kind()]
	s.mu.Unlock()
	if mode == crashBefore {
		return 0, errCrash
	}
	out, err := s.Store.Put(ctx, r)
	if err != nil {
		return out, err
	}
	s.mu.Lock()
	s.puts[r.Kind()]++
	s.events = append(s.events, fmt.Sprintf("put %d", r.Kind()))
	s.mu.Unlock()
	if mode == crashAfter {
		return 0, errCrash
	}
	return out, nil
}

func (f *blobFast) recOn(st archive.Store) *recorder.Recorder {
	f.t.Helper()
	c := archCfg(st)
	c.Now = followHead(f.ch)
	c.FastTimeoutBlocks = 20
	r, err := recorder.NewFast(c, recorder.FastDeps{Signer: f.sig, Node: f.node}, f.rd)
	require.NoError(f.t, err)
	f.t.Cleanup(func() { _ = r.Close(context.Background()) })
	return r
}

func TestFastBlobWritesThePayloadThenTheIntentThenBroadcasts(t *testing.T) {
	f := newBlobFast(t)
	st := newStepStore(f.st)
	f.node.before = func([]byte) { st.note("broadcast") }
	_, err := f.recOn(st).Publish(bg, f.blob)
	require.NoError(t, err)
	assert.Equal(t, []string{"put 1", "put 13", "broadcast"}, st.log())
}

// A crash at every step before the broadcast leaves nothing on the wire, and
// a restart neither writes a second intent nor signs anything anew.
func TestFastBlobCrashAtEveryStepBeforeTheBroadcast(t *testing.T) {
	for _, tc := range []struct {
		name  string
		kind  archive.Kind
		mode  crashMode
		check func(t *testing.T, f *blobFast, st *stepStore, err error)
	}{
		{"before the payload record", archive.KindPayload, crashBefore, func(t *testing.T, f *blobFast, st *stepStore, err error) {
			require.NoError(t, err, "nothing was written: the restart starts afresh")
			assert.Len(t, f.node.sends(), 1)
		}},
		{"after the payload record", archive.KindPayload, crashAfter, func(t *testing.T, f *blobFast, st *stepStore, err error) {
			require.ErrorIs(t, err, recorder.ErrOutcomeUnknown, "a payload without an intent from an earlier process is refused")
			assert.Empty(t, f.node.sends())
			assert.Zero(t, st.count(archive.KindAnchorIntent))
		}},
		{"before the intent", archive.KindAnchorIntent, crashBefore, func(t *testing.T, f *blobFast, st *stepStore, err error) {
			require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
			assert.Empty(t, f.node.sends())
			assert.Zero(t, st.count(archive.KindAnchorIntent))
		}},
		{"after the intent", archive.KindAnchorIntent, crashAfter, func(t *testing.T, f *blobFast, st *stepStore, err error) {
			require.NoError(t, err, "the restart finds the intent")
			sent := f.node.sends()
			require.Len(t, sent, 1)
			assert.Equal(t, f.intent(genesis).Tx, innerTx(sent[0]), "exactly the archived tx")
			assert.Equal(t, 1, st.count(archive.KindAnchorIntent), "no second intent")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newBlobFast(t)
			st := newStepStore(f.st)
			st.crash[tc.kind] = tc.mode
			_, err := f.recOn(st).Publish(bg, f.blob)
			require.Error(t, err)
			assert.Empty(t, f.node.sends(), "nothing is broadcast before the intent is durable")

			st.crash = map[archive.Kind]crashMode{}
			f.ch.AddHeader(blockAt(genesis + 1))
			_, err = f.recOn(st).Publish(bg, f.blob)
			tc.check(t, f, st, err)
			intents := 0
			for h := genesis - 8; h <= genesis+1+64; h++ {
				switch _, err := f.st.Intent(bg, commitment.DACelestiaBlob, f.comm, h); {
				case err == nil:
					intents++
				default:
					require.ErrorIs(t, err, archive.ErrNotFound)
				}
			}
			assert.LessOrEqual(t, intents, 1, "at most one intent per blob")
			assert.Equal(t, len(f.node.sends()), intents, "a broadcast only for an archived intent")
		})
	}
}

func TestFastBlobRestartsNeverWriteASecondIntentNorReSign(t *testing.T) {
	f := newBlobFast(t)
	st := newStepStore(f.st)
	f.node.script(errTransport)
	_, err := f.recOn(st).Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	tx := f.intent(genesis).Tx

	for i := 0; i < 3; i++ {
		f.ch.AddHeader(blockAt(genesis + 1 + uint64(i)))
		f.node.script(errTransport)
		_, err := f.recOn(st).Publish(bg, f.blob)
		require.ErrorIs(t, err, recorder.ErrNodeUnavailable, "restart %d", i)
	}
	pub, err := f.recOn(st).Publish(bg, f.blob)
	require.NoError(t, err)
	assert.Equal(t, genesis, pub.Ref.Height)
	assert.Equal(t, 1, st.count(archive.KindAnchorIntent))
	sent := f.node.sends()
	require.Len(t, sent, 5)
	for _, raw := range sent {
		assert.Equal(t, tx, innerTx(raw))
	}
}

// unparsable is a mismatch the node reports without the expected sequence.
var unparsable = fmt.Errorf("%w: incorrect account sequence", node.ErrSequenceMismatch)

func TestFastBlobMismatchWithoutAnExpectedSequenceIsRetryable(t *testing.T) {
	t.Run("new intent", func(t *testing.T) {
		f := newBlobFast(t)
		f.node.script(unparsable)
		r := f.rec()
		_, err := r.Publish(bg, f.blob)
		require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
		require.NotErrorIs(t, err, recorder.ErrIntentStale)
		pub, err := r.Publish(bg, f.blob)
		require.NoError(t, err)
		assert.True(t, pub.Ref.Pending())
		sent := f.node.sends()
		require.Len(t, sent, 2)
		assert.Equal(t, sent[0], sent[1], "the archived tx again")
	})
	t.Run("archived intent", func(t *testing.T) {
		f := newBlobFast(t)
		f.node.script(errTransport, unparsable)
		r := f.rec()
		_, err := r.Publish(bg, f.blob)
		require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
		_, err = r.Publish(bg, f.blob)
		require.ErrorIs(t, err, recorder.ErrNodeUnavailable)
		require.NotErrorIs(t, err, recorder.ErrIntentStale)
		_, err = r.Publish(bg, f.blob)
		require.NoError(t, err)
		sent := f.node.sends()
		require.Len(t, sent, 3)
		for _, raw := range sent[1:] {
			assert.Equal(t, sent[0], raw)
		}
	})
}

func TestFastBlobSignsAtTheHigherOfTheLocalAndTheChainSequence(t *testing.T) {
	for _, tc := range []struct {
		name  string
		chain uint64
		want  uint64
	}{
		{"chain behind the local count", 3, 4},
		{"chain moved past by another sender", 10, 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newBlobFast(t)
			r := f.rec()
			_, err := r.Publish(bg, f.blob)
			require.NoError(t, err)
			f.node.mu.Lock()
			f.node.acc.Sequence = tc.chain
			f.node.mu.Unlock()
			_, err = r.Publish(bg, []byte("a second payload"))
			require.NoError(t, err)
			sent := f.node.sends()
			require.Len(t, sent, 2)
			assert.Equal(t, tc.want, txSequence(t, innerTx(sent[1])))
		})
	}
}

func TestFastBlobValsetRefusalRetriesAreBounded(t *testing.T) {
	f := newBlobFast(t)
	valset := fmt.Errorf("%w: failed to get historical validator set", node.ErrRejected)
	f.node.script(valset, valset, valset, valset, valset)
	r := f.rec()
	_, err := r.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrAnchorTxRejected)
	sent := f.node.sends()
	require.Len(t, sent, 4, "four attempts, then the refusal stands")
	for _, raw := range sent {
		assert.Equal(t, sent[0], raw)
	}
	_, err = r.Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrAnchorTxRejected, "sticky")
	assert.Len(t, f.node.sends(), 4)
}

func TestFastBlobValsetRetryEndsWithTheCaller(t *testing.T) {
	f := newBlobFast(t)
	valset := fmt.Errorf("%w: failed to get historical validator set", node.ErrRejected)
	f.node.script(valset, valset, valset, valset)
	ctx, cancel := context.WithCancel(bg)
	f.node.before = func([]byte) { cancel() }
	_, err := f.rec().Publish(ctx, f.blob)
	require.Error(t, err)
	require.NotErrorIs(t, err, recorder.ErrAnchorTxRejected, "a canceled wait is not a refusal")
	assert.Len(t, f.node.sends(), 1)
}

// The loop and repeated Publish calls race to confirm the same anchor: the
// evidence is written once.
func TestFastBlobEvidenceIsWrittenExactlyOnce(t *testing.T) {
	f := newBlobFast(t)
	st := newStepStore(f.st)
	f.land()
	r := f.recOn(st)
	pub, err := r.Publish(bg, f.blob)
	require.NoError(t, err)
	require.True(t, pub.Ref.Pending())

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if p, err := r.Publish(bg, f.blob); err == nil && !p.Ref.Pending() {
					return
				}
			}
		}()
	}
	wg.Wait()
	require.Eventually(t, func() bool {
		_, err := f.st.Evidence(bg, commitment.DACelestiaBlob, f.comm)
		return err == nil
	}, 5*time.Second, time.Millisecond)
	require.NoError(t, r.Close(bg))
	assert.Equal(t, 1, st.count(archive.KindEvidence))
	assert.Equal(t, 1, st.count(archive.KindAnchorIntent))
	assert.Len(t, f.node.sends(), 1)
}

func TestFastBlobRestartAfterTheAnchorLandedWritesTheEvidence(t *testing.T) {
	f := newBlobFast(t)
	f.node.script(errTransport)
	_, err := f.rec().Publish(bg, f.blob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)
	rec := f.intent(genesis)

	h := genesis + 1
	f.ch.AddHeader(blockAt(h))
	f.ch.AddBlob(h, node.Blob{Namespace: ns, Data: f.blob, ShareVersion: 1, Signer: f.addr, Commitment: f.comm}, nil)
	f.node.setTx(rec.Tx, node.TxStatus{Found: true, Height: h})
	pub, err := f.rec().Publish(bg, f.blob)
	require.NoError(t, err)
	assert.False(t, pub.Ref.Pending())
	assert.Equal(t, h, pub.Ref.Height)
	assert.Len(t, f.node.sends(), 1, "a landed intent is not sent again")
}

func TestFastBlobLandedWithANonzeroCodeIsSticky(t *testing.T) {
	f := newBlobFast(t)
	f.node.onAccept = func(raw []byte) {
		f.node.setTx(innerTx(raw), node.TxStatus{Found: true, Height: genesis + 1, Code: 11})
	}
	r := f.rec()
	_, err := r.Publish(bg, f.blob)
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		_, err := r.Publish(bg, f.blob)
		return errors.Is(err, recorder.ErrAnchorTxRejected)
	}, 5*time.Second, time.Millisecond)
	_, err = f.st.Evidence(bg, commitment.DACelestiaBlob, f.comm)
	require.ErrorIs(t, err, archive.ErrNotFound)
}
