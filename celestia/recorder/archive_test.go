package recorder_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/recorder"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/dacommit/blobv1"
)

// fakeProof is a commitment proof a test can serialize and check again.
type fakeProof struct {
	Root       []byte
	Commitment []byte
}

func (p fakeProof) Verify(dataRoot, commit []byte) error {
	if !bytes.Equal(p.Root, dataRoot) || !bytes.Equal(p.Commitment, commit) {
		return errors.New("fake proof: does not match")
	}
	return nil
}

func signedHeaderBytes(h uint64) []byte { return []byte{'s', 'h', byte(h)} }

// evReader serves what the Recorder needs for the evidence record on top of a
// node.Reader: the signed header bytes and a commitment proof.
type evReader struct{ node.Reader }

func (r evReader) SignedHeader(ctx context.Context, h uint64) ([]byte, error) {
	if _, err := r.Reader.HeaderAt(ctx, h); err != nil {
		return nil, err
	}
	return signedHeaderBytes(h), nil
}

func (r evReader) CommitmentProof(ctx context.Context, h uint64, _, c []byte) (node.CommitmentProof, error) {
	hd, err := r.Reader.HeaderAt(ctx, h)
	if err != nil {
		return nil, err
	}
	return fakeProof{Root: hd.DataRoot, Commitment: bytes.Clone(c)}, nil
}

func openArchive(t *testing.T, dir string) *fsarchive.Store {
	t.Helper()
	s, err := fsarchive.Open(dir, map[commitment.DA]gate.DACommitter{commitment.DACelestiaBlob: blobv1.New()})
	require.NoError(t, err)
	return s
}

func archCfg(st archive.Store) recorder.Config {
	c := cfg()
	c.Archive = st
	return c
}

func payloadPath(t *testing.T, dir string, comm []byte) string {
	t.Helper()
	rel, err := archive.DataPath(archive.KindPayload, commitment.DACelestiaBlob, comm)
	require.NoError(t, err)
	return filepath.Join(dir, filepath.FromSlash(rel))
}

// failStore fails the Put of the listed kinds and passes everything else on.
type failStore struct {
	archive.Store
	mu    sync.Mutex
	err   error
	kinds map[archive.Kind]bool
	puts  []archive.Kind
}

func (s *failStore) Put(ctx context.Context, r archive.Record) (archive.Outcome, error) {
	s.mu.Lock()
	s.puts = append(s.puts, r.Kind())
	fail := s.kinds[r.Kind()]
	s.mu.Unlock()
	if fail {
		return 0, s.err
	}
	return s.Store.Put(ctx, r)
}

func TestPayloadRecordIsArchivedBeforeSubmit(t *testing.T) {
	ch := newChain()
	st := openArchive(t, t.TempDir())
	sub := newLanding(ch)
	blob := []byte("decision payload")
	comm := realCommitment(t, ns, signer, blob)
	seen := false
	sub.OnSubmit = func() {
		seen = true
		p, err := st.Payload(bg, commitment.DACelestiaBlob, comm)
		require.NoError(t, err, "the archive holds the payload before the submit")
		assert.Equal(t, blob, p.Blob)
		assert.Equal(t, ns, p.Namespace)
		assert.Equal(t, signer, p.Signer)
		assert.EqualValues(t, genesis, p.IntentHeight, "chain head before the submit")
	}
	rec := mk(t, archCfg(st), sub, evReader{ch})
	_, err := rec.Publish(bg, blob)
	require.NoError(t, err)
	assert.True(t, seen)
}

func TestEvidenceIsArchivedAfterReadBack(t *testing.T) {
	ch := newChain()
	st := openArchive(t, t.TempDir())
	sub := newLanding(ch)
	blob := []byte("decision payload")
	comm := realCommitment(t, ns, signer, blob)
	sub.OnSubmit = func() {
		_, err := st.Evidence(bg, commitment.DACelestiaBlob, comm)
		assert.ErrorIs(t, err, archive.ErrNotFound, "no evidence before the anchor is read back")
	}
	rec := mk(t, archCfg(st), sub, evReader{ch})
	p, err := rec.Publish(bg, blob)
	require.NoError(t, err)

	ev, err := st.Evidence(bg, commitment.DACelestiaBlob, comm)
	require.NoError(t, err)
	assert.Equal(t, p.Ref.Height, ev.Height)
	assert.Equal(t, ns, ev.Namespace)
	assert.Equal(t, signedHeaderBytes(p.Ref.Height), ev.Header, "signed header at H")

	var proof fakeProof
	require.NoError(t, json.Unmarshal(ev.BlobProof, &proof))
	require.NoError(t, proof.Verify(blockAt(p.Ref.Height).DataRoot, comm), "the stored proof verifies against the header at H")
}

func TestNoEvidenceWhenTheAnchorIsNotVisible(t *testing.T) {
	ch := newChain()
	st := openArchive(t, t.TempDir())
	sub := newLanding(ch)
	blob := []byte("x")
	comm := realCommitment(t, ns, signer, blob)
	rec := mk(t, archCfg(st), sub, evReader{&lagReader{Reader: ch, hdrMiss: 1 << 30}})
	_, err := rec.Publish(bg, blob)
	require.ErrorIs(t, err, recorder.ErrNotVisible)

	_, err = st.Payload(bg, commitment.DACelestiaBlob, comm)
	require.NoError(t, err, "the payload stays: the blob may still land")
	_, err = st.Evidence(bg, commitment.DACelestiaBlob, comm)
	require.ErrorIs(t, err, archive.ErrNotFound)
}

func TestArchiveFailureBeforeSubmitSubmitsNothing(t *testing.T) {
	cases := map[string]error{
		"store down":     errBoom,
		"store conflict": archive.ErrConflict,
		"store corrupt":  archive.ErrCorrupt,
	}
	for name, cause := range cases {
		t.Run(name, func(t *testing.T) {
			ch := newChain()
			sub := newLanding(ch)
			fs := &failStore{Store: openArchive(t, t.TempDir()), err: cause, kinds: map[archive.Kind]bool{archive.KindPayload: true}}
			rec := mk(t, archCfg(fs), sub, evReader{ch})
			_, err := rec.Publish(bg, []byte("x"))
			require.ErrorIs(t, err, recorder.ErrArchiveUnavailable)
			require.ErrorIs(t, err, cause, "the cause stays visible")
			assert.NotErrorIs(t, err, gate.ErrPayloadUnavailable)
			assert.Zero(t, sub.Calls, "nothing is submitted")
			assert.Zero(t, ch.Submitted)
		})
	}
}

func TestUnwritableArchiveDirectorySubmitsNothing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permissions do not bind root")
	}
	dir := t.TempDir()
	st := openArchive(t, dir)
	require.NoError(t, os.Chmod(dir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	ch := newChain()
	sub := newLanding(ch)
	rec := mk(t, archCfg(st), sub, evReader{ch})
	_, err := rec.Publish(bg, []byte("x"))
	require.ErrorIs(t, err, recorder.ErrArchiveUnavailable)
	assert.Zero(t, sub.Calls)
}

func TestEvidenceWriteFailureResumesWithoutPayingAgain(t *testing.T) {
	ch := newChain()
	sub := newLanding(ch)
	fs := &failStore{Store: openArchive(t, t.TempDir()), err: errBoom, kinds: map[archive.Kind]bool{archive.KindEvidence: true}}
	rec := mk(t, archCfg(fs), sub, evReader{ch})
	blob := []byte("x")

	_, err := rec.Publish(bg, blob)
	require.ErrorIs(t, err, recorder.ErrArchiveUnavailable)
	require.Equal(t, 1, sub.Calls)

	fs.mu.Lock()
	fs.kinds = nil
	fs.mu.Unlock()
	p, err := rec.Publish(bg, blob)
	require.NoError(t, err)
	assert.Equal(t, 1, sub.Calls, "the retry never submits again")
	assert.Equal(t, genesis+1, p.Ref.Height)
	_, err = fs.Store.Evidence(bg, commitment.DACelestiaBlob, realCommitment(t, ns, signer, blob))
	require.NoError(t, err)
}

func TestEvidenceConflictIsAnArchiveFault(t *testing.T) {
	ch := newChain()
	sub := newLanding(ch)
	fs := &failStore{Store: openArchive(t, t.TempDir()), err: archive.ErrConflict, kinds: map[archive.Kind]bool{archive.KindEvidence: true}}
	rec := mk(t, archCfg(fs), sub, evReader{ch})
	_, err := rec.Publish(bg, []byte("x"))
	require.ErrorIs(t, err, recorder.ErrArchiveUnavailable)
	require.ErrorIs(t, err, archive.ErrConflict)
}

func TestRestartBeforeSubmitKeepsOneRecordAndSubmitsOnce(t *testing.T) {
	dir := t.TempDir()
	ch := newChain()
	blob := []byte("decision payload")
	comm := realCommitment(t, ns, signer, blob)

	// The first process dies after the payload write: the submit never lands.
	first := newLanding(ch)
	first.NoLand, first.Err = true, context.Canceled
	_, err := mk(t, archCfg(openArchive(t, dir)), first, evReader{ch}).Publish(bg, blob)
	require.Error(t, err)
	before, err := os.ReadFile(payloadPath(t, dir, comm))
	require.NoError(t, err)

	// A new process over the same archive.
	for h := genesis + 1; h <= genesis+3; h++ {
		ch.AddHeader(blockAt(h))
	}
	second := newLanding(ch)
	st := openArchive(t, dir)
	p, err := mk(t, archCfg(st), second, evReader{ch}).Publish(bg, blob)
	require.NoError(t, err)
	assert.Equal(t, 1, second.Calls)

	after, err := os.ReadFile(payloadPath(t, dir, comm))
	require.NoError(t, err)
	assert.Equal(t, before, after, "the payload record is not rewritten, intent height included")
	pr, err := st.Payload(bg, commitment.DACelestiaBlob, comm)
	require.NoError(t, err)
	assert.EqualValues(t, genesis, pr.IntentHeight)
	ev, err := st.Evidence(bg, commitment.DACelestiaBlob, comm)
	require.NoError(t, err)
	assert.Equal(t, p.Ref.Height, ev.Height)
}

func TestRestartAfterSubmitFindsTheEarlierBlobAndDoesNotPayAgain(t *testing.T) {
	dir := t.TempDir()
	ch := newChain()
	blob := []byte("decision payload")
	comm := realCommitment(t, ns, signer, blob)

	// The first process lost the answer after the blob landed.
	first := newLanding(ch)
	first.Err, first.ErrAfterLand = context.DeadlineExceeded, true
	_, err := mk(t, archCfg(openArchive(t, dir)), first, evReader{ch}).Publish(bg, blob)
	require.ErrorIs(t, err, recorder.ErrOutcomeUnknown)

	second := newLanding(ch)
	st := openArchive(t, dir)
	p, err := mk(t, archCfg(st), second, evReader{ch}).Publish(bg, blob)
	require.NoError(t, err)
	assert.Zero(t, second.Calls, "found by the scan from the intent height, never submitted twice")
	assert.Equal(t, genesis+1, p.Ref.Height)
	ev, err := st.Evidence(bg, commitment.DACelestiaBlob, comm)
	require.NoError(t, err)
	assert.Equal(t, p.Ref.Height, ev.Height)
}

func TestCorruptPayloadRecordIsOperational(t *testing.T) {
	dir := t.TempDir()
	st := openArchive(t, dir)
	ch := newChain()
	blob := []byte("decision payload")
	comm := realCommitment(t, ns, signer, blob)

	// Archive the payload once, then damage the stored record.
	_, err := mk(t, archCfg(st), newLanding(ch), evReader{ch}).Publish(bg, blob)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(payloadPath(t, dir, comm), []byte("not a record"), 0o644))

	ch2 := newChain()
	sub := newLanding(ch2)
	_, err = mk(t, archCfg(st), sub, evReader{ch2}).Publish(bg, blob)
	require.ErrorIs(t, err, recorder.ErrArchiveUnavailable)
	require.ErrorIs(t, err, archive.ErrCorrupt)
	assert.NotErrorIs(t, err, gate.ErrPayloadUnavailable)
	assert.NotErrorIs(t, err, archive.ErrConflict)
	assert.Zero(t, sub.Calls, "nothing is submitted over a damaged archive")
}

func TestConcurrentPublishesOfOneBlobArchiveAndSubmitOnce(t *testing.T) {
	ch := newChain()
	st := openArchive(t, t.TempDir())
	sub := newLanding(ch)
	rec := mk(t, archCfg(st), sub, evReader{ch})
	blob := []byte("one blob")

	var wg sync.WaitGroup
	refs := make([]uint64, 4)
	errs := make([]error, 4)
	for i := range refs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, err := rec.Publish(bg, blob)
			errs[i], refs[i] = err, p.Ref.Height
		}()
	}
	wg.Wait()
	sub.mu.Lock()
	calls := sub.Calls
	sub.mu.Unlock()
	assert.Equal(t, 1, calls)
	ok := 0
	for i := range errs {
		if errs[i] == nil {
			ok++
			assert.Equal(t, genesis+1, refs[i])
		}
	}
	assert.GreaterOrEqual(t, ok, 1)
	_, err := st.Evidence(bg, commitment.DACelestiaBlob, realCommitment(t, ns, signer, blob))
	require.NoError(t, err)
}
