package fsarchive_test

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/dacommit/blobv1"
	"github.com/vgonkivs/edicta/test/archivefix"
)

var _ archive.Store = (*fsarchive.Store)(nil)

var bg = context.Background()

func committers(fx *archivefix.Fixture) map[commitment.DA]gate.DACommitter {
	return map[commitment.DA]gate.DACommitter{
		commitment.DAFibre:        fx.FibreCommitter(),
		commitment.DACelestiaBlob: blobv1.New(),
	}
}

func open(t *testing.T, fx *archivefix.Fixture, opts ...fsarchive.Option) (*fsarchive.Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := fsarchive.Open(dir, committers(fx), opts...)
	require.NoError(t, err)
	return s, dir
}

func hashOf(t *testing.T, s string) commitment.Hash {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	var h commitment.Hash
	copy(h[:], b)
	return h
}

func stateName(s archive.DecisionState) string { return s.State.String() }

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func TestStateScenarios(t *testing.T) {
	fx := archivefix.Load(t)
	require.NotEmpty(t, fx.Scenarios)
	for _, sc := range fx.Scenarios {
		t.Run(sc.ID, func(t *testing.T) {
			s, dir := open(t, fx)
			for i, st := range sc.Steps {
				c, ok := fx.Cases[st.Put]
				require.True(t, ok, st.Put)
				out, err := s.Put(bg, c.Record)
				if want := archivefix.ExpectedErr(t, st.Expect); want != nil {
					require.ErrorIs(t, err, want, "step %d %s", i, st.Put)
				} else {
					require.NoError(t, err, "step %d %s", i, st.Put)
					if st.Expect == "written" {
						assert.Equal(t, archive.Written, out, "step %d %s", i, st.Put)
					} else {
						assert.Equal(t, archive.Unchanged, out, "step %d %s", i, st.Put)
					}
				}
				if st.After != nil {
					got, err := s.State(bg, hashOf(t, st.After.Hash))
					require.NoError(t, err)
					assert.Equal(t, st.After.State, stateName(got), "step %d state", i)
					assert.Equal(t, nonNil(st.After.Rejections), nonNil(got.Rejections), "step %d rejections", i)
				}
			}
			var want []string
			for _, id := range sc.Final {
				c := fx.Cases[id]
				want = append(want, c.Key)
				got, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(c.Key)))
				require.NoError(t, err, id)
				if c.CBOR != nil {
					assert.Equal(t, c.CBOR, got, id)
				}
			}
			sort.Strings(want)
			assert.Equal(t, nonNil(want), nonNil(archivefix.Files(t, dir)))
		})
	}
}

func TestStoredRecordsReadBack(t *testing.T) {
	fx := archivefix.Load(t)
	s, _ := open(t, fx)
	for _, id := range []string{
		"payload_da2_minimal_lmt", "evidence_da2_minimal_lmt",
		"payload_da1_live", "evidence_da1_live",
		"decision_minimal_lmt", "rejection_minimal_lmt_not_yet_valid",
		"authorization_minimal_lmt_da",
	} {
		_, err := s.Put(bg, fx.Cases[id].Record)
		require.NoError(t, err, id)
	}
	p := fx.Cases["payload_da2_minimal_lmt"].Record.(*archive.PayloadRecord)
	got, err := s.Payload(bg, p.DA, p.Commitment)
	require.NoError(t, err)
	assert.Equal(t, p, got)

	e := fx.Cases["evidence_da1_live"].Record.(*archive.EvidenceRecord)
	gotE, err := s.Evidence(bg, e.DA, e.Commitment)
	require.NoError(t, err)
	assert.Equal(t, e, gotE)

	d := fx.Cases["decision_minimal_lmt"].Record.(*archive.DecisionRecord)
	h := hashOf(t, "e2ea62234c504e4df72e172c8e0da5f02a1eeb784ccd39ac9e20f6dd4c7c8f1d")
	gotD, err := s.Decision(bg, h)
	require.NoError(t, err)
	assert.Equal(t, d, gotD)

	a := fx.Cases["authorization_minimal_lmt_da"].Record.(*archive.AuthorizationRecord)
	gotA, err := s.Authorization(bg, h)
	require.NoError(t, err)
	assert.Equal(t, a, gotA)

	r := fx.Cases["rejection_minimal_lmt_not_yet_valid"].Record.(*archive.RejectionRecord)
	gotR, err := s.Rejection(bg, h, r.Error)
	require.NoError(t, err)
	assert.Equal(t, r, gotR)
}

func TestReadAbsent(t *testing.T) {
	fx := archivefix.Load(t)
	s, _ := open(t, fx)
	p := fx.Cases["payload_da2_minimal_lmt"].Record.(*archive.PayloadRecord)
	var h commitment.Hash
	_, err := s.Payload(bg, p.DA, p.Commitment)
	require.ErrorIs(t, err, archive.ErrNotFound)
	_, err = s.Evidence(bg, p.DA, p.Commitment)
	require.ErrorIs(t, err, archive.ErrNotFound)
	_, err = s.Decision(bg, h)
	require.ErrorIs(t, err, archive.ErrNotFound)
	_, err = s.Authorization(bg, h)
	require.ErrorIs(t, err, archive.ErrNotFound)
	_, err = s.Rejection(bg, h, "ErrExpired")
	require.ErrorIs(t, err, archive.ErrNotFound)
	st, err := s.State(bg, h)
	require.NoError(t, err)
	assert.Equal(t, "absent", stateName(st))
}

func TestWriteOnceKeepsFirstIntent(t *testing.T) {
	fx := archivefix.Load(t)
	s, dir := open(t, fx)
	first, later := fx.Cases["payload_da2_minimal_lmt"], fx.Cases["payload_da2_minimal_lmt_later_intent"]
	_, err := s.Put(bg, first.Record)
	require.NoError(t, err)
	out, err := s.Put(bg, later.Record)
	require.NoError(t, err)
	assert.Equal(t, archive.Unchanged, out)
	got, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(first.Key)))
	require.NoError(t, err)
	assert.Equal(t, first.CBOR, got)
}

func TestDACheckRefusalWritesNothing(t *testing.T) {
	fx := archivefix.Load(t)
	s, dir := open(t, fx)

	bad2 := fx.Cases["payload_da2_wrong_commitment"].Record
	_, err := s.Put(bg, bad2)
	require.ErrorIs(t, err, gate.ErrDACommitmentMismatch)

	bad1 := *fx.Cases["payload_da1_live"].Record.(*archive.PayloadRecord)
	bad1.Blob = []byte{0x66}
	_, err = s.Put(bg, &bad1)
	require.ErrorIs(t, err, gate.ErrDACommitmentMismatch)

	assert.Empty(t, archivefix.Files(t, dir))
	p := bad2.(*archive.PayloadRecord)
	_, err = s.Payload(bg, p.DA, p.Commitment)
	require.ErrorIs(t, err, archive.ErrNotFound)
}

func TestDACheckUsesNamespaceAndSigner(t *testing.T) {
	fx := archivefix.Load(t)
	s, dir := open(t, fx)
	base := fx.Cases["payload_da2_minimal_lmt"].Record.(*archive.PayloadRecord)

	ns := *base
	ns.Namespace = append([]byte(nil), base.Namespace...)
	ns.Namespace[len(ns.Namespace)-1] ^= 1
	_, err := s.Put(bg, &ns)
	require.ErrorIs(t, err, gate.ErrDACommitmentMismatch)

	sg := *base
	sg.Signer = append([]byte(nil), base.Signer...)
	sg.Signer[0] ^= 1
	_, err = s.Put(bg, &sg)
	require.ErrorIs(t, err, gate.ErrDACommitmentMismatch)

	assert.Empty(t, archivefix.Files(t, dir))
}

func TestPayloadForUnconfiguredDAUnsupported(t *testing.T) {
	fx := archivefix.Load(t)
	dir := t.TempDir()
	s, err := fsarchive.Open(dir, map[commitment.DA]gate.DACommitter{commitment.DACelestiaBlob: blobv1.New()})
	require.NoError(t, err)
	_, err = s.Put(bg, fx.Cases["payload_da1_live"].Record)
	require.ErrorIs(t, err, gate.ErrArchiveRecomputeUnsupported)
	assert.Empty(t, archivefix.Files(t, dir))
}

func TestOrderingWritesNothing(t *testing.T) {
	fx := archivefix.Load(t)
	s, dir := open(t, fx)
	for _, id := range []string{
		"evidence_da2_minimal_lmt", "evidence_da1_live",
		"authorization_minimal_lmt_da", "rejection_minimal_lmt_not_yet_valid",
	} {
		_, err := s.Put(bg, fx.Cases[id].Record)
		require.ErrorIs(t, err, archive.ErrNotFound, id)
	}
	assert.Empty(t, archivefix.Files(t, dir))
}

func TestMarkerAfterAuthorizedIsSkippedNotRefused(t *testing.T) {
	fx := archivefix.Load(t)
	s, dir := open(t, fx)
	for _, id := range []string{"decision_minimal_lmt", "authorization_minimal_lmt_da"} {
		_, err := s.Put(bg, fx.Cases[id].Record)
		require.NoError(t, err)
	}
	before := archivefix.Files(t, dir)
	out, err := s.Put(bg, fx.Cases["rejection_minimal_lmt_payload_unavailable"].Record)
	require.NoError(t, err)
	assert.Equal(t, archive.Unchanged, out)
	assert.Equal(t, before, archivefix.Files(t, dir))
}

func TestAuthorizedIsFinal(t *testing.T) {
	fx := archivefix.Load(t)
	s, _ := open(t, fx)
	h := hashOf(t, "e2ea62234c504e4df72e172c8e0da5f02a1eeb784ccd39ac9e20f6dd4c7c8f1d")
	for _, id := range []string{
		"decision_minimal_lmt", "rejection_minimal_lmt_not_yet_valid", "authorization_minimal_lmt_da",
		"rejection_minimal_lmt_payload_unavailable", "decision_minimal_lmt", "authorization_minimal_lmt_da_repaired",
	} {
		_, err := s.Put(bg, fx.Cases[id].Record)
		require.NoError(t, err, id)
	}
	st, err := s.State(bg, h)
	require.NoError(t, err)
	assert.Equal(t, "authorized", stateName(st))
	assert.Equal(t, []string{"ErrNotYetValid"}, st.Rejections)
	_, err = s.Put(bg, fx.Cases["authorization_minimal_lmt_archive"].Record)
	require.ErrorIs(t, err, archive.ErrConflict)
}

func TestReopenKeepsRecords(t *testing.T) {
	fx := archivefix.Load(t)
	dir := t.TempDir()
	s, err := fsarchive.Open(dir, committers(fx))
	require.NoError(t, err)
	c := fx.Cases["payload_da2_minimal_lmt"]
	_, err = s.Put(bg, c.Record)
	require.NoError(t, err)

	s2, err := fsarchive.Open(dir, committers(fx))
	require.NoError(t, err)
	p := c.Record.(*archive.PayloadRecord)
	got, err := s2.Payload(bg, p.DA, p.Commitment)
	require.NoError(t, err)
	assert.Equal(t, p, got)
	out, err := s2.Put(bg, fx.Cases["payload_da2_minimal_lmt_later_intent"].Record)
	require.NoError(t, err)
	assert.Equal(t, archive.Unchanged, out)
}

func TestFailedWriteLeavesNothing(t *testing.T) {
	fx := archivefix.Load(t)
	boom := errors.New("injected")
	var calls int
	var paths []string
	s, dir := open(t, fx, fsarchive.WithBeforeRename(func(finalPath string) error {
		calls++
		paths = append(paths, finalPath)
		return boom
	}))

	for _, id := range []string{"payload_da2_minimal_lmt", "payload_da1_live", "decision_minimal_lmt"} {
		c := fx.Cases[id]
		_, err := s.Put(bg, c.Record)
		require.Error(t, err, id)
		assert.NotErrorIs(t, err, archive.ErrConflict)
		assert.NotErrorIs(t, err, archive.ErrNotFound)
		assert.Empty(t, archivefix.Files(t, dir), id)
	}
	assert.Equal(t, 3, calls)
	for _, p := range paths {
		_, err := os.Stat(p)
		assert.True(t, os.IsNotExist(err), p)
	}

	p := fx.Cases["payload_da2_minimal_lmt"].Record.(*archive.PayloadRecord)
	_, err := s.Payload(bg, p.DA, p.Commitment)
	require.ErrorIs(t, err, archive.ErrNotFound)
	st, err := s.State(bg, hashOf(t, "e2ea62234c504e4df72e172c8e0da5f02a1eeb784ccd39ac9e20f6dd4c7c8f1d"))
	require.NoError(t, err)
	assert.Equal(t, "absent", stateName(st))
}

func TestWriteRecoversAfterFailure(t *testing.T) {
	fx := archivefix.Load(t)
	fail := true
	s, dir := open(t, fx, fsarchive.WithBeforeRename(func(string) error {
		if fail {
			return errors.New("injected")
		}
		return nil
	}))
	c := fx.Cases["payload_da2_minimal_lmt"]
	_, err := s.Put(bg, c.Record)
	require.Error(t, err)
	fail = false
	out, err := s.Put(bg, c.Record)
	require.NoError(t, err)
	assert.Equal(t, archive.Written, out)
	assert.Equal(t, []string{c.Key}, archivefix.Files(t, dir))
}

// A process killed between the temp file and the rename leaves the temp file
// behind and never the record.
func TestInterruptedWriteIsInvisible(t *testing.T) {
	fx := archivefix.Load(t)
	var interrupt = true
	s, dir := open(t, fx, fsarchive.WithBeforeRename(func(string) error {
		if interrupt {
			runtime.Goexit()
		}
		return nil
	}))
	c := fx.Cases["decision_minimal_lmt"]
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = s.Put(bg, c.Record)
	}()
	<-done

	for _, f := range archivefix.Files(t, dir) {
		assert.NotEqual(t, c.Key, f)
	}
	h := hashOf(t, "e2ea62234c504e4df72e172c8e0da5f02a1eeb784ccd39ac9e20f6dd4c7c8f1d")
	_, err := s.Decision(bg, h)
	require.ErrorIs(t, err, archive.ErrNotFound)
	st, err := s.State(bg, h)
	require.NoError(t, err)
	assert.Equal(t, "absent", stateName(st))

	interrupt = false
	s2, err := fsarchive.Open(dir, committers(fx))
	require.NoError(t, err)
	_, err = s2.Decision(bg, h)
	require.ErrorIs(t, err, archive.ErrNotFound)
	out, err := s2.Put(bg, c.Record)
	require.NoError(t, err)
	assert.Equal(t, archive.Written, out)
	got, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(c.Key)))
	require.NoError(t, err)
	assert.Equal(t, c.CBOR, got)
}

func plant(t *testing.T, dir, key string, b []byte) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(key))
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(t, os.WriteFile(p, b, 0o644))
}

func TestRecordUnderWrongKeyIsCorrupt(t *testing.T) {
	fx := archivefix.Load(t)
	s, dir := open(t, fx)

	p := fx.Cases["payload_da2_minimal_lmt"].Record.(*archive.PayloadRecord)
	other := fx.Cases["payload_da2_256k"].Record.(*archive.PayloadRecord)
	plant(t, dir, "payload/2/"+hex.EncodeToString(other.Commitment), fx.Cases["payload_da2_minimal_lmt"].CBOR)
	_, err := s.Payload(bg, other.DA, other.Commitment)
	require.ErrorIs(t, err, archive.ErrCorrupt)
	assert.NotErrorIs(t, err, archive.ErrNotFound)

	plant(t, dir, "payload/1/"+hex.EncodeToString(p.Commitment), fx.Cases["payload_da2_minimal_lmt"].CBOR)
	_, err = s.Payload(bg, commitment.DAFibre, p.Commitment)
	require.ErrorIs(t, err, archive.ErrCorrupt)

	ev := fx.Cases["evidence_da2_minimal_lmt"].Record.(*archive.EvidenceRecord)
	plant(t, dir, "evidence/2/"+hex.EncodeToString(other.Commitment), fx.Cases["evidence_da2_minimal_lmt"].CBOR)
	_, err = s.Evidence(bg, ev.DA, other.Commitment)
	require.ErrorIs(t, err, archive.ErrCorrupt)

	h2 := hashOf(t, "476a1b65952e00d9cd36df2547b9c4404cb5f4b3606671f8e3c30cef5ec3249a")
	plant(t, dir, "decision/"+hex.EncodeToString(h2[:]), fx.Cases["decision_minimal_lmt"].CBOR)
	_, err = s.Decision(bg, h2)
	require.ErrorIs(t, err, archive.ErrCorrupt)

	plant(t, dir, "authorization/"+hex.EncodeToString(h2[:]), fx.Cases["authorization_minimal_lmt_da"].CBOR)
	_, err = s.Authorization(bg, h2)
	require.ErrorIs(t, err, archive.ErrCorrupt)

	h := hashOf(t, "e2ea62234c504e4df72e172c8e0da5f02a1eeb784ccd39ac9e20f6dd4c7c8f1d")
	plant(t, dir, "rejection/"+hex.EncodeToString(h[:])+"/ErrExpired", fx.Cases["rejection_minimal_lmt_not_yet_valid"].CBOR)
	_, err = s.Rejection(bg, h, "ErrExpired")
	require.ErrorIs(t, err, archive.ErrCorrupt)
}

func TestCorruptFileIsNotAbsent(t *testing.T) {
	fx := archivefix.Load(t)
	s, dir := open(t, fx)
	p := fx.Cases["payload_da2_minimal_lmt"].Record.(*archive.PayloadRecord)
	key := fx.Cases["payload_da2_minimal_lmt"].Key
	plant(t, dir, key, fx.Cases["payload_da2_minimal_lmt"].CBOR[:50])
	_, err := s.Payload(bg, p.DA, p.Commitment)
	require.ErrorIs(t, err, archive.ErrCorrupt)
	assert.NotErrorIs(t, err, archive.ErrNotFound)

	_, err = s.Put(bg, p)
	require.Error(t, err)
	got, rerr := os.ReadFile(filepath.Join(dir, filepath.FromSlash(key)))
	require.NoError(t, rerr)
	assert.Equal(t, fx.Cases["payload_da2_minimal_lmt"].CBOR[:50], got, "a corrupt record is never overwritten")
}

func TestGateSource(t *testing.T) {
	fx := archivefix.Load(t)
	s, dir := open(t, fx)
	src := archive.NewGateSource(s)
	var _ gate.BlobSource = src

	c := fx.Cases["payload_da2_minimal_lmt"]
	p := c.Record.(*archive.PayloadRecord)
	ref := commitment.PayloadRef{
		DA: p.DA, Namespace: p.Namespace, Commitment: p.Commitment, Height: 4200000, Signer: p.Signer,
	}

	_, err := src.Fetch(bg, ref, 1<<20)
	require.ErrorIs(t, err, gate.ErrBlobNotFound)

	_, err = s.Put(bg, p)
	require.NoError(t, err)
	got, err := src.Fetch(bg, ref, 1<<20)
	require.NoError(t, err)
	assert.Equal(t, p.Blob, got)

	got, err = src.Fetch(bg, ref, uint64(len(p.Blob)))
	require.NoError(t, err)
	assert.Equal(t, p.Blob, got)

	got, err = src.Fetch(bg, ref, 10)
	require.NoError(t, err)
	assert.Equal(t, p.Blob[:11], got)

	other := ref
	other.Commitment = fx.Cases["payload_da2_256k"].Record.(*archive.PayloadRecord).Commitment
	_, err = src.Fetch(bg, other, 1<<20)
	require.ErrorIs(t, err, gate.ErrBlobNotFound)

	otherDA := ref
	otherDA.DA = commitment.DAFibre
	_, err = src.Fetch(bg, otherDA, 1<<20)
	require.ErrorIs(t, err, gate.ErrBlobNotFound)

	plant(t, dir, c.Key, c.CBOR[:40])
	_, err = src.Fetch(bg, ref, 1<<20)
	require.ErrorIs(t, err, archive.ErrCorrupt)
	assert.NotErrorIs(t, err, gate.ErrBlobNotFound)
}

func TestGateSourceIgnoresNamespaceAndSigner(t *testing.T) {
	fx := archivefix.Load(t)
	s, _ := open(t, fx)
	p := fx.Cases["payload_da2_minimal_lmt"].Record.(*archive.PayloadRecord)
	_, err := s.Put(bg, p)
	require.NoError(t, err)
	ref := commitment.PayloadRef{DA: p.DA, Namespace: make([]byte, 29), Commitment: p.Commitment, Height: 1, Signer: make([]byte, 20)}
	got, err := archive.NewGateSource(s).Fetch(bg, ref, 1<<20)
	require.NoError(t, err)
	assert.Equal(t, p.Blob, got)
}

const writers = 24

func TestConcurrentSameKeyOneWinner(t *testing.T) {
	fx := archivefix.Load(t)
	s, dir := open(t, fx)
	base := *fx.Cases["payload_da2_minimal_lmt"].Record.(*archive.PayloadRecord)

	outs := make([]archive.Outcome, writers)
	errs := make([]error, writers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := base
			p.IntentHeight = uint64(1000 + i)
			<-start
			outs[i], errs[i] = s.Put(bg, &p)
		}()
	}
	close(start)
	wg.Wait()

	winner := -1
	for i := range outs {
		require.NoError(t, errs[i])
		if outs[i] == archive.Written {
			require.Equal(t, -1, winner, "two winners")
			winner = i
		} else {
			assert.Equal(t, archive.Unchanged, outs[i])
		}
	}
	require.NotEqual(t, -1, winner)
	got, err := s.Payload(bg, base.DA, base.Commitment)
	require.NoError(t, err)
	assert.EqualValues(t, 1000+winner, got.IntentHeight)
	assert.Len(t, archivefix.Files(t, dir), 1)
}

func TestConcurrentDifferentIdentity(t *testing.T) {
	fx := archivefix.Load(t)
	s, dir := open(t, fx)
	a, b := fx.Cases["decision_minimal_lmt"], fx.Cases["decision_minimal_lmt_resigned"]
	recs := []archive.Record{a.Record, b.Record}

	outs := make([]archive.Outcome, writers)
	errs := make([]error, writers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			outs[i], errs[i] = s.Put(bg, recs[i%2])
		}()
	}
	close(start)
	wg.Wait()

	written := -1
	for i := range outs {
		switch {
		case errs[i] == nil && outs[i] == archive.Written:
			require.Equal(t, -1, written, "two winners")
			written = i
		case errs[i] == nil:
			require.Equal(t, archive.Unchanged, outs[i])
		default:
			require.ErrorIs(t, errs[i], archive.ErrConflict)
		}
	}
	require.NotEqual(t, -1, written)
	for i := range outs {
		if i%2 == written%2 {
			assert.NoError(t, errs[i])
		} else {
			assert.ErrorIs(t, errs[i], archive.ErrConflict)
		}
	}
	files := archivefix.Files(t, dir)
	require.Equal(t, []string{a.Key}, files)
	got, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(a.Key)))
	require.NoError(t, err)
	if written%2 == 0 {
		assert.Equal(t, a.CBOR, got)
	} else {
		assert.Equal(t, b.CBOR, got)
	}
}

func TestConcurrentMarkersAndAuthorization(t *testing.T) {
	fx := archivefix.Load(t)
	s, _ := open(t, fx)
	h := hashOf(t, "e2ea62234c504e4df72e172c8e0da5f02a1eeb784ccd39ac9e20f6dd4c7c8f1d")
	_, err := s.Put(bg, fx.Cases["decision_minimal_lmt"].Record)
	require.NoError(t, err)

	names := []string{
		"ErrActionMismatch", "ErrAnchorNotFound", "ErrAnchorTooOld", "ErrExpired",
		"ErrNotYetValid", "ErrPayloadUnavailable", "ErrRetentionUnavailable", "ErrNonceUsed",
	}
	tmpl := *fx.Cases["rejection_minimal_lmt_not_yet_valid"].Record.(*archive.RejectionRecord)
	auth := fx.Cases["authorization_minimal_lmt_da"].Record

	type res struct {
		name string
		out  archive.Outcome
		err  error
	}
	results := make(chan res, len(names)+1)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i, n := range names {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := tmpl
			r.Error = n
			r.RejectedAt += uint64(i)
			<-start
			out, err := s.Put(bg, &r)
			results <- res{n, out, err}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		out, err := s.Put(bg, auth)
		results <- res{"", out, err}
	}()
	close(start)
	wg.Wait()
	close(results)

	var written []string
	for r := range results {
		require.NoError(t, r.err, r.name)
		if r.name == "" {
			assert.Equal(t, archive.Written, r.out)
		} else if r.out == archive.Written {
			written = append(written, r.name)
		}
	}
	st, err := s.State(bg, h)
	require.NoError(t, err)
	assert.Equal(t, "authorized", stateName(st))
	sort.Strings(written)
	got := append([]string(nil), st.Rejections...)
	sort.Strings(got)
	assert.Equal(t, nonNil(written), nonNil(got), "a marker reports written exactly when it is stored")
}
