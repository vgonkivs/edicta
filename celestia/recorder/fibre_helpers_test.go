package recorder_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
	"github.com/vgonkivs/edicta/celestia/recorder"
	"github.com/vgonkivs/edicta/celestia/test/fibrefix"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/fibre/fibrecommit"
	"github.com/vgonkivs/edicta/sdk"
)

const (
	fibreChainID  = "mocha-5"
	fibreEndpoint = "consensus.example:9090"
	// fibreWindow is the PaymentPromiseHeightWindow of the fake chain, small
	// enough to scan in a test; the settle span is fibreWindow+2 unless the
	// configured settle blocks are larger.
	fibreWindow = 300
	fibreSettle = 256
	fibreSpan   = fibreWindow + 2
	// startHead is above the promise height of the live PFF.
	startHead = uint64(1402815)
	// pendingTTLBlocks is more than the one hour a pending entry lives, at one
	// second per block.
	pendingTTLBlocks = 3700
)

type planFn = func(call int, ns, data []byte) nodefake.SubmitPlan

// fibreFx is a da = 1 Recorder world around the live Mocha PayForFibre: one
// chain, one submitter, a clock that follows the true chain head, and the live
// blob, whose certificate is the only one that verifies.
type fibreFx struct {
	t    *testing.T
	l    *fibrefix.Live
	node *nodefake.FibreNode
	sub  *nodefake.FibreSubmitter

	blob  []byte
	comm  [32]byte
	us    uint64
	synth fibrefix.Block

	truth atomic.Uint64
	skew  atomic.Int64
}

func newFibreFx(t *testing.T) *fibreFx {
	t.Helper()
	l := fibrefix.LoadLive(t)
	f := &fibreFx{t: t, l: l, blob: l.Payload}
	comm, err := fibrecommit.Commitment(f.blob)
	require.NoError(t, err)
	require.Equal(t, l.Ref.Commitment, comm[:], "the live payload is the committed blob")
	f.comm = comm
	f.us, err = fibrecommit.UploadSize(uint64(len(f.blob)))
	require.NoError(t, err)

	f.node = nodefake.NewFibreNode(fibreEndpoint, f.timeAt, fibrefix.BuildBlock(t))
	f.node.SetHistoricalInfo(l.PromiseHeight, l.Hist)
	f.node.SetSignedHeader(l.PromiseHeight, fibrefix.BoundSignedHeader(t, l.PromiseHeaderProto(t)))
	f.node.SetValidatorSet(l.PromiseHeight+1, l.PromiseValsetNext(t))
	f.node.SetFibreParams(node.FibreParams{RetentionS: 14400, PromiseHeightWindow: fibreWindow})
	f.sub = &nodefake.FibreSubmitter{
		Addr: make([]byte, 20), EscrowVal: node.Escrow{AvailableUtia: 100_000_000}, Endpt: fibreEndpoint, Chain: f.node,
	}
	f.grow(startHead)
	return f
}

// timeAt dates block h so that the live block keeps its real time.
func (f *fibreFx) timeAt(h uint64) time.Time {
	return f.l.Header.Time.Add(time.Duration(int64(h)-int64(f.l.Height)) * time.Second)
}

// now is the Recorder's clock: the time of the true head, however far the
// node itself has got, plus the skew a test sets.
func (f *fibreFx) now() time.Time {
	return f.timeAt(max(f.node.Head(), f.truth.Load())).Add(time.Duration(f.skew.Load()))
}

// grow moves the true chain and the node to head h.
func (f *fibreFx) grow(h uint64) {
	f.truth.Store(h)
	f.node.SetHead(h)
}

// lag puts the node at head h while the true chain stays where it is.
func (f *fibreFx) lag(h uint64) { f.node.SetHead(h) }

func (f *fibreFx) openArchive(dir string) *fsarchive.Store {
	f.t.Helper()
	s, err := fsarchive.Open(dir, fibrefix.Committers(f.t))
	require.NoError(f.t, err)
	return s
}

func (f *fibreFx) cfg(st archive.Store) recorder.FibreConfig {
	return recorder.FibreConfig{
		Namespace: f.l.Ref.Namespace, MaxDataBytes: 1 << 10, SubmitTimeout: 5 * time.Second,
		UploadDrain: time.Hour, MaxDraining: 8, VisibleTimeout: 50 * time.Millisecond, PollInterval: time.Millisecond,
		ScanBlocks: 1024, SettleBlocks: fibreSettle, OwnNode: true, Archive: st, Now: f.now,
	}
}

func (f *fibreFx) deps() recorder.FibreDeps {
	c, err := fibrecommit.New(fibrecommit.DefaultMaxDataSize)
	require.NoError(f.t, err)
	return recorder.FibreDeps{
		Submitter: f.sub, Reader: f.node, Chain: f.node, ChainID: fibreChainID, Committer: c,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// newRec builds a Recorder and ends its uploads with the test.
func (f *fibreFx) newRec(c recorder.FibreConfig) *recorder.FibreRecorder {
	f.t.Helper()
	r, err := recorder.NewFibre(c, f.deps())
	require.NoError(f.t, err)
	f.t.Cleanup(func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_ = r.Close(ctx)
	})
	return r
}

// pff is the live PayForFibre in a block at height h. At the live height it is
// the real block; elsewhere the same tx sits in a synthetic block with real
// proofs.
func (f *fibreFx) pff(h uint64) *nodefake.LandedPFF {
	f.t.Helper()
	hdr := f.l.Header
	if h == f.l.Height {
		return &nodefake.LandedPFF{Header: hdr, Block: fibrefix.VectorBlock(f.t, f.l.Case), Tx: f.l.PFFTx, Index: 1}
	}
	if f.synth.DataHash == nil {
		f.synth = fibrefix.BuildBlock(f.t, f.l.PFFTx)
	}
	hdr.Height = int64(h)
	hdr.DataHash = append([]byte(nil), f.synth.DataHash...)
	hdr.Time = f.timeAt(h)
	return &nodefake.LandedPFF{Header: hdr, Block: f.synth, Tx: f.l.PFFTx, Index: 1}
}

// result is what an honest node reports for a submit of data that landed at h.
func (f *fibreFx) result(ns, data []byte, h uint64) node.FibreResult {
	c, err := fibrecommit.Commitment(data)
	require.NoError(f.t, err)
	us, err := fibrecommit.UploadSize(uint64(len(data)))
	require.NoError(f.t, err)
	return node.FibreResult{
		BlobID: fibrecommit.BlobID(c), Height: h, TxHash: sha256.Sum256(f.l.PFFTx), PromiseHeight: f.l.PromiseHeight,
		Namespace: ns, Commitment: c, BlobSize: uint32(us),
	}
}

// ok lands the live PFF at h and reports it honestly.
func (f *fibreFx) ok(h uint64) planFn {
	return func(_ int, ns, data []byte) nodefake.SubmitPlan {
		return nodefake.SubmitPlan{Land: f.pff(h), Result: f.result(ns, data, h)}
	}
}

// fail returns err and lands nothing.
func (f *fibreFx) fail(err error) planFn {
	return func(int, []byte, []byte) nodefake.SubmitPlan { return nodefake.SubmitPlan{Err: err} }
}

// failAfterLand lands the live PFF at h and still returns err: the node died
// after the chain took the tx.
func (f *fibreFx) failAfterLand(h uint64, err error) planFn {
	return func(int, []byte, []byte) nodefake.SubmitPlan { return nodefake.SubmitPlan{Land: f.pff(h), Err: err} }
}

// seq runs one plan per call; the last one repeats.
func seq(ps ...planFn) planFn {
	return func(call int, ns, data []byte) nodefake.SubmitPlan {
		i := min(call-1, len(ps)-1)
		return ps[i](call, ns, data)
	}
}

// landLater lands the live PFF at h with no submit involved, as a tx that was
// still in flight does.
func (f *fibreFx) landLater(h uint64) {
	f.node.Land(*f.pff(h))
}

// diedAfterPayload leaves the payload record of a process that archived its
// intent at the current head and was killed before it paid for anything.
func (f *fibreFx) diedAfterPayload(st archive.Store) {
	f.t.Helper()
	_, err := st.Put(context.Background(), &archive.PayloadRecord{
		DA: commitment.DAFibre, Commitment: f.comm[:], Blob: f.blob, IntentHeight: f.node.Head(),
	})
	require.NoError(f.t, err)
}

// flakyStore passes calls on and fails the configured ones.
type flakyStore struct {
	archive.Store
	mu      sync.Mutex
	putFail map[archive.Kind]error
	getFail map[archive.Kind]error
	puts    []archive.Kind
	// onPut, when set, sees every record before it is stored.
	onPut func(archive.Record)
}

func newFlaky(s archive.Store) *flakyStore {
	return &flakyStore{Store: s, putFail: map[archive.Kind]error{}, getFail: map[archive.Kind]error{}}
}

func (s *flakyStore) failPut(k archive.Kind, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		delete(s.putFail, k)
		return
	}
	s.putFail[k] = err
}

func (s *flakyStore) failGet(k archive.Kind, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		delete(s.getFail, k)
		return
	}
	s.getFail[k] = err
}

func (s *flakyStore) putCount(k archive.Kind) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, p := range s.puts {
		if p == k {
			n++
		}
	}
	return n
}

func (s *flakyStore) Put(ctx context.Context, r archive.Record) (archive.Outcome, error) {
	s.mu.Lock()
	s.puts = append(s.puts, r.Kind())
	err := s.putFail[r.Kind()]
	hook := s.onPut
	s.mu.Unlock()
	if hook != nil {
		hook(r)
	}
	if err != nil {
		return 0, err
	}
	return s.Store.Put(ctx, r)
}

func (s *flakyStore) Payload(ctx context.Context, da commitment.DA, c []byte) (*archive.PayloadRecord, error) {
	s.mu.Lock()
	err := s.getFail[archive.KindPayload]
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return s.Store.Payload(ctx, da, c)
}

func (s *flakyStore) Evidence(ctx context.Context, da commitment.DA, c []byte) (*archive.EvidenceRecord, error) {
	s.mu.Lock()
	err := s.getFail[archive.KindEvidence]
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return s.Store.Evidence(ctx, da, c)
}

func fibrefixBound(t testing.TB, h cmtproto.Header) []byte { return fibrefix.BoundSignedHeader(t, h) }

// unboundSigned is a signed header whose commit names another block.
func unboundSigned(t testing.TB, h cmtproto.Header) []byte {
	t.Helper()
	var sh cmtproto.SignedHeader
	require.NoError(t, sh.Unmarshal(fibrefix.BoundSignedHeader(t, h)))
	sh.Commit.BlockID.Hash[0] ^= 1
	raw, err := sh.Marshal()
	require.NoError(t, err)
	return raw
}

func writeFile(dir, rel string, b []byte) error {
	return os.WriteFile(filepath.Join(dir, filepath.FromSlash(rel)), b, 0o644)
}

func sha256Sum(b []byte) [32]byte { return sha256.Sum256(b) }

// publishUntil calls Publish until it stops reporting an unresolved outcome,
// at most n times. Every unresolved answer must be ErrOutcomeUnknown and must
// leave the submit count where it was.
func publishUntil(t *testing.T, f *fibreFx, rec *recorder.FibreRecorder, n int) (sdk.Published, error) {
	t.Helper()
	calls := f.sub.Calls()
	var (
		pub sdk.Published
		err error
	)
	for i := 0; i < n; i++ {
		pub, err = rec.Publish(bg, f.blob)
		if err == nil || !errors.Is(err, recorder.ErrOutcomeUnknown) {
			return pub, err
		}
		require.Equal(t, calls, f.sub.Calls(), "an unresolved outcome never submits")
	}
	return pub, err
}
