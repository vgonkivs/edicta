package edictad_test

import (
	"context"
	"encoding/hex"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/celestia/edictad"
	"github.com/vgonkivs/edicta/celestia/nodefake"
	"github.com/vgonkivs/edicta/celestia/recorder"
	"github.com/vgonkivs/edicta/celestia/test/fibrefix"
	"github.com/vgonkivs/edicta/celestia/test/fibreworld"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/edictaapi"
	"github.com/vgonkivs/edicta/fibre/fibrecommit"
	"github.com/vgonkivs/edicta/gate/registry/boltreg"
	"github.com/vgonkivs/edicta/sdk"
)

type eventLog struct {
	mu sync.Mutex
	ev []string
}

func (l *eventLog) add(s string) { l.mu.Lock(); l.ev = append(l.ev, s); l.mu.Unlock() }
func (l *eventLog) list() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.ev...)
}

// fakeFibreRec stands in for the FibreRecorder behind the NewFibre seam.
type fakeFibreRec struct {
	log      *eventLog
	closeErr error
	closes   atomic.Int32
	deadline atomic.Pointer[time.Time]
	ctxDone  atomic.Bool
	hook     func()
	skipped  atomic.Uint64
}

func (f *fakeFibreRec) SkippedIntents() uint64 { return f.skipped.Load() }

func (f *fakeFibreRec) Publish(context.Context, []byte) (sdk.Published, error) {
	return sdk.Published{}, errSeam
}

func (f *fakeFibreRec) Close(ctx context.Context) error {
	f.closes.Add(1)
	if d, ok := ctx.Deadline(); ok {
		f.deadline.Store(&d)
	}
	f.ctxDone.Store(ctx.Err() != nil)
	f.log.add("recorder.close")
	if f.hook != nil {
		f.hook()
	}
	return f.closeErr
}

// fakeSigningCloser is the closer NewFibreSigning returns.
type fakeSigningCloser struct {
	log    *eventLog
	closes atomic.Int32
	hook   func()
	err    error
}

func (c *fakeSigningCloser) Close() error {
	c.closes.Add(1)
	c.log.add("signing.close")
	if c.hook != nil {
		c.hook()
	}
	return c.err
}

type fibreRecFakes struct {
	log    *eventLog
	rec    *fakeFibreRec
	closer *fakeSigningCloser
	node   *nodefake.FibreNode
	sub    *nodefake.FibreSubmitter
	cfg    atomic.Pointer[recorder.FibreConfig]
	deps   atomic.Pointer[recorder.FibreDeps]
	builds atomic.Int32
}

// newFibreRecEnv is a da = fibre env whose Recorder is built by a seam.
func newFibreRecEnv(t *testing.T) (*env, *fibreFakes, *fibreRecFakes) {
	t.Helper()
	e, ff := newFibreEnv(t)
	log := &eventLog{}
	rf := &fibreRecFakes{log: log, rec: &fakeFibreRec{log: log}, closer: &fakeSigningCloser{log: log}}
	rf.node = nodefake.NewFibreNode(fibreworld.Endpoint, func(uint64) time.Time { return t0 }, fibrefix.BuildBlock(t))
	rf.sub = &nodefake.FibreSubmitter{Addr: recAddr, Endpt: fibreworld.Endpoint, Chain: rf.node}
	st, err := fsarchive.Open(e.path("archive"), fibrefix.Committers(t))
	require.NoError(t, err)
	e.deps.Archive = st
	ff.deps.Submitter, ff.deps.RecorderChain, ff.deps.SigningCloser = rf.sub, rf.node, rf.closer
	ff.deps.NewFibre = func(cfg recorder.FibreConfig, d recorder.FibreDeps) (edictad.FibreRecorder, error) {
		rf.builds.Add(1)
		rf.cfg.Store(&cfg)
		rf.deps.Store(&d)
		return rf.rec, nil
	}
	return e, ff, rf
}

func (e *env) registryReopens() {
	e.t.Helper()
	reg, err := boltreg.Open(e.path("registry.db"), 1)
	require.NoError(e.t, err, "the registry was closed")
	require.NoError(e.t, reg.Close())
}

func TestFibreRecorderIsBuiltFromTheConfig(t *testing.T) {
	e, _, rf := newFibreRecEnv(t)
	e.start(fibreRecEdits()...)

	require.EqualValues(t, 1, rf.builds.Load())
	cfg, d := rf.cfg.Load(), rf.deps.Load()
	assert.Equal(t, nsBytes, cfg.Namespace)
	assert.EqualValues(t, 1048576, cfg.MaxDataBytes)
	assert.Equal(t, 200*time.Second, cfg.SubmitTimeout)
	assert.Equal(t, 100*time.Second, cfg.UploadDrain)
	assert.EqualValues(t, 5, cfg.EscrowMarginUtia)
	assert.True(t, cfg.OwnNode)
	assert.True(t, cfg.Archive == e.deps.Archive, "the Recorder writes to the gate's archive")
	require.NotNil(t, cfg.Now)
	assert.Equal(t, t0, cfg.Now(), "the Recorder follows the daemon clock")

	assert.Same(t, rf.sub, d.Submitter)
	assert.Same(t, rf.node, d.Chain)
	assert.Equal(t, fibreChainID, d.ChainID)
	assert.NotNil(t, d.Committer)
	assert.NotNil(t, d.Reader)
}

func TestFibreRecorderIsNotBuiltWithoutTheRecorder(t *testing.T) {
	e, _, rf := newFibreRecEnv(t)
	e.start(fibreEdits()...)
	assert.Zero(t, rf.builds.Load())
}

func TestFibreHealthReportsTheSubmitterAccount(t *testing.T) {
	e, _, _ := newFibreRecEnv(t)
	e.start(fibreRecEdits()...)
	h, err := e.client("").Health(bg)
	require.NoError(t, err)
	assert.Equal(t, recAddr, h.RecorderSigner)
	assert.Equal(t, nsBytes, h.Namespace)
	assert.Equal(t, []uint64{1}, h.AllowedDA)
}

func TestFibreRecorderStartRefusals(t *testing.T) {
	cases := map[string]func(e *env, ff *fibreFakes, rf *fibreRecFakes){
		"no submitter":      func(_ *env, ff *fibreFakes, _ *fibreRecFakes) { ff.deps.Submitter = nil },
		"no recorder chain": func(_ *env, ff *fibreFakes, _ *fibreRecFakes) { ff.deps.RecorderChain = nil },
		"NewFibre refuses": func(_ *env, ff *fibreFakes, _ *fibreRecFakes) {
			ff.deps.NewFibre = func(recorder.FibreConfig, recorder.FibreDeps) (edictad.FibreRecorder, error) { return nil, errSeam }
		},
		"listener fails": func(e *env, _ *fibreFakes, _ *fibreRecFakes) {
			e.deps.Listen = func(string, string) (net.Listener, error) { return nil, errSeam }
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			e, ff, rf := newFibreRecEnv(t)
			setup(e, ff, rf)
			srv, err := edictad.Start(bg, e.cfg(fibreRecEdits()...), e.deps)
			require.Error(t, err)
			require.Nil(t, srv)
			assert.EqualValues(t, 1, rf.closer.closes.Load(), "the signing closer is closed once")
			assert.LessOrEqual(t, rf.rec.closes.Load(), int32(1))
			if e.registryExists() {
				e.registryReopens()
			}
		})
	}
}

func TestFibreRecorderStartFailureAfterTheBuildClosesEverythingOnce(t *testing.T) {
	e, _, rf := newFibreRecEnv(t)
	e.deps.Listen = func(string, string) (net.Listener, error) { return nil, errSeam }
	srv, err := edictad.Start(bg, e.cfg(fibreRecEdits()...), e.deps)
	require.ErrorIs(t, err, errSeam)
	require.Nil(t, srv)
	assert.EqualValues(t, 1, rf.rec.closes.Load())
	assert.EqualValues(t, 1, rf.closer.closes.Load())
	assert.Equal(t, []string{"recorder.close", "signing.close"}, rf.log.list())
	e.registryReopens()
}

func TestFibreRecorderBuildFailureClosesTheSigningClientOnce(t *testing.T) {
	e, ff, rf := newFibreRecEnv(t)
	ff.deps.NewFibre = func(recorder.FibreConfig, recorder.FibreDeps) (edictad.FibreRecorder, error) { return nil, errSeam }
	_, err := edictad.Start(bg, e.cfg(fibreRecEdits()...), e.deps)
	require.ErrorIs(t, err, errSeam)
	assert.EqualValues(t, 1, rf.closer.closes.Load())
	assert.Zero(t, rf.rec.closes.Load(), "there is no Recorder to close")
	e.registryReopens()
}

func TestFibreShutdownOrder(t *testing.T) {
	e, _, rf := newFibreRecEnv(t)
	e.deps.WrapGate = func(edictaapi.Gate) edictaapi.Gate { return e.spy }
	entered, release := make(chan struct{}), make(chan struct{})
	e.spy.authFn = func() ([]byte, error) {
		close(entered)
		<-release
		rf.log.add("http.done")
		return []byte("auth-bytes"), nil
	}
	var registryHeld atomic.Bool
	rf.closer.hook = func() {
		// The registry file is still locked while the signing client closes.
		reg, err := boltreg.Open(e.path("registry.db"), 1)
		if err == nil {
			_ = reg.Close()
			return
		}
		registryHeld.Store(true)
	}
	srv := e.start(fibreRecEdits()...)

	got := make(chan error, 1)
	go func() { _, err := e.client("").Authorize(bg, []byte("e"), []byte("a"), testSalt); got <- err }()
	<-entered
	down := make(chan error, 1)
	go func() { down <- srv.Shutdown(bg) }()
	close(release)
	require.NoError(t, <-got)
	require.NoError(t, <-down)

	assert.Equal(t, []string{"http.done", "recorder.close", "signing.close"}, rf.log.list())
	assert.True(t, registryHeld.Load(), "the registry closes after the signing client")
	e.registryReopens()
}

func TestFibreShutdownBoundsTheRecorderClose(t *testing.T) {
	e, _, rf := newFibreRecEnv(t)
	srv := e.start(fibreRecEdits()...)
	require.NoError(t, srv.Shutdown(bg))
	d := rf.rec.deadline.Load()
	require.NotNil(t, d, "Close gets a context with a deadline although Shutdown's has none")
	assert.WithinDuration(t, time.Now().Add(120*time.Second), *d, 30*time.Second, "close_timeout_s")
}

func TestFibreShutdownRunsEachCloseOnce(t *testing.T) {
	e, _, rf := newFibreRecEnv(t)
	srv := e.start(fibreRecEdits()...)
	require.NoError(t, srv.Shutdown(bg))
	require.NoError(t, srv.Shutdown(bg))
	assert.EqualValues(t, 1, rf.rec.closes.Load())
	assert.EqualValues(t, 1, rf.closer.closes.Load())
	e.registryReopens()
}

func TestFibreRecorderCloseErrorSkipsNothing(t *testing.T) {
	e, _, rf := newFibreRecEnv(t)
	rf.rec.closeErr = errSeam
	srv := e.start(fibreRecEdits()...)
	err := srv.Shutdown(bg)
	require.ErrorIs(t, err, errSeam, "a Close error is returned")
	assert.EqualValues(t, 1, rf.closer.closes.Load(), "the signing client is still closed")
	e.registryReopens()
	assert.Contains(t, e.logs.String(), errSeam.Error(), "and logged")
}

// A publish through the real Recorder over the live Mocha vector: the HTTP
// request pays, anchors and archives the blob.
func TestFibrePublishEndToEnd(t *testing.T) {
	w := fibreworld.New(t)
	e, ff := newFibreEnv(t)
	for _, h := range []uint64{90, 100} {
		e.chain.AddHeader(fibreHeader(h, w.Now))
	}
	e.deps.Clock = clock{w.Now}
	e.deps.Archive = w.St
	e.deps.WrapGate = nil
	ff.deps.Chain, ff.deps.Bridge = w.Node, w.Node
	ff.deps.Submitter, ff.deps.RecorderChain = w.Sub, w.Node
	closer := &fakeSigningCloser{log: &eventLog{}}
	ff.deps.SigningCloser = closer
	// The Recorder's drain timer is real: short ones keep the final Shutdown quick.
	e.start(fibreRecEdits(rep(hex.EncodeToString(nsBytes), hex.EncodeToString(w.Live.Ref.Namespace)),
		rep("upload_drain_s = 100", "upload_drain_s = 1"), rep("close_timeout_s = 120", "close_timeout_s = 1"))...)

	pub, err := e.client("", edictaapi.WithClock(clock{w.Now})).Publish(bg, w.Live.Payload)
	require.NoError(t, err)
	want, err := fibrecommit.Commitment(w.Live.Payload)
	require.NoError(t, err)
	assert.Equal(t, commitment.DAFibre, pub.Ref.DA)
	assert.Equal(t, want[:], pub.Ref.Commitment)
	assert.Equal(t, w.Live.Height, pub.Ref.Height)
	assert.Equal(t, 1, w.Sub.Calls(), "paid once")

	require.NoError(t, e.srv.Shutdown(bg))
	assert.EqualValues(t, 1, closer.closes.Load())
}

// Submitting and reading must go to one node; the real constructor checks it.
func TestFibreRecorderRefusesASubmitNodeThatIsNotTheReadNode(t *testing.T) {
	e, ff, rf := newFibreRecEnv(t)
	ff.deps.NewFibre = nil
	rf.sub.Endpt = "other.example:9090"
	srv, err := edictad.Start(bg, e.cfg(fibreRecEdits()...), e.deps)
	require.Error(t, err)
	require.Nil(t, srv)
	assert.Zero(t, e.listens)
	assert.EqualValues(t, 1, rf.closer.closes.Load())
	e.registryReopens()
}

// A shutdown whose context ends while a request still runs cuts the request off
// and closes everything once.
func TestFibreShutdownCutShortStillClosesEverything(t *testing.T) {
	e, _, rf := newFibreRecEnv(t)
	e.deps.WrapGate = func(edictaapi.Gate) edictaapi.Gate { return e.spy }
	entered, release := make(chan struct{}), make(chan struct{})
	e.spy.authFn = func() ([]byte, error) { close(entered); <-release; return []byte("a"), nil }
	srv := e.start(fibreRecEdits()...)
	go func() { _, _ = e.client("").Authorize(bg, []byte("e"), []byte("a"), testSalt) }()
	<-entered

	ctx, cancel := context.WithTimeout(bg, 50*time.Millisecond)
	defer cancel()
	err := srv.Shutdown(ctx)
	close(release)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.EqualValues(t, 1, rf.rec.closes.Load())
	assert.EqualValues(t, 1, rf.closer.closes.Load())
	assert.Equal(t, []string{"recorder.close", "signing.close"}, rf.log.list())
	e.registryReopens()

	require.NoError(t, srv.Shutdown(bg), "a second call has nothing left to close")
	assert.EqualValues(t, 1, rf.rec.closes.Load())
	assert.EqualValues(t, 1, rf.closer.closes.Load())
}

// The Recorder's close runs inside the shutdown context, so a context that has
// ended cancels the drain wait at once.
func TestFibreRecorderCloseHonoursTheShutdownContext(t *testing.T) {
	e, _, rf := newFibreRecEnv(t)
	srv := e.start(fibreRecEdits()...)
	ctx, cancel := context.WithCancel(bg)
	cancel()
	_ = srv.Shutdown(ctx)
	assert.True(t, rf.rec.ctxDone.Load())
	assert.EqualValues(t, 1, rf.rec.closes.Load())
}

func TestFibreSigningCloseErrorIsReturned(t *testing.T) {
	e, _, rf := newFibreRecEnv(t)
	rf.closer.err = errSeam
	srv := e.start(fibreRecEdits()...)
	require.ErrorIs(t, srv.Shutdown(bg), errSeam)
	e.registryReopens()
}

func TestFibreRecorderIsCappedByTheBlobLimit(t *testing.T) {
	e, _, rf := newFibreRecEnv(t)
	e.start(fibreRecEdits(rep("max_blob_bytes = 1048576\n", "max_blob_bytes = 4096\n"))...)
	assert.EqualValues(t, 4096, rf.cfg.Load().MaxDataBytes)
}
