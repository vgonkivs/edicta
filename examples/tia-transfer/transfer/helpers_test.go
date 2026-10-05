package transfer_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankmsg"
	"github.com/vgonkivs/edicta/examples/tia-transfer/transfer"
)

const (
	nowUnix  = uint64(1791000060)
	skew     = uint64(30)
	gateID   = "gate-paper-1"
	chainID  = "mocha-4"
	hrp      = "celestia"
	denom    = "utia"
	sender   = "celestia1qqp0ztywuvn8agqn6znr4k35eda494vv7klwtc"
	receiver = "celestia1mzkhlmxtluk4gmet2kja0yv8kxc2n07ml6lld3"
	otherDst = "celestia1nxeu03k3d4gdza0u0vcqtjy7ckc8efghdg3j4c"
	headH    = uint64(1000)
	blockS   = uint64(6)
)

var bg = context.Background()

func seedKey(b byte) ed25519.PrivateKey {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = b
	}
	return ed25519.NewKeyFromSeed(s)
}

func gatePub() ed25519.PublicKey { return seedKey(7).Public().(ed25519.PublicKey) }

func chash(b byte) commitment.Hash {
	var h commitment.Hash
	for i := range h {
		h[i] = b
	}
	return h
}

// fakeClock moves only when the executor waits.
type fakeClock struct {
	mu    sync.Mutex
	t     time.Time
	waits []time.Duration
	// follow makes the clock advance with real time on top of the waits, so
	// real context deadlines built from it are meaningful.
	follow bool
	off    time.Duration
}

func newClock() *fakeClock { return &fakeClock{t: time.Unix(int64(nowUnix), 0)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.follow {
		return time.Now().Add(c.off)
	}
	return c.t
}

// followRealTime starts the clock at the real time; waits still jump it.
func (c *fakeClock) followRealTime() {
	c.mu.Lock()
	c.follow, c.off = true, 0
	c.mu.Unlock()
}

func (c *fakeClock) unix() uint64        { return uint64(c.Now().Unix()) }
func (c *fakeClock) setTime(t time.Time) { c.mu.Lock(); c.t = t; c.mu.Unlock() }
func (c *fakeClock) set(u uint64)        { c.mu.Lock(); c.t = time.Unix(int64(u), 0); c.mu.Unlock() }

func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
	c.off += d
	c.waits = append(c.waits, d)
	ch := make(chan time.Time, 1)
	ch <- c.t
	return ch
}

func (c *fakeClock) waited() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.waits...)
}

// fakeRail is a chain whose height follows the shared clock.
type fakeRail struct {
	mu    sync.Mutex
	clock *fakeClock

	frozen        bool
	includeAt     uint64 // 0: never included
	code          uint32
	interval      time.Duration
	signErr       error
	headErr       error
	broadcastErrs []error // consumed one per Broadcast call
	badBody       bool    // Sign returns a TxRaw whose body differs
	onBroadcast   func(n int)
	// heightFn, when set, replaces the clock-driven height. It runs with the
	// rail lock held and may read r.bodies.
	heightFn func(clockUnix uint64) uint64
	// commitAtClock: once the wall clock reaches it (and something was
	// broadcast) Status reports the tx committed at commitHeight.
	commitAtClock uint64
	commitHeight  uint64
	onStatus      func(n int)
	statusTimes   []uint64

	// nodeHeightFn is the height of the node that answers Status; nil means
	// the same as the head.
	nodeHeightFn func(clockUnix uint64) uint64
	// heightErrFn, when set, makes the height-only read fail.
	heightErrFn func(clockUnix uint64) error
	onHeight    func(n int)
	// statusOverride, when it reports true, replaces the answer of Status.
	statusOverride func(n int, nodeHeight uint64) (transfer.TxStatus, bool)
	// hang counts, per call kind, the first calls that block until their
	// context ends.
	hang    map[string]int
	callLog []callInfo
	heightN int

	bodies       [][]byte
	chainIDs     []string
	maxFees      []uint64
	signed       [][]byte
	broadcasts   [][]byte
	bcastHeights []uint64
	bcastTimes   []uint64
	statusHashes [][32]byte
	statusHeight []uint64
}

type callInfo struct {
	kind        string
	hasDeadline bool
	deadline    time.Time
	remaining   time.Duration
	clockNow    time.Time
	blocked     time.Duration
}

func newRail(c *fakeClock) *fakeRail {
	return &fakeRail{clock: c, interval: time.Duration(blockS) * time.Second}
}

func (r *fakeRail) height() uint64 {
	if r.heightFn != nil {
		return r.heightFn(r.clock.unix())
	}
	if r.frozen {
		return headH
	}
	return headH + (r.clock.unix()-nowUnix)/blockS
}

func (r *fakeRail) nodeHeight() uint64 {
	if r.nodeHeightFn != nil {
		return r.nodeHeightFn(r.clock.unix())
	}
	return r.height()
}

// enter records the context of a call and blocks if the call is meant to hang.
func (r *fakeRail) enter(ctx context.Context, kind string) error {
	dl, ok := ctx.Deadline()
	started := time.Now()
	r.mu.Lock()
	r.callLog = append(r.callLog, callInfo{kind: kind, hasDeadline: ok, deadline: dl, remaining: time.Until(dl), clockNow: r.clock.Now()})
	idx := len(r.callLog) - 1
	hang := r.hang[kind] > 0
	if hang {
		r.hang[kind]--
	}
	r.mu.Unlock()
	if hang {
		<-ctx.Done()
		r.mu.Lock()
		r.callLog[idx].blocked = time.Since(started)
		r.mu.Unlock()
		return ctx.Err()
	}
	return nil
}

func (r *fakeRail) calls(kind string) []callInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []callInfo
	for _, c := range r.callLog {
		if c.kind == kind {
			out = append(out, c)
		}
	}
	return out
}

func (r *fakeRail) Domain(context.Context) (transfer.Domain, error) {
	return transfer.Domain{ChainID: chainID, Denom: denom, HRP: hrp, Sender: sender}, nil
}

func (r *fakeRail) Head(context.Context) (uint64, uint64, time.Duration, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.headErr != nil {
		return 0, 0, 0, r.headErr
	}
	return r.height(), r.clock.unix(), r.interval, nil
}

func (r *fakeRail) Height(ctx context.Context) (uint64, error) {
	if err := r.enter(ctx, "height"); err != nil {
		return 0, err
	}
	r.mu.Lock()
	r.heightN++
	n, hook := r.heightN, r.onHeight
	r.mu.Unlock()
	if hook != nil {
		hook(n)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.heightErrFn != nil {
		if err := r.heightErrFn(r.clock.unix()); err != nil {
			return 0, err
		}
	}
	if r.headErr != nil {
		return 0, r.headErr
	}
	return r.height(), nil
}

func uv(v int) []byte { return binary.AppendUvarint(nil, uint64(v)) }

func (r *fakeRail) Sign(_ context.Context, body []byte, cid string, maxFee uint64) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.signErr != nil {
		return nil, r.signErr
	}
	r.bodies = append(r.bodies, append([]byte(nil), body...))
	r.chainIDs = append(r.chainIDs, cid)
	r.maxFees = append(r.maxFees, maxFee)
	n := len(r.bodies)
	b := append([]byte(nil), body...)
	if r.badBody {
		b[len(b)-1] ^= 1
	}
	auth := []byte{0x0a, 0x02, 0x08, byte(n)}
	sig := sha256.Sum256(append([]byte{byte(n)}, body...))
	raw := append([]byte{0x0a}, uv(len(b))...)
	raw = append(raw, b...)
	raw = append(raw, 0x12)
	raw = append(raw, uv(len(auth))...)
	raw = append(raw, auth...)
	raw = append(raw, 0x1a, 0x20)
	raw = append(raw, sig[:]...)
	r.signed = append(r.signed, raw)
	return raw, nil
}

func (r *fakeRail) Broadcast(ctx context.Context, raw []byte) error {
	if err := r.enter(ctx, "broadcast"); err != nil {
		return err
	}
	r.mu.Lock()
	r.broadcasts = append(r.broadcasts, append([]byte(nil), raw...))
	r.bcastHeights = append(r.bcastHeights, r.height())
	r.bcastTimes = append(r.bcastTimes, r.clock.unix())
	n := len(r.broadcasts)
	var err error
	if len(r.broadcastErrs) > 0 {
		err, r.broadcastErrs = r.broadcastErrs[0], r.broadcastErrs[1:]
	}
	hook := r.onBroadcast
	r.mu.Unlock()
	if hook != nil {
		hook(n)
	}
	return err
}

func (r *fakeRail) Status(ctx context.Context, h [32]byte) (transfer.TxStatus, error) {
	if err := r.enter(ctx, "status"); err != nil {
		return transfer.TxStatus{}, err
	}
	r.mu.Lock()
	n := len(r.statusHashes) + 1
	hook := r.onStatus
	r.mu.Unlock()
	if hook != nil {
		hook(n)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.statusHashes = append(r.statusHashes, h)
	nh := r.nodeHeight()
	r.statusHeight = append(r.statusHeight, nh)
	r.statusTimes = append(r.statusTimes, r.clock.unix())
	if r.statusOverride != nil {
		if st, ok := r.statusOverride(n, nh); ok {
			st.NodeHeight = nh
			return st, nil
		}
	}
	if r.commitAtClock != 0 && len(r.broadcasts) > 0 && r.clock.unix() >= r.commitAtClock {
		return transfer.TxStatus{State: transfer.TxCommitted, Height: r.commitHeight, Code: r.code, NodeHeight: nh}, nil
	}
	for _, raw := range r.signed {
		if sha256.Sum256(raw) != h {
			continue
		}
		if len(r.broadcasts) > 0 && r.includeAt != 0 && nh >= r.includeAt {
			return transfer.TxStatus{State: transfer.TxCommitted, Height: r.includeAt, Code: r.code, NodeHeight: nh}, nil
		}
		return transfer.TxStatus{State: transfer.TxPending, NodeHeight: nh}, nil
	}
	return transfer.TxStatus{State: transfer.TxUnknown, NodeHeight: nh}, nil
}

func (r *fakeRail) signCalls() int      { r.mu.Lock(); defer r.mu.Unlock(); return len(r.signed) }
func (r *fakeRail) broadcastCalls() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.broadcasts) }

// spyStore logs every call to the real store and can fail chosen ones.
type spyStore struct {
	transfer.Store
	mu                  sync.Mutex
	log                 []string
	failPrep            error
	failFinish          error
	failBegin           error
	failAband           error
	rail                *fakeRail
	broadcastsAtPrepare int
}

func (s *spyStore) note(n string) { s.mu.Lock(); s.log = append(s.log, n); s.mu.Unlock() }

func (s *spyStore) calls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.log...)
}

func (s *spyStore) has(n string) bool {
	for _, c := range s.calls() {
		if c == n {
			return true
		}
	}
	return false
}

func (s *spyStore) Begin(ctx context.Context, h commitment.Hash, exp uint64) error {
	s.note("begin")
	if s.failBegin != nil {
		return s.failBegin
	}
	return s.Store.Begin(ctx, h, exp)
}

func (s *spyStore) Prepare(ctx context.Context, h commitment.Hash, p transfer.Prepared) error {
	s.note("prepare")
	if s.rail != nil {
		s.mu.Lock()
		s.broadcastsAtPrepare = s.rail.broadcastCalls()
		s.mu.Unlock()
	}
	if s.failPrep != nil {
		return s.failPrep
	}
	return s.Store.Prepare(ctx, h, p)
}

func (s *spyStore) Finish(ctx context.Context, h commitment.Hash, height uint64, code uint32) error {
	s.note("finish")
	s.mu.Lock()
	err := s.failFinish
	s.failFinish = nil
	s.mu.Unlock()
	if err != nil {
		return err
	}
	return s.Store.Finish(ctx, h, height, code)
}

func (s *spyStore) HandOff(ctx context.Context, h commitment.Hash, reason string) error {
	s.note("handoff")
	return s.Store.HandOff(ctx, h, reason)
}

func (s *spyStore) Abandon(ctx context.Context, h commitment.Hash) error {
	s.note("abandon")
	if s.failAband != nil {
		return s.failAband
	}
	return s.Store.Abandon(ctx, h)
}

type rig struct {
	t     *testing.T
	clock *fakeClock
	rail  *fakeRail
	store *spyStore
	cfg   transfer.Config
	exec  *transfer.Executor
	guard context.Context // set by cancelOnStatus
}

func newRig(t *testing.T, mods ...func(*transfer.Config)) *rig {
	t.Helper()
	c := newClock()
	r := &rig{t: t, clock: c, rail: newRail(c), guard: context.Background()}
	r.store = &spyStore{Store: transfer.NewMemStore(), rail: r.rail}
	r.cfg = transfer.Config{
		GatePubKey: gatePub(),
		GateID:     gateID,
		SkewS:      skew,
		SignKey:    seedKey(5),
	}
	for _, m := range mods {
		m(&r.cfg)
	}
	r.exec = r.restart()
	return r
}

// restart builds a new executor on the same rail, store and clock, as after
// a crash.
func (r *rig) restart() *transfer.Executor {
	r.t.Helper()
	e, err := transfer.NewExecutor(r.cfg,
		transfer.Domain{ChainID: chainID, Denom: denom, HRP: hrp, Sender: sender},
		r.rail, r.store, r.clock)
	require.NoError(r.t, err)
	return e
}

func msgBytes(t *testing.T, m bankmsg.MsgSend) []byte {
	t.Helper()
	b, err := bankmsg.Encode(m, hrp)
	require.NoError(t, err)
	return b
}

func actionBytes(t *testing.T, cid string, m bankmsg.MsgSend) []byte {
	t.Helper()
	b, err := bankaction.Encode(bankaction.Action{ChainID: cid, Msg: msgBytes(t, m)})
	require.NoError(t, err)
	return b
}

func validMsg() bankmsg.MsgSend {
	return bankmsg.MsgSend{From: sender, To: receiver, Denom: denom, Amount: 1000}
}

type authOpt func(*commitment.Authorization)

func authorize(t *testing.T, key ed25519.PrivateKey, ch commitment.Hash, actionType string, action []byte, opts ...authOpt) []byte {
	t.Helper()
	ah, err := commitment.ActionHash(actionType, action)
	require.NoError(t, err)
	a := commitment.Authorization{
		CommitmentHash: ch[:], ActionHash: ah[:], GateID: gateID,
		Expires: nowUnix + 600, Path: commitment.PathDA,
	}
	for _, o := range opts {
		o(&a)
	}
	canon, err := commitment.EncodeAuthorization(&a)
	require.NoError(t, err)
	sig := ed25519.Sign(key, commitment.AuthorizationSigningMessage(commitment.HashAuthorization(canon)))
	out, err := commitment.EncodeSignedAuthorization(&commitment.SignedAuthorization{Authorization: a, Signature: sig})
	require.NoError(t, err)
	return out
}

func goodAuth(t *testing.T, ch commitment.Hash, action []byte, opts ...authOpt) []byte {
	t.Helper()
	return authorize(t, seedKey(7), ch, bankaction.ActionType, action, opts...)
}

func (r *fakeRail) statusCalls() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.statusHashes) }
