package recorder

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/celestia/gatechain"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/fibre/fibrecommit"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/sdk"
)

// EscrowShortfall is the error of an escrow that cannot pay for an upload.
type EscrowShortfall struct {
	NeedUtia      uint64
	AvailableUtia uint64
	ShortUtia     uint64
}

func (e *EscrowShortfall) Error() string {
	return fmt.Sprintf("%v: need %d utia, available %d, short %d", ErrEscrowInsufficient, e.NeedUtia, e.AvailableUtia, e.ShortUtia)
}

func (e *EscrowShortfall) Unwrap() error { return ErrEscrowInsufficient }

const (
	fibreBaseGas   = 650_000
	fibreGasPerRow = 45_000
	fibreRowBytes  = 262_144

	// fibreSettleFloor is the promise height window of the known networks
	// (1000 blocks) plus the two blocks the span adds and
	// fibreFreshnessBlocks.
	fibreSettleFloor = 1000 + 2 + fibreFreshnessBlocks
	// fibreFreshnessBlocks covers how far the first head seen for a blob may
	// lag the head an earlier process read (headFreshness plus the clock
	// skew bound, at the fastest expected block time).
	fibreFreshnessBlocks = 64
	maxFibreClockSkew    = 2 * time.Minute
)

// FibreCostUtia is the escrow charge of one pay-for-fibre tx for an upload of
// uploadSize bytes: 650000 + 45000*ceil(uploadSize/262144) utia at one utia
// per gas.
func FibreCostUtia(uploadSize uint64) uint64 {
	rows := uploadSize / fibreRowBytes
	if uploadSize%fibreRowBytes != 0 {
		rows++
	}
	return fibreBaseGas + fibreGasPerRow*rows
}

// FibreConfig configures a FibreRecorder.
type FibreConfig struct {
	// Namespace is a 29-byte version 0 user namespace.
	Namespace []byte
	// MaxDataBytes is the largest blob; default 1 MiB, at most the
	// committer's cap.
	MaxDataBytes uint64
	// SubmitTimeout bounds SubmitFibre; default 5m.
	SubmitTimeout time.Duration
	// UploadDrain is how long shard uploads may continue after SubmitFibre
	// returns; default 2m.
	UploadDrain time.Duration
	// MaxDraining bounds submits in flight or draining, each of which holds
	// about 13 times its payload in memory; default 2.
	MaxDraining int
	// EscrowMarginUtia is kept on top of the cost of an upload.
	EscrowMarginUtia uint64
	// VisibleTimeout bounds the wait until the read nodes serve the anchor;
	// default 60s.
	VisibleTimeout time.Duration
	// PollInterval is the read node polling period; default 1s.
	PollInterval time.Duration
	// ScanBlocks caps how many heights one settle reads per call; it cannot
	// go below 1024.
	ScanBlocks uint64
	// SettleBlocks is the floor of the settle span; the span is at least the
	// chain's promise height window plus a margin for a lagging first head.
	// Default 1024; a non-zero value below 1024 is refused.
	SettleBlocks uint64
	// MaxClockSkew bounds the distance between the local clock, which dates
	// the promise, and the chain head time; default 60s, at most 2m. The
	// gate's retention margin must exceed it.
	MaxClockSkew time.Duration
	// MaxPending caps blobs whose outcome is unresolved; default 4096.
	MaxPending int
	// OwnNode attests that the submit node is the operator's own.
	OwnNode bool
	// Archive receives the payload before the submit and the evidence after
	// it. Required: without it a restart could pay twice. There must be one
	// writer per (signer, archive): two recorders on the same signer and
	// archive, in one process or two, can both pay for one blob.
	Archive archive.Store
	// Now is the clock for entry expiry and the clock check; nil means time.Now.
	Now func() time.Time
}

// WithDefaults returns c with zero fields replaced by their defaults. Call it
// before ValidateBasic.
func (c FibreConfig) WithDefaults() FibreConfig {
	c.Namespace = bytes.Clone(c.Namespace)
	if c.MaxDataBytes == 0 {
		c.MaxDataBytes = 1 << 20
	}
	if c.SubmitTimeout <= 0 {
		c.SubmitTimeout = 5 * time.Minute
	}
	if c.UploadDrain <= 0 {
		c.UploadDrain = 2 * time.Minute
	}
	if c.MaxDraining <= 0 {
		c.MaxDraining = 2
	}
	if c.VisibleTimeout <= 0 {
		c.VisibleTimeout = 60 * time.Second
	}
	if c.PollInterval <= 0 {
		c.PollInterval = time.Second
	}
	if c.ScanBlocks < scanFloor {
		c.ScanBlocks = scanFloor
	}
	if c.SettleBlocks == 0 {
		c.SettleBlocks = fibreSettleFloor
	}
	if c.MaxClockSkew <= 0 {
		c.MaxClockSkew = 60 * time.Second
	}
	if c.MaxPending <= 0 {
		c.MaxPending = defaultMaxPending
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c
}

// ValidateBasic checks the stateless fields.
func (c FibreConfig) ValidateBasic() error {
	if err := checkNamespace(c.Namespace); err != nil {
		return err
	}
	if c.SettleBlocks != 0 && c.SettleBlocks < fibreSettleFloor {
		return fmt.Errorf("%w: settle window of %d blocks is below %d", errInvalidInput, c.SettleBlocks, fibreSettleFloor)
	}
	if c.MaxClockSkew > maxFibreClockSkew {
		return fmt.Errorf("%w: max clock skew %s is above %s", errInvalidInput, c.MaxClockSkew, maxFibreClockSkew)
	}
	if !c.OwnNode {
		return fmt.Errorf("%w: da = 1 submits only through the operator's own node; set OwnNode", errInvalidInput)
	}
	return nil
}

// FibreChain is the own-node consensus read set beyond the anchor lookup.
type FibreChain interface {
	node.FibreChainReader
	LatestHeight(ctx context.Context) (uint64, error)
	TxPlace(ctx context.Context, hash [32]byte) (node.TxPlacement, error)
	ValidatorSet(ctx context.Context, height uint64) ([]byte, error)
	FibreParams(ctx context.Context) (node.FibreParams, error)
	// Addr is the consensus gRPC address the reads go to.
	Addr() string
}

// FibreDeps are the collaborators of a FibreRecorder.
type FibreDeps struct {
	Submitter node.FibreSubmitter
	// Reader is the own consensus node plus the bridge.
	Reader    node.FibreAnchorReader
	Chain     FibreChain
	ChainID   string
	Committer *fibrecommit.Committer
	Log       *slog.Logger
	// Fast, when set, makes Publish return pending references. Its uploader
	// must read from the same consensus node as Chain. Submitter is still
	// needed for the escrow reads.
	Fast *FastDeps
}

// FibreRecorder implements sdk.Publisher for da = 1 through the operator's
// own node.
type FibreRecorder struct {
	cfg FibreConfig
	d   FibreDeps
	eng *engine
	// scanner skips the certificate: it only finds candidates. confirmer
	// applies the certificate rule the gate applies.
	scanner   *gatechain.FibreAnchors
	confirmer *gatechain.FibreAnchors
	slots     chan struct{}

	mu       sync.Mutex
	closed   bool
	active   int
	idle     chan struct{}
	reserved uint64
	cancels  map[int]context.CancelFunc
	nextID   int

	fast      *fastCore
	delayWarn sync.Once
}

var (
	_ sdk.Publisher = (*FibreRecorder)(nil)
	_ backend       = (*FibreRecorder)(nil)
)

// NewFibre validates cfg and the wiring. Submitting and reading must go to
// the same consensus node, so that the heads the settle logic reads and the
// valset heights the promise uses come from one node: the consensus endpoint
// must name one node, not a load balancer. Build the Submitter with
// node.NewFibreSigning.
func NewFibre(cfg FibreConfig, d FibreDeps) (*FibreRecorder, error) {
	cfg = cfg.WithDefaults()
	if err := cfg.ValidateBasic(); err != nil {
		return nil, err
	}
	if cfg.Archive == nil {
		return nil, fmt.Errorf("%w: da = 1 needs an archive", errInvalidInput)
	}
	if d.Submitter == nil || d.Reader == nil || d.Chain == nil || d.Committer == nil || d.ChainID == "" {
		return nil, fmt.Errorf("%w: missing dependency", errInvalidInput)
	}
	if cfg.MaxDataBytes > d.Committer.MaxDataSize() {
		return nil, fmt.Errorf("%w: MaxDataBytes %d above the committer cap %d", errInvalidInput, cfg.MaxDataBytes, d.Committer.MaxDataSize())
	}
	if normEndpoint(d.Submitter.Endpoint()) != normEndpoint(d.Chain.Addr()) {
		return nil, fmt.Errorf("%w: the submit node %q is not the read node %q", errInvalidInput, d.Submitter.Endpoint(), d.Chain.Addr())
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.Fast != nil {
		if err := d.Fast.check(commitment.DAFibre); err != nil {
			return nil, err
		}
		if normEndpoint(d.Fast.Uploader.Endpoint()) != normEndpoint(d.Chain.Addr()) {
			return nil, fmt.Errorf("%w: the upload node %q is not the read node %q", errInvalidInput, d.Fast.Uploader.Endpoint(), d.Chain.Addr())
		}
		if d.Fast.Log == nil {
			d.Fast.Log = d.Log
		}
	}
	r := &FibreRecorder{
		cfg: cfg, d: d,
		eng:       newEngine(cfg.Archive, cfg.Now, cfg.MaxPending, cfg.ScanBlocks),
		scanner:   gatechain.NewFibreAnchors(d.Reader, d.ChainID, gatechain.FibreAnchorOptions{SkipCertificate: true, Log: d.Log}),
		confirmer: gatechain.NewFibreAnchors(d.Reader, d.ChainID, gatechain.FibreAnchorOptions{Log: d.Log}),
		slots:     make(chan struct{}, cfg.MaxDraining),
		cancels:   map[int]context.CancelFunc{},
	}
	if d.Fast != nil {
		var err error
		if r.fast, err = newFastCore(r.eng, *d.Fast, cfg.PollInterval); err != nil {
			return nil, err
		}
		r.fast.start(func(context.Context) (fastDA, error) { return r, nil })
	}
	return r, nil
}

// normEndpoint lower-cases a host:port and strips a scheme.
func normEndpoint(s string) string {
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	return strings.ToLower(s)
}

// Publish uploads blob, pays for it, and returns once the anchor and its
// evidence are verified and archived. With FibreDeps.Fast it returns the
// pending reference once the anchor intent is archived and sent.
func (r *FibreRecorder) Publish(ctx context.Context, blob []byte) (sdk.Published, error) {
	if err := ctx.Err(); err != nil {
		return sdk.Published{}, err
	}
	if uint64(len(blob)) > r.cfg.MaxDataBytes {
		return sdk.Published{}, fmt.Errorf("%w: %d bytes", ErrTooLarge, len(blob))
	}
	blob = bytes.Clone(blob)
	c, err := fibrecommit.Commitment(blob)
	if err != nil {
		return sdk.Published{}, fmt.Errorf("recorder: commitment: %w", err)
	}
	if r.fast != nil {
		return r.publishFast(ctx, c[:], blob)
	}
	return r.eng.publish(ctx, r, c[:], blob)
}

// Close refuses new publishes, waits until ctx ends for uploads to drain, and
// then cancels whatever is still uploading. Call it before closing the node
// client.
func (r *FibreRecorder) Close(ctx context.Context) error {
	r.eng.closeIntake()
	r.mu.Lock()
	r.closed = true
	var wait chan struct{}
	if r.active > 0 {
		if r.idle == nil {
			r.idle = make(chan struct{})
		}
		wait = r.idle
	}
	r.mu.Unlock()

	var err error
	if wait != nil {
		select {
		case <-wait:
		case <-ctx.Done():
			err = ctx.Err()
		}
	}
	r.mu.Lock()
	for _, cancel := range r.cancels {
		cancel()
	}
	r.mu.Unlock()
	if r.fast != nil {
		err = errors.Join(err, r.fast.close(ctx))
	}
	return err
}

func (r *FibreRecorder) da() commitment.DA { return commitment.DAFibre }

// A failed submit is submitted again once its settle window has passed: the
// chain bounds when the earlier attempt can still land.
func (r *FibreRecorder) retries() bool { return true }

func (r *FibreRecorder) head(ctx context.Context) (uint64, time.Time, error) {
	h, err := r.d.Chain.LatestHeight(ctx)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("%w: head: %w", ErrNodeUnavailable, err)
	}
	if h == 0 {
		return 0, time.Time{}, fmt.Errorf("%w: head at height 0", ErrNodeUnavailable)
	}
	hdr, err := r.d.Chain.Header(ctx, h)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("%w: head header: %w", ErrNodeUnavailable, err)
	}
	return h, hdr.Time, nil
}

func (r *FibreRecorder) payloadRecord(comm, blob []byte, intent uint64) *archive.PayloadRecord {
	return &archive.PayloadRecord{DA: commitment.DAFibre, Commitment: bytes.Clone(comm), Blob: bytes.Clone(blob), IntentHeight: intent}
}

func (r *FibreRecorder) samePayload(old *archive.PayloadRecord, blob []byte) error {
	if !bytes.Equal(old.Blob, blob) {
		return archive.ErrConflict
	}
	return nil
}

// span is the chain's own bound: a pay-for-fibre tx is accepted only within
// the promise height window of the promise height, and the promise height is
// at most the head the client read. It is read at every settle and never
// shrinks for an entry already waiting.
func (r *FibreRecorder) span(ctx context.Context) (uint64, error) {
	p, err := r.d.Chain.FibreParams(ctx)
	if err != nil {
		return 0, fmt.Errorf("%w: fibre params: %w", ErrNodeUnavailable, err)
	}
	if p.PromiseHeightWindow == 0 {
		return 0, fmt.Errorf("%w: the node reports no promise height window", ErrNodeUnavailable)
	}
	return max(r.cfg.SettleBlocks, p.PromiseHeightWindow+2+fibreFreshnessBlocks), nil
}

func (r *FibreRecorder) present(ctx context.Context, comm []byte, height uint64) (bool, error) {
	_, err := r.scanner.Lookup(ctx, r.ref(comm, height))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, gate.ErrAnchorNotFound):
		return false, nil
	default:
		return false, err
	}
}

func (r *FibreRecorder) ref(comm []byte, height uint64) commitment.PayloadRef {
	return commitment.PayloadRef{DA: commitment.DAFibre, Namespace: bytes.Clone(r.cfg.Namespace), Commitment: bytes.Clone(comm), Height: height}
}

func uploadSize(blob []byte) (uint64, error) {
	us, err := fibrecommit.UploadSize(uint64(len(blob)))
	if err != nil {
		return 0, fmt.Errorf("recorder: upload size: %w", err)
	}
	return us, nil
}

// preflight takes an upload slot and checks the escrow. No path here or
// anywhere in the Recorder moves funds.
func (r *FibreRecorder) preflight(ctx context.Context, blob []byte, headTime time.Time) (func(), error) {
	if d := absDuration(r.cfg.Now().Sub(headTime)); d > r.cfg.MaxClockSkew {
		return nil, fmt.Errorf("%w: %s from the head time", ErrClockSkew, d)
	}
	us, err := uploadSize(blob)
	if err != nil {
		return nil, err
	}
	cost := FibreCostUtia(us)

	select {
	case r.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		<-r.slots
		return nil, errClosed
	}
	r.active++
	// The cost of submits in flight is not in the escrow yet, so it counts
	// against it, and this one counts from now on.
	need := satAdd(satAdd(cost, r.cfg.EscrowMarginUtia), r.reserved)
	r.reserved = satAdd(r.reserved, cost)
	r.mu.Unlock()

	esc, err := r.d.Submitter.Escrow(ctx)
	if err != nil {
		r.unreserve(cost)
		r.free()
		return nil, fmt.Errorf("%w: escrow: %w", ErrNodeUnavailable, err)
	}
	if esc.AvailableUtia < need {
		r.unreserve(cost)
		r.free()
		return nil, &EscrowShortfall{NeedUtia: need, AvailableUtia: esc.AvailableUtia, ShortUtia: need - esc.AvailableUtia}
	}
	return r.free, nil
}

func satAdd(a, b uint64) uint64 {
	if a > math.MaxUint64-b {
		return math.MaxUint64
	}
	return a + b
}

func (r *FibreRecorder) unreserve(cost uint64) {
	r.mu.Lock()
	r.reserved -= min(r.reserved, cost)
	r.mu.Unlock()
}

// free gives the slot back; the last one wakes Close.
func (r *FibreRecorder) free() {
	r.mu.Lock()
	r.active--
	if r.active <= 0 && r.idle != nil {
		close(r.idle)
		r.idle = nil
	}
	r.mu.Unlock()
	<-r.slots
}

// submit runs upload, payment and inclusion under a context detached from the
// caller: the shard uploads that continue after SubmitFibre returns must
// outlive Publish, so the caller's cancel and SubmitTimeout end the call
// itself, and UploadDrain ends what is left. release is called when the
// drain ends.
func (r *FibreRecorder) submit(ctx context.Context, comm, blob []byte, release func()) (uint64, error) {
	us, err := uploadSize(blob)
	if err != nil {
		release()
		return 0, err
	}
	cost := FibreCostUtia(us)

	uctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	r.mu.Lock()
	id := r.nextID
	r.nextID++
	r.cancels[id] = cancel
	r.mu.Unlock()
	stop := context.AfterFunc(ctx, cancel)
	timer := time.AfterFunc(r.cfg.SubmitTimeout, cancel)

	res, serr := r.d.Submitter.SubmitFibre(uctx, r.cfg.Namespace, blob)

	stop()
	timer.Stop()
	time.AfterFunc(r.cfg.UploadDrain, func() {
		cancel()
		r.mu.Lock()
		delete(r.cancels, id)
		r.mu.Unlock()
		release()
	})
	r.unreserve(cost)

	if serr != nil {
		return 0, fmt.Errorf("%w: %w", ErrOutcomeUnknown, serr)
	}
	if res.BlobID != fibrecommit.BlobID([32]byte(comm)) || !bytes.Equal(res.Namespace, r.cfg.Namespace) ||
		!bytes.Equal(res.Commitment[:], comm) || uint64(res.BlobSize) != us {
		return 0, fmt.Errorf("%w: the node reported other blob fields than computed", ErrSubmitMismatch)
	}
	return res.Height, nil
}

func (r *FibreRecorder) confirm(ctx context.Context, comm, _ []byte, height uint64, claimed bool) (sdk.Published, error) {
	ref := r.ref(comm, height)
	var fa gatechain.FibreAnchor
	var err error
	if claimed {
		fa, err = r.awaitVisible(ctx, ref)
	} else {
		fa, err = r.confirmer.Lookup(ctx, ref)
		switch {
		case err == nil:
		case errors.Is(err, gate.ErrAnchorNotFound):
			// The scan found a successful tx of this blob here, so only the
			// certificate can be what fails.
			err = fmt.Errorf("%w: %w", ErrAnchorRejected, err)
		default:
			err = fmt.Errorf("%w: confirm: %w", ErrNodeUnavailable, err)
		}
	}
	if err != nil {
		return sdk.Published{}, err
	}
	pub, ev, err := r.buildEvidence(ctx, ref, fa)
	if err != nil {
		return sdk.Published{}, err
	}
	if _, err := r.cfg.Archive.Put(ctx, ev); err != nil {
		return sdk.Published{}, archiveFault("write evidence record", err)
	}
	return pub, nil
}

// awaitVisible waits until the node's claim of the height holds on the read
// nodes. A claim that does not hold is not an absent anchor: the settle scan
// decides.
func (r *FibreRecorder) awaitVisible(ctx context.Context, ref commitment.PayloadRef) (gatechain.FibreAnchor, error) {
	deadline := time.Now().Add(r.cfg.VisibleTimeout)
	for {
		fa, err := r.confirmer.Lookup(ctx, ref)
		if err == nil {
			return fa, nil
		}
		if errors.Is(err, gate.ErrAnchorNotFound) {
			return gatechain.FibreAnchor{}, fmt.Errorf("%w: the node's height claim does not hold", ErrOutcomeUnknown)
		}
		if cerr := ctx.Err(); cerr != nil {
			return gatechain.FibreAnchor{}, fmt.Errorf("%w: %w", ErrNodeUnavailable, cerr)
		}
		if !time.Now().Before(deadline) {
			return gatechain.FibreAnchor{}, fmt.Errorf("%w: %w", ErrNotVisible, err)
		}
		t := time.NewTimer(r.cfg.PollInterval)
		select {
		case <-ctx.Done():
			t.Stop()
		case <-t.C:
		}
	}
}
