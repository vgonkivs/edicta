package verifycli

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/celestia/cometrpc"
	"github.com/vgonkivs/edicta/celestia/headertrust"
	"github.com/vgonkivs/edicta/celestia/inclusion"
	"github.com/vgonkivs/edicta/celestia/railverify"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/verifier"
)

// bankHRP is the address prefix of the chains the bank-send checker serves.
const bankHRP = "celestia"

// trustInfo is what the report says about where the trusted header came from
// and whom the verdict relies on.
type trustInfo struct {
	mode          string
	rep           *headertrust.CheckpointReport
	headersHost   string
	headerSources map[uint64]string
	crossSources  []string
	warnings      []string
}

func (i *trustInfo) source(h uint64, name string) {
	if i.headerSources == nil {
		i.headerSources = map[uint64]string{}
	}
	i.headerSources[h] = name
}

func (i *trustInfo) warn(format string, a ...any) {
	i.warnings = append(i.warnings, fmt.Sprintf(format, a...))
}

func (i *trustInfo) apply(v *reportView) {
	v.HeaderTrust.Mode = i.mode
	v.HeaderTrust.HeadersSource = i.headersHost
	v.HeaderTrust.HeaderSources = i.headerSources
	v.HeaderTrust.CrossSources = i.crossSources
	if i.rep != nil {
		v.HeaderTrust.Sources = i.rep.Sources
		v.HeaderTrust.Agreed = i.rep.Agreed
		v.HeaderTrust.Quorum = i.rep.Quorum
	}
	v.Warnings = append(v.Warnings, i.warnings...)
	v.TrustModel = i.model()
}

// model says in one line whom the header trust rests on, so that nobody reads
// "valid" as a signature check: no validator signature is verified anywhere.
func (i *trustInfo) model() string {
	const linked = "headers are linked by hash only, no validator signatures are checked"
	via := ""
	if i.headersHost != "" {
		via = "; headers served by " + i.headersHost
	}
	switch i.mode {
	case "explicit":
		return "checkpoint given by the auditor; " + linked + via
	case "agreed":
		who := "no operator"
		if i.rep != nil && len(i.rep.Sources) > 0 {
			who = fmt.Sprintf("%d operator(s) (%s)", len(i.rep.Sources), strings.Join(i.rep.Sources, ", "))
		}
		return "checkpoint taken from " + who + "; " + linked + via
	case "file":
		return "trusted header from the file the auditor gave; " + linked + via
	}
	return ""
}

func parseCheckpoint(s string) (uint64, []byte, error) {
	hs, hh, ok := strings.Cut(s, ":")
	if !ok {
		return 0, nil, errors.New("--checkpoint must be HEIGHT:HASH")
	}
	h, err := strconv.ParseUint(hs, 10, 63)
	if err != nil || h == 0 {
		return 0, nil, errors.New("--checkpoint height is not a positive number")
	}
	b, err := hex.DecodeString(hh)
	if err != nil || len(b) != 32 {
		return 0, nil, errors.New("--checkpoint hash is not 64 hex characters")
	}
	return h, b, nil
}

// rangeChain fetches headers twenty at a time and serves the walk from the
// last batch, which cuts the calls of a long walk by that factor. The walk
// goes down from the checkpoint, so a batch ends at the height asked for. A
// source that cannot answer a range is asked for the single header.
type rangeChain struct {
	src   *cometrpc.Source
	top   uint64
	first uint64
	batch [][]byte
}

// Name is the operator behind the walk, for the reports of a header that does
// not link.
func (c *rangeChain) Name() string { return c.src.Name() }

func (c *rangeChain) Header(ctx context.Context, h uint64) ([]byte, error) {
	if h >= c.first && h-c.first < uint64(len(c.batch)) {
		return bytes.Clone(c.batch[h-c.first]), nil
	}
	if h >= 1 && h <= c.top {
		// Below the lowest height a node keeps a range ending at h fails,
		// and one starting at h may still answer.
		for _, r := range [][2]uint64{{h - min(h-1, 19), h}, {h, min(h+19, c.top)}} {
			batch, err := c.src.Headers(ctx, r[0], r[1])
			if err == nil {
				c.first, c.batch = r[0], batch
				return bytes.Clone(batch[h-r[0]]), nil
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
	}
	return c.src.Header(ctx, h)
}

// recordingReader keeps what the verifier itself read from the archive, so
// that the trust layer can offer the evidence header to the walk without
// reading the archive again: a second read could answer differently.
type recordingReader struct {
	verifier.Reader
	mu  sync.Mutex
	dec *archive.DecisionRecord
	evs map[string]*archive.EvidenceRecord
}

func newRecordingReader(r verifier.Reader) *recordingReader {
	return &recordingReader{Reader: r, evs: map[string]*archive.EvidenceRecord{}}
}

func evKey(da commitment.DA, commit []byte) string {
	return fmt.Sprintf("%d/%x", da, commit)
}

func (r *recordingReader) Decision(ctx context.Context, h commitment.Hash) (*archive.DecisionRecord, error) {
	d, err := r.Reader.Decision(ctx, h)
	if err == nil {
		r.mu.Lock()
		r.dec = d
		r.mu.Unlock()
	}
	return d, err
}

func (r *recordingReader) Evidence(ctx context.Context, da commitment.DA, commit []byte) (*archive.EvidenceRecord, error) {
	e, err := r.Reader.Evidence(ctx, da, commit)
	if err == nil {
		r.mu.Lock()
		r.evs[evKey(da, commit)] = e
		r.mu.Unlock()
	}
	return e, err
}

// The policy records are not recorded; they pass through when the wrapped
// reader serves them.
var _ archive.PolicyReader = (*recordingReader)(nil)

func (r *recordingReader) policyReader() (archive.PolicyReader, error) {
	pr, ok := r.Reader.(archive.PolicyReader)
	if !ok {
		return nil, archive.ErrNotFound
	}
	return pr, nil
}

func (r *recordingReader) Mandate(ctx context.Context, h commitment.Hash) (*archive.MandateRecord, error) {
	pr, err := r.policyReader()
	if err != nil {
		return nil, err
	}
	return pr.Mandate(ctx, h)
}

func (r *recordingReader) PolicyAllow(ctx context.Context, h commitment.Hash) (*archive.PolicyAllowRecord, error) {
	pr, err := r.policyReader()
	if err != nil {
		return nil, err
	}
	return pr.PolicyAllow(ctx, h)
}

func (r *recordingReader) PolicyDeny(ctx context.Context, h commitment.Hash, reason string) (*archive.PolicyDenyRecord, error) {
	pr, err := r.policyReader()
	if err != nil {
		return nil, err
	}
	return pr.PolicyDeny(ctx, h, reason)
}

func (r *recordingReader) PolicyBucket(ctx context.Context, h commitment.Hash) (*archive.PolicyBucketRecord, error) {
	pr, err := r.policyReader()
	if err != nil {
		return nil, err
	}
	return pr.PolicyBucket(ctx, h)
}

func (r *recordingReader) PolicyClosed(ctx context.Context, h commitment.Hash) (*archive.PolicyClosedRecord, error) {
	pr, err := r.policyReader()
	if err != nil {
		return nil, err
	}
	return pr.PolicyClosed(ctx, h)
}

func (r *recordingReader) PolicySuccessor(ctx context.Context, h commitment.Hash) (*archive.PolicySuccessorRecord, error) {
	pr, err := r.policyReader()
	if err != nil {
		return nil, err
	}
	return pr.PolicySuccessor(ctx, h)
}

// A wrapped reader without private blobs or reveals answers ErrNotFound. The
// verifier reads an archive that lacks the reader exactly as one that lacks
// the record, so the wrapper changes no outcome; an operational error here
// would instead abort the whole verification.
var (
	_ archive.PrivateReader = (*recordingReader)(nil)
	_ archive.RevealReader  = (*recordingReader)(nil)
)

func (r *recordingReader) PrivateBlob(ctx context.Context, kind policy.PrivateKind, h commitment.Hash) (*archive.PrivateBlobRecord, error) {
	pr, ok := r.Reader.(archive.PrivateReader)
	if !ok {
		return nil, archive.ErrNotFound
	}
	return pr.PrivateBlob(ctx, kind, h)
}

func (r *recordingReader) Reveal(ctx context.Context, h commitment.Hash) (*archive.RevealRecord, error) {
	rr, ok := r.Reader.(archive.RevealReader)
	if !ok {
		return nil, archive.ErrNotFound
	}
	return rr.Reveal(ctx, h)
}

// headers are the headers of the evidence the verifier read, offered first
// to the walk. A header that does not link then fails the decision, because
// the archive presented a header the chain does not have.
func (r *recordingReader) headers() (map[uint64][]byte, error) {
	known := map[uint64][]byte{}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.dec == nil {
		return known, nil
	}
	sc, err := commitment.DecodeSigned(r.dec.Envelope)
	if err != nil {
		return known, nil
	}
	ref := sc.Commitment.PayloadRef
	ev := r.evs[evKey(ref.DA, ref.Commitment)]
	if ev == nil {
		return known, nil
	}
	if len(ev.Header) > 0 && ev.Height != 0 {
		inner, err := headertrust.HeaderOfSigned(ev.Header)
		if err != nil {
			return nil, fmt.Errorf("archived anchor header at height %d: %w", ev.Height, err)
		}
		known[ev.Height] = inner
	}
	if ref.DA == commitment.DAFibre && len(ev.PromiseHeader) > 0 && ev.PromiseHeight != 0 {
		inner, err := headertrust.HeaderOfSigned(ev.PromiseHeader)
		if err != nil {
			return nil, fmt.Errorf("archived promise header at height %d: %w", ev.PromiseHeight, err)
		}
		known[ev.PromiseHeight] = inner
	}
	return known, nil
}

// lazyTrust resolves the checkpoint on the first question, because the
// archived header the walk prefers is only known once the verifier has read
// the evidence. Its errors are cached: the checkpoint does not change within
// a run.
type lazyTrust struct {
	rec    *recordingReader
	online *cometrpc.Source
	f      flags
	ckpt   []*cometrpc.Source
	cross  []*cometrpc.Source
	info   *trustInfo

	done     bool
	inner    verifier.HeaderTrust
	err      error
	rep      headertrust.CheckpointReport
	known    map[uint64][]byte
	cpHeight uint64
	// window serves the headers of the archived absence proofs after the
	// online source.
	window headertrust.HeaderChain
}

func newLazyTrust(rec *recordingReader, f flags, info *trustInfo) (*lazyTrust, error) {
	online, err := cometrpc.New(f.headersRPC, nil)
	if err != nil {
		return nil, err
	}
	lt := &lazyTrust{rec: rec, online: online, f: f, info: info}
	info.headersHost = online.Name()
	if f.checkpoint != "" {
		info.mode = "explicit"
	} else {
		info.mode = "agreed"
	}
	if err := inclusion.CheckDistinctSources(f.checkpointRPC); err != nil {
		return nil, fmt.Errorf("--checkpoint-rpc: %w", err)
	}
	if err := inclusion.CheckDistinctSources(f.crossRPC); err != nil {
		return nil, fmt.Errorf("--cross-check: %w", err)
	}
	for _, u := range f.checkpointRPC {
		s, err := cometrpc.New(u, nil)
		if err != nil {
			return nil, err
		}
		lt.ckpt = append(lt.ckpt, s)
	}
	for _, u := range f.crossRPC {
		s, err := cometrpc.New(u, nil)
		if err != nil {
			return nil, err
		}
		for _, c := range lt.ckpt {
			if c.Name() == s.Name() {
				return nil, fmt.Errorf("--cross-check %s is on a host that gave the checkpoint", u)
			}
		}
		if s.Name() == online.Name() {
			return nil, fmt.Errorf("--cross-check %s is on the host of --headers-rpc, which already served the walk", u)
		}
		lt.cross = append(lt.cross, s)
	}
	return lt, nil
}

// distinctNodes drops the sources that are the same node as one already
// taken, by the node id of /status, and says so in the report. A source whose
// id cannot be read counts by its host alone.
func distinctNodes(ctx context.Context, info *trustInfo, taken []*cometrpc.Source, srcs []*cometrpc.Source) []*cometrpc.Source {
	if len(srcs) == 0 {
		return nil
	}
	ids := map[string]string{}
	for _, s := range taken {
		if id, err := s.NodeID(ctx); err == nil {
			ids[id] = s.Name()
		}
	}
	var out []*cometrpc.Source
	for _, s := range srcs {
		if id, err := s.NodeID(ctx); err == nil {
			if first, dup := ids[id]; dup {
				info.warn("source %s is the same node as %s and is not counted", s.Name(), first)
				continue
			}
			ids[id] = s.Name()
		}
		out = append(out, s)
	}
	return out
}

func (l *lazyTrust) init(ctx context.Context) {
	l.done = true
	known, err := l.rec.headers()
	if err != nil {
		l.err = verifier.WithReason(verifier.ReasonHeaderNotLinking, nil, err)
		return
	}
	l.known = known
	var cp headertrust.Checkpoint
	if l.f.checkpoint != "" {
		h, hash, _ := parseCheckpoint(l.f.checkpoint)
		raw, err := l.online.Header(ctx, h)
		if err != nil {
			l.err = verifier.WithReason(verifier.ReasonHeaderSourceUnavailable, []string{l.online.Name()},
				fmt.Errorf("%w: checkpoint header: %w", verifier.ErrTrustInput, err))
			return
		}
		got, err := headertrust.HashOfHeader(raw)
		if err != nil || !bytes.Equal(got, hash) {
			l.err = verifier.WithReason(verifier.ReasonHeaderDisagreement, []string{l.online.Name()},
				fmt.Errorf("%w: %s: the headers source %s does not serve the checkpoint you gave at height %d", verifier.ErrTrustInput, verifier.DisagreementText, l.online.Name(), h))
			return
		}
		cp = headertrust.Checkpoint{Height: h, Hash: hash, Header: raw}
	} else {
		srcs := make([]headertrust.NamedChain, len(l.ckpt))
		for i, s := range l.ckpt {
			srcs[i] = s
		}
		c, rep, err := headertrust.AgreedCheckpoint(ctx, srcs, l.f.quorum)
		l.rep = rep
		l.info.rep = &l.rep
		if err != nil {
			l.err = err
			return
		}
		cp = c
	}
	taken := append([]*cometrpc.Source{l.online}, l.ckpt...)
	cross := distinctNodes(ctx, l.info, taken, l.cross)
	chains := make([]headertrust.HeaderChain, len(cross))
	for i, s := range cross {
		chains[i] = s
		l.info.crossSources = append(l.info.crossSources, s.Name())
	}
	var walk headertrust.HeaderChain = &rangeChain{src: l.online, top: cp.Height - 1}
	if l.window != nil {
		walk = firstOf{walk, l.window}
	}
	l.cpHeight = cp.Height
	l.inner = headertrust.New(cp, headertrust.Prefer(l.known, walk), chains)
}

func (l *lazyTrust) Trusted(ctx context.Context, height uint64, hash []byte) (verifier.TrustResult, error) {
	if !l.done {
		l.init(ctx)
	}
	if l.err != nil {
		return verifier.TrustResult{}, l.err
	}
	if _, ok := l.known[height]; ok {
		l.info.source(height, "archive")
	} else {
		l.info.source(height, l.online.Name())
	}
	return l.inner.Trusted(ctx, height, hash)
}

// trustedChain serves only headers that header trust has tied to the trusted
// chain. The bank-send checker judges the chain id and the inclusion proof
// against the header it gets here, so a header source that lies can make the
// check unchecked but never failed or passed. Every error carries the reason
// and the source it blames.
type trustedChain struct {
	src   *cometrpc.Source
	trust verifier.HeaderTrust
}

func (c trustedChain) Header(ctx context.Context, h uint64) ([]byte, error) {
	blame := []string{c.src.Name()}
	raw, err := c.src.Header(ctx, h)
	if err != nil {
		return nil, verifier.WithReason(verifier.ReasonHeaderNotLinking, blame, err)
	}
	if c.trust == nil {
		return nil, verifier.WithReason(verifier.ReasonNoTrustedHeader, nil, errors.New("no trusted header to check it against"))
	}
	hash, err := headertrust.HashOfHeader(raw)
	if err != nil {
		return nil, verifier.WithReason(verifier.ReasonHeaderNotLinking, blame, fmt.Errorf("%s served an unusable header: %w", c.src.Name(), err))
	}
	res, err := c.trust.Trusted(ctx, h, hash)
	if err != nil {
		if _, _, ok := verifier.ReasonOf(err); !ok {
			err = verifier.WithReason(verifier.ReasonHeaderNotLinking, blame, err)
		}
		return nil, fmt.Errorf("the header %s served at height %d is not on the trusted chain: %w", c.src.Name(), h, err)
	}
	if !res.Checked {
		return nil, verifier.WithReason(verifier.ReasonHeaderNotLinking, blame, errors.New("header trust did not check the header"))
	}
	return raw, nil
}

// bankChecker builds the bank-send checker for the chain the authorized
// action names. The header at the transaction height reaches it only through
// header trust.
type bankChecker struct {
	txs     []*cometrpc.Source
	headers *cometrpc.Source
	trust   verifier.HeaderTrust
	cross   []*cometrpc.Source
	info    *trustInfo
	// chainID is the chain a revealed private action is rebuilt for; empty
	// takes the DA chain.
	chainID string
}

// newBankChecker takes the tx sources in order, the first the primary and the
// rest alternates, and the cross sources. Every source must be on a host of
// its own.
func newBankChecker(txURLs []string, headersURL string, crossURLs []string, trust verifier.HeaderTrust, info *trustInfo,
	chainID string) (verifier.ExecutionChecker, error) {
	if len(txURLs) == 0 {
		return nil, errors.New("no --tx-rpc")
	}
	if headersURL == "" {
		headersURL = txURLs[0]
	}
	hs, err := cometrpc.New(headersURL, nil)
	if err != nil {
		return nil, err
	}
	b := &bankChecker{headers: hs, trust: trust, info: info, chainID: chainID}
	taken := map[string]string{hs.Name(): "--headers-rpc"}
	for i, u := range txURLs {
		s, err := cometrpc.New(u, nil)
		if err != nil {
			return nil, err
		}
		// The primary may share the headers host: with no --headers-rpc the
		// same node serves both. Alternates must be other operators.
		if prev, dup := taken[s.Name()]; dup && i > 0 {
			return nil, fmt.Errorf("--tx-rpc %s is on the host of %s", u, prev)
		}
		taken[s.Name()] = "--tx-rpc"
		b.txs = append(b.txs, s)
	}
	for _, u := range crossURLs {
		s, err := cometrpc.New(u, nil)
		if err != nil {
			return nil, err
		}
		if prev, dup := taken[s.Name()]; dup {
			return nil, fmt.Errorf("--cross-check %s is on the host of %s", u, prev)
		}
		taken[s.Name()] = "--cross-check"
		b.cross = append(b.cross, s)
	}
	return b, nil
}

func (b *bankChecker) CheckExecution(ctx context.Context, in verifier.ExecutionInput) (verifier.ExecutionFacts, error) {
	act, err := bankaction.Decode(in.Action)
	if err != nil {
		return verifier.ExecutionFacts{}, fmt.Errorf("%w: %w", verifier.ErrExecutionViolation, err)
	}
	// The primary is kept whatever its node id says; an alternate or a cross
	// source that is the same node as one already taken adds no independence.
	primary := b.txs[0]
	var alts []railverify.TxSource
	for _, s := range distinctNodes(ctx, b.info, []*cometrpc.Source{primary, b.headers}, b.txs[1:]) {
		alts = append(alts, s)
	}
	var cross []railverify.TxSource
	for _, s := range distinctNodes(ctx, b.info, append([]*cometrpc.Source{primary, b.headers}, b.txs[1:]...), b.cross) {
		cross = append(cross, s)
	}
	c, err := railverify.NewBankSend(railverify.Config{ChainID: act.ChainID, HRP: bankHRP}, primary,
		trustedChain{b.headers, b.trust}, cross,
		railverify.WithAlternates(alts...), railverify.WithResultsSources(b.headers))
	if err != nil {
		return verifier.ExecutionFacts{}, err
	}
	return c.CheckExecution(ctx, in)
}

// PublicExecution: a bank send is a public transaction, so the gate's reveal
// of a private action can be checked against it.
func (b *bankChecker) PublicExecution() bool { return true }

// ActionFromTx rebuilds the action of the transaction the receipt names. The
// action of a private decision is not known, so its chain id is the one the
// profile is configured for (--exec-chain-id), else that of the trusted
// header at the reference height: a transaction on another chain gives
// another action, which the action hash then refuses.
func (b *bankChecker) ActionFromTx(ctx context.Context, in verifier.ExecutionInput) ([]byte, error) {
	headers := trustedChain{b.headers, b.trust}
	chainID := b.chainID
	if chainID == "" {
		raw, err := headers.Header(ctx, in.AnchorHeight)
		if err != nil {
			return nil, err
		}
		var ph cmtproto.Header
		if err := ph.Unmarshal(raw); err != nil || ph.ChainID == "" {
			return nil, fmt.Errorf("the trusted header at %d names no chain", in.AnchorHeight)
		}
		chainID = ph.ChainID
	}
	primary := b.txs[0]
	var alts []railverify.TxSource
	for _, s := range distinctNodes(ctx, b.info, []*cometrpc.Source{primary, b.headers}, b.txs[1:]) {
		alts = append(alts, s)
	}
	c, err := railverify.NewBankSend(railverify.Config{ChainID: chainID, HRP: bankHRP}, primary, headers, nil,
		railverify.WithAlternates(alts...))
	if err != nil {
		return nil, err
	}
	ar, ok := c.(verifier.ActionRevealer)
	if !ok {
		return nil, errors.New("the bank-send checker offers no reveal")
	}
	return ar.ActionFromTx(ctx, in)
}
