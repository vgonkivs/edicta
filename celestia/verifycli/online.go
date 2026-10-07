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

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/celestia/cometrpc"
	"github.com/vgonkivs/edicta/celestia/headertrust"
	"github.com/vgonkivs/edicta/celestia/inclusion"
	"github.com/vgonkivs/edicta/celestia/railverify"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
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
// last batch, which cuts the calls of a long walk by that factor. A source
// that cannot answer a range is asked for the single header.
type rangeChain struct {
	src   *cometrpc.Source
	top   uint64
	first uint64
	batch [][]byte
}

func (c *rangeChain) Header(ctx context.Context, h uint64) ([]byte, error) {
	if h >= c.first && h-c.first < uint64(len(c.batch)) {
		return c.batch[h-c.first], nil
	}
	if h <= c.top {
		hi := min(h+19, c.top)
		if batch, err := c.src.Headers(ctx, h, hi); err == nil {
			c.first, c.batch = h, batch
			return batch[0], nil
		}
		if err := ctx.Err(); err != nil {
			return nil, err
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

// headers are the headers of the evidence the verifier read, offered first
// to the walk. A header that does not link then fails the decision, because
// the archive presented a header the chain does not have.
func (r *recordingReader) headers() map[uint64][]byte {
	known := map[uint64][]byte{}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.dec == nil {
		return known
	}
	sc, err := commitment.DecodeSigned(r.dec.Envelope)
	if err != nil {
		return known
	}
	ref := sc.Commitment.PayloadRef
	ev := r.evs[evKey(ref.DA, ref.Commitment)]
	if ev == nil {
		return known
	}
	if len(ev.Header) > 0 && ev.Height != 0 {
		known[ev.Height] = ev.Header
	}
	if ref.DA == commitment.DAFibre && len(ev.PromiseHeader) > 0 && ev.PromiseHeight != 0 {
		known[ev.PromiseHeight] = ev.PromiseHeader
	}
	return known
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

	done  bool
	inner verifier.HeaderTrust
	err   error
	rep   headertrust.CheckpointReport
	known map[uint64][]byte
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
				info.warn("cross-check source %s is the same node as %s and is not counted", s.Name(), first)
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
	l.known = l.rec.headers()
	var cp headertrust.Checkpoint
	if l.f.checkpoint != "" {
		h, hash, _ := parseCheckpoint(l.f.checkpoint)
		raw, err := l.online.Header(ctx, h)
		if err != nil {
			l.err = fmt.Errorf("%w: checkpoint header: %w", verifier.ErrTrustInput, err)
			return
		}
		got, err := headertrust.HashOfHeader(raw)
		if err != nil || !bytes.Equal(got, hash) {
			l.err = fmt.Errorf("%w: the headers source %s does not serve the checkpoint you gave at height %d", verifier.ErrTrustInput, l.online.Name(), h)
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
	walk := &rangeChain{src: l.online, top: cp.Height - 1}
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
// check unchecked but never failed or passed.
type trustedChain struct {
	src   *cometrpc.Source
	trust verifier.HeaderTrust
}

func (c trustedChain) Header(ctx context.Context, h uint64) ([]byte, error) {
	raw, err := c.src.Header(ctx, h)
	if err != nil {
		return nil, err
	}
	if c.trust == nil {
		return nil, errors.New("no trusted header to check it against")
	}
	hash, err := headertrust.HashOfHeader(raw)
	if err != nil {
		return nil, fmt.Errorf("%s served an unusable header: %w", c.src.Name(), err)
	}
	res, err := c.trust.Trusted(ctx, h, hash)
	if err != nil {
		return nil, fmt.Errorf("the header %s served is not on the trusted chain: %w", c.src.Name(), err)
	}
	if !res.Checked {
		return nil, errors.New("header trust did not check the header")
	}
	return raw, nil
}

// bankChecker builds the bank-send checker for the chain the authorized
// action names. The header at the transaction height reaches it only through
// header trust.
type bankChecker struct {
	tx      *cometrpc.Source
	headers *cometrpc.Source
	trust   verifier.HeaderTrust
	cross   []*cometrpc.Source
	info    *trustInfo
}

func newBankChecker(txURL, headersURL string, crossURLs []string, trust verifier.HeaderTrust, info *trustInfo) (verifier.ExecutionChecker, error) {
	tx, err := cometrpc.New(txURL, nil)
	if err != nil {
		return nil, err
	}
	if headersURL == "" {
		headersURL = txURL
	}
	hs, err := cometrpc.New(headersURL, nil)
	if err != nil {
		return nil, err
	}
	b := &bankChecker{tx: tx, headers: hs, trust: trust, info: info}
	for _, u := range crossURLs {
		s, err := cometrpc.New(u, nil)
		if err != nil {
			return nil, err
		}
		if s.Name() == tx.Name() {
			return nil, fmt.Errorf("--cross-check %s is on the host of --tx-rpc", u)
		}
		if s.Name() == hs.Name() {
			return nil, fmt.Errorf("--cross-check %s is on the host of --headers-rpc", u)
		}
		b.cross = append(b.cross, s)
	}
	return b, nil
}

func (b *bankChecker) CheckExecution(ctx context.Context, in verifier.ExecutionInput) (verifier.ExecutionFacts, error) {
	act, err := bankaction.Decode(in.Action)
	if err != nil {
		return verifier.ExecutionFacts{}, err
	}
	var cross []railverify.TxSource
	for _, s := range distinctNodes(ctx, b.info, []*cometrpc.Source{b.tx, b.headers}, b.cross) {
		cross = append(cross, s)
	}
	c, err := railverify.NewBankSend(railverify.Config{ChainID: act.ChainID, HRP: bankHRP}, b.tx, trustedChain{b.headers, b.trust}, cross)
	if err != nil {
		return verifier.ExecutionFacts{}, err
	}
	return c.CheckExecution(ctx, in)
}
