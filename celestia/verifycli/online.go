package verifycli

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

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

// trustInfo is what the report says about where the trusted header came from.
type trustInfo struct {
	mode string
	rep  *headertrust.CheckpointReport
}

func (i *trustInfo) apply(v *reportView) {
	v.HeaderTrust.Mode = i.mode
	if i.rep != nil {
		v.HeaderTrust.Sources = i.rep.Sources
		v.HeaderTrust.Agreed = i.rep.Agreed
		v.HeaderTrust.Quorum = i.rep.Quorum
	}
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
	if err != nil || len(b) == 0 {
		return 0, nil, errors.New("--checkpoint hash is not hex")
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

// lazyTrust resolves the checkpoint on the first question, because the
// archived header the walk prefers is only known once the decision is read.
// Its errors are cached: the checkpoint does not change within a run.
type lazyTrust struct {
	r      verifier.Reader
	h      commitment.Hash
	online *cometrpc.Source
	f      flags
	ckpt   []*cometrpc.Source
	cross  []*cometrpc.Source
	info   *trustInfo

	done  bool
	inner verifier.HeaderTrust
	err   error
	rep   headertrust.CheckpointReport
}

func newLazyTrust(r verifier.Reader, f flags, info *trustInfo) (*lazyTrust, error) {
	online, err := cometrpc.New(f.headersRPC, nil)
	if err != nil {
		return nil, err
	}
	lt := &lazyTrust{r: r, h: f.hash, online: online, f: f, info: info}
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
		lt.cross = append(lt.cross, s)
	}
	return lt, nil
}

// archivedHeaders are the headers of the evidence, offered first to the
// walk. A header that does not link then fails the decision, because the
// archive presented a header the chain does not have.
func (l *lazyTrust) archivedHeaders(ctx context.Context) map[uint64][]byte {
	known := map[uint64][]byte{}
	dec, err := l.r.Decision(ctx, l.h)
	if err != nil {
		return known
	}
	sc, err := commitment.DecodeSigned(dec.Envelope)
	if err != nil {
		return known
	}
	ref := sc.Commitment.PayloadRef
	ev, err := l.r.Evidence(ctx, ref.DA, ref.Commitment)
	if err != nil {
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

func (l *lazyTrust) init(ctx context.Context) {
	l.done = true
	var cp headertrust.Checkpoint
	if l.f.checkpoint != "" {
		h, hash, _ := parseCheckpoint(l.f.checkpoint)
		raw, err := l.online.Header(ctx, h)
		if err != nil {
			l.err = fmt.Errorf("%w: checkpoint header: %w", verifier.ErrTrustInput, err)
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
	cross := make([]headertrust.HeaderChain, len(l.cross))
	for i, s := range l.cross {
		cross[i] = s
	}
	walk := &rangeChain{src: l.online, top: cp.Height - 1}
	l.inner = headertrust.New(cp, headertrust.Prefer(l.archivedHeaders(ctx), walk), cross)
}

func (l *lazyTrust) Trusted(ctx context.Context, height uint64, hash []byte) (verifier.TrustResult, error) {
	if !l.done {
		l.init(ctx)
	}
	if l.err != nil {
		return verifier.TrustResult{}, l.err
	}
	return l.inner.Trusted(ctx, height, hash)
}

// bankChecker builds the bank-send checker for the chain the authorized
// action names. The header at the transaction height is then checked against
// that chain id, and by header trust against the trusted header.
type bankChecker struct {
	tx      *cometrpc.Source
	headers *cometrpc.Source
	cross   []railverify.TxSource
}

func newBankChecker(txURL, headersURL string, crossURLs []string) (verifier.ExecutionChecker, error) {
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
	b := &bankChecker{tx: tx, headers: hs}
	for _, u := range crossURLs {
		s, err := cometrpc.New(u, nil)
		if err != nil {
			return nil, err
		}
		if s.Name() == tx.Name() {
			return nil, fmt.Errorf("--cross-check %s is on the host of --tx-rpc", u)
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
	c, err := railverify.NewBankSend(railverify.Config{ChainID: act.ChainID, HRP: bankHRP}, b.tx, b.headers, b.cross)
	if err != nil {
		return verifier.ExecutionFacts{}, err
	}
	return c.CheckExecution(ctx, in)
}
