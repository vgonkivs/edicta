package railverify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	core "github.com/cometbft/cometbft/types"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/vgonkivs/edicta/celestia/headertrust"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
	"github.com/vgonkivs/edicta/verifier"
)

type bankSend struct {
	cfg        Config
	candidates []TxSource
	headers    headertrust.HeaderChain
	cross      []TxSource
	results    []ResultsSource
	verifyTx   ProofVerifier
}

// Option changes how NewBankSend builds the checker.
type Option func(*bankSend)

// WithAlternates adds tx sources that are tried, in order, after the primary
// when its answer is unusable.
func WithAlternates(alts ...TxSource) Option {
	return func(c *bankSend) { c.candidates = append(c.candidates, alts...) }
}

// WithResultsSources adds sources of block results besides the tx and cross
// sources that serve them.
func WithResultsSources(srcs ...ResultsSource) Option {
	return func(c *bankSend) { c.results = append(c.results, srcs...) }
}

// WithProofVerifier replaces the inclusion proof check, which is for tests
// that need a proof of a transaction that is not on a real chain.
func WithProofVerifier(v ProofVerifier) Option {
	return func(c *bankSend) { c.verifyTx = v }
}

// NewBankSend returns the checker of the bank-send profile. headers is the
// chain the verifier walks, so the header read here is the one header trust
// then checks. A source that repeats another's host is refused: they would
// not be independent.
func NewBankSend(cfg Config, primary TxSource, headers headertrust.HeaderChain, cross []TxSource, opts ...Option) (verifier.ExecutionChecker, error) {
	if err := cfg.ValidateBasic(); err != nil {
		return nil, err
	}
	if primary == nil {
		return nil, errors.New("railverify: no primary source")
	}
	if headers == nil {
		return nil, errors.New("railverify: no header chain")
	}
	c := &bankSend{
		cfg: cfg, candidates: []TxSource{primary}, headers: headers,
		cross: append([]TxSource(nil), cross...), verifyTx: VerifyShareProofAt,
	}
	for _, o := range opts {
		o(c)
	}
	seen := map[string]bool{}
	for _, s := range c.candidates {
		if s == nil {
			return nil, errors.New("railverify: nil tx source")
		}
		if seen[s.Name()] {
			return nil, fmt.Errorf("railverify: tx source %q repeats another source", s.Name())
		}
		seen[s.Name()] = true
	}
	for _, s := range c.cross {
		if s == nil {
			return nil, errors.New("railverify: nil cross source")
		}
		if seen[s.Name()] {
			return nil, fmt.Errorf("railverify: cross source %q repeats another source", s.Name())
		}
		seen[s.Name()] = true
	}
	for _, s := range c.results {
		if s == nil {
			return nil, errors.New("railverify: nil results source")
		}
	}
	if c.verifyTx == nil {
		return nil, errors.New("railverify: no proof verifier")
	}
	return c, nil
}

func parseLowerHex32(s string) ([32]byte, bool) {
	var out [32]byte
	if len(s) != 64 {
		return out, false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return out, false
		}
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, false
	}
	copy(out[:], b)
	return out, true
}

// bodyOfTxRaw returns body_bytes of a TxRaw that has fields 1 and 2 once
// each, then field 3 at least once, all length-delimited with shortest
// varints, and nothing else. The chain's own decoder keeps the last of a
// repeated field and accepts any order, so anything looser could show a body
// the chain did not execute.
func bodyOfTxRaw(b []byte) ([]byte, error) {
	bad := func(why string) error { return fmt.Errorf("%w: %s", ErrTxMalformed, why) }
	next := func(want protowire.Number) ([]byte, bool, error) {
		if len(b) == 0 {
			return nil, false, nil
		}
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return nil, false, bad("tag")
		}
		if num != want {
			return nil, false, nil
		}
		if typ != protowire.BytesType {
			return nil, false, bad("wire type")
		}
		if n != 1 {
			return nil, false, bad("tag form")
		}
		rest := b[n:]
		l, ln := protowire.ConsumeVarint(rest)
		if ln < 0 {
			return nil, false, bad("length")
		}
		if ln != protowire.SizeVarint(l) {
			return nil, false, bad("length is not shortest")
		}
		rest = rest[ln:]
		if uint64(len(rest)) < l {
			return nil, false, bad("truncated")
		}
		v := rest[:l]
		b = rest[l:]
		return v, true, nil
	}
	body, ok, err := next(1)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, bad("no body_bytes")
	}
	if _, ok, err = next(2); err != nil {
		return nil, err
	} else if !ok {
		return nil, bad("no auth_info_bytes")
	}
	sigs := 0
	for {
		_, ok, err := next(3)
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		sigs++
	}
	if sigs == 0 {
		return nil, bad("no signature")
	}
	if len(b) != 0 {
		return nil, bad("trailing or out-of-order data")
	}
	return body, nil
}

func violation(err error) error {
	return fmt.Errorf("%w: %w", verifier.ErrExecutionViolation, err)
}

// answer is the candidate whose answer passed every rule that a source's
// word is judged by: the bytes hash to rail_ref, the header at its height is
// on the trusted chain, and a proof, if any, verifies against that header.
type answer struct {
	src           TxSource
	tx            RawTx
	hdr           core.Header
	inclusion     string
	proof         ProofInfo
	chainMismatch bool
}

// aside is a candidate set aside, with the reason and the sources it blames.
type aside struct {
	name   string
	reason verifier.Reason
	names  []string
	err    error
}

// tried is the result of one candidate: a usable answer, a reason to set it
// aside and try the next, or a finding that ends the check.
type tried struct {
	ans   *answer
	aside *aside
	fatal error
}

func decodeHeader(raw []byte, height uint64) (core.Header, error) {
	var ph cmtproto.Header
	if err := ph.Unmarshal(raw); err != nil {
		return core.Header{}, err
	}
	hdr, err := core.HeaderFromProto(&ph)
	if err != nil {
		return core.Header{}, err
	}
	if hdr.Height < 1 || uint64(hdr.Height) != height {
		return core.Header{}, fmt.Errorf("header claims height %d, asked for %d", hdr.Height, height)
	}
	return hdr, nil
}

// headerReason says which reason an error of the trusted header chain stands
// for. Only the three that concern a header at a transaction's height are
// kept; any other trouble means no source gave a header that links.
func headerReason(err error) (verifier.Reason, []string) {
	reason, names, ok := verifier.ReasonOf(err)
	if ok {
		switch reason {
		case verifier.ReasonHeaderAboveCheckpoint, verifier.ReasonHeaderNotLinking, verifier.ReasonHeaderDisagreement:
			return reason, names
		}
	}
	return verifier.ReasonHeaderNotLinking, names
}

func (c *bankSend) try(ctx context.Context, src TxSource, ref [32]byte, act bankaction.Action, in verifier.ExecutionInput) tried {
	name := src.Name()
	set := func(reason verifier.Reason, names []string, err error) tried {
		return tried{aside: &aside{name: name, reason: reason, names: names, err: err}}
	}
	timeout := func() tried {
		return tried{fatal: verifier.WithReason(verifier.ReasonTimeout, nil, ctx.Err())}
	}

	tx, err := src.Tx(ctx, ref, true)
	if err != nil {
		if ctx.Err() != nil {
			return timeout()
		}
		if errors.Is(err, ErrTxNotFound) {
			return set(verifier.ReasonTxNotFound, []string{name}, err)
		}
		if !errors.Is(err, ErrTxSourceUnavailable) {
			err = fmt.Errorf("%w: %w", ErrTxSourceUnavailable, err)
		}
		return set(verifier.ReasonTxSourceUnavailable, []string{name}, err)
	}
	if sha256.Sum256(tx.Bytes) != ref {
		return set(verifier.ReasonTxHashMismatch, []string{name}, ErrTxHashMismatch)
	}
	if tx.Height == 0 {
		return set(verifier.ReasonTxSourceUnavailable, []string{name}, fmt.Errorf("%w: no height", ErrTxSourceUnavailable))
	}
	body, err := bodyOfTxRaw(tx.Bytes)
	if err != nil {
		return tried{fatal: err}
	}
	if _, err := bankaction.CheckBody(act, in.CommitmentHash, body); err != nil {
		return tried{fatal: violation(err)}
	}

	raw, err := c.headers.Header(ctx, tx.Height)
	if err != nil {
		if ctx.Err() != nil {
			return timeout()
		}
		reason, names := headerReason(err)
		herr := fmt.Errorf("%w: header %d: %w", verifier.ErrExecutionUnchecked, tx.Height, err)
		if reason == verifier.ReasonHeaderDisagreement {
			return tried{fatal: verifier.WithReason(reason, names, herr)}
		}
		if len(names) == 0 {
			names = []string{name}
		}
		return set(reason, names, herr)
	}
	hdr, err := decodeHeader(raw, tx.Height)
	if err != nil {
		return set(verifier.ReasonHeaderNotLinking, []string{name}, fmt.Errorf("%w: header %d is unusable: %w", verifier.ErrExecutionUnchecked, tx.Height, err))
	}

	a := &answer{src: src, tx: tx, hdr: hdr, inclusion: verifier.InclusionNodeAttested, chainMismatch: hdr.ChainID != act.ChainID}
	if len(tx.Proof) > 0 {
		info, err := c.verifyTx(tx.Proof, tx.Bytes, hdr.DataHash)
		if err != nil {
			if !errors.Is(err, ErrTxProof) {
				err = fmt.Errorf("%w: %w", ErrTxProof, err)
			}
			return set(verifier.ReasonTxProofInvalid, []string{name}, err)
		}
		a.inclusion, a.proof = verifier.InclusionProven, info
	}
	return tried{ans: a}
}

// CheckExecution runs the profile's rules in order: chain configuration,
// lookup, then for each candidate hash, TxRaw, body, the header at the
// answer's height and inclusion; then the cross sources and the result proof.
// It returns the facts, and leaves the outcome rules that need only facts to
// verifier.JudgeExecution.
func (c *bankSend) CheckExecution(ctx context.Context, in verifier.ExecutionInput) (verifier.ExecutionFacts, error) {
	none := verifier.ExecutionFacts{}
	act, err := bankaction.Decode(in.Action)
	if err != nil {
		return none, violation(err)
	}
	if act.ChainID != c.cfg.ChainID {
		return none, verifier.WithReason(verifier.ReasonChainConfig, nil,
			fmt.Errorf("%w: the action names %q, the checker is set to %q", ErrChainConfig, act.ChainID, c.cfg.ChainID))
	}
	ref, ok := parseLowerHex32(in.RailRef)
	if !ok {
		return none, ErrRailRefMalformed
	}

	var (
		sources []verifier.ExecutionSource
		asides  []aside
		used    *answer
	)
	for i, src := range c.candidates {
		role := verifier.RoleAlternate
		if i == 0 {
			role = verifier.RolePrimary
		}
		t := c.try(ctx, src, ref, act, in)
		switch {
		case t.fatal != nil:
			// The answer was taken up, and the finding rests on it.
			if reason, _, _ := verifier.ReasonOf(t.fatal); reason != verifier.ReasonTimeout {
				sources = append(sources, verifier.ExecutionSource{Name: src.Name(), Role: role, Result: verifier.SourceUsed})
			}
			return verifier.ExecutionFacts{Sources: sources}, t.fatal
		case t.aside != nil:
			asides = append(asides, *t.aside)
			sources = append(sources, verifier.ExecutionSource{
				Name: src.Name(), Role: role, Result: verifier.SourceSetAside, Reason: t.aside.reason, Detail: t.aside.err.Error(),
			})
			continue
		}
		used = t.ans
		sources = append(sources, verifier.ExecutionSource{Name: src.Name(), Role: role, Result: verifier.SourceUsed})
		break
	}
	if used == nil {
		return verifier.ExecutionFacts{Sources: sources}, noUsableAnswer(asides)
	}

	f := verifier.ExecutionFacts{
		Height: used.tx.Height, HeaderHash: used.hdr.Hash(), BlockTime: uint64(used.hdr.Time.Unix()),
		Inclusion: used.inclusion, Outcome: outcomeOf(used.tx.Code), Result: verifier.ResultNodeAttested,
		ChainMismatch: used.chainMismatch, CrossCheck: verifier.CrossOff, Sources: sources,
	}

	crossCodes, err := c.askCross(ctx, ref, used, &f)
	if err != nil {
		return f, err
	}

	if f.Inclusion == verifier.InclusionProven && !f.ChainMismatch && f.Height > in.AnchorHeight {
		rp, err := c.proveResult(ctx, f.Height, act.ChainID, used.proof, c.resultsSources(used))
		if err != nil {
			return f, err
		}
		if rp.proven {
			f.Result, f.Outcome = verifier.ResultProven, outcomeOf(rp.code)
			for i, code := range crossCodes {
				if f.Sources[len(f.Sources)-len(crossCodes)+i].Result == verifier.SourceAgree && code != rp.code {
					f.Sources[len(f.Sources)-len(crossCodes)+i].Result = verifier.SourceDisagree
				}
			}
		} else {
			f.ResultProblem = rp.problem
		}
	}
	if f.Result != verifier.ResultProven && f.CrossCheck == verifier.CrossPass {
		f.Result = verifier.ResultCrossConfirmed
	}
	return f, nil
}

func outcomeOf(code uint32) string {
	if code == 0 {
		return verifier.OutcomeSuccess
	}
	return verifier.OutcomeFailure
}

// noUsableAnswer is the unchecked error when every candidate was set aside:
// it names each of them, and its cause is the last one's.
func noUsableAnswer(asides []aside) error {
	last := asides[len(asides)-1]
	var names []string
	var parts []string
	for _, a := range asides {
		for _, n := range a.names {
			if !slices.Contains(names, n) {
				names = append(names, n)
			}
		}
		parts = append(parts, fmt.Sprintf("%s: %s", a.name, a.reason))
	}
	return verifier.WithReason(last.reason, names,
		fmt.Errorf("%w: no tx source gave a usable answer (%s): %w", verifier.ErrExecutionUnchecked, strings.Join(parts, "; "), last.err))
}

// askCross asks every cross source for the transaction without a proof and
// records agree, disagree or fault for each, and the aggregate. It returns
// the code each cross source reported, in order, 0 for a fault.
func (c *bankSend) askCross(ctx context.Context, ref [32]byte, used *answer, f *verifier.ExecutionFacts) ([]uint32, error) {
	if len(c.cross) == 0 {
		return nil, nil
	}
	f.CrossCheck = verifier.CrossPass
	codes := make([]uint32, 0, len(c.cross))
	for _, s := range c.cross {
		row := verifier.ExecutionSource{Name: s.Name(), Role: verifier.RoleCross}
		other, err := s.Tx(ctx, ref, false)
		switch {
		case ctx.Err() != nil:
			return nil, verifier.WithReason(verifier.ReasonTimeout, nil, ctx.Err())
		case err != nil:
			row.Result, row.Detail = verifier.SourceFault, err.Error()
		case sha256.Sum256(other.Bytes) != ref:
			row.Result, row.Detail = verifier.SourceFault, "the bytes do not hash to rail_ref"
		case other.Height != used.tx.Height || other.Code != used.tx.Code:
			row.Result, row.Detail = verifier.SourceDisagree, fmt.Sprintf("height %d code %d, the used source says height %d code %d", other.Height, other.Code, used.tx.Height, used.tx.Code)
			codes = append(codes, other.Code)
			f.Sources = append(f.Sources, row)
			f.CrossCheck = verifier.CrossMismatch
			continue
		default:
			row.Result = verifier.SourceAgree
		}
		if row.Result == verifier.SourceFault && f.CrossCheck != verifier.CrossMismatch {
			f.CrossCheck = verifier.CrossUnavailable
		}
		codes = append(codes, other.Code)
		f.Sources = append(f.Sources, row)
	}
	return codes, nil
}

// resultsSources lists where block results may come from: the tx sources and
// the cross sources that serve them, the used one first, then any added.
func (c *bankSend) resultsSources(used *answer) []ResultsSource {
	var out []ResultsSource
	seen := map[string]bool{}
	add := func(s any) {
		if rs, ok := s.(ResultsSource); ok && !seen[rs.Name()] {
			seen[rs.Name()] = true
			out = append(out, rs)
		}
	}
	add(used.src)
	for _, s := range c.candidates {
		add(s)
	}
	for _, s := range c.cross {
		add(s)
	}
	for _, s := range c.results {
		add(s)
	}
	return out
}
