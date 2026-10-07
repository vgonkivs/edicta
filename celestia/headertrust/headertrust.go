// Package headertrust ties header hashes to the chain from one trusted
// header, without validator signatures: the hash chain from the trusted
// header down to the needed height is checked link by link, so the headers
// in between may come from any untrusted source.
package headertrust

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	core "github.com/cometbft/cometbft/types"

	"github.com/vgonkivs/edicta/verifier"
)

var (
	ErrCheckpointTooLow   = errors.New("headertrust: checkpoint is below the needed height")
	ErrCheckpointMismatch = errors.New("headertrust: checkpoint header does not match its hash or height")
	ErrChainBroken        = errors.New("headertrust: header chain does not link to the trusted header")
	ErrCrossCheckMismatch = errors.New("headertrust: another node serves a different header")
	ErrChainTooLong       = errors.New("headertrust: needed height is too far below the checkpoint")
)

// MaxChainLength bounds how many headers one check fetches. The needed
// height comes from a signed decision, so it is not trusted to be near the
// checkpoint.
const MaxChainLength = 100_000

// Checkpoint is the trusted header, obtained out of band. Header is the
// protobuf tendermint.types.Header.
type Checkpoint struct {
	Height uint64
	Hash   []byte
	Header []byte
}

// HeaderChain serves protobuf headers by height. It is untrusted: every
// header from it is checked against the chain.
type HeaderChain interface {
	Header(ctx context.Context, height uint64) ([]byte, error)
}

// decode parses a protobuf header and requires the encoding to be the
// canonical one, so equal hashes mean equal bytes.
func decode(b []byte) (core.Header, error) {
	var ph cmtproto.Header
	if err := ph.Unmarshal(b); err != nil {
		return core.Header{}, err
	}
	if again, err := ph.Marshal(); err != nil || !bytes.Equal(again, b) {
		return core.Header{}, errors.New("header encoding is not canonical")
	}
	h, err := core.HeaderFromProto(&ph)
	if err != nil {
		return core.Header{}, err
	}
	if h.Height < 1 {
		return core.Header{}, fmt.Errorf("header height %d", h.Height)
	}
	return h, nil
}

// hashOf is the block hash of h. It is never empty.
func hashOf(h core.Header) ([]byte, error) {
	sum := h.Hash()
	if len(sum) != 32 {
		return nil, errors.New("header has no hash")
	}
	return sum, nil
}

// HashOfHeader is the block hash of a canonical protobuf header.
func HashOfHeader(raw []byte) ([]byte, error) {
	h, err := decode(raw)
	if err != nil {
		return nil, err
	}
	return hashOf(h)
}

// VerifyBackwards checks that hash is the hash of the header at height, given
// the trusted header cp and the encoded headers height .. cp.Height-1 in
// ascending order: each header's hash must equal the last_block_id hash of
// its successor. No signature is checked.
func VerifyBackwards(cp Checkpoint, headers [][]byte, height uint64, hash []byte) error {
	_, _, err := verifyBackwards(cp, headers, height, hash)
	return err
}

// verifyBackwards also reports the height of the header that broke the
// chain, when the break is that one header's fault and not the claimed hash's.
func verifyBackwards(cp Checkpoint, headers [][]byte, height uint64, hash []byte) (culprit uint64, atHeader bool, err error) {
	if cp.Height < height {
		return 0, false, fmt.Errorf("%w: checkpoint %d, needed %d", ErrCheckpointTooLow, cp.Height, height)
	}
	top, err := decode(cp.Header)
	if err != nil {
		return 0, false, fmt.Errorf("%w: %w", ErrCheckpointMismatch, err)
	}
	topHash, err := hashOf(top)
	if err != nil {
		return 0, false, fmt.Errorf("%w: %w", ErrCheckpointMismatch, err)
	}
	if uint64(top.Height) != cp.Height || !bytes.Equal(topHash, cp.Hash) {
		return 0, false, fmt.Errorf("%w: height %d", ErrCheckpointMismatch, cp.Height)
	}
	if uint64(len(headers)) != cp.Height-height {
		return 0, false, fmt.Errorf("%w: %d headers for %d links", ErrChainBroken, len(headers), cp.Height-height)
	}

	want := top.LastBlockID.Hash
	got := topHash
	for i := len(headers) - 1; i >= 0; i-- {
		at := height + uint64(i)
		h, err := decode(headers[i])
		if err != nil {
			return at, true, fmt.Errorf("%w: header %d: %w", ErrChainBroken, at, err)
		}
		if uint64(h.Height) != at {
			return at, true, fmt.Errorf("%w: header %d claims height %d", ErrChainBroken, at, h.Height)
		}
		sum, err := hashOf(h)
		if err != nil {
			return at, true, fmt.Errorf("%w: header %d: %w", ErrChainBroken, at, err)
		}
		if !bytes.Equal(sum, want) {
			return at, true, fmt.Errorf("%w: header %d does not match the link from %d", ErrChainBroken, at, at+1)
		}
		want, got = h.LastBlockID.Hash, sum
	}
	if !bytes.Equal(got, hash) {
		return 0, false, fmt.Errorf("%w: hash at height %d differs from the chain's", ErrChainBroken, height)
	}
	return 0, false, nil
}

type trust struct {
	cp    Checkpoint
	chain HeaderChain
	cross []HeaderChain
}

// New returns a header trust anchored at cp. chain supplies the headers
// between the needed height and cp; cross, if any, are independent nodes
// whose header at the needed height is compared.
func New(cp Checkpoint, chain HeaderChain, cross []HeaderChain) verifier.HeaderTrust {
	return &trust{cp: cp, chain: chain, cross: cross}
}

// Trusted reports the checkpoint in the result on every path, so the report
// can name the header the verdict hung from. A checkpoint that is too low, a
// chain that is too long and headers that cannot be fetched are auditor
// input problems and wrap verifier.ErrTrustInput.
func (t *trust) Trusted(ctx context.Context, height uint64, hash []byte) (verifier.TrustResult, error) {
	res := verifier.TrustResult{
		CheckpointH:    t.cp.Height,
		CheckpointHash: bytes.Clone(t.cp.Hash),
	}
	if err := ctx.Err(); err != nil {
		return res, fmt.Errorf("headertrust: %w", err)
	}
	if t.cp.Height < height {
		return res, verifier.WithReason(verifier.ReasonHeaderAboveCheckpoint, nil,
			fmt.Errorf("%w: %w: checkpoint %d, needed %d", verifier.ErrTrustInput, ErrCheckpointTooLow, t.cp.Height, height))
	}
	if t.cp.Height-height > MaxChainLength {
		return res, verifier.WithReason(verifier.ReasonHeaderSourceUnavailable, nil,
			fmt.Errorf("%w: %w: %d links, use a checkpoint closer to the needed height", verifier.ErrTrustInput, ErrChainTooLong, t.cp.Height-height))
	}
	headers := make([][]byte, 0, t.cp.Height-height)
	for h := height; h < t.cp.Height; h++ {
		b, err := t.chain.Header(ctx, h)
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return res, fmt.Errorf("headertrust: %w", cerr)
			}
			return res, verifier.WithReason(verifier.ReasonHeaderSourceUnavailable, nameOf(t.chain),
				fmt.Errorf("%w: headertrust: header %d: %w", verifier.ErrTrustInput, h, err))
		}
		headers = append(headers, b)
	}
	if culprit, atHeader, err := verifyBackwards(t.cp, headers, height, hash); err != nil {
		return res, t.chainProblem(culprit, atHeader, err)
	}
	res.Checked = true
	res.CrossCheck = "off"
	if len(t.cross) == 0 {
		return res, nil
	}
	var who string
	res.CrossCheck, who = t.crossCheck(ctx, height, hash)
	if res.CrossCheck == "mismatch" {
		var names []string
		if who != "" {
			names = []string{who}
		}
		return res, verifier.WithReason(verifier.ReasonHeaderDisagreement, names,
			fmt.Errorf("%w: height %d: %s", ErrCrossCheckMismatch, height, verifier.DisagreementText))
	}
	return res, nil
}

// chainProblem gives a break in the backward chain its reason. A header that
// came from an online source and does not link is that source's fault. Any
// other break, a header from the archive or the trusted file, or a claimed
// hash the chain does not have, means what was presented does not belong to
// the trusted chain.
func (t *trust) chainProblem(culprit uint64, atHeader bool, err error) error {
	if errors.Is(err, ErrCheckpointMismatch) {
		return verifier.WithReason(verifier.ReasonNoTrustedHeader, nil, err)
	}
	if p, ok := t.chain.(*preferChain); ok && atHeader && !p.isKnown(culprit) {
		return verifier.WithReason(verifier.ReasonHeaderNotLinking, nameOf(p.then), fmt.Errorf("%w: %w", verifier.ErrTrustInput, err))
	}
	return verifier.WithReason(verifier.ReasonChainMismatch, nil, err)
}

// nameOf is the operator behind a header source, when it says.
func nameOf(c HeaderChain) []string {
	if n, ok := c.(interface{ Name() string }); ok && n.Name() != "" {
		return []string{n.Name()}
	}
	return nil
}

// crossCheck asks every node. A node that cannot answer, or answers for
// another height, counts as unavailable; any node with another hash is a
// mismatch whatever the others say, and is named if it has a name.
func (t *trust) crossCheck(ctx context.Context, height uint64, hash []byte) (string, string) {
	result := "pass"
	for _, c := range t.cross {
		b, err := c.Header(ctx, height)
		if err != nil {
			result = worse(result, "unavailable")
			continue
		}
		h, err := decode(b)
		if err != nil || uint64(h.Height) != height {
			result = worse(result, "unavailable")
			continue
		}
		sum, err := hashOf(h)
		if err != nil {
			result = worse(result, "unavailable")
			continue
		}
		if !bytes.Equal(sum, hash) {
			who := ""
			if n := nameOf(c); len(n) > 0 {
				who = n[0]
			}
			return "mismatch", who
		}
	}
	return result, ""
}

func worse(a, b string) string {
	if a == "pass" {
		return b
	}
	return a
}

// NamedChain is an online header source that also reports its latest height
// and a name for the operator behind it (the normalized host).
type NamedChain interface {
	HeaderChain
	Name() string
	Latest(ctx context.Context) (uint64, error)
}

// ErrCheckpointDisagree marks sources that give different hashes for one
// height. It is a disagreement whatever the quorum: the verifier cannot tell
// which side is honest, so the result is unchecked and says so.
var ErrCheckpointDisagree = errors.New("headertrust: checkpoint sources disagree")

// CheckpointReport says which header an agreed checkpoint is and who agreed.
type CheckpointReport struct {
	Height  uint64
	Hash    []byte
	Sources []string
	Agreed  int
	Quorum  int
}

// nodeIDSource is implemented by sources that can report the node id of
// their status, so two host names of one node count once.
type nodeIDSource interface {
	NodeID(ctx context.Context) (string, error)
}

// AgreedCheckpoint takes h as the lowest latest height of the sources that
// answer, reads the header at h from each and recomputes its hash. Any two
// differing hashes are ErrCheckpointDisagree. Fewer than quorum distinct
// operators (by name, and by node id where known) agreeing wraps
// verifier.ErrTrustInput.
func AgreedCheckpoint(ctx context.Context, srcs []NamedChain, quorum int) (Checkpoint, CheckpointReport, error) {
	rep := CheckpointReport{Quorum: quorum}
	if quorum < 1 {
		return Checkpoint{}, rep, fmt.Errorf("headertrust: quorum %d is below 1", quorum)
	}
	if len(srcs) == 0 || quorum > len(srcs) {
		return Checkpoint{}, rep, fmt.Errorf("headertrust: %d sources cannot reach quorum %d", len(srcs), quorum)
	}
	for _, s := range srcs {
		if s == nil {
			return Checkpoint{}, rep, errors.New("headertrust: nil checkpoint source")
		}
	}

	type live struct {
		src    NamedChain
		latest uint64
	}
	var lives []live
	for _, s := range srcs {
		latest, err := s.Latest(ctx)
		if cerr := ctx.Err(); cerr != nil {
			return Checkpoint{}, rep, fmt.Errorf("headertrust: %w", cerr)
		}
		if err == nil && latest > 0 {
			lives = append(lives, live{s, latest})
		}
	}
	if len(lives) == 0 {
		return Checkpoint{}, rep, verifier.WithReason(verifier.ReasonHeaderSourceUnavailable, nil,
			fmt.Errorf("%w: no checkpoint source reported its latest height", verifier.ErrTrustInput))
	}
	t := lives[0].latest
	for _, l := range lives {
		t = min(t, l.latest)
	}

	type answer struct {
		src  NamedChain
		raw  []byte
		hash []byte
	}
	var answers []answer
	for _, l := range lives {
		raw, err := l.src.Header(ctx, t)
		if cerr := ctx.Err(); cerr != nil {
			return Checkpoint{}, rep, fmt.Errorf("headertrust: %w", cerr)
		}
		if err != nil {
			continue
		}
		h, err := decode(raw)
		if err != nil || uint64(h.Height) != t {
			continue
		}
		sum, err := hashOf(h)
		if err != nil {
			continue
		}
		answers = append(answers, answer{l.src, raw, sum})
	}
	for _, a := range answers {
		if !bytes.Equal(a.hash, answers[0].hash) {
			return Checkpoint{}, rep, verifier.WithReason(verifier.ReasonHeaderDisagreement, []string{answers[0].src.Name(), a.src.Name()},
				fmt.Errorf("%w: height %d: %s", ErrCheckpointDisagree, t, verifier.DisagreementText))
		}
	}

	names := map[string]bool{}
	ids := map[string]bool{}
	for _, a := range answers {
		name := a.src.Name()
		if names[name] {
			continue
		}
		id := ""
		if is, ok := a.src.(nodeIDSource); ok {
			if v, err := is.NodeID(ctx); err == nil {
				id = v
			}
		}
		if id != "" && ids[id] {
			continue
		}
		names[name] = true
		if id != "" {
			ids[id] = true
		}
		rep.Sources = append(rep.Sources, name)
	}
	rep.Agreed = len(rep.Sources)
	if len(answers) > 0 {
		rep.Height, rep.Hash = t, bytes.Clone(answers[0].hash)
	}
	if rep.Agreed < quorum {
		reason := verifier.ReasonCheckpointQuorum
		if rep.Agreed == 0 {
			reason = verifier.ReasonHeaderSourceUnavailable
		}
		return Checkpoint{}, rep, verifier.WithReason(reason, nil,
			fmt.Errorf("%w: %d of %d required operators agree at height %d", verifier.ErrTrustInput, rep.Agreed, quorum, t))
	}
	return Checkpoint{Height: t, Hash: bytes.Clone(answers[0].hash), Header: bytes.Clone(answers[0].raw)}, rep, nil
}

type preferChain struct {
	known map[uint64][]byte
	then  HeaderChain
}

// Prefer serves the known headers (the archived anchor header) first and
// everything else from then. Served headers are still checked link by link.
func Prefer(known map[uint64][]byte, then HeaderChain) HeaderChain {
	c := make(map[uint64][]byte, len(known))
	for h, b := range known {
		c[h] = bytes.Clone(b)
	}
	return &preferChain{known: c, then: then}
}

func (p *preferChain) isKnown(h uint64) bool { _, ok := p.known[h]; return ok }

func (p *preferChain) Header(ctx context.Context, h uint64) ([]byte, error) {
	if b, ok := p.known[h]; ok {
		return bytes.Clone(b), nil
	}
	return p.then.Header(ctx, h)
}
