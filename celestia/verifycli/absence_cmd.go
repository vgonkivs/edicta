package verifycli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	core "github.com/cometbft/cometbft/types"

	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/celestia/absence"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/verifier"
)

// absenceHeightView is one height of the absence command's report.
type absenceHeightView struct {
	Height  uint64 `json:"height"`
	Result  string `json:"result"`
	Rule    string `json:"rule"`
	Bytes   int    `json:"bytes,omitempty"`
	Written bool   `json:"written"`
	Error   string `json:"error,omitempty"`
}

type absenceView struct {
	CommitmentHash string              `json:"commitment_hash"`
	DA             uint64              `json:"da"`
	H0             uint64              `json:"h0"`
	AnchorDeadline uint64              `json:"anchor_deadline"`
	Result         string              `json:"result"`
	AnchorHeight   uint64              `json:"anchor_height,omitempty"`
	FirstUnproven  uint64              `json:"first_unproven,omitempty"`
	Heights        int                 `json:"heights"`
	Bytes          int                 `json:"bytes"`
	Written        int                 `json:"written"`
	Source         string              `json:"source"`
	PerHeight      []absenceHeightView `json:"per_height"`
}

// openWritable opens the archive the absence command writes its records to.
func openWritable(dir string) (*fsarchive.Store, error) {
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("archive %q is not a directory", dir)
	}
	cm, err := committers()
	if err != nil {
		return nil, err
	}
	store, err := fsarchive.Open(dir, cm)
	if err != nil {
		return nil, fmt.Errorf("open archive: %w", err)
	}
	return store, nil
}

// runAbsence builds the absence proofs of a verified pending reference's
// window, verifies every one against the trusted chain and writes those
// that verify.
func runAbsence(ctx context.Context, f flags, out io.Writer) (int, error) {
	store, err := openWritable(f.archiveDir)
	if err != nil {
		return codeUsage, usageError{err}
	}
	fetch, closeFetch, err := absenceFetcher(ctx, f)
	if err != nil {
		return codeUsage, usageError{err}
	}
	defer closeFetch()
	window := &windowHeaders{r: store, fetch: fetch}
	rec := newRecordingReader(store)
	deps, err := buildDeps(rec, f.gateKeys, f.params)
	if err != nil {
		return codeUsage, usageError{err}
	}
	info := &trustInfo{}
	var trust verifier.HeaderTrust
	if f.trustedPath != "" {
		if trust, err = loadTrusted(f.trustedPath, window); err != nil {
			return codeUsage, usageError{err}
		}
	} else {
		lt, err := newLazyTrust(rec, f, info)
		if err != nil {
			return codeUsage, usageError{err}
		}
		lt.window = window
		trust = lt
	}
	deps.Trust = trust
	v, err := verifier.New(deps)
	if err != nil {
		return codeUsage, usageError{err}
	}
	rep, err := v.Verify(ctx, f.hash)
	if err != nil {
		return codeUsage, err
	}
	if rep.Fast == nil {
		return codeUsage, usageError{errors.New("the decision is not a pending reference with a verified fast-mode Authorization")}
	}
	ref := rep.PayloadRef
	window.set(ref)
	q := absence.Query{DA: ref.DA, Namespace: ref.Namespace, Commitment: ref.Commitment}
	if ref.DA == commitment.DACelestiaBlob {
		q.Signer = ref.Signer
	}
	view := absenceView{
		CommitmentHash: hashHex(f.hash), DA: uint64(ref.DA), H0: rep.Fast.H0, AnchorDeadline: rep.Fast.AnchorDeadline,
		Source: fetch.Name(),
	}
	for h := rep.Fast.H0; h <= rep.Fast.AnchorDeadline; h++ {
		hv := absenceHeight(ctx, store, fetch, trust, q, h)
		if err := ctx.Err(); err != nil {
			return codeUsage, err
		}
		view.PerHeight = append(view.PerHeight, hv)
		view.Bytes += hv.Bytes
		if hv.Written {
			view.Written++
		}
	}
	view.Heights = len(view.PerHeight)
	view.Result = string(verifier.AbsenceAbsent)
	for _, hv := range view.PerHeight {
		if hv.Result == absence.Present.String() {
			view.Result, view.AnchorHeight = string(verifier.AbsencePresent), hv.Height
			break
		}
	}
	if view.Result == string(verifier.AbsenceAbsent) {
		for _, hv := range view.PerHeight {
			if hv.Result != absence.Absent.String() {
				view.Result, view.FirstUnproven = string(verifier.AbsenceUnproven), hv.Height
				break
			}
		}
	}
	code := codeValid
	for _, hv := range view.PerHeight {
		if hv.Result == absence.Unproven.String() {
			code = codeUnchecked
		}
	}
	if f.asJSON {
		b, err := json.MarshalIndent(view, "", "  ")
		if err != nil {
			return codeUsage, err
		}
		fmt.Fprintf(out, "%s\n", b)
		return code, nil
	}
	writeAbsenceText(out, view)
	return code, nil
}

// absenceHeight fetches, verifies and, when it verifies, stores the proof of
// one height.
func absenceHeight(ctx context.Context, store *fsarchive.Store, fetch *absence.Fetcher, trust verifier.HeaderTrust,
	q absence.Query, h uint64) absenceHeightView {
	hv := absenceHeightView{Height: h, Result: absence.Unproven.String(), Rule: string(absence.RuleNoProof)}
	rec, err := fetch.Fetch(ctx, q, h)
	if err != nil {
		hv.Error = err.Error()
		return hv
	}
	hv.Bytes = absence.Size(rec)
	trusted := absence.TrustedHashes{}
	chainID := ""
	for _, part := range []struct {
		at  uint64
		raw []byte
	}{{h, rec.Header}, {h + 1, rec.NextHeader}} {
		if part.raw == nil {
			continue
		}
		hash, cid, err := signedHeaderHash(part.raw)
		if err != nil {
			continue
		}
		res, err := trust.Trusted(ctx, part.at, hash)
		if err == nil && res.Checked && res.CrossCheck != verifier.CrossMismatch {
			trusted[part.at] = hash
			if chainID == "" {
				chainID = cid
			}
		}
	}
	if q.DA == commitment.DAFibre {
		q.ChainID = chainID
	}
	if q.DA == commitment.DAFibre && chainID == "" {
		hv.Rule, hv.Error = string(absence.RuleHeader), fmt.Sprintf("%v: the header at %d does not tie to the trusted chain", absence.ErrHeader, h)
		return hv
	}
	o := absence.VerifyHeight(rec, q, h, trusted)
	hv.Result, hv.Rule = o.Result.String(), string(o.Rule)
	if o.Err != nil {
		hv.Error = o.Err.Error()
		return hv
	}
	if _, err := store.Put(ctx, rec); err != nil {
		hv.Error = fmt.Sprintf("verified, not written: %v", err)
		return hv
	}
	hv.Written = true
	return hv
}

func signedHeaderHash(raw []byte) ([]byte, string, error) {
	var pb cmtproto.SignedHeader
	if err := pb.Unmarshal(raw); err != nil {
		return nil, "", err
	}
	sh, err := core.SignedHeaderFromProto(&pb)
	if err != nil {
		return nil, "", err
	}
	return sh.Header.Hash(), sh.ChainID, nil
}

func hashHex(h commitment.Hash) string { return fmt.Sprintf("%x", h[:]) }

func writeAbsenceText(out io.Writer, v absenceView) {
	p := func(format string, a ...any) { fmt.Fprintf(out, format+"\n", a...) }
	p("commitment: %s", v.CommitmentHash)
	p("window: h0 %d to anchor deadline %d, da %d, proofs from %s", v.H0, v.AnchorDeadline, v.DA, v.Source)
	for _, hv := range v.PerHeight {
		line := strconv.FormatUint(hv.Height, 10) + ": " + hv.Result + " (" + hv.Rule + ")"
		if hv.Written {
			line += ", written"
		}
		if hv.Error != "" {
			line += ": " + hv.Error
		}
		p("  %s", line)
	}
	switch v.Result {
	case string(verifier.AbsenceAbsent):
		p("absence: absent at %d..%d, %d heights, %d bytes; %d records written", v.H0, v.AnchorDeadline, v.Heights, v.Bytes, v.Written)
	case string(verifier.AbsencePresent):
		p("absence: the anchor is present at %d; %d records written", v.AnchorHeight, v.Written)
	default:
		p("absence: not proven, first height %d; %d of %d records written", v.FirstUnproven, v.Written, v.Heights)
	}
}
