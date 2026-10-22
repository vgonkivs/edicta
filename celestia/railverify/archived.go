package railverify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/celestiaorg/celestia-app/v10/pkg/appconsts"
	"github.com/celestiaorg/celestia-app/v10/pkg/proof"
	"github.com/celestiaorg/go-square/v4/share"
	abci "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/crypto/merkle"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	core "github.com/cometbft/cometbft/types"

	"github.com/vgonkivs/edicta/engine/archive"
	"github.com/vgonkivs/edicta/engine/verifier"
)

// The rules an archived execution result is checked by, in order.
const (
	RuleXR1 = "XR1"
	RuleXR2 = "XR2"
	RuleXR3 = "XR3"
	RuleXR4 = "XR4"
	RuleXR5 = "XR5"
	RuleXR6 = "XR6"
	RuleXR7 = "XR7"
	RuleXR8 = "XR8"
)

// ArchivedSetAside is an archived execution result that does not prove what
// it claims: the first rule it fails and the reason of the execution check.
// It shows a bad record, never a bad execution.
type ArchivedSetAside struct {
	Rule   string
	Reason verifier.Reason
	Err    error
}

func (e *ArchivedSetAside) Error() string {
	return fmt.Sprintf("%s (%s): %v", e.Rule, e.Reason, e.Err)
}

func (e *ArchivedSetAside) Unwrap() error { return e.Err }

func setAside(rule string, reason verifier.Reason, format string, a ...any) error {
	return &ArchivedSetAside{Rule: rule, Reason: reason, Err: fmt.Errorf("%w: "+format, append([]any{verifier.ErrExecutionUnchecked}, a...)...)}
}

// ArchivedFacts are what an archived execution result proves once its rules
// hold: Tx is the unit of the transaction namespace that hashes to the
// record's rail_ref, at TxIndex of block Height, and Code is its result.
type ArchivedFacts struct {
	Height         uint64
	Header         core.Header
	HeaderHash     []byte
	NextHeaderHash []byte
	TxIndex        uint64
	ResultsTotal   uint64
	Tx             []byte
	Result         []byte
	Code           uint32
}

// CheckArchived checks an archived execution result for the transaction
// railRef of chain chainID. Both headers must reach the
// trusted chain through trust. An *ArchivedSetAside error sets the record
// aside; any other error ends the execution check (a timeout, or a header
// that sources disagree on).
func CheckArchived(ctx context.Context, rec *archive.ExecutionResultRecord, chainID string, railRef [32]byte, trust verifier.HeaderTrust) (ArchivedFacts, error) {
	if trust == nil {
		return ArchivedFacts{}, errors.New("railverify: no header trust for an archived execution result")
	}
	return checkArchived(ctx, rec, chainID, railRef, func(ctx context.Context, hdr, next headerAt) error {
		for _, x := range []headerAt{hdr, next} {
			if err := trustedAt(ctx, trust, x); err != nil {
				return err
			}
		}
		return nil
	})
}

// SelfCheckArchived is the writer's check of a record it built, which has no
// trust root: the record is checked against its own key, and instead of
// reaching the trusted chain the next header must name the header in
// last_block_id; every other check is the verifier's.
func SelfCheckArchived(rec *archive.ExecutionResultRecord) (ArchivedFacts, error) {
	if rec == nil || len(rec.RailRef) != 32 {
		return ArchivedFacts{}, setAside(RuleXR1, verifier.ReasonTxProofInvalid, "the record has no rail_ref")
	}
	var ref [32]byte
	copy(ref[:], rec.RailRef)
	return checkArchived(context.Background(), rec, rec.ChainID, ref, func(_ context.Context, hdr, next headerAt) error {
		if !bytes.Equal(next.h.LastBlockID.Hash, hdr.hash) {
			return setAside(RuleXR2, verifier.ReasonTxProofInvalid, "next_header does not name header in last_block_id")
		}
		return nil
	})
}

type headerAt struct {
	h    core.Header
	hash []byte
}

// trustedAt ties one header of a record to the trusted chain.
func trustedAt(ctx context.Context, trust verifier.HeaderTrust, x headerAt) error {
	height := uint64(x.h.Height)
	res, err := trust.Trusted(ctx, height, x.hash)
	if cerr := ctx.Err(); cerr != nil {
		return verifier.WithReason(verifier.ReasonTimeout, nil, cerr)
	}
	if err != nil {
		reason, names, _ := verifier.ReasonOf(err)
		switch reason {
		case verifier.ReasonHeaderDisagreement:
			return verifier.WithReason(reason, names, fmt.Errorf("%w: header %d: %w", verifier.ErrExecutionUnchecked, height, err))
		case verifier.ReasonHeaderAboveCheckpoint, verifier.ReasonNoTrustedHeader:
			return setAside(RuleXR2, verifier.ReasonResultHeaderUnreachable, "header trust does not reach height %d: %v", height, err)
		}
		return setAside(RuleXR2, verifier.ReasonHeaderNotLinking, "the header at %d is not on the trusted chain: %v", height, err)
	}
	if !res.Checked {
		return setAside(RuleXR2, verifier.ReasonHeaderNotLinking, "header trust did not check the header at %d", height)
	}
	if res.CrossCheck == verifier.CrossMismatch {
		return verifier.WithReason(verifier.ReasonHeaderDisagreement, nil,
			fmt.Errorf("%w: height %d: %s", verifier.ErrExecutionUnchecked, height, verifier.DisagreementText))
	}
	return nil
}

// proofKeys are the record's share proofs in key order; ns is the namespace
// the key must prove, zero for the closing share.
var proofKeys = []struct {
	key uint64
	ns  share.Namespace
}{{9, share.TxNamespace}, {10, share.PayForBlobNamespace}, {11, share.PayForFibreNamespace}, {12, share.Namespace{}}}

func proofOf(rec *archive.ExecutionResultRecord, key uint64) []byte {
	switch key {
	case 9:
		return rec.TxProof
	case 10:
		return rec.PFBProof
	case 11:
		return rec.PFFProof
	}
	return rec.ClosingProof
}

func checkArchived(ctx context.Context, rec *archive.ExecutionResultRecord, chainID string, railRef [32]byte,
	link func(context.Context, headerAt, headerAt) error) (facts ArchivedFacts, err error) {
	// The proofs are archive data, and the share and tree code is not
	// written for hostile input. A panic is reported under the rule that was
	// running, so that a fault in the trust callback is not blamed on the
	// proofs.
	rule := RuleXR1
	defer func() {
		if r := recover(); r != nil {
			facts, err = ArchivedFacts{}, setAside(rule, verifier.ReasonTxProofInvalid, "checking the record panicked: %v", r)
		}
	}()
	if rec == nil {
		return ArchivedFacts{}, setAside(RuleXR1, verifier.ReasonTxProofInvalid, "no record")
	}

	// The record is the one of the key asked for.
	if rec.ChainID != chainID || !bytes.Equal(rec.RailRef, railRef[:]) {
		return ArchivedFacts{}, setAside(RuleXR1, verifier.ReasonTxProofInvalid, "the record carries another key")
	}

	// Both headers decode at the record's height and the next one, of its
	// chain, and hang from the trusted chain.
	rule = RuleXR2
	if rec.Height == 0 || rec.Height >= 1<<63-1 {
		return ArchivedFacts{}, setAside(RuleXR2, verifier.ReasonTxProofInvalid, "height %d", rec.Height)
	}
	hdr, err := archivedHeader(rec.Header, rec.Height, rec.ChainID)
	if err != nil {
		return ArchivedFacts{}, setAside(RuleXR2, verifier.ReasonTxProofInvalid, "header: %v", err)
	}
	next, err := archivedHeader(rec.NextHeader, rec.Height+1, rec.ChainID)
	if err != nil {
		return ArchivedFacts{}, setAside(RuleXR2, verifier.ReasonTxProofInvalid, "next_header: %v", err)
	}
	if err := link(ctx, hdr, next); err != nil {
		return ArchivedFacts{}, err
	}

	// The index rule below holds only for the app version it was written
	// for.
	rule = RuleXR3
	if hdr.h.Version.App != appconsts.Version {
		return ArchivedFacts{}, setAside(RuleXR3, verifier.ReasonResultIndexUnbound,
			"block %d is of app version %d; the index rule holds for %d only", rec.Height, hdr.h.Version.App, appconsts.Version)
	}

	// Each share proof proves its namespace against data_hash, and the
	// ranges follow each other from share 0 up to a closing share or the
	// square's end, so no transaction of the namespaces is left out.
	rule = RuleXR4
	var (
		end, k  int
		closed  bool
		counts  = map[uint64]int{}
		txUnits [][]byte
	)
	for _, pk := range proofKeys {
		raw := proofOf(rec, pk.key)
		if raw == nil {
			continue
		}
		shares, s, e, kw, err := provenRange(raw, pk.key, pk.ns, hdr.h.DataHash)
		if err != nil {
			return ArchivedFacts{}, err
		}
		if k != 0 && kw != k {
			return ArchivedFacts{}, setAside(RuleXR4, verifier.ReasonTxProofInvalid, "key %d: another square width", pk.key)
		}
		k = kw
		if s != end {
			return ArchivedFacts{}, setAside(RuleXR5, verifier.ReasonTxProofInvalid, "key %d starts at share %d, the previous range ends at %d", pk.key, s, end)
		}
		end = e
		if pk.key == 12 {
			if e-s != 1 {
				return ArchivedFacts{}, setAside(RuleXR5, verifier.ReasonTxProofInvalid, "the closing proof covers %d shares", e-s)
			}
			closed = true
			continue
		}
		units, err := wholeSequence(shares, pk.key)
		if err != nil {
			return ArchivedFacts{}, err
		}
		counts[pk.key] = len(units)
		if pk.key == 9 {
			txUnits = units
		}
	}
	if !closed && end != k*k {
		return ArchivedFacts{}, setAside(RuleXR5, verifier.ReasonTxProofInvalid,
			"the transaction namespaces end at share %d, neither at a closing share nor at the square's end %d", end, k*k)
	}

	// The namespaces hold exactly as many transactions as the block has
	// results.
	rule = RuleXR6
	sum := uint64(0)
	for _, n := range counts {
		sum += uint64(n)
	}
	if sum != rec.ResultsTotal {
		return ArchivedFacts{}, setAside(RuleXR6, verifier.ReasonResultIndexUnbound,
			"%d transactions in the transaction namespaces, results_total %d", sum, rec.ResultsTotal)
	}

	// Exactly one ordinary transaction hashes to rail_ref, at tx_index.
	rule = RuleXR7
	at, found := -1, 0
	for j, u := range txUnits {
		if sha256.Sum256(u) == railRef {
			at, found = j, found+1
		}
	}
	switch {
	case found == 0:
		return ArchivedFacts{}, setAside(RuleXR7, verifier.ReasonTxHashMismatch, "no ordinary transaction of the block hashes to rail_ref")
	case found > 1:
		return ArchivedFacts{}, setAside(RuleXR7, verifier.ReasonResultIndexUnbound, "%d ordinary transactions hash to rail_ref", found)
	case uint64(at) != rec.TxIndex || rec.TxIndex >= rec.ResultsTotal:
		return ArchivedFacts{}, setAside(RuleXR7, verifier.ReasonResultIndexUnbound, "the transaction is unit %d, tx_index %d", at, rec.TxIndex)
	}

	// The result and its path reach last_results_hash of the next header.
	rule = RuleXR8
	code, err := provenResult(rec, next.h.LastResultsHash)
	if err != nil {
		return ArchivedFacts{}, err
	}
	return ArchivedFacts{
		Height: rec.Height, Header: hdr.h, HeaderHash: bytes.Clone(hdr.hash), NextHeaderHash: bytes.Clone(next.hash),
		TxIndex: rec.TxIndex, ResultsTotal: rec.ResultsTotal, Tx: bytes.Clone(txUnits[at]), Result: bytes.Clone(rec.Result), Code: code,
	}, nil
}

// archivedHeader decodes a protobuf header that must be the one at height of
// chainID. Its encoding need not be canonical: what is used is the decoded
// header, which its hash fixes.
func archivedHeader(raw []byte, height uint64, chainID string) (headerAt, error) {
	var ph cmtproto.Header
	if err := ph.Unmarshal(raw); err != nil {
		return headerAt{}, err
	}
	h, err := core.HeaderFromProto(&ph)
	if err != nil {
		return headerAt{}, err
	}
	if err := h.ValidateBasic(); err != nil {
		return headerAt{}, err
	}
	if h.Height < 1 || uint64(h.Height) != height || h.ChainID != chainID {
		return headerAt{}, fmt.Errorf("height %d of chain %q, want %d of %q", h.Height, h.ChainID, height, chainID)
	}
	hash := h.Hash()
	if len(hash) != 32 {
		return headerAt{}, errors.New("no hash")
	}
	return headerAt{h: h, hash: hash}, nil
}

// provenRange checks one share proof of the record: its namespace is
// the key's, it proves consecutive shares [s, e) of the original square
// against dataHash, and every share is of its namespace. It returns the
// shares, the range and the square width.
func provenRange(raw []byte, key uint64, want share.Namespace, dataHash []byte) ([]share.Share, int, int, int, error) {
	bad := func(format string, a ...any) ([]share.Share, int, int, int, error) {
		return nil, 0, 0, 0, setAside(RuleXR4, verifier.ReasonTxProofInvalid, "key %d: "+format, append([]any{key}, a...)...)
	}
	var sp proof.ShareProof
	if err := sp.Unmarshal(raw); err != nil {
		return bad("%v", err)
	}
	if sp.NamespaceVersion > 0xff {
		return bad("namespace version %d", sp.NamespaceVersion)
	}
	ns, err := share.NewNamespace(uint8(sp.NamespaceVersion), sp.NamespaceId)
	if err != nil {
		return bad("namespace: %v", err)
	}
	if key == 12 {
		if !share.PayForFibreNamespace.IsLessThan(ns) {
			return bad("the closing share's namespace %x does not follow the transaction namespaces", ns.Bytes())
		}
	} else if !ns.Equals(want) {
		return bad("namespace %x", ns.Bytes())
	}
	k := ShareProofWidth(sp)
	s, e, ok := ShareProofSpan(sp, k)
	if !ok || len(sp.Data) != e-s {
		return bad("does not prove consecutive shares of the original square")
	}
	if err := sp.Validate(dataHash); err != nil {
		return bad("%v", err)
	}
	shares, err := share.FromBytes(sp.Data)
	if err != nil {
		return bad("shares: %v", err)
	}
	for _, sh := range shares {
		if !sh.Namespace().Equals(ns) {
			return bad("a share of another namespace")
		}
	}
	return shares, s, e, k, nil
}

// wholeSequence requires the shares of a transaction namespace to be one
// whole compact sequence and returns its units.
func wholeSequence(shares []share.Share, key uint64) ([][]byte, error) {
	if !shares[0].IsSequenceStart() || compactShareCount(int(shares[0].SequenceLen())) != len(shares) {
		return nil, setAside(RuleXR5, verifier.ReasonTxProofInvalid, "key %d is not one whole compact sequence", key)
	}
	for i := 1; i < len(shares); i++ {
		if shares[i].IsSequenceStart() {
			return nil, setAside(RuleXR5, verifier.ReasonTxProofInvalid, "key %d: a second sequence starts at its share %d", key, i)
		}
	}
	units, err := share.ParseTxs(shares)
	if err != nil {
		return nil, setAside(RuleXR5, verifier.ReasonTxProofInvalid, "key %d units: %v", key, err)
	}
	return units, nil
}

// provenResult checks the result leaf and its path to the results root and
// returns the result code.
func provenResult(rec *archive.ExecutionResultRecord, root []byte) (uint32, error) {
	var res abci.ExecTxResult
	if err := res.Unmarshal(rec.Result); err != nil {
		return 0, setAside(RuleXR8, verifier.ReasonResultsRootMismatch, "result: %v", err)
	}
	det := abci.ExecTxResult{Code: res.Code, Data: res.Data, GasWanted: res.GasWanted, GasUsed: res.GasUsed}
	again, err := det.Marshal()
	if err != nil || !bytes.Equal(again, rec.Result) {
		return 0, setAside(RuleXR8, verifier.ReasonResultsRootMismatch, "the result is not the leaf of its deterministic fields")
	}
	if len(rec.ResultPath)%32 != 0 || rec.ResultsTotal > 1<<62 || rec.TxIndex >= rec.ResultsTotal {
		return 0, setAside(RuleXR8, verifier.ReasonResultsRootMismatch, "result path shape")
	}
	aunts := make([][]byte, 0, len(rec.ResultPath)/32)
	for i := 0; i < len(rec.ResultPath); i += 32 {
		aunts = append(aunts, rec.ResultPath[i:i+32])
	}
	leaf := sha256.Sum256(append([]byte{0}, rec.Result...))
	mp := merkle.Proof{Total: int64(rec.ResultsTotal), Index: int64(rec.TxIndex), LeafHash: leaf[:], Aunts: aunts}
	if err := mp.Verify(root, rec.Result); err != nil {
		return 0, setAside(RuleXR8, verifier.ReasonResultsRootMismatch, "the result path does not reach last_results_hash: %v", err)
	}
	return res.Code, nil
}

// ShareProofWidth is the width k of the original square from a share proof
// whose row proofs count the 2k row and 2k column roots; 0 when that is not
// 4k with k a power of two.
func ShareProofWidth(sp proof.ShareProof) int {
	if sp.RowProof == nil || len(sp.RowProof.Proofs) == 0 || sp.RowProof.Proofs[0] == nil {
		return 0
	}
	t := sp.RowProof.Proofs[0].Total
	if t < 4 || t%4 != 0 || t > 4*int64(appconsts.SquareSizeUpperBound) {
		return 0
	}
	k := t / 4
	if k&(k-1) != 0 {
		return 0
	}
	return int(k)
}

// ShareProofSpan returns the shares [start, end) of the original square of
// width k that sp proves, row by row: rows below k, consecutive, every row
// but the first starting at 0 and every row but the last ending at k. ok is
// false for any other shape.
func ShareProofSpan(sp proof.ShareProof, k int) (start, end int, ok bool) {
	rp := sp.RowProof
	if k == 0 || rp == nil {
		return 0, 0, false
	}
	rows := len(rp.RowRoots)
	if rows == 0 || len(rp.Proofs) != rows || len(sp.ShareProofs) != rows || int64(rp.EndRow)-int64(rp.StartRow)+1 != int64(rows) {
		return 0, 0, false
	}
	for i, p := range rp.Proofs {
		if p == nil || p.Total != int64(4*k) || p.Index != int64(rp.StartRow)+int64(i) || p.Index >= int64(k) {
			return 0, 0, false
		}
	}
	for i, p := range sp.ShareProofs {
		if p == nil || p.Start < 0 || p.End <= p.Start || int(p.End) > k {
			return 0, 0, false
		}
		if i > 0 && p.Start != 0 || i < rows-1 && int(p.End) != k {
			return 0, 0, false
		}
	}
	return int(rp.StartRow)*k + int(sp.ShareProofs[0].Start), int(rp.EndRow)*k + int(sp.ShareProofs[rows-1].End), true
}

// compactShareCount is the number of compact shares a sequence of seqLen
// bytes takes.
func compactShareCount(seqLen int) int {
	if seqLen <= share.FirstCompactShareContentSize {
		return 1
	}
	rest := seqLen - share.FirstCompactShareContentSize
	return 1 + (rest+share.ContinuationCompactShareContentSize-1)/share.ContinuationCompactShareContentSize
}
