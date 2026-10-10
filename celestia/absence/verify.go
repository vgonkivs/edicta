package absence

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/celestiaorg/celestia-app/v10/pkg/da"
	daproto "github.com/celestiaorg/celestia-app/v10/proto/celestia/core/v1/da"
	fibretypes "github.com/celestiaorg/celestia-app/v10/x/fibre/types"
	"github.com/celestiaorg/celestia-node/share"
	"github.com/celestiaorg/celestia-node/share/shwap"
	"github.com/celestiaorg/go-square/v4/inclusion"
	libshare "github.com/celestiaorg/go-square/v4/share"
	"github.com/cometbft/cometbft/crypto/merkle"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	core "github.com/cometbft/cometbft/types"
	cosmostx "github.com/cosmos/cosmos-sdk/types/tx"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/celestia/fibreproof"
	"github.com/vgonkivs/edicta/commitment"
)

// Query names the anchor whose absence is proven.
type Query struct {
	DA         commitment.DA
	Namespace  []byte // payload_ref.namespace
	Commitment []byte // payload_ref.commitment
	Signer     []byte // payload_ref.signer, da = 2 only
	ChainID    string // the chain a PayForFibre promise must name, da = 1 only
}

// ValidateBasic checks the query fields.
func (q Query) ValidateBasic() error {
	if err := q.validateTarget(); err != nil {
		return err
	}
	if q.DA == commitment.DAFibre && q.ChainID == "" {
		return fmt.Errorf("%w: da = 1 needs the chain id", ErrQuery)
	}
	return nil
}

// validateTarget checks the fields that name the anchor.
func (q Query) validateTarget() error {
	switch {
	case q.DA != commitment.DAFibre && q.DA != commitment.DACelestiaBlob:
		return fmt.Errorf("%w: da %d", ErrQuery, q.DA)
	case len(q.Commitment) != commitmentSize:
		return fmt.Errorf("%w: commitment is %d bytes", ErrQuery, len(q.Commitment))
	case !namespaceOK(q.Namespace):
		return fmt.Errorf("%w: namespace %x is not a user blob namespace", ErrQuery, q.Namespace)
	case q.DA == commitment.DACelestiaBlob && len(q.Signer) != signerSize:
		return fmt.Errorf("%w: signer is %d bytes", ErrQuery, len(q.Signer))
	case q.DA == commitment.DAFibre && q.Signer != nil:
		return fmt.Errorf("%w: signer is not defined for da = 1", ErrQuery)
	}
	return nil
}

// TrustedHashes maps a height to the block hash header trust reached there
// (one backward chain from a trusted checkpoint at or above the deadline).
type TrustedHashes map[uint64][]byte

// Result is what one height, or a window, shows. The zero value is Unproven.
type Result uint8

const (
	Unproven Result = iota
	Absent
	Present
)

func (r Result) String() string {
	switch r {
	case Absent:
		return "absent"
	case Present:
		return "present"
	default:
		return "unproven"
	}
}

// Rule names the check that decided a height, with the identifiers the
// verifier report and the vectors use.
type Rule string

const (
	RuleNoProof       Rule = "none"
	RuleRecord        Rule = "record"
	RuleHeader        Rule = "AB1"
	RuleDAH           Rule = "AB2"
	RuleNamespaceData Rule = "AB3"
	RuleCandidates    Rule = "AB4"
	RuleResults       Rule = "AB5"
	RuleBlobs         Rule = "AB6"
)

// Candidate is a PayForFibre tx of the height that matches the query.
type Candidate struct {
	Position int // among the units reassembled from the PFF namespace
	// ResultIndex is set only when the tail rule bound the index; a
	// uniform all-zero result set at another app version binds none.
	ResultIndex int
	IndexBound  bool
	Code        uint32
}

// Blob is a blob found in the queried namespace.
type Blob struct {
	ShareVersion uint8
	Signer       []byte // share version 1 only
	Commitment   []byte // share version 1 only
}

// Outcome is the verdict for one height. Err is set iff Result is Unproven.
// The details (Rows and after) are set only for a proven height.
type Outcome struct {
	Height     uint64
	Result     Result
	Rule       Rule
	Err        error
	Rows       []int
	PFFTxs     int
	Candidates []Candidate
	Blobs      []Blob
}

func unproven(h uint64, rule Rule, sentinel error, format string, a ...any) Outcome {
	return Outcome{Height: h, Result: Unproven, Rule: rule, Err: fmt.Errorf("%w: "+format, append([]any{sentinel}, a...)...)}
}

// VerifyHeight checks one record for height h of the query against the
// trusted hashes. It never returns Absent unless every byte the verdict rests
// on is tied to a trusted header.
func VerifyHeight(rec *archive.AbsenceProofRecord, q Query, h uint64, trusted TrustedHashes) (out Outcome) {
	if err := q.ValidateBasic(); err != nil {
		return Outcome{Height: h, Result: Unproven, Rule: RuleRecord, Err: err}
	}
	// Every byte of the record is attacker-supplied, and the upstream
	// decoders are as exposed as the verifiers.
	defer func() {
		if r := recover(); r != nil {
			out = unproven(h, out.Rule, sentinelFor(out.Rule), "panic in upstream code: %v", r)
		}
	}()
	if rec == nil {
		return unproven(h, RuleNoProof, ErrNoProof, "height %d", h)
	}
	out.Rule = RuleRecord
	if rec.DA != q.DA || !bytes.Equal(rec.Commitment, q.Commitment) || !bytes.Equal(rec.Namespace, q.Namespace) ||
		rec.Height != h {
		return unproven(h, RuleRecord, ErrRecordMismatch, "da %d, height %d", rec.DA, rec.Height)
	}

	out.Rule = RuleHeader
	sh, err := trustedHeader(rec.Header, h, trusted)
	if err != nil {
		return unproven(h, RuleHeader, ErrHeader, "%w", err)
	}

	out.Rule = RuleDAH
	var dp daproto.DataAvailabilityHeader
	if err := dp.Unmarshal(rec.DAH); err != nil {
		return unproven(h, RuleDAH, ErrDAH, "protobuf: %w", err)
	}
	dah := &da.DataAvailabilityHeader{RowRoots: dp.RowRoots, ColumnRoots: dp.ColumnRoots}
	if err := fibreproof.CheckDAH(dah, sh.DataHash); err != nil {
		return unproven(h, RuleDAH, ErrDAH, "%w", err)
	}

	out.Rule = RuleNamespaceData
	ns := libshare.PayForFibreNamespace
	if q.DA == commitment.DACelestiaBlob {
		if ns, err = libshare.NewNamespaceFromBytes(q.Namespace); err != nil {
			return unproven(h, RuleNamespaceData, ErrNamespaceData, "namespace: %w", err)
		}
	}
	var nd shwap.NamespaceData
	if _, err := nd.ReadFrom(bytes.NewReader(rec.NamespaceData)); err != nil {
		return unproven(h, RuleNamespaceData, ErrNamespaceData, "decode: %w", err)
	}
	if err := nd.Verify(dah, ns); err != nil {
		return unproven(h, RuleNamespaceData, ErrNamespaceData, "%w", err)
	}
	rows, err := share.RowsWithNamespace(dah, ns)
	if err != nil {
		return unproven(h, RuleNamespaceData, ErrNamespaceData, "%w", err)
	}
	shares := nd.Flatten()

	if q.DA == commitment.DACelestiaBlob {
		out.Rule = RuleBlobs
		return blobs(h, q, rows, shares)
	}
	out.Rule = RuleCandidates
	return fibre(h, q, rec, sh, rows, shares, trusted)
}

func sentinelFor(r Rule) error {
	switch r {
	case RuleHeader:
		return ErrHeader
	case RuleDAH:
		return ErrDAH
	case RuleNamespaceData:
		return ErrNamespaceData
	case RuleResults:
		return ErrResultUnproven
	case RuleCandidates, RuleBlobs:
		return ErrShares
	default:
		return ErrRecordMismatch
	}
}

// decodeSignedHeader decodes an untrusted protobuf SignedHeader that must be
// for height h. Upstream decoding accepts one without a header, and every
// caller reads the header, so that is refused here.
func decodeSignedHeader(b []byte, h uint64) (*core.SignedHeader, error) {
	var pb cmtproto.SignedHeader
	if err := pb.Unmarshal(b); err != nil {
		return nil, fmt.Errorf("signed header protobuf: %w", err)
	}
	if pb.Header == nil {
		return nil, errors.New("signed header has no header")
	}
	sh, err := core.SignedHeaderFromProto(&pb)
	if err != nil {
		return nil, fmt.Errorf("signed header: %w", err)
	}
	if sh.Header == nil {
		return nil, errors.New("signed header has no header")
	}
	if sh.Height < 0 || uint64(sh.Height) != h {
		return nil, fmt.Errorf("header height %d, want %d", sh.Height, h)
	}
	return sh, nil
}

// SignedHeaderHash returns the block hash and chain id of an untrusted
// protobuf SignedHeader that must be for height h.
func SignedHeaderHash(b []byte, h uint64) (hash []byte, chainID string, err error) {
	defer func() {
		if r := recover(); r != nil {
			hash, chainID, err = nil, "", fmt.Errorf("signed header at %d: panic in upstream code: %v", h, r)
		}
	}()
	sh, err := decodeSignedHeader(b, h)
	if err != nil {
		return nil, "", err
	}
	hash = sh.Header.Hash()
	if len(hash) != 32 {
		return nil, "", fmt.Errorf("header at %d has no hash", h)
	}
	return hash, sh.ChainID, nil
}

func trustedHeader(b []byte, h uint64, trusted TrustedHashes) (*core.SignedHeader, error) {
	sh, err := decodeSignedHeader(b, h)
	if err != nil {
		return nil, err
	}
	want, ok := trusted[h]
	if !ok {
		return nil, fmt.Errorf("header trust does not reach %d", h)
	}
	hash := sh.Header.Hash()
	if len(hash) == 0 || !bytes.Equal(hash, want) {
		return nil, fmt.Errorf("header hash at %d differs from the trusted hash", h)
	}
	if sh.Commit == nil || sh.Commit.Height != sh.Height || !bytes.Equal(sh.Commit.BlockID.Hash, hash) {
		return nil, fmt.Errorf("commit at %d is not for this header", h)
	}
	return sh, nil
}

func blobs(h uint64, q Query, rows []int, shares []libshare.Share) Outcome {
	out := Outcome{Height: h, Rule: RuleBlobs, Rows: rows}
	if len(shares) == 0 {
		out.Result = Absent
		return out
	}
	parsed, err := libshare.ParseBlobs(shares)
	if err != nil {
		return unproven(h, RuleBlobs, ErrShares, "%w", err)
	}
	present := false
	for _, b := range parsed {
		bd := Blob{ShareVersion: b.ShareVersion()}
		if b.ShareVersion() == libshare.ShareVersionOne {
			com, err := inclusion.CreateCommitment(b, merkle.HashFromByteSlices, SubtreeRootThreshold)
			if err != nil {
				return unproven(h, RuleBlobs, ErrShares, "share commitment: %w", err)
			}
			bd.Signer, bd.Commitment = bytes.Clone(b.Signer()), com
			present = present || (bytes.Equal(com, q.Commitment) && bytes.Equal(b.Signer(), q.Signer))
		}
		out.Blobs = append(out.Blobs, bd)
	}
	out.Result = Absent
	if present {
		out.Result = Present
	}
	return out
}

func fibre(h uint64, q Query, rec *archive.AbsenceProofRecord, sh *core.SignedHeader, rows []int, shares []libshare.Share,
	trusted TrustedHashes) Outcome {
	out := Outcome{Height: h, Rule: RuleCandidates, Rows: rows}
	// The namespace rows are selected by the pinned layout. At another app version Fibre
	// txs may sit elsewhere or be encoded otherwise, so neither an empty
	// PFF_NS nor units without a candidate prove the anchor absent.
	pinned := sh.Version.App == PinnedAppVersion
	if len(shares) == 0 {
		if !pinned {
			return unproven(h, RuleCandidates, ErrOtherAppVersion, "app version %d, PFF_NS empty", sh.Version.App)
		}
		out.Result = Absent
		return out
	}
	units, err := fibreproof.Reassemble(shares)
	if err != nil {
		return unproven(h, RuleCandidates, ErrShares, "%w", err)
	}
	out.PFFTxs = len(units)
	var cands []int
	for j, tx := range units {
		match, err := isCandidate(tx, q, h)
		if err != nil {
			return unproven(h, RuleCandidates, ErrShares, "unit %d: %w", j, err)
		}
		if match {
			cands = append(cands, j)
		}
	}
	if len(cands) == 0 {
		if !pinned {
			return unproven(h, RuleCandidates, ErrOtherAppVersion, "app version %d, no candidate among %d unit(s)",
				sh.Version.App, len(units))
		}
		out.Result = Absent
		return out
	}

	out.Rule = RuleResults
	if rec.Results == nil || rec.NextHeader == nil {
		return unproven(h, RuleResults, ErrResultsMissing, "%d candidate(s)", len(cands))
	}
	next, err := trustedHeader(rec.NextHeader, h+1, trusted)
	if err != nil {
		return unproven(h, RuleResults, ErrResultUnproven, "next header: %w", err)
	}
	codes, err := provenCodes(rec.Results, next.LastResultsHash)
	if err != nil {
		return unproven(h, RuleResults, ErrResultUnproven, "%w", err)
	}
	n, p := len(codes), len(units)
	if n < p || p < 1 {
		return unproven(h, RuleResults, ErrResultUnproven, "n >= p >= 1 does not hold: n %d, p %d", n, p)
	}

	// A block of another app version may follow other square rules, so its
	// results bind no index and can never prove absence. Every code 0 still
	// proves presence, because the root fixes every result.
	if !pinned {
		for _, c := range codes {
			if c != 0 {
				return unproven(h, RuleResults, ErrResultUnproven,
					"app version %d without every code 0", sh.Version.App)
			}
		}
		for _, j := range cands {
			out.Candidates = append(out.Candidates, Candidate{Position: j})
		}
		out.Result = Present
		return out
	}

	// At the pinned version the Fibre txs are the last p txs of the block, in
	// PFF namespace order, with one result per tx.
	out.Result = Absent
	for _, j := range cands {
		i := n - p + j
		out.Candidates = append(out.Candidates, Candidate{Position: j, ResultIndex: i, IndexBound: true, Code: codes[i]})
		if codes[i] == 0 {
			out.Result = Present
		}
	}
	return out
}

// isCandidate decodes a PFF_NS unit the way the anchor check reads a
// PayForFibre tx and reports whether it promises the queried blob no later
// than h. A unit that does not decode is an error whatever the upstream
// classifier says: what it promises is unknown, so skipping it could hide
// the anchor.
func isCandidate(tx []byte, q Query, h uint64) (bool, error) {
	var raw cosmostx.TxRaw
	if err := raw.Unmarshal(tx); err != nil {
		return false, fmt.Errorf("tx: %w", err)
	}
	var body cosmostx.TxBody
	if err := body.Unmarshal(raw.BodyBytes); err != nil {
		return false, fmt.Errorf("tx body: %w", err)
	}
	if len(body.Messages) != 1 || body.Messages[0] == nil {
		return false, fmt.Errorf("tx with %d messages", len(body.Messages))
	}
	if body.Messages[0].TypeUrl != pffTypeURL {
		return false, fmt.Errorf("message type %q", body.Messages[0].TypeUrl)
	}
	var msg fibretypes.MsgPayForFibre
	if err := msg.Unmarshal(body.Messages[0].Value); err != nil {
		return false, fmt.Errorf("MsgPayForFibre: %w", err)
	}
	pp := msg.PaymentPromise
	if len(pp.Namespace) != namespaceSize || len(pp.Commitment) != commitmentSize {
		return false, fmt.Errorf("promise namespace of %d bytes, commitment of %d", len(pp.Namespace), len(pp.Commitment))
	}
	return bytes.Equal(pp.Namespace, q.Namespace) && bytes.Equal(pp.Commitment, q.Commitment) &&
		pp.BlobVersion == 0 && pp.ChainId == q.ChainID && pp.Height <= int64(h), nil
}
