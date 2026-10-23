package execcapture

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/celestiaorg/celestia-app/v10/pkg/appconsts"
	"github.com/celestiaorg/celestia-app/v10/pkg/da"
	"github.com/celestiaorg/celestia-app/v10/pkg/proof"
	fibretypes "github.com/celestiaorg/celestia-app/v10/x/fibre/types"
	square "github.com/celestiaorg/go-square/v4"
	"github.com/celestiaorg/go-square/v4/share"
)

// NamespaceProof proves the shares [Start, End) of the original square, all
// in Namespace, against the data root of the block's header. Proof is the
// protobuf ShareProof (the celestia-app and celestia-core messages share one
// wire layout).
type NamespaceProof struct {
	Namespace []byte `json:"namespace"`
	Start     int    `json:"start"`
	End       int    `json:"end"`
	Proof     []byte `json:"proof"`
}

// txNamespaces are the compact namespaces whose units are the block's
// transactions, in the order the block lists them: ordinary txs, blob txs
// (as index wrappers), then Fibre txs.
var txNamespaces = []share.Namespace{share.TxNamespace, share.PayForBlobNamespace, share.PayForFibreNamespace}

// positionProofs rebuilds the square of txs under the pinned square rules,
// requires its data root to be dataHash, and proves every transaction
// namespace in full, plus the first share after them, so that the proven
// ranges cover [0, end] without a gap: a reader then knows every unit that
// precedes a transaction.
func positionProofs(txs [][]byte, dataHash []byte) (out []NamespaceProof, err error) {
	// The transactions are a node's answer, and the square builder is not
	// written for hostile input.
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, fmt.Errorf("%w: block does not build a square: %v", ErrUnproven, r)
		}
	}()
	if len(txs) == 0 {
		return nil, fmt.Errorf("%w: block has no transactions", ErrUnproven)
	}
	classified, err := fibretypes.ClassifyTxs(txs)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnproven, err)
	}
	sq, err := square.Construct(classified, appconsts.SquareSizeUpperBound, appconsts.SubtreeRootThreshold)
	if err != nil {
		return nil, fmt.Errorf("%w: block does not build a square: %w", ErrUnproven, err)
	}
	eds, err := da.ExtendShares(share.ToBytes(sq))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnproven, err)
	}
	dah, err := da.NewDataAvailabilityHeader(eds)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnproven, err)
	}
	if !bytes.Equal(dah.Hash(), dataHash) {
		return nil, fmt.Errorf("%w: the block's transactions do not rebuild data_hash", ErrUnproven)
	}
	end := 0
	add := func(ns share.Namespace, r share.Range) error {
		sp, err := proof.NewShareInclusionProofFromEDS(eds, ns, r)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrUnproven, err)
		}
		raw, err := sp.Marshal()
		if err != nil {
			return fmt.Errorf("%w: %w", ErrUnproven, err)
		}
		out = append(out, NamespaceProof{Namespace: ns.Bytes(), Start: r.Start, End: r.End, Proof: raw})
		return nil
	}
	for _, ns := range txNamespaces {
		r := share.GetShareRangeForNamespace(sq, ns)
		if r.IsEmpty() {
			continue
		}
		if r.Start != end {
			return nil, fmt.Errorf("%w: namespace %x starts at share %d, not %d", ErrUnproven, ns.Bytes(), r.Start, end)
		}
		if err := add(ns, r); err != nil {
			return nil, err
		}
		end = r.End
	}
	if end < len(sq) {
		if err := add(sq[end].Namespace(), share.NewRange(end, end+1)); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// position derives the index of the transaction railRef in its block from
// the proofs alone: the proven ranges must run from share 0 without a gap,
// end at a share past the transaction namespaces (or at the square's end),
// and each verify against dataHash. The ordinary-tx units come first in
// block order, then the blob txs, then the Fibre txs, so an ordinary tx at
// position j of the transaction namespace is at index j, and the unit counts
// of the three namespaces add up to the block's transaction count n. The
// rule holds for the pinned square rules only.
func position(proofs []NamespaceProof, dataHash []byte, railRef [32]byte, n int) (int, []byte, error) {
	var (
		counts = map[string]int{}
		units  [][]byte
		end    = 0
		closed = false
	)
	for i, np := range proofs {
		if closed {
			return 0, nil, fmt.Errorf("%w: a proof after the closing share", ErrUnproven)
		}
		var sp proof.ShareProof
		if err := sp.Unmarshal(np.Proof); err != nil {
			return 0, nil, fmt.Errorf("%w: proof %d: %w", ErrUnproven, i, err)
		}
		if np.Start != end || np.End <= np.Start || len(sp.Data) != np.End-np.Start {
			return 0, nil, fmt.Errorf("%w: proof %d covers [%d, %d), the next share is %d", ErrUnproven, i, np.Start, np.End, end)
		}
		ns, err := share.NewNamespaceFromBytes(np.Namespace)
		if err != nil || sp.NamespaceVersion != uint32(ns.Version()) || !bytes.Equal(sp.NamespaceId, ns.ID()) {
			return 0, nil, fmt.Errorf("%w: proof %d namespace", ErrUnproven, i)
		}
		if !coversRange(sp, np.Start, np.End) {
			return 0, nil, fmt.Errorf("%w: proof %d does not prove the shares [%d, %d) of the original square", ErrUnproven, i, np.Start, np.End)
		}
		if err := sp.Validate(dataHash); err != nil {
			return 0, nil, fmt.Errorf("%w: proof %d: %w", ErrUnproven, i, err)
		}
		shares, err := share.FromBytes(sp.Data)
		if err != nil {
			return 0, nil, fmt.Errorf("%w: proof %d shares: %w", ErrUnproven, i, err)
		}
		for _, s := range shares {
			if !s.Namespace().Equals(ns) {
				return 0, nil, fmt.Errorf("%w: proof %d holds a share of another namespace", ErrUnproven, i)
			}
		}
		end = np.End
		if !isTxNamespace(ns) {
			if !share.PayForFibreNamespace.IsLessThan(ns) {
				return 0, nil, fmt.Errorf("%w: proof %d: the closing share's namespace %x does not follow the transaction namespaces", ErrUnproven, i, np.Namespace)
			}
			closed = true
			continue
		}
		if _, dup := counts[string(ns.Bytes())]; dup {
			return 0, nil, fmt.Errorf("%w: namespace %x proven twice", ErrUnproven, ns.Bytes())
		}
		if !shares[0].IsSequenceStart() || compactShares(int(shares[0].SequenceLen())) != len(shares) {
			return 0, nil, fmt.Errorf("%w: proof %d is not one whole sequence", ErrUnproven, i)
		}
		us, err := share.ParseTxs(shares)
		if err != nil {
			return 0, nil, fmt.Errorf("%w: proof %d units: %w", ErrUnproven, i, err)
		}
		counts[string(ns.Bytes())] = len(us)
		if ns.Equals(share.TxNamespace) {
			units = us
		}
	}
	if !closed && end == 0 {
		return 0, nil, fmt.Errorf("%w: no namespace proof", ErrUnproven)
	}
	if !closed {
		// Without a closing share the proven ranges must end the square.
		var last proof.ShareProof
		if err := last.Unmarshal(proofs[len(proofs)-1].Proof); err != nil || squareWidth(last)*squareWidth(last) != end {
			return 0, nil, fmt.Errorf("%w: the transaction namespaces are not shown to end at share %d", ErrUnproven, end)
		}
	}
	total := 0
	for _, c := range counts {
		total += c
	}
	if total != n {
		return 0, nil, fmt.Errorf("%w: %d units in the transaction namespaces, %d results", ErrUnproven, total, n)
	}
	at, found := -1, 0
	for j, u := range units {
		if sha256.Sum256(u) == railRef {
			at = j
			found++
		}
	}
	if found != 1 {
		return 0, nil, fmt.Errorf("%w: %d ordinary transactions hash to the rail_ref", ErrUnproven, found)
	}
	return at, units[at], nil
}

func isTxNamespace(ns share.Namespace) bool {
	for _, t := range txNamespaces {
		if ns.Equals(t) {
			return true
		}
	}
	return false
}

// squareWidth is the width k of the original square, from a row proof whose
// total counts the 2k row roots and 2k column roots.
func squareWidth(sp proof.ShareProof) int {
	if sp.RowProof == nil || len(sp.RowProof.Proofs) == 0 || sp.RowProof.Proofs[0] == nil {
		return 0
	}
	t := sp.RowProof.Proofs[0].Total
	if t < 4 || t%4 != 0 {
		return 0
	}
	return int(t / 4)
}

// coversRange reports whether sp proves exactly the shares [start, end) of
// the original square, row by row in order.
func coversRange(sp proof.ShareProof, start, end int) bool {
	k := squareWidth(sp)
	rp := sp.RowProof
	if k == 0 || start < 0 || end <= start || end > k*k {
		return false
	}
	rows := len(rp.RowRoots)
	if rows == 0 || len(rp.Proofs) != rows || len(sp.ShareProofs) != rows ||
		int(rp.StartRow) != start/k || int(rp.EndRow) != (end-1)/k || int(rp.EndRow)-int(rp.StartRow)+1 != rows {
		return false
	}
	for i, p := range rp.Proofs {
		if p == nil || p.Total != int64(4*k) || p.Index != int64(rp.StartRow)+int64(i) {
			return false
		}
	}
	for i, p := range sp.ShareProofs {
		if p == nil {
			return false
		}
		wantStart, wantEnd := 0, k
		if i == 0 {
			wantStart = start % k
		}
		if i == rows-1 {
			wantEnd = (end-1)%k + 1
		}
		if int(p.Start) != wantStart || int(p.End) != wantEnd {
			return false
		}
	}
	return true
}

// compactShares is the number of compact shares a sequence of seqLen bytes
// takes.
func compactShares(seqLen int) int {
	if seqLen <= share.FirstCompactShareContentSize {
		return 1
	}
	rest := seqLen - share.FirstCompactShareContentSize
	return 1 + (rest+share.ContinuationCompactShareContentSize-1)/share.ContinuationCompactShareContentSize
}
