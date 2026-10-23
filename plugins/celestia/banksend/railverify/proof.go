package railverify

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/bits"

	cmtjson "github.com/cometbft/cometbft/libs/json"
	core "github.com/cometbft/cometbft/types"
)

const (
	shareSize     = 512
	namespaceSize = 29
	// maxProofJSON bounds the proof before it is parsed. A block of 128 MiB
	// would need far more, but the proof of one small transaction does not.
	maxProofJSON = 4 << 20
)

func proofErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrTxProof, fmt.Sprintf(format, a...))
}

// ProofInfo is what a verified share proof says about where the transaction
// stands among the block's transactions.
type ProofInfo struct {
	// IndexBound is set when the proof starts at share 0 of the square, so
	// the units before the transaction's are all the block's earlier normal
	// transactions. Index is then the transaction's position in block order.
	IndexBound bool
	Index      int
}

// ProofVerifier checks a node's inclusion proof of tx against the data root
// of a trusted header.
type ProofVerifier func(proofJSON, tx, dataHash []byte) (ProofInfo, error)

// VerifyShareProof checks that tx is one unit of the compact shares that
// proofJSON proves under dataHash, in the transaction namespace. It checks
// what ShareProof.Validate leaves out: the namespace, that the rows are rows
// of the original square at the positions they claim, and that the unit
// boundaries are the ones the shares' reserved bytes give.
func VerifyShareProof(proofJSON, tx, dataHash []byte) error {
	_, err := VerifyShareProofAt(proofJSON, tx, dataHash)
	return err
}

// VerifyShareProofAt is VerifyShareProof that also reports where the
// transaction stands, when the proof binds that.
func VerifyShareProofAt(proofJSON, tx, dataHash []byte) (info ProofInfo, err error) {
	// The proof is a node's answer, and the decoders behind Validate are not
	// written for hostile input. A panic there is a bad proof.
	defer func() {
		if r := recover(); r != nil {
			info, err = ProofInfo{}, proofErr("malformed proof")
		}
	}()
	if len(proofJSON) == 0 || len(proofJSON) > maxProofJSON {
		return ProofInfo{}, proofErr("proof size")
	}
	if len(dataHash) != 32 {
		return ProofInfo{}, proofErr("data hash length")
	}
	var sp core.ShareProof
	if err := cmtjson.Unmarshal(proofJSON, &sp); err != nil {
		return ProofInfo{}, proofErr("decode: %v", err)
	}
	txNS := append(make([]byte, 27), 1)
	if sp.NamespaceVersion != 0 || !bytes.Equal(sp.NamespaceID, txNS) {
		return ProofInfo{}, proofErr("namespace is not the transaction namespace")
	}
	rows := len(sp.RowProof.RowRoots)
	if rows == 0 || len(sp.ShareProofs) != rows || len(sp.RowProof.Proofs) != rows || len(sp.Data) == 0 {
		return ProofInfo{}, proofErr("shape")
	}
	if err := sp.Validate(dataHash); err != nil {
		return ProofInfo{}, proofErr("%v", err)
	}

	// The extended square has 2k rows, so a row proof's total is 4k: the 2k
	// row roots and the 2k column roots.
	total := sp.RowProof.Proofs[0].Total
	if total < 4 || total%4 != 0 || bits.OnesCount64(uint64(total/4)) != 1 {
		return ProofInfo{}, proofErr("total %d", total)
	}
	k := total / 4
	for i, p := range sp.RowProof.Proofs {
		if p.Total != total || p.Index != int64(sp.RowProof.StartRow)+int64(i) || p.Index >= k {
			return ProofInfo{}, proofErr("row %d is not a row of the original square", i)
		}
	}
	if int64(sp.RowProof.EndRow)-int64(sp.RowProof.StartRow)+1 != int64(rows) {
		return ProofInfo{}, proofErr("row range")
	}
	for i, p := range sp.ShareProofs {
		if p.Start < 0 || p.End <= p.Start || int64(p.End) > k {
			return ProofInfo{}, proofErr("share range %d", i)
		}
		if i < rows-1 && int64(p.End) != k {
			return ProofInfo{}, proofErr("row %d does not end at the row end", i)
		}
		if i > 0 && p.Start != 0 {
			return ProofInfo{}, proofErr("row %d does not start at 0", i)
		}
	}

	shareNS := append([]byte{0}, txNS...)
	var stream []byte
	// The first unit of share 0 of the square starts right after the share's
	// header; only then do the units before the transaction's count its
	// position in block order.
	fromSquareStart := sp.RowProof.StartRow == 0 && sp.ShareProofs[0].Start == 0
	for i, s := range sp.Data {
		if len(s) != shareSize || !bytes.Equal(s[:namespaceSize], shareNS) {
			return ProofInfo{}, proofErr("share %d is not in the transaction namespace", i)
		}
		infoByte := s[namespaceSize]
		if infoByte>>1 != 0 {
			return ProofInfo{}, proofErr("share %d version", i)
		}
		reserved := namespaceSize + 1
		if infoByte&1 == 1 {
			reserved += 4 // sequence length
		}
		if i == 0 {
			off := int(binary.BigEndian.Uint32(s[reserved : reserved+4]))
			if off < reserved+4 || off >= shareSize {
				return ProofInfo{}, proofErr("no unit starts in the first share")
			}
			fromSquareStart = fromSquareStart && infoByte&1 == 1 && off == reserved+4
			stream = append(stream, s[off:]...)
			continue
		}
		if infoByte&1 == 1 {
			return ProofInfo{}, proofErr("share %d starts a sequence", i)
		}
		stream = append(stream, s[reserved+4:]...)
	}

	units, at, unit := 0, 0, 0
	for len(stream) > 0 {
		l, n := uvarint(stream)
		if n <= 0 || uint64(len(stream)-n) < l {
			break
		}
		if u := stream[n : n+int(l)]; len(tx) > 0 && bytes.Equal(u, tx) {
			units++
			at = unit
		}
		unit++
		stream = stream[n+int(l):]
	}
	if units != 1 {
		return ProofInfo{}, proofErr("the proven shares hold %d units equal to the transaction", units)
	}
	return ProofInfo{IndexBound: fromSquareStart, Index: at}, nil
}

// uvarint reads an unsigned varint of at most ten bytes; n <= 0 means it
// does not fit.
func uvarint(b []byte) (v uint64, n int) {
	for i, c := range b {
		if i >= 10 {
			return 0, -1
		}
		v |= uint64(c&0x7f) << (7 * uint(i))
		if c < 0x80 {
			return v, i + 1
		}
	}
	return 0, 0
}
