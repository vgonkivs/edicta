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

// VerifyShareProof checks that tx is one unit of the compact shares that
// proofJSON proves under dataHash, in the transaction namespace. It checks
// what ShareProof.Validate leaves out: the namespace, that the rows are rows
// of the original square at the positions they claim, and that the unit
// boundaries are the ones the shares' reserved bytes give.
func VerifyShareProof(proofJSON, tx, dataHash []byte) (err error) {
	// The proof is a node's answer, and the decoders behind Validate are not
	// written for hostile input. A panic there is a bad proof.
	defer func() {
		if r := recover(); r != nil {
			err = proofErr("malformed proof")
		}
	}()
	if len(proofJSON) == 0 || len(proofJSON) > maxProofJSON {
		return proofErr("proof size")
	}
	if len(dataHash) != 32 {
		return proofErr("data hash length")
	}
	var sp core.ShareProof
	if err := cmtjson.Unmarshal(proofJSON, &sp); err != nil {
		return proofErr("decode: %v", err)
	}
	txNS := append(make([]byte, 27), 1)
	if sp.NamespaceVersion != 0 || !bytes.Equal(sp.NamespaceID, txNS) {
		return proofErr("namespace is not the transaction namespace")
	}
	rows := len(sp.RowProof.RowRoots)
	if rows == 0 || len(sp.ShareProofs) != rows || len(sp.RowProof.Proofs) != rows || len(sp.Data) == 0 {
		return proofErr("shape")
	}
	if err := sp.Validate(dataHash); err != nil {
		return proofErr("%v", err)
	}

	// The extended square has 2k rows, so a row proof's total is 4k: the 2k
	// row roots and the 2k column roots.
	total := sp.RowProof.Proofs[0].Total
	if total < 4 || total%4 != 0 || bits.OnesCount64(uint64(total/4)) != 1 {
		return proofErr("total %d", total)
	}
	k := total / 4
	for i, p := range sp.RowProof.Proofs {
		if p.Total != total || p.Index != int64(sp.RowProof.StartRow)+int64(i) || p.Index >= k {
			return proofErr("row %d is not a row of the original square", i)
		}
	}
	if int64(sp.RowProof.EndRow)-int64(sp.RowProof.StartRow)+1 != int64(rows) {
		return proofErr("row range")
	}
	for i, p := range sp.ShareProofs {
		if p.Start < 0 || p.End <= p.Start || int64(p.End) > k {
			return proofErr("share range %d", i)
		}
		if i < rows-1 && int64(p.End) != k {
			return proofErr("row %d does not end at the row end", i)
		}
		if i > 0 && p.Start != 0 {
			return proofErr("row %d does not start at 0", i)
		}
	}

	shareNS := append([]byte{0}, txNS...)
	var stream []byte
	for i, s := range sp.Data {
		if len(s) != shareSize || !bytes.Equal(s[:namespaceSize], shareNS) {
			return proofErr("share %d is not in the transaction namespace", i)
		}
		info := s[namespaceSize]
		if info>>1 != 0 {
			return proofErr("share %d version", i)
		}
		reserved := namespaceSize + 1
		if info&1 == 1 {
			reserved += 4 // sequence length
		}
		if i == 0 {
			off := int(binary.BigEndian.Uint32(s[reserved : reserved+4]))
			if off < reserved+4 || off >= shareSize {
				return proofErr("no unit starts in the first share")
			}
			stream = append(stream, s[off:]...)
			continue
		}
		if info&1 == 1 {
			return proofErr("share %d starts a sequence", i)
		}
		stream = append(stream, s[reserved+4:]...)
	}

	units := 0
	for len(stream) > 0 {
		l, n := uvarint(stream)
		if n <= 0 || uint64(len(stream)-n) < l {
			break
		}
		if unit := stream[n : n+int(l)]; len(tx) > 0 && bytes.Equal(unit, tx) {
			units++
		}
		stream = stream[n+int(l):]
	}
	if units != 1 {
		return proofErr("the proven shares hold %d units equal to the transaction", units)
	}
	return nil
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
