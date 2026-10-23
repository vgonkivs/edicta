// Package fibreproof holds the checks of the da = 1 anchor proof that the
// gate and the verifier share: the DAH against the data hash, the namespace
// data against the DAH, the reassembly of the PayForFibre txs, and the
// archive form of the proof.
package fibreproof

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/celestiaorg/celestia-app/v10/pkg/da"
	"github.com/celestiaorg/celestia-node/share/shwap"
	libshare "github.com/celestiaorg/go-square/v4/share"
)

// CheckDAH requires the DAH to pass ValidateBasic and to hash to the data
// hash of the header.
func CheckDAH(dah *da.DataAvailabilityHeader, dataHash []byte) error {
	if err := dah.ValidateBasic(); err != nil {
		return err
	}
	// Hash caches its result in the struct it is called on, so the caller
	// passes a fresh value.
	if !bytes.Equal(dah.Hash(), dataHash) {
		return errors.New("dah does not hash to the header data hash")
	}
	return nil
}

// VerifyNamespaceData decodes the namespace data stream of the PayForFibre
// namespace, verifies it against the DAH (complete NMT namespace proofs) and
// returns the reassembled txs.
func VerifyNamespaceData(dah *da.DataAvailabilityHeader, stream []byte) ([][]byte, error) {
	var nd shwap.NamespaceData
	if _, err := nd.ReadFrom(bytes.NewReader(stream)); err != nil {
		return nil, err
	}
	if err := nd.Verify(dah, libshare.PayForFibreNamespace); err != nil {
		return nil, err
	}
	return Reassemble(nd.Flatten())
}

// Reassemble parses the compact shares of the PayForFibre namespace and
// accepts them only if splitting the txs again gives the same shares. That
// rules out a cut last unit, a missing or extra share and a second sequence,
// all of which ParseTxs alone tolerates or drops without an error.
func Reassemble(shares []libshare.Share) ([][]byte, error) {
	if len(shares) == 0 {
		return nil, nil
	}
	txs, err := libshare.ParseTxs(shares)
	if err != nil {
		return nil, fmt.Errorf("parse txs: %w", err)
	}
	css := libshare.NewCompactShareSplitter(libshare.PayForFibreNamespace, libshare.ShareVersionZero)
	for _, tx := range txs {
		if err := css.WriteTx(tx); err != nil {
			return nil, fmt.Errorf("split txs: %w", err)
		}
	}
	again, err := css.Export()
	if err != nil {
		return nil, fmt.Errorf("split txs: %w", err)
	}
	if len(again) != len(shares) {
		return nil, fmt.Errorf("re-split gives %d shares, the namespace has %d", len(again), len(shares))
	}
	for i := range again {
		if !bytes.Equal(again[i].ToBytes(), shares[i].ToBytes()) {
			return nil, fmt.Errorf("re-split differs at share %d", i)
		}
	}
	return txs, nil
}

// EncodeProof is the archive form of the anchor proof: the deterministic CBOR
// map {1: 1, 2: DAH protobuf, 3: namespace data stream}.
func EncodeProof(dahProto, stream []byte) []byte {
	var b bytes.Buffer
	b.WriteByte(0xa3)
	b.Write([]byte{0x01, 0x01, 0x02})
	bytesHead(&b, uint64(len(dahProto)))
	b.Write(dahProto)
	b.WriteByte(0x03)
	bytesHead(&b, uint64(len(stream)))
	b.Write(stream)
	return b.Bytes()
}

// DecodeProof splits a form-1 proof. Anything that EncodeProof would not
// write for the same parts is refused.
func DecodeProof(raw []byte) (dahProto, stream []byte, err error) {
	rest := raw
	if !bytes.HasPrefix(rest, []byte{0xa3, 0x01, 0x01, 0x02}) {
		return nil, nil, errors.New("not a form-1 anchor proof")
	}
	rest = rest[4:]
	if dahProto, rest, err = readBytes(rest); err != nil {
		return nil, nil, fmt.Errorf("dah: %w", err)
	}
	if len(rest) == 0 || rest[0] != 0x03 {
		return nil, nil, errors.New("namespace data key missing")
	}
	if stream, rest, err = readBytes(rest[1:]); err != nil {
		return nil, nil, fmt.Errorf("namespace data: %w", err)
	}
	if len(rest) != 0 {
		return nil, nil, errors.New("bytes after the proof")
	}
	if !bytes.Equal(EncodeProof(dahProto, stream), raw) {
		return nil, nil, errors.New("proof is not in the deterministic form")
	}
	return dahProto, stream, nil
}

// readBytes reads one CBOR byte string head and body.
func readBytes(b []byte) (body, rest []byte, err error) {
	if len(b) == 0 || b[0]>>5 != 2 {
		return nil, nil, errors.New("not a byte string")
	}
	n := uint64(b[0] & 0x1f)
	b = b[1:]
	if n >= 24 {
		size := 1 << (n - 24)
		if n > 27 || len(b) < size {
			return nil, nil, errors.New("bad length head")
		}
		n = 0
		for _, c := range b[:size] {
			n = n<<8 | uint64(c)
		}
		b = b[size:]
	}
	if uint64(len(b)) < n {
		return nil, nil, errors.New("byte string is cut")
	}
	return b[:n], b[n:], nil
}

// bytesHead writes the shortest head of a byte string of length n.
func bytesHead(b *bytes.Buffer, n uint64) {
	const major = 2 << 5
	switch {
	case n < 24:
		b.WriteByte(major | byte(n))
	case n <= 0xff:
		b.Write([]byte{major | 24, byte(n)})
	case n <= 0xffff:
		b.Write([]byte{major | 25, byte(n >> 8), byte(n)})
	case n <= 0xffffffff:
		b.Write([]byte{major | 26, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
	default:
		b.WriteByte(major | 27)
		for i := 7; i >= 0; i-- {
			b.WriteByte(byte(n >> (8 * i)))
		}
	}
}
