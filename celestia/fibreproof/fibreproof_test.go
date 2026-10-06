package fibreproof_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/celestiaorg/celestia-app/v10/pkg/da"
	daproto "github.com/celestiaorg/celestia-app/v10/proto/celestia/core/v1/da"
	libshare "github.com/celestiaorg/go-square/v4/share"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/fibreproof"
	"github.com/vgonkivs/edicta/celestia/test/fibrefix"
)

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestLiveCasesVerify(t *testing.T) {
	v := fibrefix.LoadAnchorVector(t)
	for _, c := range v.Live.Cases {
		t.Run(c.ID, func(t *testing.T) {
			b := fibrefix.VectorBlock(t, c)
			require.NoError(t, fibreproof.CheckDAH(b.DAH(), b.DataHash))
			txs, err := fibreproof.VerifyNamespaceData(b.DAH(), b.Stream(t))
			require.NoError(t, err)
			require.Len(t, txs, len(c.Expect.Txs))
			for i, tx := range txs {
				assert.Equal(t, c.Expect.Txs[i].SHA256, sha(tx))
			}
		})
	}
}

func TestArchiveProofVectors(t *testing.T) {
	v := fibrefix.LoadAnchorVector(t)
	for _, c := range v.Live.Cases {
		t.Run(c.ID, func(t *testing.T) {
			b := fibrefix.VectorBlock(t, c)
			want := fibrefix.Unhex(t, c.Expect.ArchiveProof.Hex)
			require.Equal(t, c.Expect.ArchiveProof.SHA256, sha(want))

			got := b.Proof(t)
			assert.Equal(t, want, got, "the encoder writes the vector bytes")

			dahProto, stream, err := fibreproof.DecodeProof(want)
			require.NoError(t, err)
			assert.Equal(t, b.DAHProto(t), dahProto)
			assert.Equal(t, b.Stream(t), stream)
			assert.Equal(t, want, fibreproof.EncodeProof(dahProto, stream))
		})
	}
}

func TestVectorMutations(t *testing.T) {
	v := fibrefix.LoadAnchorVector(t)
	for _, m := range v.Mutations {
		t.Run(m.ID, func(t *testing.T) {
			require.Equal(t, "reject", m.Expect.Verdict)
			base := fibrefix.VectorBlock(t, v.CaseByID(t, m.Case))
			stream := base.Stream(t)
			b := base
			switch m.Op.Kind {
			case "truncate_stream":
				n := fibrefix.Num(t, m.Op.Bytes)
				stream = stream[:len(stream)-n]
			case "verify_namespace":
				t.Skip("the namespace is fixed in the API")
			default:
				var ok bool
				b, ok = fibrefix.ApplyOp(t, base, m.Op)
				require.True(t, ok)
				stream = b.Stream(t)
			}
			err := fibreproof.CheckDAH(b.DAH(), b.DataHash)
			if m.Expect.Fails == "NA2" {
				require.Error(t, err)
				return
			}
			require.NoError(t, err, "only the namespace data is tampered")
			txs, err := fibreproof.VerifyNamespaceData(b.DAH(), stream)
			require.Error(t, err)
			assert.Nil(t, txs)
		})
	}
}

func TestCheckDAHDataHashLength(t *testing.T) {
	b := fibrefix.VectorBlock(t, fibrefix.LoadAnchorVector(t).Live.Cases[0])
	assert.Error(t, fibreproof.CheckDAH(b.DAH(), nil))
	assert.Error(t, fibreproof.CheckDAH(b.DAH(), b.DataHash[:31]))
	assert.Error(t, fibreproof.CheckDAH(&da.DataAvailabilityHeader{}, b.DataHash))
	assert.Error(t, fibreproof.CheckDAH(&da.DataAvailabilityHeader{RowRoots: b.Rows}, b.DataHash))
}

func TestVerifyNamespaceDataRefusesGarbage(t *testing.T) {
	b := fibrefix.VectorBlock(t, fibrefix.LoadAnchorVector(t).Live.Cases[0])
	for name, stream := range map[string][]byte{
		"nil":          nil,
		"one byte":     {0x01},
		"huge length":  {0xff, 0xff, 0xff, 0xff, 0x0f},
		"zero length":  {0x00},
		"trailing":     append(b.Stream(t), 0x00),
		"random bytes": bytes.Repeat([]byte{0xa5}, 64),
	} {
		t.Run(name, func(t *testing.T) {
			require.NotPanics(t, func() {
				txs, err := fibreproof.VerifyNamespaceData(b.DAH(), stream)
				require.Error(t, err)
				assert.Nil(t, txs)
			})
		})
	}
}

func TestReassembleVectors(t *testing.T) {
	v := fibrefix.LoadAnchorVector(t)
	require.Len(t, v.Reassembly, 14)
	for _, c := range v.Reassembly {
		t.Run(c.ID, func(t *testing.T) {
			var shares []libshare.Share
			for _, h := range c.Shares {
				s, err := libshare.NewShare(fibrefix.Unhex(t, h))
				require.NoError(t, err)
				shares = append(shares, s)
			}
			txs, err := fibreproof.Reassemble(shares)
			if c.Expect.Verdict == "reject" {
				require.Error(t, err)
				assert.Nil(t, txs)
				return
			}
			require.NoError(t, err)
			require.Len(t, txs, len(c.Expect.TxsSHA))
			for i, tx := range txs {
				assert.Equal(t, c.Expect.TxsSHA[i], sha(tx))
			}
		})
	}
}

func TestReassembleSynthetic(t *testing.T) {
	a, b := bytes.Repeat([]byte{1}, 700), bytes.Repeat([]byte{2}, 900)
	good := fibrefix.SplitTxs(t, a, b)
	require.GreaterOrEqual(t, len(good), 3)

	tests := []struct {
		name   string
		shares []libshare.Share
		ok     bool
	}{
		{"complete", good, true},
		{"cut", good[:len(good)-1], false},
		{"first share missing", good[1:], false},
		{"padded with a copy", append(append([]libshare.Share{}, good...), good[len(good)-1]), false},
		{"reordered", append([]libshare.Share{good[1], good[0]}, good[2:]...), false},
		{"duplicated first", append([]libshare.Share{good[0]}, good...), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			txs, err := fibreproof.Reassemble(tc.shares)
			if !tc.ok {
				require.Error(t, err)
				assert.Nil(t, txs)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, [][]byte{a, b}, txs)
		})
	}
}

func TestVerifyNamespaceDataSyntheticBlocks(t *testing.T) {
	a, b := bytes.Repeat([]byte{1}, 700), bytes.Repeat([]byte{2}, 900)
	good := fibrefix.SplitTxs(t, a, b)
	tests := []struct {
		name   string
		shares []libshare.Share
		ok     bool
	}{
		{"complete", good, true},
		{"cut", good[:len(good)-1], false},
		{"padded", append(append([]libshare.Share{}, good...), good[len(good)-1]), false},
		{"reordered", append([]libshare.Share{good[1], good[0]}, good[2:]...), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			blk := fibrefix.BuildBlockFromShares(t, tc.shares)
			require.NoError(t, fibreproof.CheckDAH(blk.DAH(), blk.DataHash), "the block itself is consistent")
			txs, err := fibreproof.VerifyNamespaceData(blk.DAH(), blk.Stream(t))
			if tc.ok {
				require.NoError(t, err)
				assert.Equal(t, [][]byte{a, b}, txs)
				return
			}
			require.Error(t, err)
			assert.Nil(t, txs)
		})
	}
}

func TestEmptyNamespaceIsProvenAbsent(t *testing.T) {
	blk := fibrefix.BuildBlock(t)
	require.NoError(t, fibreproof.CheckDAH(blk.DAH(), blk.DataHash))
	txs, err := fibreproof.VerifyNamespaceData(blk.DAH(), blk.Stream(t))
	require.NoError(t, err)
	assert.Empty(t, txs)
}

func TestProofLengthHeads(t *testing.T) {
	for _, n := range []int{0, 1, 23, 24, 255, 256, 65535, 65536} {
		dah, stream := bytes.Repeat([]byte{7}, n), bytes.Repeat([]byte{9}, n)
		raw := fibreproof.EncodeProof(dah, stream)
		gd, gs, err := fibreproof.DecodeProof(raw)
		require.NoError(t, err, n)
		assert.Equal(t, dah, gd)
		assert.Equal(t, stream, gs)
	}
	assert.Equal(t, []byte{0xa3, 0x01, 0x01, 0x02, 0x41, 0xaa, 0x03, 0x42, 0xbb, 0xcc},
		fibreproof.EncodeProof([]byte{0xaa}, []byte{0xbb, 0xcc}))
}

func TestDecodeProofRefusals(t *testing.T) {
	good := fibreproof.EncodeProof([]byte{0xaa}, []byte{0xbb, 0xcc})
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	tests := []struct {
		name string
		raw  []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"form-0 json", []byte(`{"a":1}`)},
		{"trailing byte", cat(good, []byte{0x00})},
		{"non-shortest dah head", []byte{0xa3, 0x01, 0x01, 0x02, 0x58, 0x01, 0xaa, 0x03, 0x42, 0xbb, 0xcc}},
		{"non-shortest stream head", []byte{0xa3, 0x01, 0x01, 0x02, 0x41, 0xaa, 0x03, 0x59, 0x00, 0x02, 0xbb, 0xcc}},
		{"wrong map head", cat([]byte{0xa2}, good[1:])},
		{"map with four pairs", cat([]byte{0xa4}, good[1:])},
		{"wrong version", []byte{0xa3, 0x01, 0x02, 0x02, 0x41, 0xaa, 0x03, 0x42, 0xbb, 0xcc}},
		{"wrong dah key", []byte{0xa3, 0x01, 0x01, 0x04, 0x41, 0xaa, 0x03, 0x42, 0xbb, 0xcc}},
		{"wrong stream key", []byte{0xa3, 0x01, 0x01, 0x02, 0x41, 0xaa, 0x04, 0x42, 0xbb, 0xcc}},
		{"keys swapped", []byte{0xa3, 0x01, 0x01, 0x03, 0x41, 0xaa, 0x02, 0x42, 0xbb, 0xcc}},
		{"stream key missing", []byte{0xa3, 0x01, 0x01, 0x02, 0x41, 0xaa}},
		{"dah is a text string", []byte{0xa3, 0x01, 0x01, 0x02, 0x61, 0xaa, 0x03, 0x42, 0xbb, 0xcc}},
		{"indefinite length", []byte{0xa3, 0x01, 0x01, 0x02, 0x5f, 0x41, 0xaa, 0xff, 0x03, 0x42, 0xbb, 0xcc}},
		{"reserved length head", []byte{0xa3, 0x01, 0x01, 0x02, 0x5c, 0xaa, 0x03, 0x42, 0xbb, 0xcc}},
		{"length beyond the data", []byte{0xa3, 0x01, 0x01, 0x02, 0x41, 0xaa, 0x03, 0x45, 0xbb, 0xcc}},
		{"length of 2^64-1", []byte{0xa3, 0x01, 0x01, 0x02, 0x41, 0xaa, 0x03, 0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbb}},
		{"cut length head", []byte{0xa3, 0x01, 0x01, 0x02, 0x41, 0xaa, 0x03, 0x5a, 0x00}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.NotPanics(t, func() {
				d, s, err := fibreproof.DecodeProof(tc.raw)
				require.Error(t, err)
				assert.Nil(t, d)
				assert.Nil(t, s)
			})
		})
	}
	t.Run("every proper prefix", func(t *testing.T) {
		for i := range good {
			_, _, err := fibreproof.DecodeProof(good[:i])
			require.Error(t, err, i)
		}
	})
	t.Run("the good one", func(t *testing.T) {
		_, _, err := fibreproof.DecodeProof(good)
		require.NoError(t, err)
	})
}

func FuzzDecodeProof(f *testing.F) {
	f.Add(fibreproof.EncodeProof([]byte{0xaa}, []byte{0xbb, 0xcc}))
	f.Add(fibreproof.EncodeProof(nil, nil))
	f.Add(fibreproof.EncodeProof(bytes.Repeat([]byte{1}, 300), bytes.Repeat([]byte{2}, 70000)))
	f.Add([]byte{0xa3, 0x01, 0x01, 0x02, 0x58, 0x01, 0xaa, 0x03, 0x41, 0xbb})
	f.Fuzz(func(t *testing.T, raw []byte) {
		d, s, err := fibreproof.DecodeProof(raw)
		if err != nil {
			assert.Nil(t, d)
			assert.Nil(t, s)
			return
		}
		require.Equal(t, raw, fibreproof.EncodeProof(d, s), "an accepted proof is the canonical one")
	})
}

func FuzzDecodeThenVerify(f *testing.F) {
	v := fibrefix.LoadAnchorVector(f)
	c := v.Live.Cases[0]
	raw := fibrefix.Unhex(f, c.Expect.ArchiveProof.Hex)
	f.Add(raw)
	f.Add(raw[:len(raw)/2])
	dataHash := fibrefix.Unhex(f, c.Raw.DataHash)
	f.Fuzz(func(t *testing.T, in []byte) {
		dahProto, stream, err := fibreproof.DecodeProof(in)
		if err != nil {
			return
		}
		var dp daproto.DataAvailabilityHeader
		if dp.Unmarshal(dahProto) != nil {
			return
		}
		dah := &da.DataAvailabilityHeader{RowRoots: dp.RowRoots, ColumnRoots: dp.ColumnRoots}
		if fibreproof.CheckDAH(dah, dataHash) != nil {
			return
		}
		_, _ = fibreproof.VerifyNamespaceData(dah, stream)
	})
}

func FuzzReassemble(f *testing.F) {
	shares := fibrefix.SplitTxs(f, []byte("one tx"))
	f.Add(shares[0].ToBytes()[libshare.NamespaceSize:libshare.NamespaceSize+30], uint8(1))
	f.Fuzz(func(t *testing.T, tail []byte, n uint8) {
		b := make([]byte, libshare.ShareSize)
		copy(b, libshare.PayForFibreNamespace.Bytes())
		copy(b[libshare.NamespaceSize:], tail)
		s, err := libshare.NewShare(b)
		if err != nil {
			return
		}
		in := make([]libshare.Share, int(n)%4)
		for i := range in {
			in[i] = s
		}
		txs, err := fibreproof.Reassemble(in)
		if err != nil {
			return
		}
		out := fibrefix.SplitTxs(t, txs...)
		if len(txs) == 0 {
			out = nil
		}
		require.Len(t, out, len(in))
		for i := range out {
			require.Equal(t, in[i].ToBytes(), out[i].ToBytes())
		}
	})
}
