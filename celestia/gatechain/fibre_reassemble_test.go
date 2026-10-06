package gatechain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	libshare "github.com/celestiaorg/go-square/v4/share"
)

// reassemble is checked on the shares alone: the reassembly vector has no NMT
// proof, so it cannot go through the lookup.
func TestReassembleVector(t *testing.T) {
	raw, err := os.ReadFile("../../spec/vectors/da/fibre_anchor.json")
	require.NoError(t, err)
	var v struct {
		Reassembly []struct {
			ID     string   `json:"id"`
			Shares []string `json:"shares_hex"`
			Expect struct {
				Verdict string   `json:"verdict"`
				TxsSHA  []string `json:"txs_sha256"`
			} `json:"expect"`
		} `json:"reassembly"`
	}
	require.NoError(t, json.Unmarshal(raw, &v))
	require.Len(t, v.Reassembly, 14)

	for _, c := range v.Reassembly {
		t.Run(c.ID, func(t *testing.T) {
			var shares []libshare.Share
			for _, h := range c.Shares {
				b, err := hex.DecodeString(h)
				require.NoError(t, err)
				s, err := libshare.NewShare(b)
				require.NoError(t, err)
				shares = append(shares, s)
			}
			txs, err := reassemble(shares)
			if c.Expect.Verdict == "reject" {
				require.Error(t, err)
				assert.Nil(t, txs)
				return
			}
			require.NoError(t, err)
			var got []string
			for _, tx := range txs {
				sum := sha256.Sum256(tx)
				got = append(got, hex.EncodeToString(sum[:]))
			}
			assert.Equal(t, len(c.Expect.TxsSHA), len(got))
			for i := range got {
				assert.Equal(t, c.Expect.TxsSHA[i], got[i])
			}
		})
	}
}

func TestReassembleNoShares(t *testing.T) {
	txs, err := reassemble(nil)
	require.NoError(t, err)
	assert.Empty(t, txs)
}

func FuzzReassemble(f *testing.F) {
	css := libshare.NewCompactShareSplitter(libshare.PayForFibreNamespace, libshare.ShareVersionZero)
	require.NoError(f, css.WriteTx([]byte("one tx")))
	shares, err := css.Export()
	require.NoError(f, err)
	f.Add(shares[0].ToBytes()[libshare.NamespaceSize:libshare.NamespaceSize+30], uint8(1))
	f.Fuzz(func(t *testing.T, tail []byte, n uint8) {
		// The namespace is fixed; the fuzzer drives the info byte, the
		// lengths, the reserved bytes and the data.
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
		txs, err := reassemble(in)
		if err != nil {
			return
		}
		// Accepted shares are exactly what splitting the txs gives back.
		again := libshare.NewCompactShareSplitter(libshare.PayForFibreNamespace, libshare.ShareVersionZero)
		for _, tx := range txs {
			require.NoError(t, again.WriteTx(tx))
		}
		out, err := again.Export()
		require.NoError(t, err)
		require.Len(t, out, len(in))
		for i := range out {
			require.Equal(t, in[i].ToBytes(), out[i].ToBytes())
		}
	})
}
