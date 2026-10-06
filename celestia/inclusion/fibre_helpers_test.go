package inclusion_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	fibretypes "github.com/celestiaorg/celestia-app/v10/x/fibre/types"
	"github.com/celestiaorg/celestia-node/share/eds"
	"github.com/celestiaorg/celestia-node/share/shwap"
	libshare "github.com/celestiaorg/go-square/v4/share"
	cosmostx "github.com/cosmos/cosmos-sdk/types/tx"

	"github.com/vgonkivs/edicta/celestia/nodefake"
	"github.com/vgonkivs/edicta/commitment"
)

const (
	fbCertPath   = "../../spec/vectors/da/fibre_cert.json"
	fbAnchorPath = "../../spec/vectors/da/fibre_anchor.json"
	fbChain      = "mocha-5"
	fbLiveCase   = "h1402819"
)

var fbHeaderTime = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

func fbHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func fbU(t testing.TB, s string) uint64 {
	t.Helper()
	n, err := strconv.ParseUint(s, 10, 64)
	require.NoError(t, err)
	return n
}

// fbLive is the Mocha PayForFibre at 1,402,819 and the evidence of its
// certificate, from the shared vector files.
type fbLive struct {
	pff        []byte
	hist       []byte
	promiseHdr []byte
	pffHeight  uint64
	promiseH   uint64
	ns, commit []byte
	rowRoots   [][]byte
	colRoots   [][]byte
	dataHash   []byte
	nd         shwap.NamespaceData
}

func loadFbLive(t testing.TB) fbLive {
	t.Helper()
	raw, err := os.ReadFile(fbCertPath)
	require.NoError(t, err)
	var cv struct {
		Live struct {
			Raw struct {
				PFFHeight  string `json:"pff_height"`
				PFFTxHex   string `json:"pff_tx_hex"`
				Historical struct {
					Hex string `json:"hex"`
				} `json:"historical_info"`
				Headers []struct {
					Height string `json:"height"`
					Hex    string `json:"header_hex"`
				} `json:"headers"`
			} `json:"raw"`
			Derived struct {
				Binding struct {
					NamespaceHex  string `json:"namespace_hex"`
					CommitmentHex string `json:"commitment_hex"`
				} `json:"binding"`
				Promise struct {
					Height string `json:"height"`
				} `json:"promise"`
			} `json:"derived"`
		} `json:"live"`
	}
	require.NoError(t, json.Unmarshal(raw, &cv))
	l := fbLive{
		pff: fbHex(t, cv.Live.Raw.PFFTxHex), hist: fbHex(t, cv.Live.Raw.Historical.Hex),
		pffHeight: fbU(t, cv.Live.Raw.PFFHeight), promiseH: fbU(t, cv.Live.Derived.Promise.Height),
		ns: fbHex(t, cv.Live.Derived.Binding.NamespaceHex), commit: fbHex(t, cv.Live.Derived.Binding.CommitmentHex),
	}
	for _, h := range cv.Live.Raw.Headers {
		if fbU(t, h.Height) == l.promiseH {
			l.promiseHdr = fbHex(t, h.Hex)
		}
	}
	require.NotEmpty(t, l.promiseHdr)

	raw, err = os.ReadFile(fbAnchorPath)
	require.NoError(t, err)
	var av struct {
		Live struct {
			Cases []struct {
				ID  string `json:"id"`
				Raw struct {
					Height     string   `json:"height"`
					DataHash   string   `json:"data_hash"`
					RowRoots   []string `json:"row_roots"`
					ColRoots   []string `json:"column_roots"`
					NamespaceD string   `json:"namespace_data_hex"`
				} `json:"raw"`
			} `json:"cases"`
		} `json:"live"`
	}
	require.NoError(t, json.Unmarshal(raw, &av))
	for _, c := range av.Live.Cases {
		if c.ID != fbLiveCase {
			continue
		}
		require.Equal(t, l.pffHeight, fbU(t, c.Raw.Height))
		l.dataHash = fbHex(t, c.Raw.DataHash)
		for _, r := range c.Raw.RowRoots {
			l.rowRoots = append(l.rowRoots, fbHex(t, r))
		}
		for _, r := range c.Raw.ColRoots {
			l.colRoots = append(l.colRoots, fbHex(t, r))
		}
		_, err := l.nd.ReadFrom(bytes.NewReader(fbHex(t, c.Raw.NamespaceD)))
		require.NoError(t, err)
	}
	require.NotEmpty(t, l.dataHash)
	return l
}

func (l fbLive) ref() commitment.PayloadRef {
	return commitment.PayloadRef{DA: commitment.DAFibre, Namespace: bytes.Clone(l.ns),
		Commitment: bytes.Clone(l.commit), Height: l.pffHeight}
}

// chain serves the live block and the certificate evidence.
func (l fbLive) chain() *nodefake.FibreChain {
	c := nodefake.NewFibreChain()
	c.AddHeader(l.pffHeight, l.dataHash, fbHeaderTime)
	c.SetDAH(l.pffHeight, l.rowRoots, l.colRoots)
	c.SetNamespaceData(l.pffHeight, l.nd)
	c.SetHistoricalInfo(l.promiseH, l.hist)
	c.SetSignedHeader(l.promiseH, l.promiseHdr)
	return c
}

// chainWithTxs serves a block whose PayForFibre namespace holds exactly txs,
// with real NMT proofs, plus the certificate evidence.
func (l fbLive) chainWithTxs(t testing.TB, txs ...[]byte) *nodefake.FibreChain {
	t.Helper()
	var shares []libshare.Share
	if len(txs) > 0 {
		css := libshare.NewCompactShareSplitter(libshare.PayForFibreNamespace, libshare.ShareVersionZero)
		for _, tx := range txs {
			require.NoError(t, css.WriteTx(tx))
		}
		var err error
		shares, err = css.Export()
		require.NoError(t, err)
	}
	k := 2
	for k*k < len(shares) {
		k *= 2
	}
	ods := append(append([]libshare.Share(nil), shares...), libshare.TailPaddingShares(k*k-len(shares))...)
	sq, err := eds.Rsmt2DFromShares(ods, k)
	require.NoError(t, err)
	roots, err := sq.AxisRoots(context.Background())
	require.NoError(t, err)
	nd, err := eds.NamespaceData(context.Background(), sq, libshare.PayForFibreNamespace)
	require.NoError(t, err)
	c := nodefake.NewFibreChain()
	c.AddHeader(l.pffHeight, roots.Hash(), fbHeaderTime)
	c.SetDAH(l.pffHeight, roots.RowRoots, roots.ColumnRoots)
	c.SetNamespaceData(l.pffHeight, nd)
	c.SetHistoricalInfo(l.promiseH, l.hist)
	c.SetSignedHeader(l.promiseH, l.promiseHdr)
	return c
}

// strippedPFF keeps only the first keep validator signatures. The owner
// signature covers the promise only, so the rest of the tx stays valid.
func (l fbLive) strippedPFF(t testing.TB, keep int) []byte {
	t.Helper()
	var tr cosmostx.TxRaw
	require.NoError(t, tr.Unmarshal(l.pff))
	var body cosmostx.TxBody
	require.NoError(t, body.Unmarshal(tr.BodyBytes))
	require.Len(t, body.Messages, 1)
	var msg fibretypes.MsgPayForFibre
	require.NoError(t, msg.Unmarshal(body.Messages[0].Value))
	for i := keep; i < len(msg.ValidatorSignatures); i++ {
		msg.ValidatorSignatures[i] = nil
	}
	v, err := msg.Marshal()
	require.NoError(t, err)
	body.Messages[0].Value = v
	tr.BodyBytes, err = body.Marshal()
	require.NoError(t, err)
	out, err := tr.Marshal()
	require.NoError(t, err)
	return out
}
