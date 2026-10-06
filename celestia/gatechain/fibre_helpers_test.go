package gatechain_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	fibretypes "github.com/celestiaorg/celestia-app/v10/x/fibre/types"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cosmostx "github.com/cosmos/cosmos-sdk/types/tx"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	"github.com/vgonkivs/edicta/commitment"
)

const certVectorPath = "../../spec/vectors/da/fibre_cert.json"

// live is the Mocha PFF at 1,402,819 with the evidence the certificate rule
// needs, read from the shared vector file.
type live struct {
	pff        []byte
	hist       []byte
	promiseHdr []byte
	pffHdr     []byte
	headers    map[uint64][]byte
	pffHeight  uint64
	promiseH   uint64
	ns         []byte
	commit     []byte
	blobSize   uint32
	created    time.Time
	chainID    string
	payload    []byte
}

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func loadLive(t testing.TB) live {
	t.Helper()
	raw, err := os.ReadFile(certVectorPath)
	require.NoError(t, err)
	var v struct {
		Live struct {
			Raw struct {
				ChainID    string `json:"chain_id"`
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
					BlobSize      string `json:"blob_size"`
				} `json:"binding"`
				Promise struct {
					Height  string `json:"height"`
					Created string `json:"creation_timestamp"`
				} `json:"promise"`
			} `json:"derived"`
		} `json:"live"`
	}
	require.NoError(t, json.Unmarshal(raw, &v))
	u := func(s string) uint64 {
		n, err := strconv.ParseUint(s, 10, 64)
		require.NoError(t, err)
		return n
	}
	l := live{
		pff:       unhex(t, v.Live.Raw.PFFTxHex),
		hist:      unhex(t, v.Live.Raw.Historical.Hex),
		pffHeight: u(v.Live.Raw.PFFHeight),
		promiseH:  u(v.Live.Derived.Promise.Height),
		ns:        unhex(t, v.Live.Derived.Binding.NamespaceHex),
		commit:    unhex(t, v.Live.Derived.Binding.CommitmentHex),
		blobSize:  uint32(u(v.Live.Derived.Binding.BlobSize)),
		chainID:   v.Live.Raw.ChainID,
		payload:   []byte{0x65},
		headers:   map[uint64][]byte{},
	}
	ts, err := time.Parse(time.RFC3339Nano, v.Live.Derived.Promise.Created)
	require.NoError(t, err)
	l.created = ts
	for _, h := range v.Live.Raw.Headers {
		l.headers[u(h.Height)] = unhex(t, h.Hex)
		switch u(h.Height) {
		case l.promiseH:
			l.promiseHdr = unhex(t, h.Hex)
		case l.pffHeight:
			l.pffHdr = unhex(t, h.Hex)
		}
	}
	require.NotEmpty(t, l.promiseHdr)
	require.NotEmpty(t, l.pffHdr)
	return l
}

func (l live) ref() commitment.PayloadRef {
	return commitment.PayloadRef{DA: commitment.DAFibre, Namespace: append([]byte(nil), l.ns...),
		Commitment: append([]byte(nil), l.commit...), Height: l.pffHeight}
}

func (l live) header(t testing.TB, raw []byte) cmtproto.Header {
	t.Helper()
	var h cmtproto.Header
	require.NoError(t, h.Unmarshal(raw))
	return h
}

func txHash(tx []byte) [32]byte { return sha256.Sum256(tx) }

// mutateTx rewrites the message of a PFF tx. The owner signature covers the
// promise only, so changes outside it keep the owner signature valid.
func mutateTx(t testing.TB, raw []byte, f func(*fibretypes.MsgPayForFibre)) []byte {
	t.Helper()
	var tr cosmostx.TxRaw
	require.NoError(t, tr.Unmarshal(raw))
	var body cosmostx.TxBody
	require.NoError(t, body.Unmarshal(tr.BodyBytes))
	require.Len(t, body.Messages, 1)
	var msg fibretypes.MsgPayForFibre
	require.NoError(t, msg.Unmarshal(body.Messages[0].Value))
	f(&msg)
	v, err := msg.Marshal()
	require.NoError(t, err)
	body.Messages[0].Value = v
	tr.BodyBytes, err = body.Marshal()
	require.NoError(t, err)
	out, err := tr.Marshal()
	require.NoError(t, err)
	return out
}

func parseHist(t testing.TB, raw []byte) stakingtypes.HistoricalInfo {
	t.Helper()
	var hi stakingtypes.HistoricalInfo
	require.NoError(t, hi.Unmarshal(raw))
	return hi
}

func marshalHist(t testing.TB, hi stakingtypes.HistoricalInfo) []byte {
	t.Helper()
	b, err := hi.Marshal()
	require.NoError(t, err)
	return b
}

// signedHeader wraps a bare protobuf Header in the SignedHeader the chain reader serves.
func signedHeader(t testing.TB, rawHeader []byte) []byte {
	t.Helper()
	var h cmtproto.Header
	require.NoError(t, h.Unmarshal(rawHeader))
	raw, err := (&cmtproto.SignedHeader{Header: &h, Commit: &cmtproto.Commit{Height: h.Height}}).Marshal()
	require.NoError(t, err)
	return raw
}
