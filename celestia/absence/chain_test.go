package absence_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/celestiaorg/celestia-app/v10/pkg/da"
	daproto "github.com/celestiaorg/celestia-app/v10/proto/celestia/core/v1/da"
	"github.com/celestiaorg/celestia-node/share/shwap"
	libshare "github.com/celestiaorg/go-square/v4/share"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/types/bech32"
	cosmostx "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	blobtypes "github.com/celestiaorg/celestia-app/v10/x/blob/types"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/celestia/absence"
	"github.com/vgonkivs/edicta/celestia/fibrecert"
	"github.com/vgonkivs/edicta/celestia/railverify"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/verifier"
)

// memRecords is an archive copy holding the records of one vector case.
type memRecords struct {
	recs  map[uint64]*archive.AbsenceProofRecord
	reads int
}

func (m *memRecords) Absence(_ context.Context, da commitment.DA, commit []byte, h uint64) (*archive.AbsenceProofRecord, error) {
	m.reads++
	r, ok := m.recs[h]
	if !ok || r.DA != da || !bytes.Equal(r.Commitment, commit) {
		return nil, archive.ErrNotFound
	}
	return r, nil
}

// caseOf returns the reference, the archive and the trusted hashes of a
// vector case.
func caseOf(t *testing.T, id string) (commitment.PayloadRef, uint64, *memRecords, map[uint64][]byte) {
	t.Helper()
	f := loadAbsence(t)
	for _, c := range append(f.Synthetic, f.Live...) {
		if c.ID != id {
			continue
		}
		ref := commitment.PayloadRef{DA: commitment.DA(u64(t, c.Query.DA)), Namespace: unhex(t, c.Query.Namespace),
			Commitment: unhex(t, c.Query.Commitment), Signer: unhex(t, c.Query.Signer), Height: u64(t, c.Query.H0),
			Anchor: commitment.AnchorPending}
		q := absence.Query{DA: ref.DA, Namespace: ref.Namespace, Commitment: ref.Commitment}
		m := &memRecords{recs: map[uint64]*archive.AbsenceProofRecord{}}
		for _, r := range c.Records {
			m.recs[u64(t, r.Height)] = decodeAt(t, q, u64(t, r.Height), unhex(t, r.RecordHex))
		}
		trusted := map[uint64][]byte{}
		for h, x := range c.TrustedHeaders {
			trusted[u64(t, h)] = unhex(t, x)
		}
		return ref, u64(t, c.Query.AnchorDeadline), m, trusted
	}
	require.Fail(t, "no case "+id)
	return commitment.PayloadRef{}, 0, nil, nil
}

func confirmFrom(trusted map[uint64][]byte, asked *[]uint64) verifier.Confirm {
	return func(_ context.Context, h uint64, hash []byte) bool {
		if asked != nil {
			*asked = append(*asked, h)
		}
		want, ok := trusted[h]
		return ok && bytes.Equal(want, hash)
	}
}

func TestChainAbsenceFromTheArchive(t *testing.T) {
	for id, want := range map[string]verifier.AbsenceResult{
		"window_three_heights_proven": verifier.AbsenceAbsent,
		"window_one_height_missing":   verifier.AbsenceUnproven,
		"fibre_present":               verifier.AbsencePresent,
		"fibre_unit_undecodable":      verifier.AbsenceUnproven,
		"blob_empty_namespace":        verifier.AbsenceAbsent,
		"blob_present":                verifier.AbsencePresent,
	} {
		t.Run(id, func(t *testing.T) {
			ref, d, m, trusted := caseOf(t, id)
			var asked []uint64
			w, err := absence.NewChain(absence.ChainDeps{Records: m}).Absence(t.Context(), ref, d, confirmFrom(trusted, &asked))
			require.NoError(t, err)
			assert.Equal(t, want, w.Result, "%v", w.Cause)
			assert.Equal(t, int(d-ref.Height+1), w.Heights)
			assert.NotZero(t, w.Bytes)
			assert.Equal(t, []string{absence.SourceArchive}, w.Sources)
			assert.NotEmpty(t, asked, "every header is confirmed")
			if w.Result == verifier.AbsenceUnproven {
				require.Error(t, w.Cause)
				assert.NotZero(t, w.FirstUnproven)
			}
		})
	}
}

func TestChainAbsenceMissingHeightIsNamed(t *testing.T) {
	ref, d, m, trusted := caseOf(t, "window_one_height_missing")
	w, err := absence.NewChain(absence.ChainDeps{Records: m}).Absence(t.Context(), ref, d, confirmFrom(trusted, nil))
	require.NoError(t, err)
	assert.Equal(t, uint64(4200203), w.FirstUnproven)
	require.ErrorIs(t, w.Cause, absence.ErrNoProof)
	require.ErrorIs(t, w.Cause, archive.ErrNotFound)
}

func TestChainAbsenceRestsOnConfirmedHeaders(t *testing.T) {
	ref, d, m, trusted := caseOf(t, "window_three_heights_proven")
	c := absence.NewChain(absence.ChainDeps{Records: m})

	t.Run("nothing confirmed", func(t *testing.T) {
		w, err := c.Absence(t.Context(), ref, d, confirmFrom(nil, nil))
		require.NoError(t, err)
		assert.Equal(t, verifier.AbsenceUnproven, w.Result)
		assert.Equal(t, ref.Height, w.FirstUnproven)
		require.ErrorIs(t, w.Cause, absence.ErrHeader)
	})
	t.Run("the next header of the deadline not confirmed", func(t *testing.T) {
		tr := map[uint64][]byte{}
		for h, x := range trusted {
			if h <= d {
				tr[h] = x
			}
		}
		w, err := c.Absence(t.Context(), ref, d, confirmFrom(tr, nil))
		require.NoError(t, err)
		assert.Equal(t, verifier.AbsenceUnproven, w.Result)
		assert.Equal(t, d, w.FirstUnproven)
		assert.True(t, w.ResultsAtDeadline, "a candidate at the deadline needs header d + 1")
		require.ErrorIs(t, w.Cause, absence.ErrResultUnproven)
	})
	t.Run("a cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, err := c.Absence(ctx, ref, d, confirmFrom(trusted, nil))
		require.ErrorIs(t, err, context.Canceled)
	})
	t.Run("a window over the bound", func(t *testing.T) {
		w, err := c.Absence(t.Context(), ref, ref.Height+absence.MaxWindow+1, confirmFrom(trusted, nil))
		require.NoError(t, err)
		require.ErrorIs(t, w.Cause, absence.ErrWindow)
	})
	t.Run("no source", func(t *testing.T) {
		w, err := absence.NewChain(absence.ChainDeps{}).Absence(t.Context(), ref, d, confirmFrom(trusted, nil))
		require.NoError(t, err)
		assert.Equal(t, verifier.AbsenceUnproven, w.Result)
		require.ErrorIs(t, w.Cause, absence.ErrNoProof)
	})
}

func TestChainHeaderFromTheRecord(t *testing.T) {
	ref, _, m, trusted := caseOf(t, "window_three_heights_proven")
	hd, err := absence.NewChain(absence.ChainDeps{Records: m}).Header(t.Context(), ref, ref.Height)
	require.NoError(t, err)
	assert.Equal(t, trusted[ref.Height], hd.Hash)
	assert.NotZero(t, hd.Time)

	_, err = absence.NewChain(absence.ChainDeps{Records: m}).Header(t.Context(), ref, ref.Height+100)
	require.ErrorIs(t, err, archive.ErrNotFound)
	_, err = absence.NewChain(absence.ChainDeps{}).Header(t.Context(), ref, ref.Height)
	require.Error(t, err)
}

// recordSource serves the parts of vector records as a bridge and an RPC
// would.
type recordSource struct {
	recs    map[uint64]*archive.AbsenceProofRecord
	extra   map[uint64][]byte // signed headers beyond the records
	results int
	// past makes the namespace data at least this many bytes.
	past int
}

func (s *recordSource) SignedHeader(_ context.Context, h uint64) ([]byte, error) {
	if r, ok := s.recs[h]; ok {
		return r.Header, nil
	}
	if b, ok := s.extra[h]; ok {
		return b, nil
	}
	return nil, errors.New("no header")
}

func (s *recordSource) DAH(_ context.Context, h uint64) (*da.DataAvailabilityHeader, error) {
	r, ok := s.recs[h]
	if !ok {
		return nil, errors.New("no DAH")
	}
	var dp daproto.DataAvailabilityHeader
	if err := dp.Unmarshal(r.DAH); err != nil {
		return nil, err
	}
	return &da.DataAvailabilityHeader{RowRoots: dp.RowRoots, ColumnRoots: dp.ColumnRoots}, nil
}

func (s *recordSource) NamespaceData(_ context.Context, h uint64, _ libshare.Namespace) (shwap.NamespaceData, error) {
	r, ok := s.recs[h]
	if !ok {
		return nil, errors.New("no namespace data")
	}
	var nd shwap.NamespaceData
	if _, err := nd.ReadFrom(bytes.NewReader(r.NamespaceData)); err != nil {
		return nil, err
	}
	for n := len(r.NamespaceData); len(nd) > 0 && n <= s.past; n *= 2 {
		nd = append(nd, nd...)
	}
	return nd, nil
}

func (s *recordSource) BlockResults(_ context.Context, h uint64) ([]railverify.TxResult, error) {
	s.results++
	r, ok := s.recs[h]
	if !ok || r.Results == nil {
		return nil, errors.New("no results")
	}
	var res struct {
		TxsResults []struct {
			Code      uint32 `json:"code"`
			Data      []byte `json:"data"`
			GasWanted int64  `json:"gas_wanted,string"`
			GasUsed   int64  `json:"gas_used,string"`
		} `json:"txs_results"`
	}
	if err := json.Unmarshal(r.Results, &res); err != nil {
		return nil, err
	}
	out := make([]railverify.TxResult, len(res.TxsResults))
	for i, x := range res.TxsResults {
		out[i] = railverify.TxResult{Code: x.Code, Data: x.Data, GasWanted: x.GasWanted, GasUsed: x.GasUsed}
	}
	return out, nil
}

func TestFetcherBuildsVerifiableRecords(t *testing.T) {
	ref, d, m, trusted := caseOf(t, "window_three_heights_proven")
	src := &recordSource{recs: m.recs, extra: map[uint64][]byte{}}
	for _, r := range m.recs {
		if r.NextHeader != nil {
			src.extra[r.Height+1] = r.NextHeader
		}
	}
	f, err := absence.NewFetcher(src, src, "bridge.example")
	require.NoError(t, err)
	assert.Equal(t, "bridge.example", f.Name())

	w, err := absence.NewChain(absence.ChainDeps{Fetch: f}).Absence(t.Context(), ref, d, confirmFrom(trusted, nil))
	require.NoError(t, err)
	assert.Equal(t, verifier.AbsenceAbsent, w.Result, "%v", w.Cause)
	assert.Equal(t, []string{"bridge.example"}, w.Sources)
	assert.Equal(t, 1, src.results, "only the height with a candidate reads its results")

	q := absence.Query{DA: ref.DA, Namespace: ref.Namespace, Commitment: ref.Commitment}
	rec, err := f.Fetch(t.Context(), q, d)
	require.NoError(t, err)
	_, err = archive.Encode(rec)
	require.NoError(t, err, "a fetched record is a valid kind 14 record")
	q.ChainID = loadAbsence(t).ChainID
	assert.Equal(t, absence.Absent, absence.VerifyHeight(rec, q, d, trusted).Result)

	t.Run("without a results source the candidate stays unproven", func(t *testing.T) {
		f, err := absence.NewFetcher(src, nil, "bridge.example")
		require.NoError(t, err)
		rec, err := f.Fetch(t.Context(), absence.Query{DA: ref.DA, Namespace: ref.Namespace, Commitment: ref.Commitment}, d)
		require.NoError(t, err)
		assert.Nil(t, rec.Results)
		require.ErrorIs(t, absence.VerifyHeight(rec, q, d, trusted).Err, absence.ErrResultsMissing)
	})
	t.Run("a height over the byte bound", func(t *testing.T) {
		big := &recordSource{recs: m.recs, past: absence.MaxHeightBytes}
		f, err := absence.NewFetcher(big, nil, "bridge.example")
		require.NoError(t, err)
		require.NotEmpty(t, m.recs[d-1].NamespaceData)
		_, err = f.Fetch(t.Context(), absence.Query{DA: ref.DA, Namespace: ref.Namespace, Commitment: ref.Commitment}, d-1)
		require.ErrorIs(t, err, absence.ErrTooLarge)
	})
	t.Run("a header for another height", func(t *testing.T) {
		shifted := &recordSource{recs: map[uint64]*archive.AbsenceProofRecord{d: m.recs[d-1]}}
		f, err := absence.NewFetcher(shifted, nil, "bridge.example")
		require.NoError(t, err)
		_, err = f.Fetch(t.Context(), absence.Query{DA: ref.DA, Namespace: ref.Namespace, Commitment: ref.Commitment}, d)
		require.Error(t, err)
	})
	_, err = absence.NewFetcher(nil, nil, "x")
	require.Error(t, err)
}

type memIntents struct{ rec *archive.AnchorIntentRecord }

func (m memIntents) Intent(_ context.Context, da commitment.DA, commit []byte, h uint64) (*archive.AnchorIntentRecord, error) {
	if m.rec == nil || m.rec.DA != da || !bytes.Equal(m.rec.Commitment, commit) || m.rec.RefHeight != h {
		return nil, archive.ErrNotFound
	}
	return m.rec, nil
}

func TestIntentSignerFibre(t *testing.T) {
	raw, err := os.ReadFile("../../spec/vectors/da/fibre_cert.json")
	require.NoError(t, err)
	var v struct {
		Live struct {
			Raw struct {
				ChainID string `json:"chain_id"`
				PFFTx   string `json:"pff_tx_hex"`
			} `json:"raw"`
		} `json:"live"`
	}
	require.NoError(t, json.Unmarshal(raw, &v))
	tx := unhex(t, v.Live.Raw.PFFTx)
	pff, ok, err := fibrecert.ParsePFF(tx)
	require.NoError(t, err)
	require.True(t, ok)
	p := pff.Promise
	ref := commitment.PayloadRef{DA: commitment.DAFibre, Namespace: p.Namespace, Commitment: p.Commitment[:],
		Height: p.Height, Anchor: commitment.AnchorPending}
	rec := &archive.AnchorIntentRecord{DA: commitment.DAFibre, Commitment: ref.Commitment, Namespace: ref.Namespace,
		RefHeight: ref.Height, Tx: tx, CreatedAt: uint64(p.CreationTime.Unix())}
	payloadSize := uint64(p.BlobSize) - 5
	_, addr, err := bech32.DecodeAndConvert(pff.Signer)
	require.NoError(t, err)

	c := absence.NewChain(absence.ChainDeps{Intents: memIntents{rec}})
	got, err := c.IntentSigner(t.Context(), ref, payloadSize, v.Live.Raw.ChainID)
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(addr), got)

	for name, call := range map[string]func() (string, error){
		"another chain": func() (string, error) { return c.IntentSigner(t.Context(), ref, payloadSize, "other-1") },
		"no chain id":   func() (string, error) { return c.IntentSigner(t.Context(), ref, payloadSize, "") },
		"another size":  func() (string, error) { return c.IntentSigner(t.Context(), ref, payloadSize+1<<20, v.Live.Raw.ChainID) },
		"no intent read": func() (string, error) {
			return absence.NewChain(absence.ChainDeps{}).IntentSigner(t.Context(), ref, payloadSize, v.Live.Raw.ChainID)
		},
		"created_at differs": func() (string, error) {
			r := *rec
			r.CreatedAt++
			return absence.NewChain(absence.ChainDeps{Intents: memIntents{&r}}).IntentSigner(t.Context(), ref, payloadSize, v.Live.Raw.ChainID)
		},
		"another h0": func() (string, error) {
			r := *rec
			r.RefHeight++
			x := ref
			x.Height++
			return absence.NewChain(absence.ChainDeps{Intents: memIntents{&r}}).IntentSigner(t.Context(), x, payloadSize, v.Live.Raw.ChainID)
		},
	} {
		got, err := call()
		require.NoError(t, err, name)
		assert.Empty(t, got, name)
	}
}

func TestIntentSignerBlob(t *testing.T) {
	ns := append(make([]byte, 19), []byte("edicta/d01")...)
	signer := bytes.Repeat([]byte{7}, 20)
	addr, err := bech32.ConvertAndEncode("celestia", signer)
	require.NoError(t, err)
	com := sha256.Sum256([]byte("blob"))
	ref := commitment.PayloadRef{DA: commitment.DACelestiaBlob, Namespace: ns, Commitment: com[:], Signer: signer,
		Height: 100, Anchor: commitment.AnchorPending}
	msg := &blobtypes.MsgPayForBlobs{Signer: addr, Namespaces: [][]byte{ns}, BlobSizes: []uint32{4},
		ShareCommitments: [][]byte{com[:]}, ShareVersions: []uint32{1}}
	mv, err := msg.Marshal()
	require.NoError(t, err)
	body, err := (&cosmostx.TxBody{Messages: []*codectypes.Any{{TypeUrl: "/celestia.blob.v1.MsgPayForBlobs", Value: mv}}}).Marshal()
	require.NoError(t, err)
	auth, err := (&cosmostx.AuthInfo{SignerInfos: []*cosmostx.SignerInfo{{Sequence: 1}}}).Marshal()
	require.NoError(t, err)
	tx, err := (&cosmostx.TxRaw{BodyBytes: body, AuthInfoBytes: auth, Signatures: [][]byte{make([]byte, 64)}}).Marshal()
	require.NoError(t, err)
	rec := &archive.AnchorIntentRecord{DA: commitment.DACelestiaBlob, Commitment: ref.Commitment, Namespace: ns,
		RefHeight: 100, Tx: tx, Signer: signer}

	got, err := absence.NewChain(absence.ChainDeps{Intents: memIntents{rec}}).IntentSigner(t.Context(), ref, 4, "")
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(signer), got)

	bad := *rec
	bad.Tx = []byte{1, 2, 3}
	got, err = absence.NewChain(absence.ChainDeps{Intents: memIntents{&bad}}).IntentSigner(t.Context(), ref, 4, "")
	require.NoError(t, err)
	assert.Empty(t, got)
}
