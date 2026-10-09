package absence_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/absence"
)

const absencePath = "../../spec/vectors/da/absence.json"

type vQuery struct {
	DA             string `json:"da"`
	Namespace      string `json:"namespace"`
	Commitment     string `json:"commitment"`
	Signer         string `json:"signer"`
	ChainID        string `json:"chain_id"`
	H0             string `json:"h0"`
	AnchorDeadline string `json:"anchor_deadline"`
}

type vCandidate struct {
	Position    string `json:"position"`
	ResultIndex string `json:"result_index"`
	Code        string `json:"code"`
}

type vBlob struct {
	ShareVersion string `json:"share_version"`
	Signer       string `json:"signer"`
	Commitment   string `json:"commitment"`
}

type vHeight struct {
	Height     string       `json:"height"`
	Result     string       `json:"result"`
	Rule       string       `json:"rule"`
	Rows       []string     `json:"rows"`
	PFFTxs     string       `json:"pff_txs"`
	Candidates []vCandidate `json:"candidates"`
	Blobs      []vBlob      `json:"blobs"`
}

type vWindow struct {
	Result        string `json:"result"`
	AnchorHeight  string `json:"anchor_height"`
	FirstUnproven string `json:"first_unproven"`
}

type vCase struct {
	ID             string            `json:"id"`
	Query          vQuery            `json:"query"`
	TrustedHeaders map[string]string `json:"trusted_headers"`
	Records        []struct {
		Height    string `json:"height"`
		RecordHex string `json:"record_hex"`
		SHA256    string `json:"sha256"`
		Size      string `json:"size"`
	} `json:"records"`
	Expect struct {
		Heights []vHeight `json:"heights"`
		Window  vWindow   `json:"window"`
	} `json:"expect"`
}

type vFile struct {
	Revision  string  `json:"revision"`
	ChainID   string  `json:"chain_id"`
	Synthetic []vCase `json:"synthetic"`
	Live      []vCase `json:"live"`
	Source    struct {
		ChainID string `json:"chain_id"`
	} `json:"live_source"`
}

func u64(t *testing.T, s string) uint64 {
	t.Helper()
	v, err := strconv.ParseUint(s, 10, 64)
	require.NoError(t, err)
	return v
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	if s == "" {
		return nil
	}
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func loadAbsence(t *testing.T) vFile {
	t.Helper()
	b, err := os.ReadFile(absencePath)
	require.NoError(t, err)
	var f vFile
	require.NoError(t, json.Unmarshal(b, &f))
	require.Equal(t, "v1-draft.4", f.Revision)
	return f
}

// gotHeight renders an outcome in the vector's notation.
func gotHeight(o absence.Outcome) vHeight {
	g := vHeight{Height: strconv.FormatUint(o.Height, 10), Result: o.Result.String(), Rule: string(o.Rule)}
	if o.Result == absence.Unproven {
		return g
	}
	g.Rows = []string{}
	for _, r := range o.Rows {
		g.Rows = append(g.Rows, strconv.Itoa(r))
	}
	if o.Rule == absence.RuleCandidates || o.Rule == absence.RuleResults {
		g.PFFTxs = strconv.Itoa(o.PFFTxs)
	}
	for _, c := range o.Candidates {
		vc := vCandidate{Position: strconv.Itoa(c.Position), Code: strconv.FormatUint(uint64(c.Code), 10)}
		if c.IndexBound {
			vc.ResultIndex = strconv.Itoa(c.ResultIndex)
		}
		g.Candidates = append(g.Candidates, vc)
	}
	for _, b := range o.Blobs {
		g.Blobs = append(g.Blobs, vBlob{ShareVersion: strconv.Itoa(int(b.ShareVersion)),
			Signer: hex.EncodeToString(b.Signer), Commitment: hex.EncodeToString(b.Commitment)})
	}
	return g
}

func normWant(w vHeight) vHeight {
	if w.Result != "unproven" && w.Rows == nil {
		w.Rows = []string{}
	}
	return w
}

func runCase(t *testing.T, c vCase, chainID string) {
	q := absence.Query{
		DA:         u64(t, c.Query.DA),
		Namespace:  unhex(t, c.Query.Namespace),
		Commitment: unhex(t, c.Query.Commitment),
		Signer:     unhex(t, c.Query.Signer),
	}
	require.Equal(t, chainID, c.Query.ChainID)
	if q.DA == absence.DAFibre {
		q.ChainID = c.Query.ChainID
	}
	trusted := absence.TrustedHashes{}
	for h, x := range c.TrustedHeaders {
		trusted[u64(t, h)] = unhex(t, x)
	}
	recs := map[uint64]absence.Record{}
	for _, r := range c.Records {
		b := unhex(t, r.RecordHex)
		sum := sha256.Sum256(b)
		require.Equal(t, r.SHA256, hex.EncodeToString(sum[:]))
		require.Equal(t, r.Size, strconv.Itoa(len(b)))
		rec, err := absence.DecodeRecordAt(absence.Record{DA: q.DA, Commitment: q.Commitment, Height: u64(t, r.Height)}.Path(), b)
		require.NoError(t, err, "record at %s", r.Height)
		again, err := absence.EncodeRecord(rec)
		require.NoError(t, err)
		require.Equal(t, b, again)
		recs[rec.Height] = rec
	}
	w, err := absence.VerifyWindow(q, u64(t, c.Query.H0), u64(t, c.Query.AnchorDeadline), recs, trusted)
	require.NoError(t, err)
	require.Len(t, w.Heights, len(c.Expect.Heights))
	for i, o := range w.Heights {
		assert.Equal(t, normWant(c.Expect.Heights[i]), gotHeight(o), "height %d: %v", o.Height, o.Err)
		assert.Equal(t, o.Result == absence.Unproven, o.Err != nil)
	}
	gw := vWindow{Result: w.Result.String()}
	if w.Result == absence.Present {
		gw.AnchorHeight = strconv.FormatUint(w.AnchorHeight, 10)
	}
	if w.Result == absence.Unproven {
		gw.FirstUnproven = strconv.FormatUint(w.FirstUnproven, 10)
	}
	assert.Equal(t, c.Expect.Window, gw)
}

func TestVectorsSynthetic(t *testing.T) {
	f := loadAbsence(t)
	require.NotEmpty(t, f.Synthetic)
	for _, c := range f.Synthetic {
		t.Run(c.ID, func(t *testing.T) { runCase(t, c, f.ChainID) })
	}
}

func TestVectorsLive(t *testing.T) {
	f := loadAbsence(t)
	require.NotEmpty(t, f.Live)
	for _, c := range f.Live {
		t.Run(c.ID, func(t *testing.T) { runCase(t, c, f.Source.ChainID) })
	}
}
