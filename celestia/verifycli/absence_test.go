package verifycli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/celestiaorg/celestia-app/v10/pkg/da"
	daproto "github.com/celestiaorg/celestia-app/v10/proto/celestia/core/v1/da"
	"github.com/celestiaorg/celestia-node/share/shwap"
	libshare "github.com/celestiaorg/go-square/v4/share"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/celestia/absence"
	"github.com/vgonkivs/edicta/celestia/headertrust"
	"github.com/vgonkivs/edicta/celestia/railverify"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/test/gatefix"
)

// absenceCase is the window of da/absence.json#window_three_heights_proven:
// its records, and the checkpoint the next header of its last record gives.
type absenceCase struct {
	ref      commitment.PayloadRef
	deadline uint64
	recs     map[uint64]*archive.AbsenceProofRecord
}

func loadAbsenceCase(t *testing.T, id string) absenceCase {
	t.Helper()
	raw, err := os.ReadFile("../../spec/vectors/da/absence.json")
	require.NoError(t, err)
	var f struct {
		Synthetic []struct {
			ID    string `json:"id"`
			Query struct {
				Namespace      string `json:"namespace"`
				Commitment     string `json:"commitment"`
				H0             string `json:"h0"`
				AnchorDeadline string `json:"anchor_deadline"`
			} `json:"query"`
			Records []struct {
				Height    string `json:"height"`
				RecordHex string `json:"record_hex"`
			} `json:"records"`
		} `json:"synthetic"`
	}
	require.NoError(t, json.Unmarshal(raw, &f))
	for _, c := range f.Synthetic {
		if c.ID != id {
			continue
		}
		u := func(s string) uint64 { v, err := strconv.ParseUint(s, 10, 64); require.NoError(t, err); return v }
		ac := absenceCase{
			ref: commitment.PayloadRef{DA: commitment.DAFibre, Namespace: gatefix.MustHex(t, c.Query.Namespace),
				Commitment: gatefix.MustHex(t, c.Query.Commitment), Height: u(c.Query.H0), Anchor: commitment.AnchorPending},
			deadline: u(c.Query.AnchorDeadline),
			recs:     map[uint64]*archive.AbsenceProofRecord{},
		}
		for _, r := range c.Records {
			rec, err := archive.Decode(gatefix.MustHex(t, r.RecordHex))
			require.NoError(t, err)
			ac.recs[u(r.Height)] = rec.(*archive.AbsenceProofRecord)
		}
		return ac
	}
	require.Fail(t, "no case "+id)
	return absenceCase{}
}

// trustedAt writes a trusted header file whose checkpoint is the next
// header of the last record; the headers below it come from the records.
func (ac absenceCase) trustedAt(t *testing.T) string { return ac.trusted(t, false) }

// trusted also bundles the headers of the window when asked.
func (ac absenceCase) trusted(t *testing.T, bundle bool) string {
	t.Helper()
	var bundled []string
	for h := ac.ref.Height; bundle && h <= ac.deadline; h++ {
		inner, err := headertrust.HeaderOfSigned(ac.recs[h].Header)
		require.NoError(t, err)
		bundled = append(bundled, hex.EncodeToString(inner))
	}
	last := ac.recs[ac.deadline]
	require.NotNil(t, last.NextHeader)
	inner, err := headertrust.HeaderOfSigned(last.NextHeader)
	require.NoError(t, err)
	hash, err := headertrust.HashOfHeader(inner)
	require.NoError(t, err)
	b, err := json.Marshal(map[string]any{"height": ac.deadline + 1, "hash": hex.EncodeToString(hash), "header": hex.EncodeToString(inner),
		"headers": bundled})
	require.NoError(t, err)
	p := filepath.Join(t.TempDir(), "trusted.json")
	require.NoError(t, os.WriteFile(p, b, 0o600))
	return p
}

// pendingArchive writes a fast-mode decision for the case's reference and
// its Authorization, plus the absence records of the heights given.
func (ac absenceCase) pendingArchive(t *testing.T, heights ...uint64) (string, commitment.Hash) {
	t.Helper()
	c := gatefix.Clone(gatefix.FibreTemplate(t))
	c.PayloadRef = ac.ref
	env, h := gatefix.Sign(t, "agent1", c)
	a := commitment.Authorization{Version: commitment.Version, CommitmentHash: h[:], ActionHash: c.Action.Hash,
		GateID: gatefix.GateID, Expires: authorizedAt + 300, Path: commitment.PathArchive, Mode: commitment.ModeFast,
		AnchorDeadline: ac.deadline}
	canon, err := commitment.EncodeAuthorization(&a)
	require.NoError(t, err)
	sa, err := commitment.EncodeSignedAuthorization(&commitment.SignedAuthorization{Authorization: a,
		Signature: ed25519.Sign(gatefix.Key(t, "gate1"), commitment.AuthorizationSigningMessage(commitment.HashAuthorization(canon)))})
	require.NoError(t, err)
	dir := t.TempDir()
	cm, err := committers()
	require.NoError(t, err)
	s, err := fsarchive.Open(dir, cm)
	require.NoError(t, err)
	recs := []archive.Record{
		&archive.DecisionRecord{Envelope: env, Form: archive.FormPublic, Action: gatefix.Action(t), ActionSalt: gatefix.Salt(t)},
		&archive.AuthorizationRecord{SignedAuthorization: sa, AuthorizedAt: authorizedAt},
	}
	for _, x := range heights {
		recs = append(recs, ac.recs[x])
	}
	for _, r := range recs {
		_, err := s.Put(context.Background(), r)
		require.NoError(t, err)
	}
	return dir, h
}

type fastJSON struct {
	Verdict      string `json:"verdict"`
	Mode         string `json:"mode"`
	H0           uint64 `json:"h0"`
	Deadline     uint64 `json:"anchor_deadline"`
	Publication  string `json:"publication"`
	IntentSigner string `json:"intent_signer"`
	Absence      *struct {
		Result        string `json:"result"`
		Heights       int    `json:"heights"`
		Bytes         uint64 `json:"bytes"`
		FirstUnproven uint64 `json:"first_unproven"`
	} `json:"absence"`
	Checks []checkView `json:"checks"`
}

func (f fastJSON) check(name string) checkView {
	for _, c := range f.Checks {
		if c.Name == name {
			return c
		}
	}
	return checkView{}
}

func runFast(t *testing.T, args ...string) (int, fastJSON) {
	t.Helper()
	code, out := exec(t, append(args, "--json"))
	var v fastJSON
	require.NoError(t, json.Unmarshal([]byte(out), &v), out)
	return code, v
}

func TestVerifyPendingAbsenceFromTheArchive(t *testing.T) {
	ac := loadAbsenceCase(t, "window_three_heights_proven")
	trusted := ac.trustedAt(t)
	gk := gatePubHex(t)

	dir, h := ac.pendingArchive(t, ac.ref.Height, ac.ref.Height+1, ac.deadline)
	code, v := runFast(t, "verify", hex.EncodeToString(h[:]), "--archive", dir, "--gate-key", gk, "--trusted", trusted)
	assert.Equal(t, codeInvalid, code)
	assert.Equal(t, "invalid", v.Verdict)
	assert.Equal(t, "fast", v.Mode)
	assert.Equal(t, ac.ref.Height, v.H0)
	assert.Equal(t, ac.deadline, v.Deadline)
	assert.Equal(t, "failed", v.Publication)
	assert.Equal(t, "unknown", v.IntentSigner)
	require.NotNil(t, v.Absence)
	assert.Equal(t, "absent", v.Absence.Result)
	assert.Equal(t, 3, v.Absence.Heights)
	assert.Equal(t, "fail", v.check("anchor").Status)

	_, text := exec(t, []string{"verify", hex.EncodeToString(h[:]), "--archive", dir, "--gate-key", gk, "--trusted", trusted})
	assert.Contains(t, text, "absence proof: absent at 4200201..4200203, 3 heights")
	assert.Contains(t, text, "intent signer: unknown")

	t.Run("a height missing", func(t *testing.T) {
		dir, h := ac.pendingArchive(t, ac.ref.Height, ac.deadline)
		code, v := runFast(t, "verify", hex.EncodeToString(h[:]), "--archive", dir, "--gate-key", gk, "--trusted", ac.trusted(t, true))
		assert.Equal(t, codeUnchecked, code)
		c := v.check("anchor")
		assert.Equal(t, "absence_unproven", c.Reason)
		assert.Contains(t, c.Error, "height 4200202")
		assert.Equal(t, "unknown", v.Publication)
	})
	t.Run("checkpoint below the deadline", func(t *testing.T) {
		dir, h := ac.pendingArchive(t, ac.ref.Height, ac.ref.Height+1, ac.deadline)
		low := ac.recs[ac.deadline]
		inner, err := headertrust.HeaderOfSigned(low.Header)
		require.NoError(t, err)
		hash, err := headertrust.HashOfHeader(inner)
		require.NoError(t, err)
		// A checkpoint at the deadline is below deadline + 1, which the
		// results proof of the candidate at the deadline needs.
		b, err := json.Marshal(map[string]any{"height": ac.deadline, "hash": hex.EncodeToString(hash), "header": hex.EncodeToString(inner)})
		require.NoError(t, err)
		p := filepath.Join(t.TempDir(), "low.json")
		require.NoError(t, os.WriteFile(p, b, 0o600))
		code, v := runFast(t, "verify", hex.EncodeToString(h[:]), "--archive", dir, "--gate-key", gk, "--trusted", p)
		assert.Equal(t, codeUnchecked, code)
		assert.Equal(t, "anchor_pending", v.check("anchor").Reason)
	})
}

// vectorProofs serves the parts of the vector records as a bridge would,
// and their block results.
type vectorProofs struct{ ac absenceCase }

func (p vectorProofs) rec(h uint64) (*archive.AbsenceProofRecord, error) {
	r, ok := p.ac.recs[h]
	if !ok {
		return nil, errors.New("height not served")
	}
	return r, nil
}

func (p vectorProofs) SignedHeader(_ context.Context, h uint64) ([]byte, error) {
	if r, ok := p.ac.recs[h]; ok {
		return r.Header, nil
	}
	if r, ok := p.ac.recs[h-1]; ok && r.NextHeader != nil {
		return r.NextHeader, nil
	}
	return nil, errors.New("height not served")
}

func (p vectorProofs) DAH(_ context.Context, h uint64) (*da.DataAvailabilityHeader, error) {
	r, err := p.rec(h)
	if err != nil {
		return nil, err
	}
	var dp daproto.DataAvailabilityHeader
	if err := dp.Unmarshal(r.DAH); err != nil {
		return nil, err
	}
	return &da.DataAvailabilityHeader{RowRoots: dp.RowRoots, ColumnRoots: dp.ColumnRoots}, nil
}

func (p vectorProofs) NamespaceData(_ context.Context, h uint64, _ libshare.Namespace) (shwap.NamespaceData, error) {
	r, err := p.rec(h)
	if err != nil {
		return nil, err
	}
	var nd shwap.NamespaceData
	_, err = nd.ReadFrom(bytes.NewReader(r.NamespaceData))
	return nd, err
}

func (p vectorProofs) BlockResults(_ context.Context, h uint64) ([]railverify.TxResult, error) {
	r, err := p.rec(h)
	if err != nil || r.Results == nil {
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

func serveProofs(t *testing.T, ac absenceCase) {
	t.Helper()
	prev := newProofSource
	newProofSource = func(context.Context, string) (absence.ProofSource, string, func(), error) {
		return vectorProofs{ac}, "bridge.test", func() {}, nil
	}
	t.Cleanup(func() { newProofSource = prev })
}

func TestAbsenceCommandWritesRecordsThatVerifyOffline(t *testing.T) {
	ac := loadAbsenceCase(t, "window_three_heights_proven")
	serveProofs(t, ac)
	trusted := ac.trustedAt(t)
	gk := gatePubHex(t)
	dir, h := ac.pendingArchive(t)
	ref := hex.EncodeToString(h[:])

	code, out := exec(t, []string{"absence", ref, "--archive", dir, "--gate-key", gk, "--trusted", trusted,
		"--absence-source", "http://bridge.test:26658"})
	require.Equal(t, codeValid, code, out)
	assert.Contains(t, out, "absence: absent at 4200201..4200203, 3 heights")
	assert.Contains(t, out, "3 records written")

	s, err := fsarchive.OpenReadOnly(dir, nil)
	require.NoError(t, err)
	for x := ac.ref.Height; x <= ac.deadline; x++ {
		got, err := s.Absence(context.Background(), ac.ref.DA, ac.ref.Commitment, x)
		require.NoError(t, err, "height %d", x)
		assert.Equal(t, ac.recs[x].Header, got.Header)
	}

	code, v := runFast(t, "verify", ref, "--archive", dir, "--gate-key", gk, "--trusted", trusted)
	assert.Equal(t, codeInvalid, code)
	assert.Equal(t, "failed", v.Publication)

	t.Run("json", func(t *testing.T) {
		code, out := exec(t, []string{"absence", ref, "--archive", dir, "--gate-key", gk, "--trusted", trusted,
			"--absence-source", "http://bridge.test:26658", "--json"})
		require.Equal(t, codeValid, code, out)
		var av absenceView
		require.NoError(t, json.Unmarshal([]byte(out), &av))
		assert.Equal(t, "absent", av.Result)
		assert.Equal(t, 3, av.Heights)
	})
}

func TestAbsenceCommandKeepsUnprovenHeightsOut(t *testing.T) {
	ac := loadAbsenceCase(t, "window_three_heights_proven")
	served := ac
	served.recs = map[uint64]*archive.AbsenceProofRecord{}
	for h, r := range ac.recs {
		served.recs[h] = r
	}
	tampered := *ac.recs[ac.ref.Height+1]
	tampered.DAH = append([]byte(nil), tampered.DAH...)
	tampered.DAH[len(tampered.DAH)-1] ^= 1
	served.recs[ac.ref.Height+1] = &tampered
	serveProofs(t, served)
	dir, h := ac.pendingArchive(t)

	code, out := exec(t, []string{"absence", hex.EncodeToString(h[:]), "--archive", dir, "--gate-key", gatePubHex(t),
		"--trusted", ac.trustedAt(t), "--absence-source", "http://bridge.test:26658"})
	assert.Equal(t, codeUnchecked, code, out)
	assert.Contains(t, out, "not proven, first height 4200202")
	s, err := fsarchive.OpenReadOnly(dir, nil)
	require.NoError(t, err)
	_, err = s.Absence(context.Background(), ac.ref.DA, ac.ref.Commitment, ac.ref.Height+1)
	require.ErrorIs(t, err, archive.ErrNotFound)
}

func TestVerifyWithAbsenceSource(t *testing.T) {
	ac := loadAbsenceCase(t, "window_three_heights_proven")
	serveProofs(t, ac)
	dir, h := ac.pendingArchive(t)
	code, v := runFast(t, "verify", hex.EncodeToString(h[:]), "--archive", dir, "--gate-key", gatePubHex(t),
		"--trusted", ac.trustedAt(t), "--absence-source", "http://bridge.test:26658")
	assert.Equal(t, codeInvalid, code)
	assert.Equal(t, "failed", v.Publication)
}

func TestAbsenceCommandUsage(t *testing.T) {
	h := hex.EncodeToString(make([]byte, 32))
	for name, args := range map[string][]string{
		"no archive":        {"absence", h, "--gate-key", gatePubHex(t), "--archive-url", "http://a", "--absence-source", "http://b", "--trusted", "x"},
		"no source":         {"absence", h, "--gate-key", gatePubHex(t), "--archive", t.TempDir(), "--trusted", "x"},
		"no trusted header": {"absence", h, "--gate-key", gatePubHex(t), "--archive", t.TempDir(), "--absence-source", "http://b"},
		"with a receipt":    {"absence", h, "--gate-key", gatePubHex(t), "--archive", t.TempDir(), "--absence-source", "http://b", "--trusted", "x", "--receipt", "r"},
	} {
		code, out := exec(t, args)
		assert.Equal(t, codeUsage, code, name+": "+out)
	}
	ac := loadAbsenceCase(t, "window_three_heights_proven")
	serveProofs(t, ac)
	s := newScenario(t, scenarioOpts{})
	code, out := exec(t, s.args("absence", "--absence-source", "http://b", "--trusted", s.chain.trustedFile(t, checkpointH, nil)))
	assert.Equal(t, codeUsage, code, out)
	assert.Contains(t, out, "not a pending reference")
}

// An archive that serves the proof of another height, one that shows the
// anchor present, can only hold the decision back: the reader refuses the
// record under the wrong key, and a record re-keyed to the height fails the
// header check.
func TestForgedPresentProofFromAnotherHeight(t *testing.T) {
	ac := loadAbsenceCase(t, "window_three_heights_proven")
	present := loadAbsenceCase(t, "fibre_present")
	from := present.recs[present.deadline]
	gk := gatePubHex(t)
	at := ac.ref.Height + 1

	t.Run("under the wrong key", func(t *testing.T) {
		dir, h := ac.pendingArchive(t, ac.ref.Height, ac.deadline)
		rel, err := archive.AbsencePath(ac.ref.DA, ac.ref.Commitment, at)
		require.NoError(t, err)
		b, err := archive.Encode(from)
		require.NoError(t, err)
		require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(dir, rel)), 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(dir, rel), b, 0o600))
		code, v := runFast(t, "verify", hex.EncodeToString(h[:]), "--archive", dir, "--gate-key", gk, "--trusted", ac.trusted(t, true))
		assert.Equal(t, codeUnchecked, code)
		assert.Equal(t, "unchecked", v.check("anchor").Status)
		assert.Equal(t, "absence_unproven", v.check("anchor").Reason)
		assert.Contains(t, v.check("anchor").Error, "height 4200202")
	})
	t.Run("re-keyed to the height", func(t *testing.T) {
		rekeyed := *from
		rekeyed.Height = at
		ac2 := ac
		ac2.recs = map[uint64]*archive.AbsenceProofRecord{}
		for k, r := range ac.recs {
			ac2.recs[k] = r
		}
		ac2.recs[at] = &rekeyed
		dir, h := ac2.pendingArchive(t, ac.ref.Height, at, ac.deadline)
		code, v := runFast(t, "verify", hex.EncodeToString(h[:]), "--archive", dir, "--gate-key", gk, "--trusted", ac.trusted(t, true))
		assert.Equal(t, codeUnchecked, code)
		assert.Equal(t, "absence_unproven", v.check("anchor").Reason)
		assert.NotEqual(t, "valid", v.Verdict)
	})
}
