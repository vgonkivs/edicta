package main

import (
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	fibretypes "github.com/celestiaorg/celestia-app/v10/x/fibre/types"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/celestia/test/fibrefix"
)

type da1 struct {
	live *fibrefix.Live
	d    fibrefix.Decision
}

func newDA1(t *testing.T, ev func(l *fibrefix.Live) *archive.EvidenceRecord) *da1 {
	t.Helper()
	l := fibrefix.LoadLive(t)
	e := l.Evidence(t)
	if ev != nil {
		e = ev(l)
	}
	return &da1{live: l, d: l.WriteDecision(t, e)}
}

func (s *da1) args(cmd string, extra ...string) []string {
	a := []string{cmd, "--archive", s.d.Dir, "--gate-key", s.d.GateKeyHex}
	a = append(a, extra...)
	return append(a, hex.EncodeToString(s.d.Hash[:]))
}

func TestDA1EndToEnd(t *testing.T) {
	s := newDA1(t, nil)
	trusted := s.live.TrustedFile(t, nil)

	code, out := exec(t, s.args("verify", "--trusted", trusted))
	require.Equal(t, exitValid, code, out)
	for _, line := range []string{"[ok] anchor", "[ok] header_trust", "[ok] payload", "verdict: valid"} {
		assert.Contains(t, out, line)
	}
	assert.Contains(t, out, "anchor proof form: 1, earlier candidates: 0")
	assert.Contains(t, out, `token precision "robust"`)
	assert.NotContains(t, out, "[FAIL]")
	assert.NotContains(t, out, "[unchecked]")

	code, out = exec(t, s.args("verify", "--json", "--trusted", trusted))
	require.Equal(t, exitValid, code, out)
	var rep map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &rep))
	assert.Equal(t, "valid", rep["verdict"])
	assert.Equal(t, "node-attested", rep["settlement"])
	assert.EqualValues(t, 1, rep["anchor_proof_form"])
	assert.EqualValues(t, 0, rep["anchor_candidates_earlier"])
	assert.Contains(t, rep, "anchor_candidates_earlier", "zero is printed, not omitted")
	assert.EqualValues(t, 1791196769, rep["retention_start"])
	cert, ok := rep["cert"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "robust", cert["cert_token_precision"])
	assert.Equal(t, "next_validators_hash@1402813", cert["cert_valset_header"])
	ht, ok := rep["header_trust"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "valid", ht["status"])
}

func TestDA1ReplayEndToEnd(t *testing.T) {
	s := newDA1(t, nil)
	trusted := s.live.TrustedFile(t, nil)
	code, out := exec(t, s.args("replay", "--json", "--trusted", trusted))
	require.Equal(t, exitValid, code, out)
	var rep map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &rep))
	k2, ok := rep["retention_replay"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, true, k2["replayable"])
	assert.Equal(t, true, k2["consistent"])
}

func TestDA1WithoutTrustedHeaderIsUnchecked(t *testing.T) {
	s := newDA1(t, nil)
	code, out := exec(t, s.args("verify"))
	assert.Equal(t, exitUnchecked, code, out)
	assert.Contains(t, out, "[ok] anchor", "the anchor itself verifies offline")
	assert.Contains(t, out, "[unchecked] header_trust")
	assert.NotContains(t, out, "verdict: valid")
}

func TestDA1Form0IsUncheckedWithAReason(t *testing.T) {
	s := newDA1(t, func(l *fibrefix.Live) *archive.EvidenceRecord {
		ev := l.Evidence(t)
		ev.SystemBlobProof = []byte(`{"form":0}`)
		return ev
	})
	trusted := s.live.TrustedFile(t, nil)

	code, out := exec(t, s.args("verify", "--trusted", trusted))
	assert.Equal(t, exitUnchecked, code, out)
	assert.Contains(t, out, "[unchecked] anchor")
	assert.Contains(t, out, "form-0")
	assert.Contains(t, out, "verdict: unchecked")
	assert.NotContains(t, out, "verdict: valid")

	code, out = exec(t, s.args("verify", "--json", "--trusted", trusted))
	assert.Equal(t, exitUnchecked, code)
	var rep map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &rep))
	assert.Equal(t, "unchecked", rep["verdict"])
	assert.NotContains(t, rep, "anchor_proof_form")
	assert.NotContains(t, rep, "settlement")
	for _, c := range rep["checks"].([]any) {
		m := c.(map[string]any)
		if m["name"] == "anchor" {
			assert.Equal(t, "unchecked", m["status"])
			assert.NotEmpty(t, m["error"])
		}
	}
}

func TestDA1TamperedEvidenceIsInvalid(t *testing.T) {
	tests := []struct {
		name string
		mod  func(t *testing.T, l *fibrefix.Live, ev *archive.EvidenceRecord)
	}{
		{"system blob", func(_ *testing.T, _ *fibrefix.Live, ev *archive.EvidenceRecord) { ev.SystemBlob[3] ^= 1 }},
		{"proof cut", func(_ *testing.T, _ *fibrefix.Live, ev *archive.EvidenceRecord) {
			ev.SystemBlobProof = ev.SystemBlobProof[:len(ev.SystemBlobProof)-1]
		}},
		{"validator signature", func(t *testing.T, l *fibrefix.Live, ev *archive.EvidenceRecord) {
			ev.AnchorTx = fibrefix.MutateTx(t, l.PFFTx, func(m *fibretypes.MsgPayForFibre) {
				m.ValidatorSignatures[1] = append([]byte(nil), m.ValidatorSignatures[1]...)
				m.ValidatorSignatures[1][0] ^= 1
			})
			ev.SystemBlob = fibrefix.SystemBlobOf(t, ev.AnchorTx)
		}},
		{"promise header", func(t *testing.T, l *fibrefix.Live, ev *archive.EvidenceRecord) {
			var h cmtproto.Header
			require.NoError(t, h.Unmarshal(l.Headers[l.PromiseHeight+1]))
			ev.PromiseHeader = fibrefix.SignedHeader(t, h)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newDA1(t, func(l *fibrefix.Live) *archive.EvidenceRecord {
				ev := l.Evidence(t)
				tc.mod(t, l, ev)
				return ev
			})
			code, out := exec(t, s.args("verify", "--trusted", s.live.TrustedFile(t, nil)))
			assert.Equal(t, exitInvalid, code, out)
			assert.Contains(t, out, "[FAIL] anchor")
			assert.Contains(t, out, "verdict: invalid")
			assert.NotContains(t, out, "verdict: valid")
		})
	}
}

func TestDA1EarlierCandidatesAreReportedAndWarned(t *testing.T) {
	s := newDA1(t, func(l *fibrefix.Live) *archive.EvidenceRecord {
		earlier := fibrefix.MutateTx(t, l.PFFTx, func(m *fibretypes.MsgPayForFibre) {
			m.PaymentPromise.CreationTimestamp = l.Created.Add(-time.Minute)
		})
		return l.EvidenceFor(t, fibrefix.BuildBlock(t, earlier, l.PFFTx), l.PFFTx)
	})
	// The synthetic header has another hash, so the trusted file cannot vouch
	// for it; the anchor result is still shown.
	code, out := exec(t, s.args("verify", "--json"))
	assert.Equal(t, exitUnchecked, code, out)
	var rep map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &rep))
	assert.EqualValues(t, 1, rep["anchor_proof_form"])
	assert.EqualValues(t, 1, rep["anchor_candidates_earlier"])
	assert.NotEmpty(t, rep["warnings"])
	assert.NotEqual(t, "valid", rep["verdict"])
}

func TestDA1HeaderTrustFailures(t *testing.T) {
	t.Run("promise header substituted in the bundle", func(t *testing.T) {
		s := newDA1(t, nil)
		trusted := s.live.TrustedFile(t, func(hs map[uint64][]byte) {
			var h cmtproto.Header
			require.NoError(t, h.Unmarshal(hs[s.live.PromiseHeight]))
			h.AppHash = append([]byte(nil), h.AppHash...)
			h.AppHash[0] ^= 1
			b, err := h.Marshal()
			require.NoError(t, err)
			hs[s.live.PromiseHeight] = b
		})
		code, out := exec(t, s.args("verify", "--trusted", trusted))
		assert.Equal(t, exitInvalid, code, out)
		assert.Contains(t, out, "[FAIL] header_trust")
	})
	t.Run("a header of the chain between is missing", func(t *testing.T) {
		s := newDA1(t, nil)
		trusted := s.live.TrustedFile(t, func(hs map[uint64][]byte) { delete(hs, s.live.PromiseHeight+2) })
		code, out := exec(t, s.args("verify", "--trusted", trusted))
		assert.NotEqual(t, exitValid, code, out)
		assert.NotContains(t, out, "verdict: valid")
	})
}

func TestDA1ForgedAnchorHeaderAtThePromiseHeightIsNotValid(t *testing.T) {
	s := newDA1(t, func(l *fibrefix.Live) *archive.EvidenceRecord {
		l.Ref.Height = l.PromiseHeight
		ev := l.EvidenceFor(t, fibrefix.BuildBlock(t, l.PFFTx), l.PFFTx)
		var sh cmtproto.SignedHeader
		require.NoError(t, sh.Unmarshal(ev.Header))
		sh.Header.Height = int64(l.PromiseHeight)
		ev.Header, ev.Height = fibrefix.SignedHeader(t, *sh.Header), l.PromiseHeight
		return ev
	})
	code, out := exec(t, s.args("verify", "--trusted", s.live.TrustedFile(t, nil)))
	assert.Equal(t, exitInvalid, code, out)
	assert.NotContains(t, out, "verdict: valid")
	assert.Contains(t, out, "differ")
}
