package railverify_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/railverify"
	"github.com/vgonkivs/edicta/celestia/test/cometfake"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/examples/tia-transfer/bankaction"
	"github.com/vgonkivs/edicta/verifier"
)

const outcomesPath = "../../spec/vectors/verifier/execution_outcomes.json"

type outcomeDoc struct {
	Revision string `json:"revision"`
	Defaults struct {
		ActionCBORHex    string `json:"action_cbor_hex"`
		CommitmentHash   string `json:"commitment_hash_hex"`
		ChainID          string `json:"chain_id"`
		AnchorHeight     string `json:"anchor_height"`
		CheckpointHeight string `json:"checkpoint_height"`
	} `json:"defaults"`
	Outcomes map[string]struct {
		Verdict string `json:"verdict"`
		Exit    string `json:"exit"`
	} `json:"outcomes"`
	Txs map[string]struct {
		TxHex string `json:"tx_hex"`
	} `json:"txs"`
	Cases []outcomeCase `json:"cases"`
}

type outcomeCase struct {
	ID               string `json:"id"`
	RailRefOf        string `json:"rail_ref_of"`
	RailRef          string `json:"rail_ref"`
	CheckpointHeight string `json:"checkpoint_height"`
	CheckerChainID   string `json:"checker_chain_id"`
	TrustedChainID   string `json:"trusted_chain_id"`
	HeaderAtTxHeight string `json:"header_at_tx_height"`
	ResultProof      *struct {
		State string `json:"state"`
		Code  string `json:"code"`
	} `json:"result_proof"`
	Sources []struct {
		Name   string `json:"name"`
		Role   string `json:"role"`
		Answer struct {
			Kind   string `json:"kind"`
			Tx     string `json:"tx"`
			Height string `json:"height"`
			Code   string `json:"code"`
			Proof  string `json:"proof"`
		} `json:"answer"`
	} `json:"sources"`
	Expect struct {
		Execution          string            `json:"execution"`
		HeaderTrust        string            `json:"header_trust"`
		Verdict            string            `json:"verdict"`
		Exit               string            `json:"exit"`
		Cause              string            `json:"cause"`
		Sentinel           *string           `json:"sentinel"`
		Inclusion          *string           `json:"inclusion"`
		Result             *string           `json:"result"`
		CrossCheck         *string           `json:"cross_check"`
		ProvenExecution    bool              `json:"proven_execution"`
		SourceResults      map[string]string `json:"source_results"`
		NamesSources       []string          `json:"names_sources"`
		SuggestOtherSource bool              `json:"suggest_other_source"`
	} `json:"expect"`
}

func loadOutcomes(t testing.TB) outcomeDoc {
	t.Helper()
	raw, err := os.ReadFile(outcomesPath)
	require.NoError(t, err)
	var d outcomeDoc
	require.NoError(t, json.Unmarshal(raw, &d))
	require.Equal(t, "v1-draft.5", d.Revision)
	require.NotEmpty(t, d.Cases)
	return d
}

func u64(t testing.TB, s string) uint64 {
	t.Helper()
	v, err := strconv.ParseUint(s, 10, 64)
	require.NoError(t, err, s)
	return v
}

// Proof stand-ins: the vectors say whether a proof verifies, and the live
// proofs are tested on their own.
var (
	validProof   = []byte("proof: valid")
	invalidProof = []byte("proof: invalid")
)

// vecSource serves one answer of a case, whatever hash it is asked for, and
// block results for the heights the case gives.
type vecSource struct {
	name    string
	kind    string
	tx      []byte
	height  uint64
	code    uint32
	proof   []byte
	results map[uint64][]railverify.TxResult
	blocks  map[uint64][][]byte
}

func (s *vecSource) Name() string { return s.name }

func (s *vecSource) Tx(_ context.Context, _ [32]byte, prove bool) (railverify.RawTx, error) {
	switch s.kind {
	case "not_found":
		return railverify.RawTx{}, railverify.ErrTxNotFound
	case "tx":
		out := railverify.RawTx{Bytes: s.tx, Height: s.height, Code: s.code}
		if prove {
			out.Proof = s.proof
		}
		return out, nil
	}
	return railverify.RawTx{}, errors.New("unavailable")
}

func (s *vecSource) BlockResults(_ context.Context, h uint64) ([]railverify.TxResult, error) {
	if r, ok := s.results[h]; ok {
		return r, nil
	}
	return nil, errors.New("node is not persisting finalize block responses")
}

func (s *vecSource) BlockTxs(_ context.Context, h uint64) ([][]byte, error) {
	if b, ok := s.blocks[h]; ok {
		return b, nil
	}
	return nil, errors.New("block not served")
}

// vecHeaders is the trusted header chain of a case: it reaches T, and gives
// the faults the case names.
type vecHeaders struct {
	t           *testing.T
	top         uint64
	chain       string
	mode        string
	txHeights   map[uint64]bool
	lastResults map[uint64][]byte
	dataHash    map[uint64][]byte
}

func (h *vecHeaders) Header(_ context.Context, height uint64) ([]byte, error) {
	switch {
	case height > h.top:
		return nil, verifier.WithReason(verifier.ReasonHeaderAboveCheckpoint, nil, errors.New("the checkpoint is below this height"))
	case h.mode == "not_linking" && h.txHeights[height]:
		return nil, verifier.WithReason(verifier.ReasonHeaderNotLinking, []string{"headers-rpc"}, errors.New("the header does not link"))
	case h.mode == "cross_mismatch" && h.txHeights[height]:
		return nil, verifier.WithReason(verifier.ReasonHeaderDisagreement, []string{"cross-hdr.example"}, errors.New("a cross source differs"))
	}
	hd := cometfake.MkHeader(h.chain, height, make([]byte, 32), "app")
	if root, ok := h.lastResults[height]; ok {
		hd.LastResultsHash = root
	}
	if dh, ok := h.dataHash[height]; ok {
		hd.DataHash = dh
	}
	return cometfake.Encode(h.t, hd), nil
}

// resultsOf builds, for a result proof state, the results the sources serve
// and the root the header after the block carries.
func resultsOf(t testing.TB, state string, code uint32) (served []railverify.TxResult, root []byte) {
	t.Helper()
	list := func(codes ...uint32) []railverify.TxResult {
		out := make([]railverify.TxResult, len(codes))
		for i, c := range codes {
			out[i] = railverify.TxResult{Code: c, Data: []byte{byte(i)}, GasWanted: 100, GasUsed: int64(10 + i)}
		}
		return out
	}
	rootOf := func(r []railverify.TxResult) []byte {
		b, err := railverify.ResultsRoot(r)
		require.NoError(t, err)
		return b
	}
	switch state {
	case "match_indexed":
		served = list(code, 0, 0)
	case "match_uniform":
		served = list(code, code, code)
	case "match_rebuilt":
		served = list(code+1, code, code+1)
	case "match_unindexed", "match_rebuild_mismatch":
		served = list(0, 5)
	case "root_mismatch":
		return list(0, 7), rootOf(list(0))
	default:
		return nil, nil
	}
	return served, rootOf(served)
}

var sentinelByName = map[string]error{
	"railverify.ErrTxNotFound":          railverify.ErrTxNotFound,
	"railverify.ErrTxSourceUnavailable": railverify.ErrTxSourceUnavailable,
	"railverify.ErrTxHashMismatch":      railverify.ErrTxHashMismatch,
	"railverify.ErrTxProof":             railverify.ErrTxProof,
	"railverify.ErrChainConfig":         railverify.ErrChainConfig,
	"railverify.ErrResultsProof":        railverify.ErrResultsProof,
	"railverify.ErrResultUnconfirmed":   railverify.ErrResultUnconfirmed,
	"railverify.ErrChainMismatch":       railverify.ErrChainMismatch,
	"railverify.ErrTxFailed":            railverify.ErrTxFailed,
	"railverify.ErrTxMalformed":         railverify.ErrTxMalformed,
	"railverify.ErrRailRefMalformed":    railverify.ErrRailRefMalformed,
	"bankaction.ErrBodyMismatch":        bankaction.ErrBodyMismatch,
}

// failCauses names the proven violations of the vectors by their sentinel.
var failCauses = map[string]error{
	"rail_ref_malformed":      railverify.ErrRailRefMalformed,
	"tx_malformed":            railverify.ErrTxMalformed,
	"body_mismatch":           bankaction.ErrBodyMismatch,
	"chain_mismatch":          railverify.ErrChainMismatch,
	"height_not_after_anchor": verifier.ErrExecutionBeforeAnchor,
	"tx_failed":               railverify.ErrTxFailed,
}

// TestExecutionOutcomeVectors runs every case of execution_outcomes.json
// through the bank-send checker and the core's outcome rule, so that the code
// is held to the spec's table.
func TestExecutionOutcomeVectors(t *testing.T) {
	d := loadOutcomes(t)
	for _, c := range d.Cases {
		t.Run(c.ID, func(t *testing.T) {
			runOutcomeCase(t, d, c)
		})
	}
}

func runOutcomeCase(t *testing.T, d outcomeDoc, c outcomeCase) {
	action, err := hex.DecodeString(d.Defaults.ActionCBORHex)
	require.NoError(t, err)
	var hash commitment.Hash
	hb, err := hex.DecodeString(d.Defaults.CommitmentHash)
	require.NoError(t, err)
	copy(hash[:], hb)

	txs := map[string][]byte{}
	for name, tx := range d.Txs {
		b, err := hex.DecodeString(tx.TxHex)
		require.NoError(t, err)
		txs[name] = b
	}
	railRef := c.RailRef
	if railRef == "" {
		railRef = refOf(txs[c.RailRefOf])
	}
	anchor := u64(t, d.Defaults.AnchorHeight)
	top := u64(t, d.Defaults.CheckpointHeight)
	if c.CheckpointHeight != "" {
		top = u64(t, c.CheckpointHeight)
	}
	checkerChain, trustedChain := d.Defaults.ChainID, d.Defaults.ChainID
	if c.CheckerChainID != "" {
		checkerChain = c.CheckerChainID
	}
	if c.TrustedChainID != "" {
		trustedChain = c.TrustedChainID
	}

	state, resCode := "unavailable", uint32(0)
	if c.ResultProof != nil {
		state = c.ResultProof.State
		if c.ResultProof.Code != "" {
			resCode = uint32(u64(t, c.ResultProof.Code))
		}
	}
	served, root := resultsOf(t, state, resCode)

	heads := &vecHeaders{t: t, top: top, chain: trustedChain, mode: c.HeaderAtTxHeight, txHeights: map[uint64]bool{}, lastResults: map[uint64][]byte{}, dataHash: map[uint64][]byte{}}
	var primary railverify.TxSource
	var alts, cross []railverify.TxSource
	for i, s := range c.Sources {
		vs := &vecSource{name: s.Name, kind: s.Answer.Kind, results: map[uint64][]railverify.TxResult{}, blocks: map[uint64][][]byte{}}
		if s.Answer.Kind == "tx" {
			vs.tx = txs[s.Answer.Tx]
			require.NotNil(t, vs.tx, s.Answer.Tx)
			vs.height = u64(t, s.Answer.Height)
			vs.code = uint32(u64(t, s.Answer.Code))
			switch s.Answer.Proof {
			case "valid":
				vs.proof = validProof
			case "invalid":
				vs.proof = invalidProof
			case "none":
			default:
				require.Failf(t, "unknown proof form", "%q", s.Answer.Proof)
			}
			if s.Role != "cross" {
				heads.txHeights[vs.height] = true
			}
			if served != nil {
				vs.results[vs.height] = served
				heads.lastResults[vs.height+1] = root
				// The tx is the second of three, behind a transaction that
				// owns share 0, so its proof does not bind the index.
				pad := fillers(2)
				switch state {
				case "match_rebuilt":
					block := [][]byte{pad[0], vs.tx, pad[1]}
					dh, err := railverify.RebuildDataRoot(block)
					require.NoError(t, err)
					vs.blocks[vs.height], heads.dataHash[vs.height] = block, dh
				case "match_rebuild_mismatch":
					vs.blocks[vs.height] = [][]byte{pad[0], pad[1]}
				}
			}
		}
		switch {
		case i == 0:
			require.Equal(t, "primary", s.Role)
			primary = vs
		case s.Role == "alternate":
			alts = append(alts, vs)
		case s.Role == "cross":
			cross = append(cross, vs)
		default:
			require.Failf(t, "unknown role", "%q", s.Role)
		}
	}

	verifyProof := func(proofJSON, _, _ []byte) (railverify.ProofInfo, error) {
		if string(proofJSON) == string(validProof) {
			return railverify.ProofInfo{IndexBound: state == "match_indexed", Index: 0}, nil
		}
		return railverify.ProofInfo{}, railverify.ErrTxProof
	}
	chk, err := railverify.NewBankSend(railverify.Config{ChainID: checkerChain, HRP: hrp}, primary, heads, cross,
		railverify.WithAlternates(alts...), railverify.WithProofVerifier(verifyProof))
	require.NoError(t, err)

	f, cerr := chk.CheckExecution(context.Background(), verifier.ExecutionInput{
		CommitmentHash: hash, ActionType: bankaction.ActionType, Action: action, RailRef: railRef, AnchorHeight: anchor,
	})
	j := verifier.JudgeCheck(f, cerr, anchor)

	e := c.Expect
	assert.Equal(t, e.Execution, string(j.Status))
	out, ok := d.Outcomes[e.Execution]
	require.True(t, ok)
	assert.Equal(t, out.Verdict, e.Verdict, "the vector's own table")
	assert.Equal(t, out.Exit, e.Exit)

	// A disagreement about the headers also leaves header trust unchecked.
	wantTrust := "pass"
	if j.Reason == verifier.ReasonHeaderDisagreement {
		wantTrust = "unchecked"
	}
	assert.Equal(t, e.HeaderTrust, wantTrust)

	if e.Execution == "unchecked" {
		assert.Equal(t, e.Cause, string(j.Reason))
		info, closed := j.Reason.Info()
		require.True(t, closed, "the reason is in the closed enum")
		assert.Contains(t, info.Checks, "execution")
		if e.SuggestOtherSource {
			assert.NotEmpty(t, j.Reason.Advice())
		}
		if e.NamesSources != nil {
			assert.ElementsMatch(t, e.NamesSources, j.Sources, "the check names its sources")
		}
	}
	if e.Execution == "fail" {
		want, ok := failCauses[e.Cause]
		require.True(t, ok, "the cause %q is a known violation", e.Cause)
		require.ErrorIs(t, j.Err, want)
	}
	if e.Execution == "pass" {
		assert.Equal(t, "none", e.Cause)
		require.NoError(t, cerr)
	}
	if e.Sentinel != nil {
		want, ok := sentinelByName[*e.Sentinel]
		require.True(t, ok, "the sentinel %q is known", *e.Sentinel)
		assert.ErrorIs(t, j.Err, want)
	}

	assert.Equal(t, deref(e.Inclusion), f.Inclusion)
	assert.Equal(t, deref(e.Result), f.Result)
	assert.Equal(t, deref(e.CrossCheck), f.CrossCheck)
	assert.Equal(t, e.ProvenExecution, f.Inclusion == verifier.InclusionProven && j.Reason != verifier.ReasonHeaderDisagreement)
	got := map[string]string{}
	for _, s := range f.Sources {
		got[s.Name] = s.Result
	}
	for name, want := range e.SourceResults {
		if want == "not_asked" {
			assert.NotContains(t, got, name)
			continue
		}
		assert.Equal(t, want, got[name], name)
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// TestOutcomeVectorsCoverEveryReason requires a case for each execution
// reason that a source can cause.
func TestOutcomeVectorsCoverEveryReason(t *testing.T) {
	d := loadOutcomes(t)
	seen := map[string]bool{}
	for _, c := range d.Cases {
		if c.Expect.Execution == "unchecked" {
			seen[c.Expect.Cause] = true
		}
	}
	for _, r := range verifier.Reasons() {
		for _, chk := range r.Checks {
			// policy_private comes from a private decision record, not from a
			// source.
			if chk == "execution" && r.Reason != verifier.ReasonTimeout && r.Reason != verifier.ReasonNoChecker &&
				r.Reason != verifier.ReasonBlocked && r.Reason != verifier.ReasonPolicyPrivate {
				assert.Truef(t, seen[string(r.Reason)], "reason %s has no outcome case", r.Reason)
			}
		}
	}
}
