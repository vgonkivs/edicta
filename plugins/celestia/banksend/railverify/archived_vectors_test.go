package railverify_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/engine/archive"
	"github.com/vgonkivs/edicta/engine/verifier"
	"github.com/vgonkivs/edicta/plugins/celestia/banksend/railverify"
	"github.com/vgonkivs/edicta/test/execresultfix"
)

// mapTrust is header trust that reached the listed hashes: a height it does
// not list is above its checkpoint, another hash is not on its chain.
type mapTrust struct {
	t      testing.TB
	hashes map[uint64][]byte
	asked  []uint64
}

func newMapTrust(t testing.TB, trusted map[string]string) *mapTrust {
	m := &mapTrust{t: t, hashes: map[uint64][]byte{}}
	for h, hash := range trusted {
		m.hashes[execresultfix.Uint(t, h)] = execresultfix.Hex(t, hash)
	}
	return m
}

func (m *mapTrust) Trusted(_ context.Context, height uint64, hash []byte) (verifier.TrustResult, error) {
	m.asked = append(m.asked, height)
	want, ok := m.hashes[height]
	if !ok {
		return verifier.TrustResult{}, verifier.Reasonf(verifier.ReasonHeaderAboveCheckpoint, nil, "no trusted header at %d", height)
	}
	if !bytes.Equal(want, hash) {
		return verifier.TrustResult{}, verifier.Reasonf(verifier.ReasonHeaderNotLinking, []string{"headers"}, "header %d does not link", height)
	}
	return verifier.TrustResult{Checked: true, CrossCheck: verifier.CrossOff}, nil
}

// archivedOutcome runs a vector case the way the verifier does: strict
// decoding, then the XR rules.
func archivedOutcome(t *testing.T, c execresultfix.Case) (execresultfix.Outcome, error) {
	rec, err := archive.DecodeExecutionResult(execresultfix.Hex(t, c.CBORHex))
	if err != nil {
		return execresultfix.Outcome{Result: "set_aside", Rule: "decode", Reason: string(verifier.ReasonTxProofInvalid)}, err
	}
	f, err := railverify.CheckArchived(context.Background(), rec, c.Query.ChainID, c.Query.RailRefBytes(t), newMapTrust(t, c.Trusted))
	var sa *railverify.ArchivedSetAside
	if errors.As(err, &sa) {
		return execresultfix.Outcome{Result: "set_aside", Rule: sa.Rule, Reason: string(sa.Reason)}, err
	}
	require.NoError(t, err)
	outcome := verifier.OutcomeSuccess
	if f.Code != 0 {
		outcome = verifier.OutcomeFailure
	}
	return execresultfix.Outcome{Result: "pass", Rule: "none", Reason: "none", Facts: map[string]string{
		"height": strconv.FormatUint(f.Height, 10), "header_hash": hex.EncodeToString(f.HeaderHash),
		"tx_index": strconv.FormatUint(f.TxIndex, 10), "tx_hex": hex.EncodeToString(f.Tx),
		"inclusion": verifier.InclusionProven, "result": verifier.ResultProven,
		"code": strconv.FormatUint(uint64(f.Code), 10), "outcome": outcome,
	}}, nil
}

func TestArchivedResultVectors(t *testing.T) {
	f := execresultfix.Load(t)
	rules := map[string]bool{}
	for _, c := range f.Cases {
		t.Run(c.ID, func(t *testing.T) {
			got, err := archivedOutcome(t, c)
			assert.Equal(t, c.Expect, got, "%v", err)
			rules[got.Rule] = true
		})
	}
	for _, r := range []string{"XR1", "XR2", "XR3", "XR4", "XR5", "XR6", "XR7", "XR8", "decode", "none"} {
		assert.True(t, rules[r], "no case gives %s", r)
	}
}

// A set-aside record shows a bad record, never a bad execution.
func TestArchivedSetAsideIsUnchecked(t *testing.T) {
	f := execresultfix.Load(t)
	for _, c := range f.Cases {
		if c.Expect.Result != "set_aside" || c.Expect.Rule == "decode" {
			continue
		}
		_, err := archivedOutcome(t, c)
		require.ErrorIs(t, err, verifier.ErrExecutionUnchecked, c.ID)
		require.NotErrorIs(t, err, verifier.ErrExecutionViolation, c.ID)
	}
}

func TestArchivedRecordsPassTheSelfCheck(t *testing.T) {
	f := execresultfix.Load(t)
	for _, r := range f.Records {
		facts, err := railverify.SelfCheckArchived(r.Build(t))
		require.NoError(t, err, r.ID)
		assert.Equal(t, execresultfix.Uint(t, r.Input["height"]), facts.Height, r.ID)
	}
	// A forgery whose fabricated headers link passes it too: it has no
	// trust root.
	for _, m := range f.Migration {
		for _, raw := range m.Stored {
			rec, err := archive.DecodeExecutionResult(execresultfix.Hex(t, raw))
			require.NoError(t, err, m.ID)
			_, err = railverify.SelfCheckArchived(rec)
			require.NoError(t, err, m.ID)
		}
	}
}

func TestArchivedHeaderTrustOutcomes(t *testing.T) {
	f := execresultfix.Load(t)
	c := f.Cases[0]
	require.Equal(t, "pass", c.Expect.Result)
	rec, err := archive.DecodeExecutionResult(execresultfix.Hex(t, c.CBORHex))
	require.NoError(t, err)
	ref := c.Query.RailRefBytes(t)

	for name, tc := range map[string]struct {
		trust   verifier.HeaderTrust
		reason  verifier.Reason
		aside   bool
		timeout bool
	}{
		"disagreement ends the check":   {trust: errTrust{verifier.WithReason(verifier.ReasonHeaderDisagreement, []string{"x"}, errors.New("cross"))}, reason: verifier.ReasonHeaderDisagreement},
		"cross mismatch ends the check": {trust: resTrust{verifier.TrustResult{Checked: true, CrossCheck: verifier.CrossMismatch}}, reason: verifier.ReasonHeaderDisagreement},
		"not checked":                   {trust: resTrust{verifier.TrustResult{}}, reason: verifier.ReasonHeaderNotLinking, aside: true},
		"no trusted header":             {trust: errTrust{verifier.WithReason(verifier.ReasonNoTrustedHeader, nil, nil)}, reason: verifier.ReasonResultHeaderUnreachable, aside: true},
		"source unavailable":            {trust: errTrust{verifier.WithReason(verifier.ReasonHeaderSourceUnavailable, nil, nil)}, reason: verifier.ReasonHeaderNotLinking, aside: true},
		"untyped error":                 {trust: errTrust{errors.New("boom")}, reason: verifier.ReasonHeaderNotLinking, aside: true},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := railverify.CheckArchived(context.Background(), rec, c.Query.ChainID, ref, tc.trust)
			require.Error(t, err)
			var sa *railverify.ArchivedSetAside
			assert.Equal(t, tc.aside, errors.As(err, &sa))
			reason, _, ok := verifier.ReasonOf(err)
			if tc.aside {
				reason, ok = sa.Reason, true
				assert.Equal(t, railverify.RuleXR2, sa.Rule)
			}
			require.True(t, ok)
			assert.Equal(t, tc.reason, reason)
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = railverify.CheckArchived(ctx, rec, c.Query.ChainID, ref, resTrust{verifier.TrustResult{Checked: true}})
	reason, _, _ := verifier.ReasonOf(err)
	assert.Equal(t, verifier.ReasonTimeout, reason)

	_, err = railverify.CheckArchived(context.Background(), rec, c.Query.ChainID, ref, nil)
	require.Error(t, err)
}

type errTrust struct{ err error }

func (e errTrust) Trusted(context.Context, uint64, []byte) (verifier.TrustResult, error) {
	return verifier.TrustResult{}, e.err
}

type resTrust struct{ res verifier.TrustResult }

func (r resTrust) Trusted(context.Context, uint64, []byte) (verifier.TrustResult, error) {
	return r.res, nil
}

// Hostile bytes in any proof key never panic and never pass.
func TestArchivedHostileProofs(t *testing.T) {
	f := execresultfix.Load(t)
	c := f.Cases[0]
	base, err := archive.DecodeExecutionResult(execresultfix.Hex(t, c.CBORHex))
	require.NoError(t, err)
	trust := newMapTrust(t, c.Trusted)
	junk := [][]byte{{0x0a}, {0x0a, 0x05, 1, 2}, bytes.Repeat([]byte{0xff}, 64), {0x22, 0x02, 0x10, 0x01}}
	for i, j := range junk {
		for key := 9; key <= 12; key++ {
			rec := *base
			switch key {
			case 9:
				rec.TxProof = j
			case 10:
				rec.PFBProof = j
			case 11:
				rec.PFFProof = j
			case 12:
				rec.ClosingProof = j
			}
			_, err := railverify.CheckArchived(context.Background(), &rec, c.Query.ChainID, c.Query.RailRefBytes(t), trust)
			var sa *railverify.ArchivedSetAside
			require.True(t, errors.As(err, &sa), "junk %d key %d: %v", i, key, err)
		}
	}
}
