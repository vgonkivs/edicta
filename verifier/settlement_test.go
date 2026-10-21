// SPDX-License-Identifier: Apache-2.0

package verifier_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/test/gatefix"
	"github.com/vgonkivs/edicta/verifier"
)

// fakeSettlement records its input and answers with a fixed result.
type fakeSettlement struct {
	in     *verifier.SettlementInput
	result any
	err    error
}

func (f *fakeSettlement) CheckSettlement(_ context.Context, in verifier.SettlementInput) (any, error) {
	f.in = &in
	return f.result, f.err
}

func TestSettlementReportIsVerdictNeutral(t *testing.T) {
	p := newParts(t)
	receipt := validReceipt(t, p)

	base := newRig(t, p).verify(t, verifier.WithReceipt(receipt))
	require.Equal(t, verifier.VerdictValid, base.Verdict)
	assert.Nil(t, base.RailSettlement, "no report unless asked")

	for _, tc := range []struct {
		name   string
		result any
		err    error
	}{
		{"a violation", "violated", nil},
		{"a checker error", nil, errors.New("sources down")},
		{"a pass", "pass", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeSettlement{result: tc.result, err: tc.err}
			r := newRig(t, p)
			r.deps.Settlements = map[string]verifier.SettlementChecker{gatefix.ActionType: fake}
			rep := r.verify(t, verifier.WithReceipt(receipt), verifier.WithSettlement())

			assert.Equal(t, base.Verdict, rep.Verdict)
			assert.Equal(t, base.Checks, rep.Checks)
			assert.Equal(t, base.Warnings, rep.Warnings)
			require.NotNil(t, rep.RailSettlement)
			assert.Empty(t, rep.RailSettlement.Blocked)
			assert.Equal(t, tc.result, rep.RailSettlement.Result)
			assert.Equal(t, tc.err, rep.RailSettlement.Err)

			require.NotNil(t, fake.in)
			assert.Equal(t, p.hash, fake.in.CommitmentHash)
			assert.Equal(t, gatefix.ActionType, fake.in.ActionType)
			assert.Equal(t, p.action, fake.in.Action)
			assert.Equal(t, railRef, fake.in.RailRef)
			assert.Equal(t, uint64(authExpires), fake.in.Expires)
			assert.Equal(t, uint64(blockTime), fake.in.TRef)
		})
	}
}

func TestSettlementReportBlocked(t *testing.T) {
	t.Run("no receipt", func(t *testing.T) {
		p := newParts(t)
		fake := &fakeSettlement{}
		r := newRig(t, p)
		r.deps.Settlements = map[string]verifier.SettlementChecker{gatefix.ActionType: fake}
		rep := r.verify(t, verifier.WithSettlement())
		require.NotNil(t, rep.RailSettlement)
		assert.Equal(t, string(verifier.CheckReceipt), rep.RailSettlement.Blocked)
		assert.Nil(t, fake.in)
	})
	t.Run("receipt of another gate key", func(t *testing.T) {
		p := newParts(t)
		fake := &fakeSettlement{}
		r := newRig(t, p)
		r.deps.Settlements = map[string]verifier.SettlementChecker{gatefix.ActionType: fake}
		rep := r.verify(t, verifier.WithReceipt(signReceipt(t, gatefix.Key(t, "agent2"), p, nil)), verifier.WithSettlement())
		assert.Equal(t, string(verifier.CheckReceipt), rep.RailSettlement.Blocked)
		assert.Nil(t, fake.in)
	})
	t.Run("no checker for the type", func(t *testing.T) {
		p := newParts(t)
		rep := newRig(t, p).verify(t, verifier.WithReceipt(validReceipt(t, p)), verifier.WithSettlement())
		require.NotNil(t, rep.RailSettlement)
		assert.Equal(t, verifier.SettlementNoChecker, rep.RailSettlement.Blocked)
		assert.Equal(t, verifier.VerdictValid, rep.Verdict)
	})
	t.Run("not authorized", func(t *testing.T) {
		p := newParts(t)
		p.auth = nil
		fake := &fakeSettlement{}
		r := newRig(t, p)
		r.deps.Settlements = map[string]verifier.SettlementChecker{gatefix.ActionType: fake}
		rep := r.verify(t, verifier.WithSettlement())
		require.NotNil(t, rep.RailSettlement)
		assert.Equal(t, string(verifier.CheckAuthorization), rep.RailSettlement.Blocked)
		assert.Nil(t, fake.in)
	})
	t.Run("no decision", func(t *testing.T) {
		p := newParts(t)
		r := newRig(t, p)
		v := r.verifier(t)
		rep, err := v.Verify(context.Background(), commitment.Hash{1}, verifier.WithSettlement())
		require.NoError(t, err)
		require.NotNil(t, rep.RailSettlement)
		assert.Equal(t, string(verifier.CheckDecision), rep.RailSettlement.Blocked)
	})
}

func TestSettlementNilChecker(t *testing.T) {
	r := newRig(t, newParts(t))
	r.deps.Settlements = map[string]verifier.SettlementChecker{gatefix.ActionType: nil}
	_, err := verifier.New(r.deps)
	require.ErrorIs(t, err, verifier.ErrInvalidConfig)
}
