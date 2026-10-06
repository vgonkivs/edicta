package verifier_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/verifier"
)

func replay(t *testing.T, r *rig) verifier.ReplayReport {
	t.Helper()
	rr, err := r.verifier(t).Replay(context.Background(), r.p.hash)
	require.NoError(t, err)
	return rr
}

func TestReplayReproducesThePath(t *testing.T) {
	tests := []struct {
		name      string
		path      commitment.PayloadPath
		blockTime uint64
		route     commitment.PayloadPath
		within    bool
		ok        bool
	}{
		{"window holds, gate used the DA path", commitment.PathDA, blockTime, commitment.PathDA, true, true},
		{"window holds, gate fell back to the archive", commitment.PathArchive, blockTime, commitment.PathDA, true, true},
		// valid_until + margin = start + r + 1
		{"window fails, gate used the archive", commitment.PathArchive, 1791000900 + 600 - 14400 - 1, commitment.PathArchive, false, true},
		{"window fails, gate claims the DA path", commitment.PathDA, 1791000900 + 600 - 14400 - 1, commitment.PathArchive, false, false},
		{"window holds at the exact limit", commitment.PathDA, 1791000900 + 600 - 14400, commitment.PathDA, true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newParts(t)
			p.k2.BlockTime = tc.blockTime
			p.auth = signAuth(t, gateKey(t), p.hash, p.c, tc.path, authExpires)
			r := newRig(t, p)
			r.anchor.blockTime = tc.blockTime

			rr := replay(t, r)
			if tc.ok {
				assert.Equal(t, verifier.VerdictValid, rr.Report.Verdict)
			} else {
				assert.Equal(t, verifier.VerdictInvalid, rr.Report.Verdict)
			}
			k := rr.K2
			require.True(t, k.Replayable)
			assert.Equal(t, uint64(14400), k.R)
			assert.Equal(t, tc.blockTime, k.Start)
			assert.Equal(t, uint64(600), k.Margin)
			assert.Equal(t, tc.within, k.Within)
			assert.Equal(t, tc.route, k.Route)
			assert.Equal(t, tc.path, k.AuthorizedPath)
			assert.Equal(t, tc.ok, k.Consistent)
			if !tc.ok {
				require.ErrorIs(t, k.Err, verifier.ErrGateInconsistent)
			} else {
				assert.NoError(t, k.Err)
			}
		})
	}
}

func TestReplayWithoutK2InputsIsNotReplayable(t *testing.T) {
	p := newParts(t)
	p.k2 = nil
	rr := replay(t, newRig(t, p))
	assert.False(t, rr.K2.Replayable)
	assert.Equal(t, verifier.VerdictValid, rr.Report.Verdict, "the missing inputs do not invalidate the decision")
}

func TestReplayInheritsVerifyFailures(t *testing.T) {
	p := newParts(t)
	p.action[0] ^= 1
	rr := replay(t, newRig(t, p))
	assert.Equal(t, verifier.VerdictInvalid, rr.Report.Verdict)
	failed(t, rr.Report, verifier.CheckAction)
	assert.False(t, rr.K2.Replayable, "no path is replayed for a decision that does not verify")
}

func TestReplayOfPendingDecision(t *testing.T) {
	p := newParts(t)
	p.auth, p.k2 = nil, nil
	rr := replay(t, newRig(t, p))
	assert.Equal(t, verifier.VerdictNotAuthorized, rr.Report.Verdict)
	assert.False(t, rr.Report.AuthorizationVerified)
	assert.False(t, rr.K2.Replayable)
}

func TestReplayDifferentBlockTimeInArchiveAndEvidence(t *testing.T) {
	p := newParts(t)
	r := newRig(t, p)
	r.anchor.blockTime = blockTime + 1
	rr := replay(t, r)
	require.True(t, rr.K2.Replayable)
	assert.False(t, rr.K2.Consistent, "the archived T_H differs from the verified one")
	require.ErrorIs(t, rr.K2.Err, verifier.ErrGateInconsistent)
}
