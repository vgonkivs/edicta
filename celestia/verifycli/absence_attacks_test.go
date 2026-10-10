package verifycli

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
)

// A bridge that serves, at a height of the window, the parts of a proof from
// another height (one that shows the anchor present) gets nothing written:
// its header is not the trusted one, so the height stays not proven, and a
// later offline verify cannot be swayed by it.
func TestAbsenceCommandRefusesAProofFromAnotherHeight(t *testing.T) {
	ac := loadAbsentWindow(t)
	present := loadAbsenceCase(t, "fibre_present")
	at := ac.ref.Height + 1
	served := ac
	served.recs = map[uint64]*archive.AbsenceProofRecord{}
	for h, r := range ac.recs {
		served.recs[h] = r
	}
	forged := *present.recs[present.deadline]
	forged.Height = at
	served.recs[at] = &forged
	serveProofs(t, served)
	dir, h := ac.pendingArchive(t)
	ref := hex.EncodeToString(h[:])
	trusted := ac.trustedAt(t)

	code, out := exec(t, []string{"absence", ref, "--archive", dir, "--gate-key", gatePubHex(t), "--trusted", trusted,
		"--absence-source", "http://bridge.test:26658"})
	assert.Equal(t, codeUnchecked, code, out)
	assert.NotContains(t, out, "present")
	s, err := fsarchive.OpenReadOnly(dir, nil)
	require.NoError(t, err)
	_, err = s.Absence(context.Background(), ac.ref.DA, ac.ref.Commitment, at)
	require.ErrorIs(t, err, archive.ErrNotFound)

	code, v := runFast(t, "verify", ref, "--archive", dir, "--gate-key", gatePubHex(t), "--trusted", ac.trusted(t, true))
	assert.Equal(t, codeUnchecked, code)
	assert.Equal(t, "absence_unproven", v.check("anchor").Reason)
	assert.Equal(t, "unknown", v.Publication)
}

// An included anchor whose PFF ran with a non-zero result code published the
// payload inside the window. However the proofs reach the verifier, that
// height is never read as absence: the anchor is unchecked anchor_unpaid,
// never a fail, and no one is attributed.
func TestUnpaidCandidateInWindowIsNeverInvalid(t *testing.T) {
	ac := loadAbsenceCase(t, "window_three_heights_proven")
	gk := gatePubHex(t)
	for name, run := range map[string]func(t *testing.T) (int, fastJSON){
		"every height archived": func(t *testing.T) (int, fastJSON) {
			dir, h := ac.pendingArchive(t, ac.ref.Height, ac.ref.Height+1, ac.deadline)
			return runFast(t, "verify", hex.EncodeToString(h[:]), "--archive", dir, "--gate-key", gk, "--trusted", ac.trustedAt(t))
		},
		"a height not proven": func(t *testing.T) (int, fastJSON) {
			dir, h := ac.pendingArchive(t, ac.ref.Height, ac.deadline)
			return runFast(t, "verify", hex.EncodeToString(h[:]), "--archive", dir, "--gate-key", gk, "--trusted", ac.trusted(t, true))
		},
		"from an absence source": func(t *testing.T) (int, fastJSON) {
			serveProofs(t, ac)
			dir, h := ac.pendingArchive(t)
			return runFast(t, "verify", hex.EncodeToString(h[:]), "--archive", dir, "--gate-key", gk, "--trusted", ac.trustedAt(t),
				"--absence-source", "http://bridge.test:26658")
		},
		"after the absence command": func(t *testing.T) (int, fastJSON) {
			serveProofs(t, ac)
			dir, h := ac.pendingArchive(t)
			code, av, out := runAbsenceJSON(t, "absence", hex.EncodeToString(h[:]), "--archive", dir, "--gate-key", gk,
				"--trusted", ac.trustedAt(t), "--absence-source", "http://bridge.test:26658")
			require.Equal(t, codeValid, code, out)
			assert.Equal(t, "present_unpaid", av.Result)
			assert.Equal(t, ac.deadline, av.UnpaidHeight)
			return runFast(t, "verify", hex.EncodeToString(h[:]), "--archive", dir, "--gate-key", gk, "--trusted", ac.trustedAt(t))
		},
	} {
		t.Run(name, func(t *testing.T) {
			code, v := run(t)
			require.NotEqual(t, codeInvalid, code)
			assert.Equal(t, codeUnchecked, code)
			assert.Equal(t, "unchecked", v.Verdict)
			c := v.check("anchor")
			assert.Equal(t, "unchecked", c.Status, c.Error)
			assert.Equal(t, "anchor_unpaid", c.Reason)
			assert.Equal(t, ac.deadline, c.UnpaidHeight)
			assert.Equal(t, "unknown", v.Publication)
			assert.Empty(t, v.IntentSigner)
			require.NotNil(t, v.Absence)
			assert.Equal(t, "present_unpaid", v.Absence.Result)
			assert.Equal(t, ac.deadline, v.Absence.UnpaidHeight)
		})
	}
}
