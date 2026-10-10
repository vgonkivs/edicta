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
	ac := loadAbsenceCase(t, "window_three_heights_proven")
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
