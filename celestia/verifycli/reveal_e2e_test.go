package verifycli

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/celestia/test/cometfake"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/policy"
	"github.com/vgonkivs/edicta/policy/privatebox"
)

// privatize turns the bank world's public decision record into the private
// form: the decision record without the action, the action sealed to an
// auditor in a kind 15 record, and the gate's reveal with the given salt,
// if any.
func privatize(t *testing.T, w *bankWorld, revealSalt []byte) {
	t.Helper()
	ctx := context.Background()
	dir := w.s.archiveDir
	ro, err := fsarchive.OpenReadOnly(dir, nil)
	require.NoError(t, err)
	dec, err := ro.Decision(ctx, w.s.hash)
	require.NoError(t, err)
	require.Equal(t, uint64(archive.FormPublic), dec.Form)
	sc, err := commitment.DecodeSigned(dec.Envelope)
	require.NoError(t, err)
	require.NoError(t, os.Remove(filepath.Join(dir, filepath.FromSlash(archive.HashPath(archive.KindDecision, w.s.hash)))))

	sk, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	pub := sk.PublicKey().Bytes()
	aud := policy.Auditor{Kid: policy.AuditorKid(pub), Pubkey: pub, Label: "auditor"}
	env, err := privatebox.Sealer{}.Seal(policy.PrivateAction, append(bytes.Clone(dec.ActionSalt), dec.Action...), []policy.Auditor{aud})
	require.NoError(t, err)

	cm, err := committers()
	require.NoError(t, err)
	s, err := fsarchive.Open(dir, cm)
	require.NoError(t, err)
	recs := []archive.Record{
		&archive.PrivateBlobRecord{PlaintextKind: policy.PrivateAction, Hash: bytes.Clone(sc.Commitment.Action.Hash), Envelope: env},
		&archive.DecisionRecord{Envelope: dec.Envelope, Form: archive.FormPrivate},
	}
	if revealSalt != nil {
		recs = append(recs, &archive.RevealRecord{SignedReceipt: w.s.receipt(t, w.ref), ActionSalt: revealSalt})
	}
	for _, r := range recs {
		_, err := s.Put(ctx, r)
		require.NoError(t, err)
	}
}

// The reveal path end to end: a private decision on the bank-send rail,
// checked without an auditor key, passes its action check through the gate's
// reveal and the action the real bank-send checker rebuilds from the
// executed transaction.
func TestRevealThroughTheRealBankSendChecker(t *testing.T) {
	ok := []cometfake.Result{{Code: 0, Data: []byte("r"), GasWanted: 10, GasUsed: 9}}
	args := func(w *bankWorld) []string {
		return []string{"verify", hexOf(w.s.hash[:]), "--archive", w.s.archiveDir, "--gate-key", w.s.gateKey,
			"--headers-rpc", w.headers.URL, "--checkpoint", w.s.explicitCheckpoint(),
			"--receipt", w.receipt, "--tx-rpc", w.headers.URL, "--check-execution", "--json"}
	}

	t.Run("the revealed salt gives the action hash", func(t *testing.T) {
		w := newProvenWorld(t, provenOpts{results: ok})
		ro, err := fsarchive.OpenReadOnly(w.s.archiveDir, nil)
		require.NoError(t, err)
		dec, err := ro.Decision(context.Background(), w.s.hash)
		require.NoError(t, err)
		privatize(t, w, dec.ActionSalt)

		code, out := exec(t, args(w))
		require.Equal(t, exitValid, code, out)
		rep := decodeReport(t, out)
		assert.Equal(t, "valid", rep["verdict"])
		assert.Equal(t, "pass", statusOf(t, rep, "action"))
		assert.Equal(t, "pass", statusOf(t, rep, "execution"))
	})
	t.Run("a wrong salt is a bad copy, never a pass", func(t *testing.T) {
		w := newProvenWorld(t, provenOpts{results: ok})
		privatize(t, w, bytes.Repeat([]byte{0x77}, commitment.ActionSaltSize))

		code, out := exec(t, args(w))
		assert.Equal(t, exitUnchecked, code, out)
		rep := decodeReport(t, out)
		assert.Equal(t, "unchecked", statusOf(t, rep, "action"))
		assert.Equal(t, "source_corrupt", checkOf(t, rep, "action")["reason"])
	})
	t.Run("without a reveal the action stays private", func(t *testing.T) {
		w := newProvenWorld(t, provenOpts{results: ok})
		privatize(t, w, nil)

		code, out := exec(t, args(w))
		assert.Equal(t, exitUnchecked, code, out)
		assert.Equal(t, "policy_private", checkOf(t, decodeReport(t, out), "action")["reason"])
	})
}
