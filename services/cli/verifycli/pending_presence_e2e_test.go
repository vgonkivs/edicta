package verifycli

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/engine/archive"
	"github.com/vgonkivs/edicta/engine/archive/fsarchive"
	"github.com/vgonkivs/edicta/engine/commitment"
	"github.com/vgonkivs/edicta/plugins/celestia/celestiatest/fibrefix"
	"github.com/vgonkivs/edicta/test/gatefix"
)

// pendingLive is a fast-mode decision whose reference is pending at the
// promise height of the live PayForFibre, with that anchor archived as
// evidence inside the window.
type pendingLive struct {
	live *fibrefix.Live
	dir  string
	hash commitment.Hash
	gate string
	d    uint64
}

func newPendingLive(t *testing.T, window uint64) *pendingLive {
	t.Helper()
	l := fibrefix.LoadLive(t)
	h0 := l.PromiseHeight
	require.Greater(t, l.Height, h0)
	blockTime := uint64(l.Header.Time.Unix())
	issued := blockTime - 10

	c := gatefix.Clone(gatefix.FibreTemplate(t))
	c.PayloadRef = l.Ref
	c.PayloadRef.Height, c.PayloadRef.Anchor = h0, commitment.AnchorPending
	sum := sha256.Sum256(l.Payload)
	c.CiphertextHash, c.PayloadSize = sum[:], uint64(len(l.Payload))
	c = gatefix.Times(c, issued, issued+900)
	env, h := gatefix.Sign(t, "agent1", c)

	d := h0 + window
	authAt := blockTime + 20
	a := commitment.Authorization{Version: commitment.Version, CommitmentHash: h[:], ActionHash: c.Action.Hash, GateID: gatefix.GateID,
		Expires: authAt + 300, Path: commitment.PathArchive, Mode: commitment.ModeFast, AnchorDeadline: d}
	canon, err := commitment.EncodeAuthorization(&a)
	require.NoError(t, err)
	gk := gatefix.Key(t, "gate1")
	sa, err := commitment.EncodeSignedAuthorization(&commitment.SignedAuthorization{Authorization: a,
		Signature: ed25519.Sign(gk, commitment.AuthorizationSigningMessage(commitment.HashAuthorization(canon)))})
	require.NoError(t, err)

	dir := t.TempDir()
	s, err := fsarchive.Open(dir, fibrefix.Committers(t))
	require.NoError(t, err)
	for _, r := range []archive.Record{
		&archive.PayloadRecord{DA: commitment.DAFibre, Commitment: l.Ref.Commitment, Blob: l.Payload, IntentHeight: 1},
		l.Evidence(t),
		&archive.DecisionRecord{Envelope: env, Form: archive.FormPublic, Action: gatefix.Action(t), ActionSalt: gatefix.Salt(t)},
		&archive.AuthorizationRecord{SignedAuthorization: sa, AuthorizedAt: authAt},
	} {
		_, err := s.Put(context.Background(), r)
		require.NoError(t, err)
	}
	return &pendingLive{live: l, dir: dir, hash: h, gate: hex.EncodeToString(gk.Public().(ed25519.PublicKey)), d: d}
}

// trustedAt writes a trusted header file whose checkpoint is cp, with the
// headers from the promise height up to it.
func (p *pendingLive) trustedAt(t *testing.T, cp uint64) string {
	t.Helper()
	l := p.live
	var bundled []string
	for h := l.PromiseHeight; h < cp; h++ {
		b, ok := l.Headers[h]
		require.True(t, ok, "no live header at %d", h)
		bundled = append(bundled, hex.EncodeToString(b))
	}
	hd, ok := l.Headers[cp]
	require.True(t, ok, "no live header at %d", cp)
	b, err := json.Marshal(map[string]any{"height": cp, "hash": hex.EncodeToString(l.HeaderHashes[cp]),
		"header": hex.EncodeToString(hd), "headers": bundled})
	require.NoError(t, err)
	f := filepath.Join(t.TempDir(), "trusted.json")
	require.NoError(t, os.WriteFile(f, b, 0o600))
	return f
}

func (p *pendingLive) run(t *testing.T, trusted string) (int, fastJSON) {
	t.Helper()
	return runFast(t, "verify", hex.EncodeToString(p.hash[:]), "--archive", p.dir, "--gate-key", p.gate, "--trusted", trusted)
}

// With in-window evidence at H, a trusted header file whose checkpoint is in
// [H, D) decides the anchor; below H it stays anchor_pending.
func TestVerifyPendingPresenceCheckpointInWindow(t *testing.T) {
	p := newPendingLive(t, 100)
	H := p.live.Height
	require.Less(t, H, p.d)

	t.Run("checkpoint at H passes", func(t *testing.T) {
		code, v := p.run(t, p.trustedAt(t, H))
		c := v.check("anchor")
		require.Equal(t, "pass", c.Status, "%+v", c)
		assert.Equal(t, "anchored", v.Publication)
		assert.Equal(t, "pass", v.check("header_trust").Status)
		assert.NotEqual(t, exitInvalid, code)
	})
	t.Run("checkpoint below H is anchor_pending", func(t *testing.T) {
		code, v := p.run(t, p.trustedAt(t, H-1))
		c := v.check("anchor")
		assert.Equal(t, "unchecked", c.Status)
		assert.Equal(t, "anchor_pending", c.Reason)
		assert.Contains(t, c.Error, "anchor height")
		assert.Equal(t, exitUnchecked, code)
		assert.NotEqual(t, "valid", v.Verdict)
	})
}
