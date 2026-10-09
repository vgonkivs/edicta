package fibrefix

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/fibre/fibrecommit"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/dacommit/blobv1"
	"github.com/vgonkivs/edicta/test/gatefix"
)

// Decision is a complete authorized da = 1 decision over the live PayForFibre,
// written to an archive directory.
type Decision struct {
	Hash       commitment.Hash
	Dir        string
	GateKeyHex string
	BlockTime  uint64
	Auth       uint64
}

// Committers are the DA checks of an archive holding da = 1 and da = 2.
func Committers(t testing.TB) map[commitment.DA]gate.DACommitter {
	t.Helper()
	fc, err := fibrecommit.New(fibrecommit.DefaultMaxDataSize)
	require.NoError(t, err)
	return map[commitment.DA]gate.DACommitter{commitment.DACelestiaBlob: blobv1.New(), commitment.DAFibre: fc}
}

// WriteDecision archives the decision, the payload, the given evidence and an
// authorization signed by the vector gate key. The times sit around the block
// time of the live header.
func (l *Live) WriteDecision(t testing.TB, ev *archive.EvidenceRecord) Decision {
	t.Helper()
	blockTime := uint64(l.Header.Time.Unix())
	issued := blockTime - 10

	c := gatefix.FibreTemplate(t)
	c = gatefix.WithAction(t, c, gatefix.ActionType, gatefix.Action(t))
	c.PayloadRef = l.Ref
	sum := sha256.Sum256(l.Payload)
	c.CiphertextHash = sum[:]
	c.PayloadSize = uint64(len(l.Payload))
	c = gatefix.Times(c, issued, issued+900)
	env, h := gatefix.Sign(t, "agent1", c)

	authAt := blockTime + 20
	a := commitment.Authorization{Version: commitment.Version, CommitmentHash: h[:], ActionHash: c.Action.Hash, GateID: gatefix.GateID, Expires: authAt + 300, Path: commitment.PathDA, Mode: commitment.ModeStrict}
	canon, err := commitment.EncodeAuthorization(&a)
	require.NoError(t, err)
	gateKey := gatefix.Key(t, "gate1")
	sa, err := commitment.EncodeSignedAuthorization(&commitment.SignedAuthorization{
		Authorization: a,
		Signature:     ed25519.Sign(gateKey, commitment.AuthorizationSigningMessage(commitment.HashAuthorization(canon))),
	})
	require.NoError(t, err)

	dir := t.TempDir()
	s, err := fsarchive.Open(dir, Committers(t))
	require.NoError(t, err)
	for _, r := range []archive.Record{
		&archive.PayloadRecord{DA: commitment.DAFibre, Commitment: l.Ref.Commitment, Blob: l.Payload, IntentHeight: 1},
		ev,
		&archive.DecisionRecord{Envelope: env, Form: archive.FormPublic, Action: gatefix.Action(t), ActionSalt: gatefix.Salt(t)},
		&archive.AuthorizationRecord{SignedAuthorization: sa, AuthorizedAt: authAt, K2: &archive.K2Inputs{
			DA: commitment.DAFibre, CheckedAt: authAt, BlockTime: blockTime,
			RetentionLatestS: 14400, RetentionAtHeightS: 14400, RetentionSource: archive.RetentionBoth,
			PromiseCreated: uint64(l.Created.Unix()),
		}},
	} {
		_, err := s.Put(context.Background(), r)
		require.NoError(t, err)
	}
	return Decision{Hash: h, Dir: dir, GateKeyHex: hex.EncodeToString(gateKey.Public().(ed25519.PublicKey)), BlockTime: blockTime, Auth: authAt}
}

// TrustedFile writes the trusted header file of the live case: the checkpoint
// at the anchor height and the headers from the promise height up to it.
func (l *Live) TrustedFile(t testing.TB, mod func(headers map[uint64][]byte)) string {
	t.Helper()
	hs := map[uint64][]byte{}
	for h := l.PromiseHeight; h < l.TrustedHeight; h++ {
		hs[h] = l.Headers[h]
	}
	if mod != nil {
		mod(hs)
	}
	var bundled []string
	for h := l.PromiseHeight; h < l.TrustedHeight; h++ {
		if b, ok := hs[h]; ok {
			bundled = append(bundled, hex.EncodeToString(b))
		}
	}
	b, err := json.Marshal(map[string]any{
		"height":  l.TrustedHeight,
		"hash":    hex.EncodeToString(l.HeaderHashes[l.TrustedHeight]),
		"header":  hex.EncodeToString(l.Headers[l.TrustedHeight]),
		"headers": bundled,
	})
	require.NoError(t, err)
	p := filepath.Join(t.TempDir(), "trusted.json")
	require.NoError(t, os.WriteFile(p, b, 0o600))
	return p
}
