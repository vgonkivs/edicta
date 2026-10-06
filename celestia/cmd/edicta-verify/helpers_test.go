package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	cmtversion "github.com/cometbft/cometbft/proto/tendermint/version"
	core "github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/dacommit/blobv1"
	"github.com/vgonkivs/edicta/test/gatefix"
	"github.com/vgonkivs/edicta/verifier"
)

const (
	anchorHeight = uint64(4200000)
	checkpointH  = anchorHeight + 10
	blockTime    = uint64(1790999950)
	authorizedAt = uint64(1791000060)
)

func filler(tag string, h uint64) []byte {
	s := sha256.Sum256([]byte(tag + string(rune(h%251))))
	return s[:]
}

func mkHeader(h uint64, prev []byte, app string) core.Header {
	return core.Header{
		Version:            cmtversion.Consensus{Block: 11, App: 6},
		ChainID:            "test-1",
		Height:             int64(h),
		Time:               time.Unix(1_790_000_000+int64(h%100000), 0).UTC(),
		LastBlockID:        core.BlockID{Hash: prev, PartSetHeader: core.PartSetHeader{Total: 1, Hash: filler("psh", h)}},
		DataHash:           filler("data", h),
		ValidatorsHash:     filler("vals", 0),
		NextValidatorsHash: filler("vals", 0),
		ConsensusHash:      filler("cons", 0),
		AppHash:            filler(app, h),
		ProposerAddress:    filler("prop", 0)[:20],
	}
}

func encodeHeader(t testing.TB, h core.Header) []byte {
	t.Helper()
	p := h.ToProto()
	b, err := p.Marshal()
	require.NoError(t, err)
	return b
}

type chain struct{ hdrs map[uint64]core.Header }

func buildChain(from, to uint64) *chain {
	c := &chain{hdrs: map[uint64]core.Header{}}
	prev := filler("genesis", from)
	for h := from; h <= to; h++ {
		hd := mkHeader(h, prev, "app")
		c.hdrs[h] = hd
		prev = hd.Hash()
	}
	return c
}

func (c *chain) hash(h uint64) []byte { hd := c.hdrs[h]; return hd.Hash() }

// trustedFile writes the trusted header file: the checkpoint and the headers
// between it and the needed height.
func (c *chain) trustedFile(t testing.TB, cp uint64, mod func(headers [][]byte)) string {
	t.Helper()
	var bundled [][]byte
	for h := anchorHeight; h < cp; h++ {
		bundled = append(bundled, encodeHeader(t, c.hdrs[h]))
	}
	if mod != nil {
		mod(bundled)
	}
	var hs []string
	for _, b := range bundled {
		hs = append(hs, hex.EncodeToString(b))
	}
	b, err := json.Marshal(map[string]any{
		"height":  cp,
		"hash":    hex.EncodeToString(c.hash(cp)),
		"header":  hex.EncodeToString(encodeHeader(t, c.hdrs[cp])),
		"headers": hs,
	})
	require.NoError(t, err)
	p := filepath.Join(t.TempDir(), "trusted.json")
	require.NoError(t, os.WriteFile(p, b, 0o600))
	return p
}

type acceptAll struct{}

func (acceptAll) Check(commitment.PayloadRef, []byte) error { return nil }

// fakeAnchors is the da = 2 anchor verifier: the real one needs a node.
type fakeAnchors struct{ c *chain }

func (f fakeAnchors) VerifyAnchor(ref commitment.PayloadRef, ev *archive.EvidenceRecord) (verifier.AnchorFacts, error) {
	if !bytes.HasPrefix(ev.Header, []byte("hdr:")) {
		return verifier.AnchorFacts{}, os.ErrInvalid
	}
	return verifier.AnchorFacts{
		BlockTime: blockTime, RetentionStart: blockTime,
		HeaderHashes: map[uint64][]byte{ev.Height: f.c.hash(ev.Height)},
	}, nil
}

type scenario struct {
	archiveDir string
	hash       commitment.Hash
	gateKey    string
	chain      *chain
}

type scenarioOpts struct {
	tamperBlob bool
	pending    bool
}

func gatePubHex(t testing.TB) string {
	return hex.EncodeToString(gatefix.Key(t, "gate1").Public().(ed25519.PublicKey))
}

func newScenario(t *testing.T, o scenarioOpts) *scenario {
	t.Helper()
	c := gatefix.Template(t)
	env, h := gatefix.Sign(t, "agent1", c)
	blob := gatefix.Blob(t)
	cm := map[commitment.DA]gate.DACommitter{commitment.DACelestiaBlob: blobv1.New()}
	if o.tamperBlob {
		cm = map[commitment.DA]gate.DACommitter{commitment.DACelestiaBlob: acceptAll{}}
		blob = append([]byte(nil), blob...)
		blob[len(blob)-1] ^= 1
	}
	dir := t.TempDir()
	s, err := fsarchive.Open(dir, cm)
	require.NoError(t, err)
	ctx := context.Background()
	for _, r := range []archive.Record{
		&archive.PayloadRecord{DA: commitment.DACelestiaBlob, Commitment: c.PayloadRef.Commitment, Namespace: c.PayloadRef.Namespace, Signer: c.PayloadRef.Signer, Blob: blob, IntentHeight: 1},
		&archive.EvidenceRecord{DA: commitment.DACelestiaBlob, Commitment: c.PayloadRef.Commitment, Namespace: c.PayloadRef.Namespace, Height: anchorHeight, Header: []byte("hdr:4200000"), BlobProof: []byte("proof")},
		&archive.DecisionRecord{Envelope: env, Action: gatefix.Action(t)},
	} {
		_, err := s.Put(ctx, r)
		require.NoError(t, err)
	}
	if !o.pending {
		a := commitment.Authorization{CommitmentHash: h[:], ActionHash: c.Action.Hash, GateID: gatefix.GateID, Expires: authorizedAt + 300, Path: commitment.PathDA}
		canon, err := commitment.EncodeAuthorization(&a)
		require.NoError(t, err)
		ah := commitment.HashAuthorization(canon)
		sa, err := commitment.EncodeSignedAuthorization(&commitment.SignedAuthorization{
			Authorization: a,
			Signature:     ed25519.Sign(gatefix.Key(t, "gate1"), commitment.AuthorizationSigningMessage(ah)),
		})
		require.NoError(t, err)
		_, err = s.Put(ctx, &archive.AuthorizationRecord{
			SignedAuthorization: sa, AuthorizedAt: authorizedAt,
			K2: &archive.K2Inputs{DA: commitment.DACelestiaBlob, CheckedAt: authorizedAt, BlockTime: blockTime, BlobRetentionS: 14400},
		})
		require.NoError(t, err)
	}
	ch := buildChain(anchorHeight-5, checkpointH)
	prev := newAnchors
	newAnchors = func() map[commitment.DA]verifier.AnchorVerifier {
		return map[commitment.DA]verifier.AnchorVerifier{commitment.DACelestiaBlob: fakeAnchors{ch}}
	}
	t.Cleanup(func() { newAnchors = prev })
	return &scenario{archiveDir: dir, hash: h, gateKey: gatePubHex(t), chain: ch}
}

func (s *scenario) args(cmd string, extra ...string) []string {
	a := []string{cmd, "--archive", s.archiveDir, "--gate-key", s.gateKey}
	a = append(a, extra...)
	return append(a, hex.EncodeToString(s.hash[:]))
}

func exec(t *testing.T, args []string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := run(args, &out)
	return code, out.String()
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }

func writeFile(path, s string) error { return os.WriteFile(path, []byte(s), 0o600) }
