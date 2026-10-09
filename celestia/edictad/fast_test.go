package edictad_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	blobtypes "github.com/celestiaorg/celestia-app/v10/x/blob/types"
	squaretx "github.com/celestiaorg/go-square/v4/tx"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/types/bech32"
	cosmostx "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/celestia/edictad"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/test/gatefix"
)

const fastDelay = 50

const anchorVerifierLine = `anchor_verifier = "self"`

// fastTable is a [gate.fast] table after the gate keys; lines replace the
// default body.
func (p *policyEnv) fastTable(lines ...string) [2]string {
	body := "enabled = true\nown_node = true\npending_namespaces = [\"" + hex.EncodeToString(p.base.PayloadRef.Namespace) + "\"]\n"
	if len(lines) > 0 {
		body = ""
		for _, l := range lines {
			body += l + "\n"
		}
	}
	return rep(anchorVerifierLine, anchorVerifierLine+"\n\n[gate.fast]\n"+body)
}

func (p *policyEnv) parseFast(extra ...[2]string) (edictad.Config, error) {
	return edictad.ParseConfig([]byte(p.tomlOf(p.edits(extra...)...)))
}

func TestFastConfigIsOffByDefault(t *testing.T) {
	p := newPolicyEnv(t)
	c, err := p.parseFast()
	require.NoError(t, err)
	assert.Equal(t, edictad.FastConfig{}, c.Gate.Fast)
}

func TestFastConfigDefaults(t *testing.T) {
	p := newPolicyEnv(t)
	c, err := p.parseFast(p.fastTable())
	require.NoError(t, err)
	f := c.Gate.Fast
	assert.True(t, f.Enabled)
	assert.Equal(t, edictad.IntentSourceArchive, f.IntentSource)
	assert.EqualValues(t, 100, f.FastWindowBlocks)
	assert.EqualValues(t, 10, f.MaxH0AgeBlocks)
	assert.EqualValues(t, 3, f.MinFastSlackBlocks)
	assert.EqualValues(t, 15, f.MinPromiseSlackSeconds)
	assert.Nil(t, f.RebroadcastIntent)
}

func TestFastConfigRefusals(t *testing.T) {
	p := newPolicyEnv(t)
	ns := `pending_namespaces = ["` + hex.EncodeToString(p.base.PayloadRef.Namespace) + `"]`
	archiveDir := `dir = "` + p.path("archive") + `"`
	for name, tc := range map[string]struct {
		edits   [][2]string
		noPol   bool
		message string
	}{
		"keys without enabled": {edits: [][2]string{p.fastTable("own_node = true")}, message: "need gate.fast.enabled"},
		"no archive": {edits: [][2]string{p.fastTable(), rep(archiveDir, `dir = ""`)},
			message: "gate.fast.enabled needs the archive"},
		"no mandate":     {edits: [][2]string{p.fastTable()}, noPol: true, message: "gate.fast.enabled needs a mandate"},
		"intent source":  {edits: [][2]string{p.fastTable("enabled = true", "own_node = true", ns, `intent_source = "chain"`)}, message: "gate.fast.intent_source"},
		"not own node":   {edits: [][2]string{p.fastTable("enabled = true", ns)}, message: "gate.fast.own_node"},
		"no namespaces":  {edits: [][2]string{p.fastTable("enabled = true", "own_node = true")}, message: "gate.fast.pending_namespaces is empty"},
		"bad namespace":  {edits: [][2]string{p.fastTable("enabled = true", "own_node = true", `pending_namespaces = ["00ff"]`)}, message: "gate.fast.pending_namespaces[0]"},
		"user namespace": {edits: [][2]string{p.fastTable("enabled = true", "own_node = true", `pending_namespaces = ["`+hex.EncodeToString(make([]byte, 29))+`"]`)}, message: "pending_namespaces"},
		"duplicate namespace": {edits: [][2]string{p.fastTable("enabled = true", "own_node = true",
			`pending_namespaces = ["`+hex.EncodeToString(p.base.PayloadRef.Namespace)+`", "`+hex.EncodeToString(p.base.PayloadRef.Namespace)+`"]`)},
			message: "pending_namespaces[1] is a duplicate"},
		"rebroadcast off with blob": {edits: [][2]string{p.fastTable("enabled = true", "own_node = true", ns, "rebroadcast_intent = false")},
			message: "gate.fast.rebroadcast_intent"},
		"window too large": {edits: [][2]string{p.fastTable("enabled = true", "own_node = true", ns, "fast_window_blocks = 1001")},
			message: "fast_window_blocks"},
		"age plus slack": {edits: [][2]string{p.fastTable("enabled = true", "own_node = true", ns, "fast_window_blocks = 10", "max_h0_age_blocks = 9", "min_fast_slack_blocks = 3")},
			message: "age_plus_slack"},
	} {
		t.Run(name, func(t *testing.T) {
			var err error
			if tc.noPol {
				_, err = edictad.ParseConfig([]byte(p.tomlOf(tc.edits...)))
			} else {
				_, err = p.parseFast(tc.edits...)
			}
			require.ErrorIs(t, err, edictad.ErrConfig)
			assert.Contains(t, err.Error(), tc.message)
		})
	}
}

// A store without the intent read side refuses the start before the
// listener: fast mode would answer every pending reference with an
// unavailable intent.
func TestFastStartRefusesAStoreWithoutIntents(t *testing.T) {
	p := newPolicyEnv(t)
	p.mandate.FastModeMaxDelay = fastDelay
	p.file = p.sign(p.principal, p.mandate)
	_, ok := any(p.fs).(archive.IntentReader)
	require.False(t, ok, "the fault store hides the intent reader")

	_, err := edictad.Start(bg, p.cfg(p.edits(p.fastTable())...), p.deps)
	require.ErrorIs(t, err, edictad.ErrConfig)
	assert.Contains(t, err.Error(), "serves anchor intents")
	assert.Zero(t, p.listens)
	assert.Empty(t, p.fs.puts, "nothing is archived")
}

// pfbTx is a signed-looking tx paying for the blob of ref.
func pfbTx(t *testing.T, ref commitment.PayloadRef, size int) []byte {
	t.Helper()
	signer, err := bech32.ConvertAndEncode("celestia", ref.Signer)
	require.NoError(t, err)
	msg := &blobtypes.MsgPayForBlobs{Signer: signer, Namespaces: [][]byte{ref.Namespace}, BlobSizes: []uint32{uint32(size)},
		ShareCommitments: [][]byte{ref.Commitment}, ShareVersions: []uint32{1}}
	v, err := msg.Marshal()
	require.NoError(t, err)
	body := cosmostx.TxBody{Messages: []*codectypes.Any{{TypeUrl: "/celestia.blob.v1.MsgPayForBlobs", Value: v}}}
	bb, err := body.Marshal()
	require.NoError(t, err)
	ab, err := (&cosmostx.AuthInfo{SignerInfos: []*cosmostx.SignerInfo{{Sequence: 1}}}).Marshal()
	require.NoError(t, err)
	out, err := (&cosmostx.TxRaw{BodyBytes: bb, AuthInfoBytes: ab, Signatures: [][]byte{make([]byte, 64)}}).Marshal()
	require.NoError(t, err)
	return out
}

// A pending celestia_blob decision gets a fast-mode Authorization through the
// daemon: the intent and the blob come from the archive, the real intent
// verifier reads the bridge headers and the real broadcaster sends the
// BlobTx through the consensus client.
func TestFastModeAuthorizesAPendingDecision(t *testing.T) {
	p := newPolicyEnv(t)
	p.mandate.FastModeMaxDelay = fastDelay
	p.file = p.sign(p.principal, p.mandate)
	pending := *p.base
	pending.PayloadRef.Anchor = commitment.AnchorPending
	p.base = &pending
	ref := pending.PayloadRef
	h0 := ref.Height

	blob := gatefix.Blob(t)
	tx := pfbTx(t, ref, len(blob))
	_, err := p.real.Put(bg, &archive.PayloadRecord{DA: ref.DA, Commitment: ref.Commitment, Namespace: ref.Namespace,
		Signer: ref.Signer, Blob: blob, IntentHeight: h0})
	require.NoError(t, err)
	_, err = p.real.Put(bg, &archive.AnchorIntentRecord{DA: ref.DA, Commitment: ref.Commitment, Namespace: ref.Namespace,
		RefHeight: h0, Tx: tx, Signer: ref.Signer, CreatedAt: uint64(t0.Unix()) - 900})
	require.NoError(t, err)
	p.deps.Archive = p.real

	p.startPolicy(p.fastTable())
	d := p.send(1, 1_000_000)
	st, body := p.authorizeOn("/v1/authorize", d)
	require.Equal(t, 200, st, "%q", body)

	rec, err := p.real.Authorization(bg, d.hash)
	require.NoError(t, err)
	sa, _, err := commitment.DecodeSignedAuthorization(rec.SignedAuthorization)
	require.NoError(t, err)
	assert.EqualValues(t, commitment.ModeFast, sa.Authorization.Mode)
	assert.Equal(t, h0+fastDelay, sa.Authorization.AnchorDeadline, "the mandate's delay is the smallest bound")

	// The fake records broadcasts without a reader lock: stop the daemon first.
	require.NoError(t, p.srv.Shutdown(bg))
	require.Len(t, p.cons.Sent, 1, "the intent is broadcast once")
	btx, isBlob, err := squaretx.UnmarshalBlobTx(p.cons.Sent[0])
	require.NoError(t, err)
	require.True(t, isBlob, "a da = 2 intent goes out as a BlobTx")
	assert.Equal(t, tx, btx.Tx, "the archived tx is sent unchanged")
	require.Len(t, btx.Blobs, 1)
	assert.True(t, bytes.Equal(blob, btx.Blobs[0].Data()), "the archived blob rides with the tx")
}

// Without the table a pending reference is refused as before.
func TestFastModeOffRefusesAPendingDecision(t *testing.T) {
	p := newPolicyEnv(t)
	pending := *p.base
	pending.PayloadRef.Anchor = commitment.AnchorPending
	p.base = &pending
	p.startPolicy()
	st, body := p.authorizeOn("/v1/authorize", p.send(1, 1_000_000))
	assert.NotEqual(t, 200, st)
	assert.True(t, hasCode(body, "ErrAnchorPending"), "body %q", body)
	require.NoError(t, p.srv.Shutdown(bg))
	assert.Empty(t, p.cons.Sent, "nothing is broadcast")
}
