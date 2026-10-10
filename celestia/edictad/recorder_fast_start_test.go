package edictad_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"sync/atomic"
	"testing"
	"time"

	"github.com/celestiaorg/celestia-app/v10/app"
	"github.com/celestiaorg/celestia-app/v10/app/encoding"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/cosmos/cosmos-sdk/types/bech32"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/celestia/edictad"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/test/gatefix"
)

// keyringSigner is the real anchor signer on an in-memory key.
func keyringSigner(t *testing.T, chainID string) (node.AnchorSigner, []byte) {
	t.Helper()
	kr := keyring.NewInMemory(encoding.MakeConfig(app.ModuleEncodingRegisters...).Codec)
	_, _, err := kr.NewMnemonic("recorder", keyring.English, "m/44'/118'/0'/0/0", keyring.DefaultBIP39Passphrase, hd.Secp256k1)
	require.NoError(t, err)
	s, err := node.NewAnchorSigner(kr, "recorder", chainID)
	require.NoError(t, err)
	addr, err := s.Address(bg)
	require.NoError(t, err)
	return s, addr
}

// A publish through the daemon's fast Recorder returns a pending reference,
// the gate authorizes a decision on it in fast mode, and once the anchor lands
// the Recorder's confirmation loop archives the evidence at its height.
func TestRecorderFastPublishAuthorizeConfirm(t *testing.T) {
	p := newPolicyEnv(t)
	p.mandate.FastModeMaxDelay = fastDelay
	p.file = p.sign(p.principal, p.mandate)
	signer, addr := keyringSigner(t, "testchain-7")
	bech, err := bech32.ConvertAndEncode("celestia", addr)
	require.NoError(t, err)
	p.cons.Accounts[bech] = node.AccountInfo{Number: 7, Sequence: 3}

	// h0 is a head made before the decision is issued.
	head, err := p.chain.Head(bg)
	require.NoError(t, err)
	h0 := head.Height + 1
	hd0 := blockAt(h0, 8)
	hd0.Time = t0.Add(-60 * time.Second)
	p.chain.AddHeader(hd0)
	p.cons.SetHeight(h0)

	p.deps.Archive = p.real
	p.deps.RecorderFast = &edictad.RecorderFastDeps{Signer: signer}
	p.startPolicy(gateFastFor(), recFast())

	blob := gatefix.Blob(t)
	pub, err := p.client("").Publish(bg, blob)
	require.NoError(t, err)
	require.True(t, pub.Ref.Pending(), "fast mode returns a pending reference")
	assert.Equal(t, h0, pub.Ref.Height)
	assert.Equal(t, addr, pub.Ref.Signer, "the blob is signed by the Recorder's own account")
	assert.Equal(t, nsBytes, pub.Ref.Namespace)
	assert.EqualValues(t, hd0.Time.Unix(), pub.BlockTime)

	intent, err := p.real.Intent(bg, commitment.DACelestiaBlob, pub.Ref.Commitment, h0)
	require.NoError(t, err, "the intent is archived before Publish returns")
	_, err = p.real.Evidence(bg, commitment.DACelestiaBlob, pub.Ref.Commitment)
	require.ErrorIs(t, err, archive.ErrNotFound, "nothing has landed yet")

	base := *p.base
	base.PayloadRef = pub.Ref
	p.base = &base
	d := p.send(1, 1_000_000)
	st, body := p.authorizeOn("/v1/authorize", d)
	require.Equal(t, 200, st, "%q", body)
	auth, err := p.real.Authorization(bg, d.hash)
	require.NoError(t, err)
	sa, _, err := commitment.DecodeSignedAuthorization(auth.SignedAuthorization)
	require.NoError(t, err)
	assert.EqualValues(t, commitment.ModeFast, sa.Authorization.Mode)

	h := h0 + 1
	hdH := blockAt(h, 8)
	hdH.Time = t0
	p.chain.AddHeader(hdH)
	p.chain.AddBlob(h, node.Blob{Namespace: bytes.Clone(nsBytes), Data: bytes.Clone(blob), ShareVersion: 1,
		Signer: bytes.Clone(addr), Commitment: bytes.Clone(pub.Ref.Commitment)}, rootProof{root: hdH.DataRoot})
	p.cons.SetTx(sha256.Sum256(intent.Tx), node.TxStatus{Found: true, Height: h})
	p.cons.SetHeight(h)

	var ev *archive.EvidenceRecord
	require.Eventually(t, func() bool {
		ev, err = p.real.Evidence(bg, commitment.DACelestiaBlob, pub.Ref.Commitment)
		return err == nil
	}, 20*time.Second, 50*time.Millisecond, "the confirmation loop archives the evidence")
	assert.Equal(t, h, ev.Height, "the evidence is at the anchor height, not at h0")
	assert.Equal(t, pub.Ref.Commitment, ev.Commitment)
}

// Without the anchor signer the daemon refuses to start, before any listener.
func TestRecorderFastStartNeedsTheAnchorSigner(t *testing.T) {
	p := newPolicyEnv(t)
	p.mandate.FastModeMaxDelay = fastDelay
	p.file = p.sign(p.principal, p.mandate)
	p.deps.Archive = p.real
	_, err := edictad.Start(bg, p.cfg(p.edits(gateFastFor(), recFast())...), p.deps)
	require.ErrorIs(t, err, edictad.ErrConfig)
	assert.Contains(t, err.Error(), "recorder.fast needs an anchor signer")
	assert.Zero(t, p.listens)
}

type fixedSigner struct{ addr []byte }

func (s fixedSigner) Address(context.Context) ([]byte, error) { return bytes.Clone(s.addr), nil }
func (fixedSigner) SignPFB(context.Context, []byte, []byte, node.TxParams) ([]byte, error) {
	return nil, node.ErrUnsupported
}
func (fixedSigner) SignPFF(context.Context, []byte, node.TxParams) ([]byte, error) {
	return nil, node.ErrUnsupported
}

type fakeUploader struct {
	log    *eventLog
	closes atomic.Int32
}

func (u *fakeUploader) Upload(context.Context, []byte, []byte) (node.FibreUpload, error) {
	return node.FibreUpload{}, errSeam
}
func (u *fakeUploader) Endpoint() string { return "grpc.invalid:9090" }
func (u *fakeUploader) Close(context.Context) error {
	u.closes.Add(1)
	u.log.add("uploader.close")
	return nil
}

func fibreFastEnv(t *testing.T) (*policyEnv, *fibreRecFakes, *fakeUploader) {
	t.Helper()
	e, _, rf := newFibreRecEnv(t)
	p := mandateFor(t, e)
	up := &fakeUploader{log: rf.log}
	p.deps.RecorderFast = &edictad.RecorderFastDeps{Signer: fixedSigner{recAddr}, Uploader: up}
	return p, rf, up
}

func (p *policyEnv) fibreFastEdits() [][2]string {
	return p.edits(fibreRecEdits(gateFastFor(), recFast(fibreFastKeys(maxUploadCost(p.t))...))...)
}

func TestRecorderFastFibreIsBuiltWithTheFastDeps(t *testing.T) {
	p, rf, up := fibreFastEnv(t)
	p.start(p.fibreFastEdits()...)

	cfg, d := rf.cfg.Load(), rf.deps.Load()
	require.NotNil(t, d.Fast)
	assert.Equal(t, fixedSigner{recAddr}, d.Fast.Signer)
	assert.Same(t, up, d.Fast.Uploader)
	assert.Equal(t, p.cons, d.Fast.Node, "anchor txs go through the operator's own consensus node")
	assert.Equal(t, 5+maxUploadCost(t), cfg.EscrowMarginUtia)
	assert.NotEmpty(t, p.logLines("recorder fast mode on", "escrow_headroom_utia"))

	require.NoError(t, p.srv.Shutdown(bg))
	assert.Equal(t, []string{"recorder.close", "uploader.close", "signing.close"}, rf.log.list(),
		"the uploader closes after the Recorder, before the signing client")
	assert.EqualValues(t, 1, up.closes.Load())
}

func TestRecorderFastFibreStartRefusals(t *testing.T) {
	t.Run("no uploader", func(t *testing.T) {
		p, rf, _ := fibreFastEnv(t)
		p.deps.RecorderFast.Uploader = nil
		_, err := edictad.Start(bg, p.cfg(p.fibreFastEdits()...), p.deps)
		require.ErrorIs(t, err, edictad.ErrConfig)
		assert.Contains(t, err.Error(), "needs an uploader")
		assert.Zero(t, p.listens)
		assert.Zero(t, rf.builds.Load())
		assert.EqualValues(t, 1, rf.closer.closes.Load(), "the signing client is closed")
	})
	t.Run("anchor signer is another account", func(t *testing.T) {
		p, rf, up := fibreFastEnv(t)
		p.deps.RecorderFast.Signer = fixedSigner{bytes.Repeat([]byte{1}, 20)}
		_, err := edictad.Start(bg, p.cfg(p.fibreFastEdits()...), p.deps)
		require.ErrorIs(t, err, edictad.ErrConfig)
		assert.Contains(t, err.Error(), "not the account of the fibre submitter")
		assert.Zero(t, p.listens)
		assert.EqualValues(t, 1, up.closes.Load(), "the uploader is closed once")
		assert.EqualValues(t, 1, rf.closer.closes.Load(), "the signing client is closed once")
		assert.Zero(t, rf.builds.Load(), "the Recorder, and with it the boot recovery, is never started")
		assert.Equal(t, []string{"uploader.close", "signing.close"}, rf.log.list())
		p.registryReopens()
	})
	t.Run("refused before the build", func(t *testing.T) {
		p, _, up := fibreFastEnv(t)
		cfg := p.cfg(p.fibreFastEdits()...)
		cfg.Recorder.FastDedicatedAccount = false
		_, err := edictad.Start(bg, cfg, p.deps)
		require.ErrorIs(t, err, edictad.ErrConfig)
		assert.EqualValues(t, 1, up.closes.Load(), "Start owns the uploader even when the configuration is refused")
	})
}
