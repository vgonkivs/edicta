package wire

import (
	"context"
	"errors"
	"testing"

	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/node"
)

type stubAnchorSigner struct{ node.AnchorSigner }

type stubUploader struct{ node.FibreUploader }

type fastSeams struct {
	signerKey, signerChain string
	upload                 *node.GRPCConfig
	uploadKey              string
	uploadErr              error
}

func stubFastSeams(t *testing.T, log *callLog) *fastSeams {
	t.Helper()
	s := &fastSeams{}
	os, ou := newAnchorSignerFn, newFibreUploaderFn
	t.Cleanup(func() { newAnchorSignerFn, newFibreUploaderFn = os, ou })
	newAnchorSignerFn = func(_ keyring.Keyring, keyName, chainID string) (node.AnchorSigner, error) {
		if log != nil {
			log.add("new anchor signer")
		}
		s.signerKey, s.signerChain = keyName, chainID
		return stubAnchorSigner{}, nil
	}
	newFibreUploaderFn = func(_ context.Context, g node.GRPCConfig, _ keyring.Keyring, keyName string) (node.FibreUploader, error) {
		s.upload, s.uploadKey = &g, keyName
		if s.uploadErr != nil {
			return nil, s.uploadErr
		}
		return stubUploader{}, nil
	}
	return s
}

// A celestia_blob fast Recorder signs its own anchor txs: no signing client
// is built on its account, and the anchor signer comes after the check.
func TestBlobFastAdaptersBuildOnlyTheAnchorSigner(t *testing.T) {
	var log callLog
	stubSeams(t, &log, nil)
	fs := stubFastSeams(t, &log)
	cfg := recorderCfg(t)
	cfg.Recorder.Fast = true

	deps, closeAll, err := Adapters(context.Background(), cfg, quiet)
	require.NoError(t, err)
	defer closeAll()
	assert.Nil(t, deps.Submitter, "no submitter on the anchor account")
	require.NotNil(t, deps.RecorderFast)
	assert.Equal(t, stubAnchorSigner{}, deps.RecorderFast.Signer)
	assert.Nil(t, deps.RecorderFast.Uploader)
	assert.Equal(t, "recorder", fs.signerKey)
	assert.Equal(t, "chain-1", fs.signerChain, "the chain id the consensus node reports")
	assert.Nil(t, fs.upload, "no uploader for celestia_blob")

	calls := log.calls()
	assert.Equal(t, -1, indexOf(calls, "new signing"), "calls: %v", calls)
	assert.Less(t, indexOf(calls, "check"), indexOf(calls, "new anchor signer"), "calls: %v", calls)
}

func TestBlobFastAdaptersRefuseAMissingKey(t *testing.T) {
	var log callLog
	stubSeams(t, &log, nil)
	stubFastSeams(t, &log)
	openKeyringFn = func(node.KeyringConfig) (keyring.Keyring, error) { return nil, errors.New("no keyring") }
	cfg := recorderCfg(t)
	cfg.Recorder.Fast = true

	_, closeAll, err := Adapters(context.Background(), cfg, quiet)
	require.Error(t, err)
	closeAll()
	calls := log.calls()
	assert.GreaterOrEqual(t, indexOf(calls, "close consensus"), 0, "what was opened is closed: %v", calls)
	assert.GreaterOrEqual(t, indexOf(calls, "close read-only"), 0, "what was opened is closed: %v", calls)
}

// The da = fibre uploader is dialled at recorder.fast_upload_addr with the
// consensus endpoint's settings, on the Recorder's key.
func TestFibreFastBuildsTheSignerAndTheUploader(t *testing.T) {
	stubFibreSigning(t)
	fs := stubFastSeams(t, nil)
	cfg := fibreRecorderCfg(t)
	cfg.Recorder.Fast = true
	cfg.Recorder.FastUploadAddr = consensusAddr

	fd, err := recorderFast(context.Background(), cfg, newRecConsensus(t), quiet)
	require.NoError(t, err)
	assert.Equal(t, stubAnchorSigner{}, fd.Signer)
	assert.Equal(t, stubUploader{}, fd.Uploader)
	assert.Equal(t, "mocha-5", fs.signerChain)
	assert.Equal(t, "recorder", fs.uploadKey)
	require.NotNil(t, fs.upload)
	assert.Equal(t, consensusAddr, fs.upload.Addr)
	assert.Equal(t, cfg.Network.ConsensusGRPC.TLS, fs.upload.TLS)
}

// A failure after the signing client exists closes it: edictad.Start, which
// would own it, is never reached.
func TestFibreFastFailureClosesTheSigningClient(t *testing.T) {
	var log callLog
	stubSeams(t, &log, nil)
	newConsensusFn = func(node.GRPCConfig) (consensusConn, error) {
		return closingRecCons{newRecConsensus(t), &log}, nil
	}
	stubFibreSeams(t)
	sig := stubFibreSigning(t)
	stubFibreCheck(t, nil)
	fs := stubFastSeams(t, nil)
	fs.uploadErr = errors.New("no uploader")
	cfg := fibreRecorderCfg(t)
	cfg.Recorder.Fast = true
	cfg.Recorder.FastUploadAddr = consensusAddr

	_, closeAll, err := Adapters(context.Background(), cfg, quiet)
	require.ErrorContains(t, err, "fibre uploader")
	closeAll()
	assert.EqualValues(t, 1, sig.closer.n.Load(), "the signing client is closed")
	assert.GreaterOrEqual(t, indexOf(log.calls(), "close consensus"), 0, "calls: %v", log.calls())
}

type closingRecCons struct {
	recConsensus
	log *callLog
}

func (c closingRecCons) Close() error { c.log.add("close consensus"); return nil }
