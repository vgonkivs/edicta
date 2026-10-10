package wire

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cosmos/cosmos-sdk/crypto/keyring"

	"github.com/vgonkivs/edicta/celestia/edictad"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/secret"
)

// Seams for tests; the defaults use the real keyring signer and Fibre client.
var (
	newAnchorSignerFn  = node.NewAnchorSigner
	newFibreUploaderFn = node.NewFibreUploader
)

// recorderFast builds the fast Recorder's anchor signer and, for da = fibre,
// its uploader, both on the Recorder's own key. The uploader is dialled with
// the consensus endpoint's settings at recorder.fast_upload_addr, which the
// configuration requires to be that same endpoint. The caller hands the
// uploader to edictad.Start, which closes it.
func recorderFast(ctx context.Context, cfg edictad.Config, cons node.Consensus, log *slog.Logger) (*edictad.RecorderFastDeps, error) {
	kr, err := openRecorderKeyring(cfg, log)
	if err != nil {
		return nil, err
	}
	network, err := cons.Network(ctx)
	if err != nil {
		return nil, fmt.Errorf("consensus node: %w", err)
	}
	signer, err := newAnchorSignerFn(kr, cfg.Recorder.KeyName, network)
	if err != nil {
		return nil, fmt.Errorf("anchor signer: %w", err)
	}
	fd := &edictad.RecorderFastDeps{Signer: signer}
	if cfg.Network.DA != edictad.DAConfigFibre {
		return fd, nil
	}
	_, g, err := endpointConfigs(cfg)
	if err != nil {
		return nil, err
	}
	g.Addr = cfg.Recorder.FastUploadAddr
	up, err := newFibreUploaderFn(ctx, g, kr, cfg.Recorder.KeyName)
	if err != nil {
		return nil, fmt.Errorf("fibre uploader: %w", err)
	}
	fd.Uploader = up
	return fd, nil
}

// openRecorderKeyring opens the Recorder's keyring; the passphrase is wiped
// once the keyring has it.
func openRecorderKeyring(cfg edictad.Config, log *slog.Logger) (keyring.Keyring, error) {
	pass, err := secret.FromFile(cfg.Recorder.PassphraseFile)
	if err != nil {
		return nil, fmt.Errorf("passphrase file: %w", err)
	}
	pb := pass.Reveal()
	kr, err := openKeyringFn(node.KeyringConfig{
		Dir: cfg.Recorder.KeyringDir, Name: cfg.Recorder.KeyName, Backend: cfg.Recorder.KeyringBackend,
		AllowTest: cfg.Recorder.AllowTestKeyring, Passphrase: pb, Logger: log,
	})
	clear(pb)
	pass.Zero()
	return kr, err
}
