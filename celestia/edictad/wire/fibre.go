package wire

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/cosmos/cosmos-sdk/crypto/keyring"

	"github.com/vgonkivs/edicta/celestia/edictad"
	"github.com/vgonkivs/edicta/celestia/gatechain"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/recorder"
	"github.com/vgonkivs/edicta/celestia/secret"
	"github.com/vgonkivs/edicta/fibre/fibrecommit"
)

// fibreBridge is the bridge client the da = 1 gate needs.
type fibreBridge interface {
	node.FibreBridgeReader
	Downloader() node.FibreDownloader
	DownloadRaw(ctx context.Context, id [33]byte, maxSize uint64) ([]byte, error)
	Close()
}

// fibreDirect is the download-only Fibre client.
type fibreDirect interface {
	node.FibreDownloader
	Close(ctx context.Context) error
}

// Seams for tests; the defaults dial the real endpoints.
var (
	newFibreBridgeFn = func(ctx context.Context, b node.BridgeConfig, lim node.BridgeLimits) (fibreBridge, error) {
		return node.NewFibreBridge(ctx, b, lim)
	}
	newFibreDirectFn = func(ctx context.Context, g node.GRPCConfig) (fibreDirect, error) {
		return node.NewFibreDirect(ctx, g)
	}
	newFibreSigningFn = func(ctx context.Context, b node.BridgeConfig, g node.GRPCConfig, kr keyring.Keyring,
		keyName, network string) (io.Closer, node.Reader, node.FibreSubmitter, error) {
		return node.NewFibreSigning(ctx, b, g, kr, keyName, network)
	}
	checkFibreFn = func(ctx context.Context, r node.Reader, c node.Consensus, e node.FibreExpect) error {
		_, err := node.CheckFibre(ctx, r, c, e)
		return err
	}
)

// fibreWiring builds the da = 1 dependencies. With the Recorder enabled the
// Fibre compatibility check runs first, so that a chain it refuses is refused
// before any signing client exists.
func fibreWiring(ctx context.Context, cfg edictad.Config, rd node.Reader, cons node.Consensus, log *slog.Logger) (*edictad.FibreDeps, func(), error) {
	if cfg.Recorder.Enabled {
		ns, err := hex.DecodeString(cfg.Recorder.Namespace)
		if err != nil {
			return nil, nil, fmt.Errorf("recorder namespace: %w", err)
		}
		x := cfg.FibreExpect(log)
		x.Namespace = ns
		if err := checkFibreFn(ctx, rd, cons, x); err != nil {
			return nil, nil, fmt.Errorf("compatibility check: %w", err)
		}
	}
	return fibreAdapters(ctx, cfg, cons, log)
}

const (
	probeTimeout = 3 * time.Minute
	closeTimeout = 10 * time.Second
)

// fibreAdapters builds the da = 1 dependencies. The bridge client is built
// with the namespace data limit the configuration reads with, so the two
// cannot disagree. The download fallback and its capability probe exist only
// if the operator asked for the fallback; whether it is used is decided at
// start, by the probe, never by a declared version.
func fibreAdapters(ctx context.Context, cfg edictad.Config, cons node.Consensus, log *slog.Logger) (*edictad.FibreDeps, func(), error) {
	chain, ok := cons.(node.FibreChainReader)
	if !ok {
		return nil, nil, errors.New("the consensus client cannot read Fibre anchors")
	}
	var recChain recorder.FibreChain
	if cfg.Recorder.Enabled {
		if recChain, ok = cons.(recorder.FibreChain); !ok {
			return nil, nil, errors.New("the consensus client cannot serve the Recorder's reads")
		}
	}
	b, g, err := endpointConfigs(cfg)
	if err != nil {
		return nil, nil, err
	}
	committer, err := fibrecommit.New(cfg.Fibre.MaxDataBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("da = 1 committer: %w", err)
	}
	bridge, err := newFibreBridgeFn(ctx, b, cfg.FibreBridgeLimits())
	if err != nil {
		return nil, nil, fmt.Errorf("fibre bridge: %w", err)
	}
	direct, err := newFibreDirectFn(ctx, g)
	if err != nil {
		bridge.Close()
		return nil, nil, fmt.Errorf("fibre download client: %w", err)
	}
	closeAll := func() {
		cctx, cancel := context.WithTimeout(context.Background(), closeTimeout)
		defer cancel()
		if err := direct.Close(cctx); err != nil {
			log.Warn("edictad: closing the fibre download client", "err", err)
		}
		bridge.Close()
	}
	fd := &edictad.FibreDeps{Chain: chain, Bridge: bridge, Direct: direct, Committer: committer}
	if cfg.Recorder.Enabled {
		closer, sub, err := dialFibreSigning(ctx, cfg, b, g, cons, log)
		if err != nil {
			closeAll()
			return nil, nil, err
		}
		fd.Submitter, fd.RecorderChain, fd.SigningCloser = sub, recChain, closer
	}
	if cfg.Fibre.BridgeFallback {
		fd.Fallback = bridge.Downloader()
		fd.BridgeCompat = bridgeCompat(cfg, cons, chain, bridge, committer, log)
	}
	return fd, closeAll, nil
}

// bridgeCompat is the capability probe of the fallback bridge: it downloads
// one recent anchored blob through the same client and the same token the
// fallback uses, checks the raw answer's shape and recomputes the commitment.
func bridgeCompat(cfg edictad.Config, cons node.Consensus, chain node.FibreChainReader, bridge fibreBridge,
	committer *fibrecommit.Committer, log *slog.Logger) func(context.Context) error {
	return func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, probeTimeout)
		defer cancel()
		reader, err := node.NewFibreAnchorReader(chain, bridge)
		if err != nil {
			return err
		}
		chainID, err := cons.Network(ctx)
		if err != nil {
			return fmt.Errorf("chain id: %w", err)
		}
		opts := cfg.FibreAnchorOptions()
		opts.Log = log
		res, err := gatechain.BridgeProbe{
			Anchors:      gatechain.NewFibreAnchors(reader, chainID, opts),
			Raw:          bridge,
			Committer:    committer,
			LatestHeight: cons.LatestHeight,
			RetentionS: func(ctx context.Context) (uint64, error) {
				fp, err := cons.FibreParams(ctx)
				return fp.RetentionS, err
			},
			Now: time.Now,
		}.Run(ctx)
		if err != nil {
			return err
		}
		log.Info("edictad: bridge download probe passed", "height", res.Height, "blob_id", hex.EncodeToString(res.BlobID[:]))
		return nil
	}
}

// dialFibreSigning opens the Recorder's keyring and dials the signing client.
// Funds calls of the Fibre module are not reachable through it. The caller
// hands the closer to the daemon, which closes it after the Recorder.
func dialFibreSigning(ctx context.Context, cfg edictad.Config, b node.BridgeConfig, g node.GRPCConfig,
	cons node.Consensus, log *slog.Logger) (io.Closer, node.FibreSubmitter, error) {
	pass, err := secret.FromFile(cfg.Recorder.PassphraseFile)
	if err != nil {
		return nil, nil, fmt.Errorf("passphrase file: %w", err)
	}
	pb := pass.Reveal()
	kr, err := openKeyringFn(node.KeyringConfig{
		Dir: cfg.Recorder.KeyringDir, Name: cfg.Recorder.KeyName, Backend: cfg.Recorder.KeyringBackend,
		AllowTest: cfg.Recorder.AllowTestKeyring, Passphrase: pb, Logger: log,
	})
	clear(pb)
	pass.Zero()
	if err != nil {
		return nil, nil, err
	}
	network, err := cons.Network(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("consensus node: %w", err)
	}
	closer, _, sub, err := newFibreSigningFn(ctx, b, g, kr, cfg.Recorder.KeyName, network)
	if err != nil {
		return nil, nil, err
	}
	return closer, sub, nil
}
