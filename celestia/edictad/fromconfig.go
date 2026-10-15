package edictad

import (
	"errors"
	"fmt"
	"math/bits"

	"github.com/vgonkivs/edicta/celestia/config"
	"github.com/vgonkivs/edicta/celestia/node"
)

// ErrNotAvailable marks a key of edicta.toml that this build does not serve.
var ErrNotAvailable = errors.New("not available in this build")

// FromEdicta projects the shared edicta.toml onto the daemon configuration.
// The input must already have its defaults applied and be valid. The result
// has the daemon defaults applied and passes ValidateBasic.
func FromEdicta(in config.Config) (Config, error) {
	g := in.Gate
	if g == nil {
		return Config{}, cfgErr("[gate] is required: edictad serves the gate")
	}
	if g.FastMode {
		return Config{}, fmt.Errorf("%w: gate.fast_mode is %w", ErrConfig, ErrNotAvailable)
	}
	if g.Sessions {
		return Config{}, fmt.Errorf("%w: gate.sessions is %w", ErrConfig, ErrNotAvailable)
	}

	n := in.Network
	out := Config{
		Network: NetworkConfig{
			ChainID:       n.ChainID,
			DA:            DAConfigBlob,
			Bridge:        EndpointConfig(n.Bridge),
			ConsensusGRPC: EndpointConfig(n.ConsensusGRPC),
		},
		Archive: ArchiveConfig{Dir: in.Archive.Dir},
		Gate: GateConfig{
			GateID:         g.GateID,
			KeyFile:        g.KeyFile,
			RegistryPath:   g.RegistryPath,
			ActionTypes:    append([]string(nil), g.ActionTypes...),
			AllowlistFile:  g.AllowlistFile,
			ExecutorKeys:   append([]string(nil), g.ExecutorKeys...),
			AnchorVerifier: "self",
		},
		HTTP:   HTTPConfig{Listen: g.Listen},
		Policy: PolicyConfig{MandateFile: g.MandateFile},
	}

	if r := in.Recorder; r != nil {
		if r.DA == config.DAFibre {
			out.Network.DA = DAConfigFibre
		}
		out.Recorder = RecorderConfig{
			Enabled:        true,
			Namespace:      r.Namespace,
			KeyringDir:     r.KeyringDir,
			KeyringBackend: "file",
			KeyName:        r.KeyName,
			PassphraseFile: r.PassphraseFile,
			MaxBlobBytes:   r.MaxBlobBytes,
			Quota:          quotaFor(r),
		}
		if out.Network.DA == DAConfigFibre {
			out.Recorder.OwnNode = r.OwnNode
			out.Recorder.EscrowMarginUtia = r.EscrowHeadroomUtia
		}
	}

	if c := in.Capture; c != nil {
		out.Capture = CaptureConfig{
			Enabled:               true,
			Dir:                   c.Dir,
			CometRPC:              c.CometRPC,
			NodePruneWindowBlocks: c.NodePruneWindowBlocks,
			RetryEveryS:           c.RetryEveryS,
		}
	}

	out = out.WithDefaults()
	if err := out.ValidateBasic(); err != nil {
		return Config{}, err
	}
	if b := &out.Network.Bridge; b.Addr != "" {
		u, err := node.BridgeURL(b.Addr, b.TLS)
		if err != nil {
			return Config{}, cfgErr("network.bridge.addr: %v", err)
		}
		b.Addr = u
	}
	return out, nil
}

// quotaFor derives the publish quota from the expected rate, which is the
// only rate edicta.toml states: an hour gets a 24th of the day, rounded up,
// and the byte budget fits that many blobs of the largest size.
func quotaFor(r *config.Recorder) QuotaConfig {
	perDay := max(r.BlobsPerDay, 1)
	blob := Config{Recorder: RecorderConfig{MaxBlobBytes: r.MaxBlobBytes}}.Recorder.maxBlob()
	hi, lo := bits.Mul64(perDay, blob)
	if hi != 0 {
		lo = ^uint64(0)
	}
	return QuotaConfig{BlobsPerHour: (perDay + 23) / 24, BytesPerDay: lo}
}
