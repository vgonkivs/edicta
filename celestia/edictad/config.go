package edictad

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/vgonkivs/edicta/commitment"
)

// ErrConfig wraps every configuration refusal. Messages name keys, never values.
var ErrConfig = errors.New("edictad: invalid configuration")

// Config is the daemon configuration. Secrets are never held here: only paths
// of files that hold them.
type Config struct {
	Network  NetworkConfig  `toml:"network"`
	Recorder RecorderConfig `toml:"recorder"`
	Gate     GateConfig     `toml:"gate"`
	HTTP     HTTPConfig     `toml:"http"`
}

// NetworkConfig describes the chain access. Zero versions take the defaults of
// the compatibility check.
type NetworkConfig struct {
	// ChainID is an optional cross-check; empty means discover.
	ChainID string `toml:"chain_id"`
	// DA is the one data availability mode of this instance: blob or fibre.
	DA            string         `toml:"da"`
	MinAppVersion uint64         `toml:"min_app_version"`
	MaxAppVersion uint64         `toml:"max_app_version"`
	Bridge        EndpointConfig `toml:"bridge"`
	ConsensusGRPC EndpointConfig `toml:"consensus_grpc"`
}

// EndpointConfig is one node endpoint.
type EndpointConfig struct {
	Addr      string `toml:"addr"`
	TokenFile string `toml:"token_file"`
	TLS       bool   `toml:"tls"`
}

// RecorderConfig configures the optional Recorder. Disabled, no key is opened
// and publishing answers 404.
type RecorderConfig struct {
	Enabled          bool        `toml:"enabled"`
	Namespace        string      `toml:"namespace"` // hex, 29 bytes
	KeyringDir       string      `toml:"keyring_dir"`
	KeyringBackend   string      `toml:"keyring_backend"`
	AllowTestKeyring bool        `toml:"allow_test_keyring"`
	KeyName          string      `toml:"key_name"`
	PassphraseFile   string      `toml:"passphrase_file"`
	MaxBlobBytes     uint64      `toml:"max_blob_bytes"`
	Quota            QuotaConfig `toml:"quota"`
}

// QuotaConfig is the per-agent publish quota.
type QuotaConfig struct {
	BlobsPerHour uint64 `toml:"blobs_per_hour"`
	BytesPerDay  uint64 `toml:"bytes_per_day"`
}

// GateConfig configures the gate.
type GateConfig struct {
	GateID         string   `toml:"gate_id"`
	KeyFile        string   `toml:"key_file"` // 32-byte raw seed
	RegistryPath   string   `toml:"registry_path"`
	ActionTypes    []string `toml:"action_types"`
	AllowlistFile  string   `toml:"allowlist_file"`
	ExecutorKeys   []string `toml:"executor_keys"` // hex Ed25519 public keys
	AnchorVerifier string   `toml:"anchor_verifier"`
}

// HTTPConfig configures the API listener.
type HTTPConfig struct {
	Listen             string `toml:"listen"`
	TLSCertFile        string `toml:"tls_cert_file"`
	TLSKeyFile         string `toml:"tls_key_file"`
	AuthorizeTokenFile string `toml:"authorize_token_file"`
	RecordTokenFile    string `toml:"record_token_file"`
	// AllowInsecure permits bearer tokens over plain HTTP to a non-loopback
	// address.
	AllowInsecure bool `toml:"allow_insecure"`
}

const defaultMaxBlobBytes = 1 << 20

func cfgErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrConfig, fmt.Sprintf(format, a...))
}

// ParseConfig decodes and validates a configuration. Unknown keys are errors:
// that is also what refuses an inline secret or a compatibility-check bypass,
// and the value is never echoed.
func ParseConfig(data []byte) (Config, error) {
	var c Config
	dec := toml.NewDecoder(bytes.NewReader(data)).DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		var strict *toml.StrictMissingError
		if errors.As(err, &strict) {
			keys := make([]string, 0, len(strict.Errors))
			for _, e := range strict.Errors {
				keys = append(keys, strings.Join(e.Key(), "."))
			}
			return Config{}, cfgErr("unknown keys %q; secrets are read from files named by *_file keys, never inline", keys)
		}
		var de *toml.DecodeError
		if errors.As(err, &de) {
			row, col := de.Position()
			return Config{}, cfgErr("invalid TOML at line %d column %d", row, col)
		}
		return Config{}, cfgErr("invalid TOML")
	}
	if err := c.validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

func validID(s string, max int) bool {
	if len(s) < 1 || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
			c == '.' || c == '_' || c == ':' || c == '/' || c == '-'
		if !ok {
			return false
		}
	}
	return true
}

func (c Config) validate() error {
	n := c.Network
	if n.MinAppVersion != 0 && n.MaxAppVersion != 0 && n.MinAppVersion > n.MaxAppVersion {
		return cfgErr("network.min_app_version above network.max_app_version")
	}

	if n.DA != "blob" && n.DA != "fibre" {
		return cfgErr(`network.da must be "blob" or "fibre"`)
	}

	g := c.Gate
	switch {
	case !validID(g.GateID, 64):
		return cfgErr("gate.gate_id must be 1..64 characters of letters, digits and . _ : / -")
	case g.KeyFile == "":
		return cfgErr("gate.key_file is required")
	case g.RegistryPath == "":
		return cfgErr("gate.registry_path is required")
	case g.AllowlistFile == "":
		return cfgErr("gate.allowlist_file is required")
	case len(g.ActionTypes) == 0:
		return cfgErr("gate.action_types is empty")
	}
	for i, t := range g.ActionTypes {
		if !commitment.ValidMediaType(t, 128) {
			return cfgErr("gate.action_types[%d] is not a media type", i)
		}
		if slices.Contains(g.ActionTypes[:i], t) {
			return cfgErr("gate.action_types[%d] is a duplicate", i)
		}
	}
	if _, err := c.executorKeys(); err != nil {
		return err
	}
	// The gate's own anchor lookup on the bridge node is the operator's
	// self-check; independent header verification lives on the SDK side.
	if g.AnchorVerifier != "self" {
		return cfgErr("gate.anchor_verifier must be self")
	}

	if err := c.Recorder.validate(); err != nil {
		return err
	}
	return c.HTTP.validate()
}

func (c Config) executorKeys() ([][32]byte, error) {
	if len(c.Gate.ExecutorKeys) == 0 {
		return nil, cfgErr("gate.executor_keys is empty")
	}
	out := make([][32]byte, 0, len(c.Gate.ExecutorKeys))
	for i, s := range c.Gate.ExecutorKeys {
		b, err := hex.DecodeString(s)
		if err != nil || len(b) != 32 {
			return nil, cfgErr("gate.executor_keys[%d] must be 64 hex characters", i)
		}
		var k [32]byte
		copy(k[:], b)
		if slices.Contains(out, k) {
			return nil, cfgErr("gate.executor_keys[%d] is a duplicate", i)
		}
		if err := commitment.CheckPublicKey(b); err != nil {
			return nil, cfgErr("gate.executor_keys[%d] is not a valid public key", i)
		}
		out = append(out, k)
	}
	return out, nil
}

func (r RecorderConfig) validate() error {
	if !r.Enabled {
		return nil
	}
	if _, err := r.namespace(); err != nil {
		return err
	}
	switch {
	case r.KeyringDir == "":
		return cfgErr("recorder.keyring_dir is required when the recorder is enabled")
	case r.KeyName == "":
		return cfgErr("recorder.key_name is required when the recorder is enabled")
	case r.PassphraseFile == "":
		return cfgErr("recorder.passphrase_file is required when the recorder is enabled")
	case r.Quota.BlobsPerHour == 0 || r.Quota.BytesPerDay == 0:
		return cfgErr("recorder.quota limits must be above zero when the recorder is enabled")
	case r.maxBlob() > r.Quota.BytesPerDay:
		return cfgErr("recorder.max_blob_bytes above recorder.quota.bytes_per_day")
	}
	switch r.KeyringBackend {
	case "file":
	case "test":
		if !r.AllowTestKeyring {
			return cfgErr("recorder.keyring_backend test needs recorder.allow_test_keyring")
		}
	default:
		return cfgErr("recorder.keyring_backend must be file or test")
	}
	return nil
}

func (r RecorderConfig) maxBlob() uint64 {
	if r.MaxBlobBytes == 0 {
		return defaultMaxBlobBytes
	}
	return r.MaxBlobBytes
}

func (r RecorderConfig) namespace() ([]byte, error) {
	if r.Namespace == "" {
		return nil, cfgErr("recorder.namespace is required when the recorder is enabled")
	}
	b, err := hex.DecodeString(r.Namespace)
	if err != nil || len(b) != 29 {
		return nil, cfgErr("recorder.namespace must be 58 hex characters")
	}
	return b, nil
}

func (h HTTPConfig) hasTokens() bool { return h.AuthorizeTokenFile != "" || h.RecordTokenFile != "" }

func (h HTTPConfig) validate() error {
	if h.Listen == "" {
		return cfgErr("http.listen is required")
	}
	host, _, err := net.SplitHostPort(h.Listen)
	if err != nil {
		return cfgErr("http.listen is not host:port")
	}
	if (h.TLSCertFile == "") != (h.TLSKeyFile == "") {
		return cfgErr("http.tls_cert_file and http.tls_key_file go together")
	}
	if h.hasTokens() && h.TLSCertFile == "" && !h.AllowInsecure && !isLoopback(host) {
		return cfgErr("bearer tokens over plain HTTP to a non-loopback address need http.allow_insecure or TLS")
	}
	return nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
