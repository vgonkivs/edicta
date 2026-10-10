package edictad

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/celestia/gatechain"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/recorder"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/fibre/fibrecommit"
)

// ErrConfig wraps every configuration refusal. Messages name keys, never values.
var ErrConfig = errors.New("edictad: invalid configuration")

// Config is the daemon configuration. Secrets are never held here: only paths
// of files that hold them.
type Config struct {
	Network  NetworkConfig  `toml:"network"`
	Fibre    FibreConfig    `toml:"fibre"`
	Archive  ArchiveConfig  `toml:"archive"`
	Recorder RecorderConfig `toml:"recorder"`
	Gate     GateConfig     `toml:"gate"`
	HTTP     HTTPConfig     `toml:"http"`
	Policy   PolicyConfig   `toml:"policy"`
	Capture  CaptureConfig  `toml:"capture"`
}

// NetworkConfig describes the chain access. Zero versions take the defaults of
// the compatibility check.
type NetworkConfig struct {
	// ChainID is an optional cross-check; empty means discover.
	ChainID string `toml:"chain_id"`
	// DA is the one data availability mode of this instance: celestia_blob or
	// fibre.
	DA string `toml:"da"`
	// FibreChainIDs is the da = 1 chain allowlist; empty means mocha-5.
	FibreChainIDs []string       `toml:"fibre_chain_ids"`
	MinAppVersion uint64         `toml:"min_app_version"`
	MaxAppVersion uint64         `toml:"max_app_version"`
	Bridge        EndpointConfig `toml:"bridge"`
	ConsensusGRPC EndpointConfig `toml:"consensus_grpc"`
}

// Values of NetworkConfig.DA.
const (
	DAConfigBlob  = "celestia_blob"
	DAConfigFibre = "fibre"
)

// FibreConfig holds the keys that exist only with da = "fibre". With
// celestia_blob every field must stay zero, so a half-switched file never
// starts.
type FibreConfig struct {
	// MaxDataBytes is the cap on the payload size of a da = 1 decision.
	MaxDataBytes uint64 `toml:"max_data_bytes"`
	// MaxReadBytes bounds the namespace data of one anchor lookup and is also
	// the bridge client's limit.
	MaxReadBytes uint64 `toml:"max_read_bytes"`
	// AnchorCacheBytes is the memory of the cross-request anchor cache; zero
	// keeps none.
	AnchorCacheBytes uint64 `toml:"anchor_cache_bytes"`
	LookupTimeoutS   uint64 `toml:"lookup_timeout_s"`
	// AssumedLagBlocks widens each retention sample for a load-balanced
	// consensus endpoint; zero for an own node.
	AssumedLagBlocks uint64 `toml:"assumed_lag_blocks"`
	SampleEveryS     uint64 `toml:"sample_every_s"`
	CanaryEveryS     uint64 `toml:"canary_every_s"`
	// BridgeFallback asks for the bridge download fallback. It is enabled only
	// if the capability probe passes at start.
	BridgeFallback bool `toml:"bridge_fallback"`
}

// ArchiveConfig configures the archive the gate writes before it signs.
type ArchiveConfig struct {
	// Dir is the archive directory; one edictad per directory.
	Dir            string `toml:"dir"`
	WriteTimeoutS  uint64 `toml:"write_timeout_s"`
	SweepIntervalS uint64 `toml:"sweep_interval_s"`
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

	// The keys below exist only with da = "fibre" and the Recorder enabled.
	// OwnNode attests that the consensus endpoint is the operator's own: the
	// Recorder submits and reads through it.
	OwnNode bool `toml:"own_node"`
	// EscrowMarginUtia is kept in the escrow on top of the cost of an upload.
	EscrowMarginUtia uint64 `toml:"escrow_margin_utia"`
	SubmitTimeoutS   uint64 `toml:"submit_timeout_s"`
	// UploadDrainS is how long shard uploads may continue after a submit
	// returns.
	UploadDrainS uint64 `toml:"upload_drain_s"`
	// CloseTimeoutS bounds the wait for draining uploads at shutdown.
	CloseTimeoutS uint64 `toml:"close_timeout_s"`

	// Fast makes Publish return a pending reference once the payload and the
	// anchor intent are archived and the node accepted the anchor tx; a
	// background loop archives the evidence when the anchor lands. Off by
	// default; it needs gate.fast.enabled.
	Fast bool `toml:"fast"`
	// FastTimeoutBlocks is how many blocks above h0 the anchor tx stays
	// valid; celestia_blob only, default 100.
	FastTimeoutBlocks uint64 `toml:"fast_timeout_blocks"`
	// FastDedicatedAccount attests that the account of KeyName signs only
	// this Recorder's anchor txs. A tx from anywhere else moves the account
	// sequence and makes a signed, archived anchor tx stale, and an archived
	// anchor tx is never signed again.
	FastDedicatedAccount bool `toml:"fast_dedicated_account"`
	// FastUploadAddr is the consensus gRPC address of the da = fibre
	// uploader; it must be network.consensus_grpc.addr.
	FastUploadAddr string `toml:"fast_upload_addr"`
	// FastEscrowHeadroomUtia is kept in the da = fibre escrow on top of the
	// margin. Reservations of uploaded promises live in memory and are lost
	// on restart, while those promises can still be charged.
	FastEscrowHeadroomUtia uint64 `toml:"fast_escrow_headroom_utia"`
}

func (r RecorderConfig) hasFibreKeys() bool {
	return r.OwnNode || r.EscrowMarginUtia != 0 || r.SubmitTimeoutS != 0 || r.UploadDrainS != 0 || r.CloseTimeoutS != 0
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
	// RevealOnExecution lists the action types whose salt a receipt
	// publishes under a private mandate. Each needs a compiled profile with
	// public execution.
	RevealOnExecution []string `toml:"reveal_on_execution"`
	// Fast is stage K-fast; off by default.
	Fast FastConfig `toml:"fast"`
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

// Defaults and bounds of the keys above.
const (
	defaultArchiveWriteS  = 10
	defaultSweepIntervalS = 600
	defaultLookupTimeoutS = 60
	defaultSampleEveryS   = 30
	defaultCanaryEveryS   = 600

	defaultSubmitTimeoutS = 300
	defaultUploadDrainS   = 120
	defaultCloseTimeoutS  = 150
	maxRecorderTimeoutS   = 600

	// publishVisibleS and publishMarginS are what a publish may spend beyond
	// the submit: the wait until the read nodes serve the anchor, and slack.
	publishVisibleS = 60
	publishMarginS  = 60

	minFibreReadBytes = 64 << 10
	maxFibreReadBytes = 1 << 30
	// cacheSlack is what an anchor costs beyond its proof, so a cache that
	// cannot hold one full-size anchor is refused.
	cacheSlack = 4096
)

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
	c = c.WithDefaults()
	if err := c.ValidateBasic(); err != nil {
		return Config{}, err
	}
	if b := &c.Network.Bridge; b.Addr != "" {
		u, err := node.BridgeURL(b.Addr, b.TLS)
		if err != nil {
			return Config{}, cfgErr("network.bridge.addr: %v", err)
		}
		b.Addr = u
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

// WithDefaults fills the zero fields that have defaults. The fibre table is
// only filled with da = "fibre".
func (c Config) WithDefaults() Config {
	c.Archive = c.Archive.withDefaults()
	c.Capture = c.Capture.withDefaults()
	c.Policy = c.Policy.WithDefaults()
	c.Gate.Fast = c.Gate.Fast.WithDefaults()
	c.Recorder = c.Recorder.withFastDefaults(c.Network.DA)
	if c.Network.DA == DAConfigFibre {
		c.Fibre = c.Fibre.withDefaults()
		if c.Recorder.Enabled {
			c.Recorder = c.Recorder.withFibreDefaults()
		}
	}
	return c
}

func (r RecorderConfig) withFibreDefaults() RecorderConfig {
	if r.SubmitTimeoutS == 0 {
		r.SubmitTimeoutS = defaultSubmitTimeoutS
	}
	if r.UploadDrainS == 0 {
		r.UploadDrainS = defaultUploadDrainS
	}
	if r.CloseTimeoutS == 0 {
		r.CloseTimeoutS = defaultCloseTimeoutS
	}
	return r
}

func (a ArchiveConfig) withDefaults() ArchiveConfig {
	if a.WriteTimeoutS == 0 {
		a.WriteTimeoutS = defaultArchiveWriteS
	}
	if a.SweepIntervalS == 0 {
		a.SweepIntervalS = defaultSweepIntervalS
	}
	return a
}

func (f FibreConfig) withDefaults() FibreConfig {
	if f.MaxDataBytes == 0 {
		f.MaxDataBytes = fibrecommit.DefaultMaxDataSize
	}
	if f.MaxReadBytes == 0 {
		f.MaxReadBytes = gatechain.DefaultFibreMaxReadBytes
	}
	if f.LookupTimeoutS == 0 {
		f.LookupTimeoutS = defaultLookupTimeoutS
	}
	if f.SampleEveryS == 0 {
		f.SampleEveryS = defaultSampleEveryS
	}
	if f.CanaryEveryS == 0 {
		f.CanaryEveryS = defaultCanaryEveryS
	}
	return f
}

// DA is the data availability mode the gate serves.
func (c Config) DA() commitment.DA {
	if c.Network.DA == DAConfigFibre {
		return commitment.DAFibre
	}
	return commitment.DACelestiaBlob
}

// FibreAnchorOptions are the options of the da = 1 anchor lookup; the caller
// adds the logger.
func (c Config) FibreAnchorOptions() gatechain.FibreAnchorOptions {
	return gatechain.FibreAnchorOptions{
		MaxReadBytes:  c.Fibre.MaxReadBytes,
		CacheBytes:    c.Fibre.AnchorCacheBytes,
		LookupTimeout: time.Duration(c.Fibre.LookupTimeoutS) * time.Second,
	}
}

// FibreBridgeLimits are the limits the bridge client must be built with: it
// has to carry the largest namespace data the gate reads.
func (c Config) FibreBridgeLimits() node.BridgeLimits { return c.FibreAnchorOptions().BridgeLimits() }

// FibreRecorderConfig is the da = 1 Recorder's configuration. The caller adds
// the clock.
func (c Config) FibreRecorderConfig(ns []byte, st archive.Store) recorder.FibreConfig {
	return recorder.FibreConfig{
		Namespace:        bytes.Clone(ns),
		MaxDataBytes:     min(c.Fibre.MaxDataBytes, c.Recorder.maxBlob()),
		SubmitTimeout:    time.Duration(c.Recorder.SubmitTimeoutS) * time.Second,
		UploadDrain:      time.Duration(c.Recorder.UploadDrainS) * time.Second,
		EscrowMarginUtia: c.Recorder.escrowMargin(),
		OwnNode:          c.Recorder.OwnNode,
		Archive:          st,
	}
}

// FibreExpect is what the da = 1 compatibility check requires. A bridge
// version is never part of it: the download fallback is enabled by a
// capability probe, not by a version the operator declares.
func (c Config) FibreExpect(log *slog.Logger) node.FibreExpect {
	return node.FibreExpect{
		Expect:   node.Expect{ChainID: c.Network.ChainID},
		ChainIDs: slices.Clone(c.Network.FibreChainIDs),
		Log:      log,
	}
}

// ValidateBasic checks every field that needs no dependency. It applies no
// defaults: call WithDefaults first.
func (c Config) ValidateBasic() error {
	n := c.Network
	if n.MinAppVersion != 0 && n.MaxAppVersion != 0 && n.MinAppVersion > n.MaxAppVersion {
		return cfgErr("network.min_app_version above network.max_app_version")
	}

	switch n.DA {
	case DAConfigBlob:
	case DAConfigFibre:
	case "blob":
		return cfgErr(`network.da "blob" is not a mode: use "celestia_blob"`)
	default:
		return cfgErr(`network.da must be "celestia_blob" or "fibre"`)
	}
	if err := c.Policy.ValidateBasic(); err != nil {
		return err
	}
	if err := c.validateFastNeeds(); err != nil {
		return err
	}
	if c.Policy.Enabled() && c.Archive.Dir == "" {
		return cfgErr("policy.mandate_file needs the archive: archive.dir is required")
	}
	if err := c.validateArchive(); err != nil {
		return err
	}
	if err := c.validateCapture(); err != nil {
		return err
	}
	if err := c.validateFibre(); err != nil {
		return err
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
	for i, t := range g.RevealOnExecution {
		if !slices.Contains(g.ActionTypes, t) {
			return cfgErr("gate.reveal_on_execution[%d] is not one of gate.action_types", i)
		}
		if !compiledProfiles.PublicExecution(t) {
			return cfgErr("gate.reveal_on_execution[%d] has no compiled profile with public execution", i)
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
	if err := c.validateFast(); err != nil {
		return err
	}

	if err := c.Recorder.validate(); err != nil {
		return err
	}
	if err := c.validateRecorderFast(); err != nil {
		return err
	}
	return c.HTTP.validate()
}

func (c Config) validateArchive() error {
	a := c.Archive
	switch {
	case a.Dir == "":
		return cfgErr("archive.dir is required")
	case a.WriteTimeoutS < 1 || a.WriteTimeoutS > 60:
		return cfgErr("archive.write_timeout_s must be 1..60")
	case a.SweepIntervalS < 60 || a.SweepIntervalS > 86400:
		return cfgErr("archive.sweep_interval_s must be 60..86400")
	}
	return nil
}

func (c Config) validateFibre() error {
	n, f := c.Network, c.Fibre
	if n.DA == DAConfigBlob {
		if f != (FibreConfig{}) || len(n.FibreChainIDs) != 0 {
			return cfgErr(`the [fibre] table and network.fibre_chain_ids need network.da = "fibre"`)
		}
		if c.Recorder.hasFibreKeys() {
			return cfgErr(`recorder.own_node, escrow_margin_utia, submit_timeout_s, upload_drain_s and close_timeout_s need network.da = "fibre"`)
		}
		return nil
	}
	if n.MinAppVersion != 0 || n.MaxAppVersion != 0 {
		return cfgErr(`network.min_app_version and network.max_app_version do not apply to da = "fibre": the app version is pinned`)
	}
	for i, id := range n.FibreChainIDs {
		switch {
		case id == "" || len(id) > 20:
			return cfgErr("network.fibre_chain_ids[%d] must be 1..20 bytes", i)
		case slices.Contains(n.FibreChainIDs[:i], id):
			return cfgErr("network.fibre_chain_ids[%d] is a duplicate", i)
		}
	}
	switch {
	case f.MaxDataBytes < 1 || f.MaxDataBytes > fibrecommit.DefaultMaxDataSize:
		return cfgErr("fibre.max_data_bytes must be 1..%d", fibrecommit.DefaultMaxDataSize)
	case f.MaxReadBytes < minFibreReadBytes || f.MaxReadBytes > maxFibreReadBytes:
		return cfgErr("fibre.max_read_bytes must be %d..%d", minFibreReadBytes, maxFibreReadBytes)
	case f.AnchorCacheBytes != 0 && (f.AnchorCacheBytes < f.MaxReadBytes+cacheSlack || f.AnchorCacheBytes > 1<<30):
		return cfgErr("fibre.anchor_cache_bytes must be 0 or fibre.max_read_bytes + %d .. %d", cacheSlack, 1<<30)
	case f.LookupTimeoutS < 1 || f.LookupTimeoutS > 600:
		return cfgErr("fibre.lookup_timeout_s must be 1..600")
	case f.SampleEveryS < 1 || f.SampleEveryS > 300:
		return cfgErr("fibre.sample_every_s must be 1..300")
	case f.CanaryEveryS < 60 || f.CanaryEveryS > 3600:
		return cfgErr("fibre.canary_every_s must be 60..3600")
	}
	r := c.Recorder
	if !r.Enabled {
		if r.hasFibreKeys() {
			return cfgErr("recorder.own_node, escrow_margin_utia, submit_timeout_s, upload_drain_s and close_timeout_s need recorder.enabled")
		}
		return nil
	}
	switch {
	case !r.OwnNode:
		return cfgErr(`recorder.own_node must be true with da = "fibre": the Recorder submits only through the operator's own node`)
	case r.maxBlob() > f.MaxDataBytes:
		return cfgErr("recorder.max_blob_bytes above fibre.max_data_bytes")
	case r.SubmitTimeoutS < 1 || r.SubmitTimeoutS > maxRecorderTimeoutS:
		return cfgErr("recorder.submit_timeout_s must be 1..%d", maxRecorderTimeoutS)
	case r.UploadDrainS < 1 || r.UploadDrainS > maxRecorderTimeoutS:
		return cfgErr("recorder.upload_drain_s must be 1..%d", maxRecorderTimeoutS)
	case r.CloseTimeoutS < 1 || r.CloseTimeoutS > maxRecorderTimeoutS:
		return cfgErr("recorder.close_timeout_s must be 1..%d", maxRecorderTimeoutS)
	case r.CloseTimeoutS < r.UploadDrainS:
		return cfgErr("recorder.close_timeout_s below recorder.upload_drain_s")
	}
	return nil
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

// publishDeadline bounds one /v1/publish. With the da = fibre Recorder it
// covers the whole submit and the visibility wait, which the common request
// deadline would cut short.
func (c Config) publishDeadline() time.Duration {
	d := requestDeadline
	if c.Network.DA == DAConfigFibre && c.Recorder.Enabled {
		d = max(d, time.Duration(c.Recorder.SubmitTimeoutS+publishVisibleS+publishMarginS)*time.Second)
	}
	return d
}

// recorderCloseTimeout bounds the Recorder's close at shutdown: the draining
// uploads of da = fibre, or the confirmation loops of a celestia_blob fast
// Recorder. Zero when there is nothing to wait for.
func (c Config) recorderCloseTimeout() time.Duration {
	switch {
	case !c.Recorder.Enabled:
		return 0
	case c.Network.DA == DAConfigFibre:
		return time.Duration(c.Recorder.CloseTimeoutS) * time.Second
	case c.Recorder.Fast:
		return fastBlobCloseTimeoutS * time.Second
	}
	return 0
}

// ShutdownBudget is a context length for Shutdown that fits what it waits
// for: the longest request, the archive drain and the Recorder's close.
func (c Config) ShutdownBudget() time.Duration {
	c = c.WithDefaults()
	d := c.publishDeadline() + time.Duration(c.Archive.WriteTimeoutS)*time.Second
	return d + c.recorderCloseTimeout() + 10*time.Second
}
