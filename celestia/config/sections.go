package config

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
)

// Values of Recorder.DA.
const (
	DABlob  = "celestia_blob"
	DAFibre = "fibre"
)

// Values of Gate.KeyBackend and Signer.PayerBackend.
const (
	BackendFile = "file"
	BackendKMS  = "kms"
	BackendCDP  = "cdp"
)

// Network picks the chains and holds the endpoints of the Celestia chain and
// of the settlement chain. Every endpoint key is filled from the preset when
// empty; a key written in the file wins.
type Network struct {
	Celestia   string `toml:"celestia"`
	Settlement string `toml:"settlement"`
	Mode       string `toml:"mode"`
	// CelestiaPresetVersion and SettlementPresetVersion record the preset
	// versions the file was written against; zero means unknown.
	CelestiaPresetVersion   uint32 `toml:"celestia_preset_version"`
	SettlementPresetVersion uint32 `toml:"settlement_preset_version"`

	ChainID       string   `toml:"chain_id"`
	Bridge        Endpoint `toml:"bridge"`
	ConsensusGRPC Endpoint `toml:"consensus_grpc"`
	CometRPC      []string `toml:"comet_rpc"`
	EVM           EVM      `toml:"evm"`
}

// EVM is the settlement chain.
type EVM struct {
	ChainID        uint64   `toml:"chain_id"`
	RPC            []string `toml:"rpc"`
	USDC           USDC     `toml:"usdc"`
	FacilitatorURL string   `toml:"facilitator_url"`
	// FacilitatorNetwork is the network label the facilitator lists.
	FacilitatorNetwork string `toml:"facilitator_network"`
}

// Agent is the agent's identity and where it publishes and asks.
type Agent struct {
	ID      string `toml:"id"`
	KeyFile string `toml:"key_file"`
	// RecorderURL is the Recorder or the relay the agent publishes to.
	RecorderURL string `toml:"recorder_url"`
	GateURL     string `toml:"gate_url"`
}

// Gate is the gate's identity, key and inputs.
type Gate struct {
	GateID string `toml:"gate_id"`
	// KeyBackend is "file"; "kms" is reserved.
	KeyBackend    string   `toml:"key_backend"`
	KeyFile       string   `toml:"key_file"`
	RegistryPath  string   `toml:"registry_path"`
	AllowlistFile string   `toml:"allowlist_file"`
	MandateFile   string   `toml:"mandate_file"`
	ActionTypes   []string `toml:"action_types"`
	// ExecutorKeys are hex Ed25519 public keys.
	ExecutorKeys []string `toml:"executor_keys"`
	FastMode     bool     `toml:"fast_mode"`
	Sessions     bool     `toml:"sessions"`
	Listen       string   `toml:"listen"`
}

// Recorder is the Celestia publishing side.
type Recorder struct {
	KeyringDir     string `toml:"keyring_dir"`
	KeyName        string `toml:"key_name"`
	PassphraseFile string `toml:"passphrase_file"`
	// Namespace is 29 bytes, hex.
	Namespace string `toml:"namespace"`
	// DA is the one data availability mode: celestia_blob or fibre.
	DA           string `toml:"da"`
	MaxBlobBytes uint64 `toml:"max_blob_bytes"`
	// OwnNode attests that the consensus endpoint is the operator's own,
	// which the Fibre Recorder requires.
	OwnNode bool `toml:"own_node"`
	// EscrowHeadroomUtia is kept in the Fibre escrow on top of one upload.
	EscrowHeadroomUtia uint64 `toml:"escrow_headroom_utia"`
}

// Publisher is the second Celestia account, with its own namespace.
type Publisher struct {
	KeyringDir     string `toml:"keyring_dir"`
	KeyName        string `toml:"key_name"`
	PassphraseFile string `toml:"passphrase_file"`
	Namespace      string `toml:"namespace"`
}

// Archive is where payloads are kept: a directory, or a URL for readers.
type Archive struct {
	Dir        string   `toml:"dir"`
	URL        string   `toml:"url"`
	MirrorURLs []string `toml:"mirror_urls"`
}

// Signer is the executor-side payment signer.
type Signer struct {
	Listen string `toml:"listen"`
	// PinnedGateKeys are hex Ed25519 public keys of gates whose
	// Authorizations the signer accepts.
	PinnedGateKeys []string `toml:"pinned_gate_keys"`
	// PayerBackend is file, kms or cdp.
	PayerBackend string `toml:"payer_backend"`
	PayerKeyFile string `toml:"payer_key_file"`
	// PayerAddress is the 0x address of the payer; the backend must match it.
	PayerAddress string `toml:"payer_address"`
	// PinnedChainID and PinnedUSDC are what the signer refuses to leave; they
	// come from the settlement preset.
	PinnedChainID uint64     `toml:"pinned_chain_id"`
	PinnedUSDC    string     `toml:"pinned_usdc"`
	Risk          SignerRisk `toml:"risk"`
}

// SignerRisk are the signer's own limits, in base units of the token.
type SignerRisk struct {
	MaxPerPayment uint64 `toml:"max_per_payment"`
	MaxPerHour    uint64 `toml:"max_per_hour"`
}

// Capture keeps the proof of a rail result before the node prunes it.
type Capture struct {
	Dir                   string `toml:"dir"`
	CometRPC              string `toml:"comet_rpc"`
	NodePruneWindowBlocks uint64 `toml:"node_prune_window_blocks"`
	RetryEveryS           uint64 `toml:"retry_every_s"`
}

// Verify names the independent sources a verifier trusts.
type Verify struct {
	HeadersRPC    string   `toml:"headers_rpc"`
	TxRPC         string   `toml:"tx_rpc"`
	CheckpointRPC []string `toml:"checkpoint_rpc"`
	CrossCheckRPC []string `toml:"cross_check_rpc"`
	ExcludeHosts  []string `toml:"exclude_host"`
	Quorum        uint64   `toml:"quorum"`
}

// Defaults of the keys above.
const (
	DefaultMaxBlobBytes          = 1 << 20
	DefaultSignerListen          = "127.0.0.1:8402"
	DefaultGateListen            = "127.0.0.1:8080"
	DefaultCaptureRetryS         = 30
	DefaultNodePruneWindowBlocks = 100_000
)

// ApplyDefaults fills the zero fields of the network from its presets, then
// those of each section. It decides nothing that ValidateBasic should refuse:
// a missing required key stays missing.
func (c *Config) ApplyDefaults(p Presets) error {
	if p == nil {
		p = Builtin{}
	}
	if err := c.Network.applyDefaults(p); err != nil {
		return err
	}
	if c.Gate != nil {
		c.Gate.ApplyDefaults()
	}
	if c.Recorder != nil {
		c.Recorder.ApplyDefaults()
	}
	if c.Signer != nil {
		c.Signer.applyDefaults(c.Network)
	}
	if c.Capture != nil {
		c.Capture.ApplyDefaults()
	}
	if c.Verify != nil {
		c.Verify.ApplyDefaults()
	}
	return nil
}

func (n *Network) applyDefaults(p Presets) error {
	if n.Mode == "" {
		n.Mode = ModeSelfHosted
	}
	if n.Settlement == "" {
		n.Settlement = SettlementNone
	}
	if n.Celestia == "" {
		return cfgErr("network.celestia is required")
	}
	cp, err := p.Celestia(n.Celestia)
	if err != nil {
		return err
	}
	sp, err := p.Settlement(n.Settlement)
	if err != nil {
		return err
	}
	fill := func(dst *string, v string) {
		if *dst == "" {
			*dst = v
		}
	}
	fill(&n.ChainID, cp.ChainID)
	fill(&n.Bridge.Addr, cp.Bridge.Addr)
	fill(&n.ConsensusGRPC.Addr, cp.ConsensusGRPC.Addr)
	if n.Bridge.Addr == cp.Bridge.Addr {
		n.Bridge.TLS = n.Bridge.TLS || cp.Bridge.TLS
	}
	if n.ConsensusGRPC.Addr == cp.ConsensusGRPC.Addr {
		n.ConsensusGRPC.TLS = n.ConsensusGRPC.TLS || cp.ConsensusGRPC.TLS
	}
	if len(n.CometRPC) == 0 {
		n.CometRPC = slices.Clone(cp.CometRPC)
	}
	e := &n.EVM
	if e.ChainID == 0 {
		e.ChainID = sp.EVMChainID
	}
	if len(e.RPC) == 0 {
		e.RPC = slices.Clone(sp.RPC)
	}
	fill(&e.USDC.Address, sp.USDC.Address)
	fill(&e.USDC.Name, sp.USDC.Name)
	fill(&e.USDC.Version, sp.USDC.Version)
	fill(&e.FacilitatorURL, sp.FacilitatorURL)
	fill(&e.FacilitatorNetwork, sp.FacilitatorNetwork)
	return nil
}

// ApplyDefaults fills the zero fields that have defaults.
func (g *Gate) ApplyDefaults() {
	if g.KeyBackend == "" {
		g.KeyBackend = BackendFile
	}
	if g.Listen == "" {
		g.Listen = DefaultGateListen
	}
}

// ApplyDefaults fills the zero fields that have defaults.
func (r *Recorder) ApplyDefaults() {
	if r.DA == "" {
		r.DA = DABlob
	}
	if r.MaxBlobBytes == 0 {
		r.MaxBlobBytes = DefaultMaxBlobBytes
	}
}

func (s *Signer) applyDefaults(n Network) {
	if s.Listen == "" {
		s.Listen = DefaultSignerListen
	}
	if s.PayerBackend == "" {
		s.PayerBackend = BackendFile
	}
	if s.PinnedChainID == 0 {
		s.PinnedChainID = n.EVM.ChainID
	}
	if s.PinnedUSDC == "" {
		s.PinnedUSDC = n.EVM.USDC.Address
	}
}

// ApplyDefaults fills the zero fields that have defaults.
func (c *Capture) ApplyDefaults() {
	if c.RetryEveryS == 0 {
		c.RetryEveryS = DefaultCaptureRetryS
	}
	if c.NodePruneWindowBlocks == 0 {
		c.NodePruneWindowBlocks = DefaultNodePruneWindowBlocks
	}
}

// ApplyDefaults fills the zero fields that have defaults.
func (v *Verify) ApplyDefaults() {
	if v.Quorum == 0 {
		v.Quorum = 1
	}
}

// ValidateBasic checks every stateless rule of every present section. It
// applies no defaults: call ApplyDefaults first.
func (c Config) ValidateBasic() error {
	if err := c.Network.ValidateBasic(); err != nil {
		return err
	}
	hosted := c.Network.Mode == ModeHosted
	if c.Agent == nil {
		return cfgErr("[agent] is required")
	}
	if err := c.Agent.ValidateBasic(); err != nil {
		return err
	}
	if hosted {
		switch {
		case c.Signer == nil:
			return cfgErr(`[signer] is required with network.mode = "hosted"`)
		case c.Gate != nil || c.Recorder != nil || c.Publisher != nil || c.Archive.Dir != "":
			return cfgErr(`[gate], [recorder], [publisher] and archive.dir belong to the service with network.mode = "hosted"`)
		}
	} else {
		switch {
		case c.Gate == nil:
			return cfgErr("[gate] is required with network.mode = self-hosted")
		case c.Archive.Dir == "":
			return cfgErr("archive.dir is required with network.mode = self-hosted")
		}
	}
	if c.Gate != nil {
		if err := c.Gate.ValidateBasic(); err != nil {
			return err
		}
	}
	if c.Recorder != nil {
		if err := c.Recorder.ValidateBasic(); err != nil {
			return err
		}
	}
	if c.Publisher != nil {
		if err := c.Publisher.ValidateBasic(); err != nil {
			return err
		}
	}
	if err := c.Archive.ValidateBasic(); err != nil {
		return err
	}
	if c.Signer != nil {
		if err := c.Signer.ValidateBasic(); err != nil {
			return err
		}
		if c.Network.Settlement == SettlementNone {
			return cfgErr("[signer] needs a settlement chain: network.settlement is none")
		}
	}
	if c.Capture != nil {
		if err := c.Capture.ValidateBasic(); err != nil {
			return err
		}
	}
	if c.Verify != nil {
		if err := c.Verify.ValidateBasic(); err != nil {
			return err
		}
	}
	return c.crossCheck()
}

// crossCheck holds the rules that read two sections of one file.
func (c Config) crossCheck() error {
	if c.Recorder != nil && c.Publisher != nil {
		r, p := c.Recorder, c.Publisher
		if r.Namespace == p.Namespace {
			return cfgErr("publisher.namespace equals recorder.namespace")
		}
		if r.KeyringDir == p.KeyringDir && r.KeyName == p.KeyName {
			return cfgErr("publisher and recorder share one keyring key: use separate accounts")
		}
	}
	if c.Recorder != nil && c.Recorder.DA == DAFibre && !c.Recorder.OwnNode {
		return cfgErr(`recorder.own_node must be true with recorder.da = "fibre": the Recorder submits only through the operator's own node`)
	}
	if c.Gate != nil && c.Agent != nil && c.Gate.KeyFile != "" && c.Gate.KeyFile == c.Agent.KeyFile {
		return cfgErr("gate.key_file and agent.key_file are one file: the signing roles never overlap")
	}
	if c.Gate != nil && c.Signer != nil && c.Signer.PayerKeyFile != "" && c.Signer.PayerKeyFile == c.Gate.KeyFile {
		return cfgErr("signer.payer_key_file and gate.key_file are one file: the signing roles never overlap")
	}
	return nil
}

// ValidateBasic checks the stateless fields.
func (n Network) ValidateBasic() error {
	switch n.Mode {
	case ModeSelfHosted, ModeHosted:
	default:
		return cfgErr(`network.mode must be "self-hosted" or "hosted"`)
	}
	if n.Celestia == "" {
		return cfgErr("network.celestia is required")
	}
	if n.ChainID == "" || len(n.ChainID) > 20 {
		return cfgErr("network.chain_id must be 1..20 bytes (set it for celestia = %q)", Custom)
	}
	if n.Bridge.Addr == "" {
		return cfgErr("network.bridge.addr is required")
	}
	if n.ConsensusGRPC.Addr == "" {
		return cfgErr("network.consensus_grpc.addr is required")
	}
	for i, u := range n.CometRPC {
		if err := checkURL(u); err != nil {
			return cfgErr("network.comet_rpc[%d]: %v", i, err)
		}
	}
	if n.Settlement == SettlementNone {
		if n.EVM.ChainID != 0 || len(n.EVM.RPC) != 0 || n.EVM.USDC != (USDC{}) || n.EVM.FacilitatorURL != "" {
			return cfgErr(`[network.evm] needs a settlement chain: network.settlement is "none"`)
		}
		return nil
	}
	e := n.EVM
	switch {
	case e.ChainID == 0:
		return cfgErr("network.evm.chain_id is required (set it for settlement = %q)", Custom)
	case len(e.RPC) == 0:
		return cfgErr("network.evm.rpc is empty")
	case !validEVMAddress(e.USDC.Address):
		return cfgErr("network.evm.usdc.address must be 0x and 40 hex characters")
	case e.USDC.Name == "" || e.USDC.Version == "":
		return cfgErr("network.evm.usdc.name and version are required")
	}
	for i, u := range e.RPC {
		if err := checkURL(u); err != nil {
			return cfgErr("network.evm.rpc[%d]: %v", i, err)
		}
	}
	if e.FacilitatorURL != "" {
		if err := checkURL(e.FacilitatorURL); err != nil {
			return cfgErr("network.evm.facilitator_url: %v", err)
		}
	}
	return nil
}

// ValidateBasic checks the stateless fields.
func (a Agent) ValidateBasic() error {
	switch {
	case !validID(a.ID, 64):
		return cfgErr("agent.id must be 1..64 characters of letters, digits and . _ : / -")
	case a.KeyFile == "":
		return cfgErr("agent.key_file is required")
	}
	for k, u := range map[string]string{"agent.recorder_url": a.RecorderURL, "agent.gate_url": a.GateURL} {
		if u == "" {
			continue
		}
		if err := checkURL(u); err != nil {
			return cfgErr("%s: %v", k, err)
		}
	}
	return nil
}

// ValidateBasic checks the stateless fields.
func (g Gate) ValidateBasic() error {
	switch {
	case !validID(g.GateID, 64):
		return cfgErr("gate.gate_id must be 1..64 characters of letters, digits and . _ : / -")
	case g.KeyBackend == BackendKMS:
		return cfgErr(`gate.key_backend "kms" is not available in this build`)
	case g.KeyBackend != BackendFile:
		return cfgErr(`gate.key_backend must be "file"`)
	case g.KeyFile == "":
		return cfgErr("gate.key_file is required")
	case g.RegistryPath == "":
		return cfgErr("gate.registry_path is required")
	case g.AllowlistFile == "":
		return cfgErr("gate.allowlist_file is required")
	case len(g.ActionTypes) == 0:
		return cfgErr("gate.action_types is empty")
	case len(g.ExecutorKeys) == 0:
		return cfgErr("gate.executor_keys is empty")
	}
	for i, t := range g.ActionTypes {
		if t == "" || len(t) > 128 || strings.TrimSpace(t) != t {
			return cfgErr("gate.action_types[%d] is not a media type", i)
		}
		if slices.Contains(g.ActionTypes[:i], t) {
			return cfgErr("gate.action_types[%d] is a duplicate", i)
		}
	}
	if err := checkHexKeys("gate.executor_keys", g.ExecutorKeys); err != nil {
		return err
	}
	if _, _, err := net.SplitHostPort(g.Listen); err != nil {
		return cfgErr("gate.listen is not host:port")
	}
	return nil
}

// ValidateBasic checks the stateless fields.
func (r Recorder) ValidateBasic() error {
	switch {
	case r.KeyringDir == "":
		return cfgErr("recorder.keyring_dir is required")
	case r.KeyName == "":
		return cfgErr("recorder.key_name is required")
	case r.PassphraseFile == "":
		return cfgErr("recorder.passphrase_file is required")
	case r.DA != DABlob && r.DA != DAFibre:
		return cfgErr(`recorder.da must be "celestia_blob" or "fibre"`)
	case r.MaxBlobBytes == 0:
		return cfgErr("recorder.max_blob_bytes must be above zero")
	case r.DA == DABlob && (r.OwnNode || r.EscrowHeadroomUtia != 0):
		return cfgErr(`recorder.own_node and escrow_headroom_utia need recorder.da = "fibre"`)
	}
	return checkNamespace("recorder.namespace", r.Namespace)
}

// ValidateBasic checks the stateless fields.
func (p Publisher) ValidateBasic() error {
	switch {
	case p.KeyringDir == "":
		return cfgErr("publisher.keyring_dir is required")
	case p.KeyName == "":
		return cfgErr("publisher.key_name is required")
	case p.PassphraseFile == "":
		return cfgErr("publisher.passphrase_file is required")
	}
	return checkNamespace("publisher.namespace", p.Namespace)
}

// ValidateBasic checks the stateless fields.
func (a Archive) ValidateBasic() error {
	if a.URL != "" {
		if err := checkURL(a.URL); err != nil {
			return cfgErr("archive.url: %v", err)
		}
	}
	for i, u := range a.MirrorURLs {
		if err := checkURL(u); err != nil {
			return cfgErr("archive.mirror_urls[%d]: %v", i, err)
		}
	}
	return nil
}

// ValidateBasic checks the stateless fields.
func (s Signer) ValidateBasic() error {
	if _, _, err := net.SplitHostPort(s.Listen); err != nil {
		return cfgErr("signer.listen is not host:port")
	}
	if len(s.PinnedGateKeys) == 0 {
		return cfgErr("signer.pinned_gate_keys is empty: the signer accepts no gate it was not told about")
	}
	if err := checkHexKeys("signer.pinned_gate_keys", s.PinnedGateKeys); err != nil {
		return err
	}
	switch s.PayerBackend {
	case BackendFile:
		if s.PayerKeyFile == "" {
			return cfgErr("signer.payer_key_file is required with payer_backend = file")
		}
	case BackendKMS, BackendCDP:
		return cfgErr("signer.payer_backend %q is not available in this build", s.PayerBackend)
	default:
		return cfgErr(`signer.payer_backend must be "file", "kms" or "cdp"`)
	}
	switch {
	case s.PinnedChainID == 0:
		return cfgErr("signer.pinned_chain_id is required")
	case !validEVMAddress(s.PinnedUSDC):
		return cfgErr("signer.pinned_usdc must be 0x and 40 hex characters")
	case s.PayerAddress != "" && !validEVMAddress(s.PayerAddress):
		return cfgErr("signer.payer_address must be 0x and 40 hex characters")
	case s.Risk.MaxPerPayment == 0 || s.Risk.MaxPerHour == 0:
		return cfgErr("signer.risk.max_per_payment and max_per_hour must be above zero")
	case s.Risk.MaxPerPayment > s.Risk.MaxPerHour:
		return cfgErr("signer.risk.max_per_payment above max_per_hour")
	}
	return nil
}

// ValidateBasic checks the stateless fields.
func (c Capture) ValidateBasic() error {
	switch {
	case strings.TrimSpace(c.Dir) == "":
		return cfgErr("capture.dir is required")
	case !strings.HasPrefix(c.CometRPC, "http://") && !strings.HasPrefix(c.CometRPC, "https://"):
		return cfgErr("capture.comet_rpc must be an http or https URL")
	case c.NodePruneWindowBlocks < 100 || c.NodePruneWindowBlocks > 6_000_000:
		return cfgErr("capture.node_prune_window_blocks must be 100..6000000")
	case c.RetryEveryS < 1 || c.RetryEveryS > 3600:
		return cfgErr("capture.retry_every_s must be 1..3600")
	}
	return nil
}

// ValidateBasic checks the stateless fields.
func (v Verify) ValidateBasic() error {
	for k, u := range map[string]string{"verify.headers_rpc": v.HeadersRPC, "verify.tx_rpc": v.TxRPC} {
		if u == "" {
			continue
		}
		if err := checkURL(u); err != nil {
			return cfgErr("%s: %v", k, err)
		}
	}
	for k, l := range map[string][]string{"verify.checkpoint_rpc": v.CheckpointRPC, "verify.cross_check_rpc": v.CrossCheckRPC} {
		for i, u := range l {
			if err := checkURL(u); err != nil {
				return cfgErr("%s[%d]: %v", k, i, err)
			}
		}
	}
	if v.Quorum == 0 || (len(v.CheckpointRPC) > 0 && v.Quorum > uint64(len(v.CheckpointRPC))) {
		return cfgErr("verify.quorum must be 1..number of verify.checkpoint_rpc")
	}
	return nil
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

func checkURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return fmt.Errorf("not an absolute URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("scheme must be http or https")
	}
	if u.User != nil {
		return fmt.Errorf("credentials in a URL are refused")
	}
	return nil
}

func checkHexKeys(key string, keys []string) error {
	for i, s := range keys {
		b, err := hex.DecodeString(s)
		if err != nil || len(b) != 32 {
			return cfgErr("%s[%d] must be 64 hex characters", key, i)
		}
		if slices.Contains(keys[:i], s) {
			return cfgErr("%s[%d] is a duplicate", key, i)
		}
	}
	return nil
}

func validEVMAddress(s string) bool {
	if len(s) != 42 || s[:2] != "0x" {
		return false
	}
	_, err := hex.DecodeString(s[2:])
	return err == nil
}

// checkNamespace applies the user-namespace rule: version 0, 18 zero bytes,
// and an id whose first nine bytes are not all zero.
func checkNamespace(key, s string) error {
	if s == "" {
		return cfgErr("%s is required", key)
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 29 {
		return cfgErr("%s must be 58 hex characters", key)
	}
	if b[0] != 0 || !allZero(b[1:19]) {
		return cfgErr("%s must be a version 0 namespace", key)
	}
	if allZero(b[19:28]) {
		return cfgErr("%s is in the reserved range", key)
	}
	return nil
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}
