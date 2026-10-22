// SPDX-License-Identifier: Apache-2.0

// Package signerd wires edicta-signer from its TOML file: key files, the
// store, the Eden RPC clients, the gate client for record requests and the
// HTTP API.
package signerd

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/vgonkivs/edicta/celestia/config"
	"github.com/vgonkivs/edicta/plugins/edenescrow/edenexec"
	"github.com/vgonkivs/edicta/plugins/edenescrow/edenrpc"
	"github.com/vgonkivs/edicta/signer"
	"github.com/vgonkivs/edicta/signer/eden"
)

// Config is edicta-signer.toml. Amounts are decimal strings in the chain's
// base unit (wei); keys are hex.
type Config struct {
	Listen      string `toml:"listen"`
	AllowRemote bool   `toml:"allow_remote"`
	// TokenFile holds a bearer token of the signer API shared by every
	// agent (mode 0600). Refused while the Payment-Signature is enabled:
	// then each agent has its own credential.
	TokenFile string `toml:"token_file"`
	// Credentials are bearer tokens each pinned to one agent key.
	Credentials []Credential `toml:"credential"`
	// AdminTokenFile enables the operator routes (re-queue) under their own
	// token (mode 0600).
	AdminTokenFile string `toml:"admin_token_file"`
	// TLSCertFile and TLSKeyFile serve the API over TLS; allow_remote needs
	// them unless InsecureRemoteHTTP says a TLS proxy sits in front.
	TLSCertFile        string `toml:"tls_cert_file"`
	TLSKeyFile         string `toml:"tls_key_file"`
	InsecureRemoteHTTP bool   `toml:"insecure_remote_http"`
	StorePath          string `toml:"store_path"`

	GateID        string   `toml:"gate_id"`
	GatePubKey    string   `toml:"gate_pubkey"`
	AgentPubKeys  []string `toml:"agent_pubkeys"`
	SkewS         uint64   `toml:"skew_s"`
	RefuseFast    bool     `toml:"refuse_fast"`
	RetryInterval uint64   `toml:"retry_interval_s"`

	// PaymentSignatureField is "paymentId" (the default) or "off".
	PaymentSignatureField string `toml:"payment_signature_field"`
	// CheckServerSignature requires the facilitator's signature in the
	// quote; unset is true. The Payment-Signature needs it.
	CheckServerSignature *bool `toml:"check_server_signature"`

	Caps       Caps       `toml:"caps"`
	Record     *Record    `toml:"record"`
	Settlement Settlement `toml:"settlement"`
	Broadcast  Broadcast  `toml:"broadcast"`
	Chains     []Chain    `toml:"chain"`
}

// Credential is one API token pinned to one served agent key.
type Credential struct {
	AgentPubKey string `toml:"agent_pubkey"`
	TokenFile   string `toml:"token_file"`
}

// Broadcast configures the payment server's relay.
type Broadcast struct {
	// ServerTimeoutS bounds one relay call.
	ServerTimeoutS uint64 `toml:"server_timeout_s"`
	// RelayGraceS: after it, while no source shows a relayed deposit, the
	// same bytes are also sent directly.
	RelayGraceS uint64 `toml:"relay_grace_s"`
}

// Caps are the operator's risk limits over every served chain.
type Caps struct {
	MaxValuePerAction string `toml:"max_value_per_action"`
	MaxValuePerHour   string `toml:"max_value_per_hour"`
	MaxFeePerHour     string `toml:"max_fee_per_hour"`
}

// Record enables record requests to the gate after settlement.
type Record struct {
	GateURL string `toml:"gate_url"`
	// GateTokenFile holds the gate's record token, if the gate asks for one.
	GateTokenFile string `toml:"gate_token_file"`
	// ExecutorKeyFile is the executor's raw Ed25519 seed (mode 0600); the
	// key signs record requests and nothing else.
	ExecutorKeyFile string `toml:"executor_key_file"`
	// InsecureHTTP allows a plain http gate_url to a host that is not
	// loopback.
	InsecureHTTP bool `toml:"insecure_http"`
}

// Settlement configures the wait for the rail.
type Settlement struct {
	// AwaitLevel is L1 (the default) or L2; L0, one source's word, only
	// when written here, and never with the Payment-Signature enabled.
	AwaitLevel string `toml:"await_level"`
	// MinSources is how many operators L1 needs.
	MinSources     int    `toml:"min_sources"`
	ConfirmDepth   uint64 `toml:"confirm_depth"`
	PollIntervalMS uint64 `toml:"poll_interval_ms"`
	AwaitGraceS    uint64 `toml:"await_grace_s"`
	ResendEveryS   uint64 `toml:"resend_every_s"`
}

// Chain is one served Eden chain.
type Chain struct {
	// Preset names an Eden settlement preset (eden-mainnet, eden-testnet):
	// it supplies chain_id when unset, rpc when unset (a placeholder for
	// the operator's own node, refused until replaced) and, when no
	// settlement_rpc is written, the preset's public sources.
	Preset  string `toml:"preset"`
	ChainID uint64 `toml:"chain_id"`
	// RPC is the signer's own Eden JSON-RPC: code checks, nonce, sends,
	// and the first settlement source. RPC and SettlementRPC take a URL or
	// OPERATOR=URL; without a label the host stands in for the operator.
	RPC     string `toml:"rpc"`
	OwnNode bool   `toml:"own_node"`
	// SettlementRPC are more settlement sources, distinct hosts.
	SettlementRPC []string `toml:"settlement_rpc"`
	// Broadcaster is "houston-relay" (the default) or "direct".
	Broadcaster string `toml:"broadcaster"`
	// RelayURL is the payment server (https) whose /deposit/send relays
	// the deposit.
	RelayURL        string   `toml:"relay_url"`
	PayerKeyFile    string   `toml:"payer_key_file"`
	PayerAddress    string   `toml:"payer_address"`
	Facilitators    []string `toml:"facilitators"`
	MaxRefundDelayS uint64   `toml:"max_refund_delay_s"`
	MaxFeePerGas    string   `toml:"max_fee_per_gas"`
	MaxGas          uint64   `toml:"max_gas"`
	MaxFeePerAction string   `toml:"max_fee_per_action"`
}

// DefaultListen is the loopback port of the signer API.
const DefaultListen = "127.0.0.1:8402"

// ParseConfig reads the TOML; unknown keys are refused.
func ParseConfig(data []byte) (Config, error) {
	var c Config
	if err := toml.NewDecoder(bytes.NewReader(data)).DisallowUnknownFields().Decode(&c); err != nil {
		return Config{}, fmt.Errorf("signerd: config: %w", err)
	}
	return c, nil
}

// ApplyDefaults fills the zero fields that have defaults.
func (c *Config) ApplyDefaults() {
	if c.Listen == "" {
		c.Listen = DefaultListen
	}
	if c.SkewS == 0 {
		c.SkewS = signer.DefaultSkewS
	}
	if c.RetryInterval == 0 {
		c.RetryInterval = uint64(signer.DefaultRetryInterval / time.Second)
	}
	if c.PaymentSignatureField == "" {
		c.PaymentSignatureField = eden.FieldPaymentID
	}
	if c.CheckServerSignature == nil {
		on := true
		c.CheckServerSignature = &on
	}
	s := &c.Settlement
	if s.AwaitLevel == "" {
		s.AwaitLevel = edenexec.DefaultMinLevel.String()
	}
	if s.MinSources == 0 {
		s.MinSources = edenexec.DefaultMinSources
	}
	if s.ConfirmDepth == 0 {
		s.ConfirmDepth = edenexec.DefaultConfirmDepth
	}
	if s.PollIntervalMS == 0 {
		s.PollIntervalMS = uint64(edenexec.DefaultPollInterval / time.Millisecond)
	}
	if s.AwaitGraceS == 0 {
		s.AwaitGraceS = uint64(edenexec.DefaultAwaitGrace / time.Second)
	}
	if s.ResendEveryS == 0 {
		s.ResendEveryS = uint64(eden.DefaultResendEvery / time.Second)
	}
	b := &c.Broadcast
	if b.ServerTimeoutS == 0 {
		b.ServerTimeoutS = uint64(eden.DefaultServerTimeout / time.Second)
	}
	if b.RelayGraceS == 0 {
		b.RelayGraceS = min(uint64(eden.DefaultRelayGrace/time.Second), s.AwaitGraceS)
	}
	for i := range c.Chains {
		c.Chains[i].applyPreset()
		if c.Chains[i].Broadcaster == "" {
			c.Chains[i].Broadcaster = eden.BroadcastRelay
		}
	}
}

// escrowPreset resolves Preset; an unset one is not an error.
func (ch Chain) escrowPreset() (config.Preset, error) {
	if ch.Preset == "" {
		return config.Preset{}, nil
	}
	sp, err := (config.Builtin{}).Settlement(ch.Preset)
	switch {
	case err != nil:
		return config.Preset{}, fmt.Errorf("signerd: chain preset: %w", err)
	case !sp.IsEscrow():
		return config.Preset{}, fmt.Errorf("signerd: chain preset %q is not an Eden preset (eden-mainnet, eden-testnet)", ch.Preset)
	}
	return sp, nil
}

// applyPreset fills what the file left unset from the chain's preset. An
// unknown preset is left for ValidateBasic to refuse.
func (ch *Chain) applyPreset() {
	sp, err := ch.escrowPreset()
	if err != nil || ch.Preset == "" {
		return
	}
	if ch.ChainID == 0 {
		ch.ChainID = sp.EVMChainID
	}
	if len(sp.RPC) == 0 {
		return
	}
	if ch.RPC == "" {
		ch.RPC = sp.RPC[0]
	}
	// The preset's public sources stand in for the second operator that L1
	// needs; the first entry is the operator's own node.
	if len(ch.SettlementRPC) == 0 {
		ch.SettlementRPC = slices.Clone(sp.RPC[1:])
	}
}

// PaymentSignatureEnabled: field paymentId and the server-signature check.
func (c Config) PaymentSignatureEnabled() bool {
	return c.PaymentSignatureField == eden.FieldPaymentID && (c.CheckServerSignature == nil || *c.CheckServerSignature)
}

// awaitSources are the chain's Await sources: its own RPC first.
func (ch Chain) awaitSources() []string { return append([]string{ch.RPC}, ch.SettlementRPC...) }

// operatorOf is a source's operator: its label, or its host standing in.
func operatorOf(src string) (op string, explicit bool) {
	label, raw := edenrpc.SplitSource(src)
	if label != "" {
		return label, true
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw, false
	}
	return strings.TrimSuffix(strings.ToLower(u.Hostname()), "."), false
}

// ValidateBasic checks every stateless rule by building the signer and
// handler configurations from the file.
func (c Config) ValidateBasic() error {
	if err := signer.CheckBind(c.Listen, c.AllowRemote); err != nil {
		return err
	}
	switch {
	case c.TokenFile == "" && len(c.Credentials) == 0:
		return errors.New("signerd: token_file or a [[credential]] is required: the API never runs without a token")
	case c.StorePath == "":
		return errors.New("signerd: store_path is required")
	}
	if err := c.checkCredentials(); err != nil {
		return err
	}
	level, err := edenexec.ParseLevel(c.Settlement.AwaitLevel)
	if err != nil {
		return fmt.Errorf("signerd: settlement.await_level: %w", err)
	}
	if c.PaymentSignatureEnabled() && level < edenexec.LevelMultiSource {
		return fmt.Errorf("signerd: settlement.await_level %s: the Payment-Signature needs %s (or payment_signature_field = \"off\")",
			level, edenexec.LevelMultiSource)
	}
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return errors.New("signerd: tls_cert_file and tls_key_file go together")
	}
	// Off the loopback the token and the signed transactions would travel
	// in clear text; anyone on the path could reuse the token.
	if c.AllowRemote && c.TLSCertFile == "" && !c.InsecureRemoteHTTP {
		return errors.New("signerd: allow_remote needs tls_cert_file and tls_key_file (or insecure_remote_http = true behind a TLS proxy)")
	}
	if c.AdminTokenFile != "" && c.AdminTokenFile == c.TokenFile {
		return errors.New("signerd: admin_token_file is token_file: the operator routes need their own token")
	}
	for i, cr := range c.Credentials {
		if c.AdminTokenFile != "" && cr.TokenFile == c.AdminTokenFile {
			return fmt.Errorf("signerd: credential %d uses admin_token_file: the operator routes need their own token", i)
		}
	}
	if c.Record != nil {
		if err := checkURL(c.Record.GateURL); err != nil {
			return fmt.Errorf("signerd: record.gate_url: %w", err)
		}
		if u, _ := url.Parse(c.Record.GateURL); u.Scheme == "http" && !signer.IsLoopbackHost(u.Hostname()) && !c.Record.InsecureHTTP {
			return errors.New("signerd: record.gate_url is plain http to a host that is not loopback; use https (or record.insecure_http = true)")
		}
		if c.Record.ExecutorKeyFile == "" {
			return errors.New("signerd: record.executor_key_file is required")
		}
	}
	sc, err := c.SignerConfig()
	if err != nil {
		return err
	}
	hc, err := c.HandlerConfig()
	if err != nil {
		return err
	}
	if err := c.SettlementConfig().ValidateBasic(); err != nil {
		return fmt.Errorf("signerd: settlement: %w", err)
	}
	for _, p := range hc.Chains {
		if p.MaxFeePerAction.Cmp(sc.Caps.MaxFeePerHour) > 0 {
			return fmt.Errorf("signerd: chain %d: max_fee_per_action above caps.max_fee_per_hour refuses every deposit", p.ChainID)
		}
	}
	seen := map[string]uint64{}
	for _, ch := range c.Chains {
		sp, err := ch.escrowPreset()
		if err != nil {
			return err
		}
		if ch.Preset != "" && ch.ChainID != sp.EVMChainID {
			return fmt.Errorf("signerd: chain %d: preset %q is for chain %d", ch.ChainID, ch.Preset, sp.EVMChainID)
		}
		for _, src := range ch.awaitSources() {
			if config.IsPlaceholder(src) {
				return fmt.Errorf("signerd: chain %d: %q is a placeholder: set your own node in rpc (own_node = true) and real settlement_rpc sources", ch.ChainID, src)
			}
		}
		if ch.PayerKeyFile == "" {
			return fmt.Errorf("signerd: chain %d: payer_key_file is required", ch.ChainID)
		}
		if other, dup := seen[ch.PayerKeyFile]; dup {
			return fmt.Errorf("signerd: chains %d and %d share one payer key file: use one payer key per chain", other, ch.ChainID)
		}
		seen[ch.PayerKeyFile] = ch.ChainID
		ops := map[string]bool{}
		for _, src := range ch.awaitSources() {
			op, u := edenrpc.SplitSource(src)
			if err := checkURL(u); err != nil {
				return fmt.Errorf("signerd: chain %d: rpc: %w", ch.ChainID, err)
			}
			rc := edenrpc.Config{URL: u, Class: edenexec.ClassPublicRPC, Operator: op}
			rc.ApplyDefaults()
			if err := rc.ValidateBasic(); err != nil {
				return fmt.Errorf("signerd: chain %d: rpc: %w", ch.ChainID, err)
			}
			name, explicit := operatorOf(src)
			// A host standing in as the label cannot tell two hosts in
			// front of one node apart.
			if c.PaymentSignatureEnabled() && !explicit {
				return fmt.Errorf("signerd: chain %d: source %q has no OPERATOR= label; the Payment-Signature needs one on every source", ch.ChainID, u)
			}
			ops[name] = true
		}
		// At L1 fewer operators never reach an outcome: nothing would ever
		// be recorded or paid for.
		if level >= edenexec.LevelMultiSource && len(ops) < c.Settlement.MinSources {
			return fmt.Errorf("signerd: chain %d: %d distinct operators, await_level %s needs %d (add settlement_rpc or set await_level = \"L0\")",
				ch.ChainID, len(ops), level, c.Settlement.MinSources)
		}
		if ch.Broadcaster == eden.BroadcastRelay {
			hc := ch.relayConfig(c.Broadcast)
			if err := hc.ValidateBasic(); err != nil {
				return fmt.Errorf("signerd: chain %d: relay_url: %w", ch.ChainID, err)
			}
		} else if ch.RelayURL != "" {
			return fmt.Errorf("signerd: chain %d: relay_url set but broadcaster is %q", ch.ChainID, ch.Broadcaster)
		}
		if c.Record != nil && ch.PayerKeyFile == c.Record.ExecutorKeyFile {
			return fmt.Errorf("signerd: chain %d: the payer key file is the executor key file", ch.ChainID)
		}
	}
	return nil
}

// checkCredentials: each credential has its own token file and is pinned
// to a served agent key; a shared token_file is refused while the
// Payment-Signature is enabled, since the decision's material is public and
// only the credential tells one agent from another.
func (c Config) checkCredentials() error {
	if c.PaymentSignatureEnabled() && c.TokenFile != "" {
		return errors.New("signerd: token_file is shared by every agent; the Payment-Signature needs one [[credential]] per agent")
	}
	files := map[string]int{}
	if c.TokenFile != "" {
		files[c.TokenFile] = -1
	}
	for i, cr := range c.Credentials {
		if cr.TokenFile == "" {
			return fmt.Errorf("signerd: credential %d: token_file is required", i)
		}
		if j, dup := files[cr.TokenFile]; dup {
			return fmt.Errorf("signerd: credential %d shares its token file with %d", i, j)
		}
		files[cr.TokenFile] = i
		k, err := hexKey(fmt.Sprintf("credential %d agent_pubkey", i), cr.AgentPubKey)
		if err != nil {
			return err
		}
		served := false
		for _, a := range c.AgentPubKeys {
			if b, err := hexKey("agent_pubkeys", a); err == nil && bytes.Equal(b, k) {
				served = true
			}
		}
		if !served {
			return fmt.Errorf("signerd: credential %d is pinned to an agent key not in agent_pubkeys", i)
		}
	}
	return nil
}

func (ch Chain) relayConfig(b Broadcast) eden.HoustonConfig {
	hc := eden.HoustonConfig{BaseURL: ch.RelayURL, Timeout: time.Duration(b.ServerTimeoutS) * time.Second}
	hc.ApplyDefaults()
	return hc
}

func checkURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return errors.New("must be an absolute http or https URL")
	}
	return nil
}

func amount(name, s string) (*big.Int, error) {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok || v.Sign() <= 0 || strings.TrimSpace(s) != s {
		return nil, fmt.Errorf("signerd: %s %q is not a positive decimal integer", name, s)
	}
	return v, nil
}

func hexKey(name, s string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || len(b) != 32 {
		return nil, fmt.Errorf("signerd: %s must be 32 bytes of hex", name)
	}
	return b, nil
}

func address(name, s string) ([20]byte, error) {
	var a [20]byte
	h, ok := strings.CutPrefix(s, "0x")
	b, err := hex.DecodeString(h)
	if !ok || err != nil || len(b) != 20 {
		return a, fmt.Errorf("signerd: %s %q must be 0x and 40 hex characters", name, s)
	}
	copy(a[:], b)
	return a, nil
}

// SignerConfig is the rail-agnostic part of the file.
func (c Config) SignerConfig() (signer.Config, error) {
	gk, err := hexKey("gate_pubkey", c.GatePubKey)
	if err != nil {
		return signer.Config{}, err
	}
	agents := make([][]byte, 0, len(c.AgentPubKeys))
	for i, s := range c.AgentPubKeys {
		k, err := hexKey(fmt.Sprintf("agent_pubkeys[%d]", i), s)
		if err != nil {
			return signer.Config{}, err
		}
		agents = append(agents, k)
	}
	var caps signer.Caps
	for _, f := range []struct {
		name string
		s    string
		dst  **big.Int
	}{
		{"caps.max_value_per_action", c.Caps.MaxValuePerAction, &caps.MaxValuePerAction},
		{"caps.max_value_per_hour", c.Caps.MaxValuePerHour, &caps.MaxValuePerHour},
		{"caps.max_fee_per_hour", c.Caps.MaxFeePerHour, &caps.MaxFeePerHour},
	} {
		v, err := amount(f.name, f.s)
		if err != nil {
			return signer.Config{}, err
		}
		*f.dst = v
	}
	sc := signer.Config{
		GateID: c.GateID, GatePubKey: gk, AgentKeys: agents, SkewS: c.SkewS, RefuseFast: c.RefuseFast, Caps: caps,
		RetryInterval: time.Duration(c.RetryInterval) * time.Second,
	}
	sc.ApplyDefaults()
	return sc, sc.ValidateBasic()
}

// HandlerConfig is the form T handler's part of the file.
func (c Config) HandlerConfig() (eden.Config, error) {
	hc := eden.Config{
		AwaitGrace:            time.Duration(c.Settlement.AwaitGraceS) * time.Second,
		ResendEvery:           time.Duration(c.Settlement.ResendEveryS) * time.Second,
		RelayGrace:            time.Duration(c.Broadcast.RelayGraceS) * time.Second,
		PaymentSignatureField: c.PaymentSignatureField,
		CheckServerSignature:  c.CheckServerSignature,
	}
	for _, ch := range c.Chains {
		payer, err := address(fmt.Sprintf("chain %d payer_address", ch.ChainID), ch.PayerAddress)
		if err != nil {
			return eden.Config{}, err
		}
		p := eden.ChainPins{
			ChainID: ch.ChainID, Payer: payer, MaxRefundDelay: ch.MaxRefundDelayS, MaxGas: ch.MaxGas, Broadcast: ch.Broadcaster,
		}
		for i, f := range ch.Facilitators {
			a, err := address(fmt.Sprintf("chain %d facilitators[%d]", ch.ChainID, i), f)
			if err != nil {
				return eden.Config{}, err
			}
			p.Facilitators = append(p.Facilitators, a)
		}
		if p.MaxFeePerGas, err = amount(fmt.Sprintf("chain %d max_fee_per_gas", ch.ChainID), ch.MaxFeePerGas); err != nil {
			return eden.Config{}, err
		}
		if p.MaxFeePerAction, err = amount(fmt.Sprintf("chain %d max_fee_per_action", ch.ChainID), ch.MaxFeePerAction); err != nil {
			return eden.Config{}, err
		}
		hc.Chains = append(hc.Chains, p)
	}
	hc.ApplyDefaults()
	return hc, hc.ValidateBasic()
}

// SettlementConfig is the edenexec configuration of Await. An await_level
// that does not parse is left unset, which ValidateBasic refuses.
func (c Config) SettlementConfig() edenexec.Config {
	level, _ := edenexec.ParseLevel(c.Settlement.AwaitLevel)
	sc := edenexec.Config{
		MinLevel:     level,
		MinSources:   c.Settlement.MinSources,
		ConfirmDepth: c.Settlement.ConfirmDepth,
		PollInterval: time.Duration(c.Settlement.PollIntervalMS) * time.Millisecond,
		AwaitGrace:   time.Duration(c.Settlement.AwaitGraceS) * time.Second,
	}
	sc.ApplyDefaults()
	return sc
}
