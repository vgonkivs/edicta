package main

import (
	"crypto/ecdh"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/vgonkivs/edicta/celestia/inclusion"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/sdk/blob"
)

// ErrConfig wraps every refusal of the flags. Messages name flags, never values
// that could be secret.
var ErrConfig = errors.New("edicta-live: invalid configuration")

const (
	defaultThresholdBP = 100
	defaultSkewS       = 30
)

// Config is everything the run is told. Secrets are only ever paths of files
// (or a request for a no-echo prompt).
type Config struct {
	// edictad
	APIURL          string
	APITokenFile    string
	RecordTokenFile string // empty: same token as APITokenFile
	GateID          string // optional pin
	GatePubKey      string // optional pin, hex
	Namespace       string // optional pin, hex

	// chain access
	BridgeAddr      string
	BridgeTokenFile string
	BridgeTLS       bool
	GRPCAddr        string
	GRPCTokenFile   string
	GRPCTLS         bool
	ChainID         string // optional cross-check
	DA              string // blob or fibre; must equal edictad's
	MinAppVersion   uint64
	MaxAppVersion   uint64

	// inclusion check
	Inclusion      string // self, light or crosscheck
	RPCPrimary     string
	RPCWitnesses   []string
	TrustHeight    uint64
	TrustHash      string
	TrustPeriod    time.Duration
	CrossBridges   []string
	CrossTokenFile string
	CrossTLS       bool
	PublishWait    time.Duration

	// fast mode
	Fast       bool
	ArchiveURL string // where fast mode reads the anchor intent

	// agent
	AgentID         string
	AgentKeyFile    string // 32 raw bytes
	Recipients      []string
	GenRecipient    string // path to create
	StrategyID      string
	Reason          string
	ThresholdBP     uint64
	MaxDecisions    int
	PollInterval    time.Duration
	Timeout         time.Duration
	SkewS           uint64
	PriceSource     string
	PriceBaseURL    string
	PriceAsset      string
	PriceQuote      string
	KrakenPair      string
	UpAddr          string
	UpAmount        uint64
	DownAddr        string
	DownAmount      uint64
	DryRun          bool
	JSONOut         bool
	EvidenceFile    string
	ExecKeyringDir  string
	ExecKeyName     string
	ExecPassFile    string
	ExecPassPrompt  bool
	ExecEd25519File string // 32 raw bytes, signs the record request
	GasLimit        uint64
	Fee             uint64 // 0: derive from the node's minimum gas price
	FeeMargin       string // decimal factor on the derived fee; "" or "0": railtx.DefaultFeeMargin
	MaxFee          uint64
	Rebroadcast     time.Duration
	IndexerLag      int           // 0: the executor default
	ConfirmDelay    time.Duration // 0: the executor default
}

type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error {
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*l = append(*l, p)
		}
	}
	return nil
}

// blobOnlyFlags configure the blob inclusion checks, which da=fibre does not
// run. Accepting them would let an operator believe a light-client check ran.
var blobOnlyFlags = map[string]bool{
	"inclusion": true, "rpc-primary": true, "rpc-witness": true,
	"trust-height": true, "trust-hash": true, "crosscheck-bridge": true,
	"trust-period": true, "crosscheck-token-file": true, "crosscheck-tls": true,
}

// parseFlags parses args (without the program name) and validates the result.
func parseFlags(args []string, usage io.Writer) (Config, error) {
	var c Config
	fs := flag.NewFlagSet("edicta-live", flag.ContinueOnError)
	fs.SetOutput(usage)

	fs.StringVar(&c.APIURL, "api-url", "", "edictad base URL, for example http://127.0.0.1:8080")
	fs.StringVar(&c.APITokenFile, "api-token-file", "", "file with edictad's bearer token (authorize; also record unless --record-token-file)")
	fs.StringVar(&c.RecordTokenFile, "record-token-file", "", "file with edictad's record bearer token, if it differs")
	fs.StringVar(&c.GateID, "gate-id", "", "pin the gate id (default: learned from edictad)")
	fs.StringVar(&c.GatePubKey, "gate-pubkey", "", "pin the gate Ed25519 public key, 64 hex (default: learned from edictad; pinning is strongly advised)")
	fs.StringVar(&c.Namespace, "namespace", "", "pin the blob namespace, 58 hex (default: learned from edictad)")

	fs.StringVar(&c.BridgeAddr, "bridge-addr", "", "bridge node JSON-RPC address (reads, proofs)")
	fs.StringVar(&c.BridgeTokenFile, "bridge-token-file", "", "file with the bridge node auth token")
	fs.BoolVar(&c.BridgeTLS, "bridge-tls", false, "use TLS to the bridge node")
	fs.StringVar(&c.GRPCAddr, "grpc-addr", "", "consensus node gRPC address (account, broadcast, tx lookup)")
	fs.StringVar(&c.GRPCTokenFile, "grpc-token-file", "", "file with the consensus gRPC token")
	fs.BoolVar(&c.GRPCTLS, "grpc-tls", false, "use TLS to the consensus gRPC endpoint")
	fs.StringVar(&c.DA, "da", "blob", "data availability mode edictad runs: blob or fibre")
	fs.StringVar(&c.ChainID, "chain-id", "", "optional: refuse a node on another chain id")
	fs.Uint64Var(&c.MinAppVersion, "min-app-version", 0, "compatibility check lower bound (0 = default)")
	fs.Uint64Var(&c.MaxAppVersion, "max-app-version", 0, "compatibility check upper bound (0 = default)")

	fs.StringVar(&c.Inclusion, "inclusion", "self", "inclusion check: self (same operator), light (validator signatures) or crosscheck")
	fs.StringVar(&c.RPCPrimary, "rpc-primary", "", "light: CometBFT RPC URL of the primary provider")
	var wit listFlag
	fs.Var(&wit, "rpc-witness", "light: CometBFT RPC URL of a witness from another operator (repeatable or comma separated)")
	fs.Uint64Var(&c.TrustHeight, "trust-height", 0, "light: trusted height")
	fs.StringVar(&c.TrustHash, "trust-hash", "", "light: trusted header hash at --trust-height, 64 hex")
	fs.DurationVar(&c.TrustPeriod, "trust-period", 24*time.Hour, "light: trusting period (below the unbonding time)")
	var cb listFlag
	fs.Var(&cb, "crosscheck-bridge", "crosscheck: an independent bridge node address (at least two; repeatable)")
	fs.StringVar(&c.CrossTokenFile, "crosscheck-token-file", "", "crosscheck: auth token file shared by the --crosscheck-bridge nodes")
	fs.BoolVar(&c.CrossTLS, "crosscheck-tls", false, "crosscheck: TLS to the --crosscheck-bridge nodes")
	fs.DurationVar(&c.PublishWait, "publish-wait", 0, "bound of one publication attempt (0 = SDK default)")
	fs.BoolVar(&c.Fast, "fast", false, "sign a pending reference edictad's Recorder returns, after checking its anchor intent through --grpc-addr (and --bridge-addr for da=blob); needs --archive-url")
	fs.StringVar(&c.ArchiveURL, "archive-url", "", "fast mode: base URL of the archive edictad writes, read for the anchor intent")

	fs.StringVar(&c.AgentID, "agent-id", "", "agent id on edictad's allowlist")
	fs.StringVar(&c.AgentKeyFile, "agent-key-file", "", "agent Ed25519 key: file of exactly 32 raw seed bytes, mode 0600")
	var rec listFlag
	fs.Var(&rec, "recipient", "payload recipient as kid=<64 hex X25519 public key> (repeatable)")
	fs.StringVar(&c.GenRecipient, "gen-recipient-key", "", "create a new recipient key file at this path (mode 0600, must not exist) and add it")
	fs.StringVar(&c.StrategyID, "strategy-id", "tia-band-live", "strategy id carried in the context")
	fs.StringVar(&c.Reason, "reason", "", "optional free-text reason carried in the context")
	fs.Uint64Var(&c.ThresholdBP, "threshold-bp", defaultThresholdBP, "move in basis points that triggers a decision (100 = 1%)")
	fs.IntVar(&c.MaxDecisions, "max-decisions", 1, "stop after this many decisions")
	fs.DurationVar(&c.PollInterval, "poll-interval", 30*time.Second, "price poll interval")
	fs.DurationVar(&c.Timeout, "timeout", 30*time.Minute, "overall time limit of the run")
	fs.Uint64Var(&c.SkewS, "skew", defaultSkewS, "clock skew in seconds; must equal the gate's")
	fs.StringVar(&c.PriceSource, "price-source", "coingecko", "price source: coingecko or kraken")
	fs.StringVar(&c.PriceBaseURL, "price-base-url", "", "override the price source base URL")
	fs.StringVar(&c.PriceAsset, "asset", "celestia", "asset id (coingecko id; label for kraken)")
	fs.StringVar(&c.PriceQuote, "quote", "USD", "quote currency, upper case")
	fs.StringVar(&c.KrakenPair, "kraken-pair", "TIAUSD", "kraken: ticker pair")
	fs.StringVar(&c.UpAddr, "up-addr", "", "destination when the price moves up")
	fs.Uint64Var(&c.UpAmount, "up-amount", 0, "amount in base units (utia) when up")
	fs.StringVar(&c.DownAddr, "down-addr", "", "destination when the price moves down")
	fs.Uint64Var(&c.DownAmount, "down-amount", 0, "amount in base units (utia) when down")
	fs.BoolVar(&c.DryRun, "dry-run", false, "do everything except broadcast the transfer and record it")
	fs.BoolVar(&c.JSONOut, "json", false, "print the evidence as JSON instead of text")
	fs.StringVar(&c.EvidenceFile, "evidence-file", "", "also write the evidence JSON to this file")

	fs.StringVar(&c.ExecKeyringDir, "executor-keyring-dir", "", "executor keyring directory (file backend; not the Recorder's)")
	fs.StringVar(&c.ExecKeyName, "executor-key", "", "executor key name in that keyring")
	fs.StringVar(&c.ExecPassFile, "executor-passphrase-file", "", "file with the keyring passphrase")
	fs.BoolVar(&c.ExecPassPrompt, "executor-passphrase-prompt", false, "ask for the keyring passphrase on the terminal, no echo")
	fs.StringVar(&c.ExecEd25519File, "executor-ed25519-file", "", "executor Ed25519 key for record requests: 32 raw seed bytes, mode 0600; its public key must be in edictad's executor_keys")
	fs.Uint64Var(&c.GasLimit, "gas-limit", 150000, "gas limit of the transfer")
	fs.Uint64Var(&c.Fee, "fee", 0, "fee in base units (utia); 0 derives it from the node's minimum gas price")
	fs.StringVar(&c.FeeMargin, "fee-margin", "", "decimal factor on the node's minimum gas price when --fee is 0 (default 1.2)")
	fs.Uint64Var(&c.MaxFee, "max-fee", 1000, "the executor refuses to sign a fee above this")
	fs.DurationVar(&c.Rebroadcast, "rebroadcast-every", 10*time.Second, "resend interval of the same signed bytes")
	fs.IntVar(&c.IndexerLag, "indexer-lag-blocks", 0, "blocks past the timeout height the status node may lag before a missing tx counts as lost (0 = default 3)")
	fs.DurationVar(&c.ConfirmDelay, "confirm-delay", 0, "wait before the second status query of that final check; at most --rebroadcast-every (0 = default 2s)")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if fs.NArg() != 0 {
		return Config{}, cfgErr("unexpected arguments %q", fs.Args())
	}
	if c.DA == "fibre" {
		var set []string
		fs.Visit(func(f *flag.Flag) {
			if blobOnlyFlags[f.Name] {
				set = append(set, "--"+f.Name)
			}
		})
		if len(set) > 0 {
			sort.Strings(set)
			return Config{}, cfgErr("%s applies to --da blob only; da=fibre uses the same-operator Fibre check", strings.Join(set, ", "))
		}
	}
	c.RPCWitnesses, c.CrossBridges, c.Recipients = wit, cb, rec
	if c.BridgeAddr != "" {
		u, err := node.BridgeURL(c.BridgeAddr, c.BridgeTLS)
		if err != nil {
			return Config{}, cfgErr("--bridge-addr: %v", err)
		}
		c.BridgeAddr = u
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// bridgeID is the normalized host of a bridge address: two addresses on one
// host are one provider, whatever their port, scheme or path.
func bridgeID(addr string, tls bool) (string, error) {
	raw, err := node.BridgeURL(addr, tls)
	if err != nil {
		return "", err
	}
	return inclusion.SourceHost(raw)
}

func cfgErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrConfig, fmt.Sprintf(format, a...))
}

// validateInclusion checks the blob inclusion mode and its fields.
func (c Config) validateInclusion() error {
	switch c.Inclusion {
	case "self":
	case "light":
		switch {
		case c.RPCPrimary == "":
			return cfgErr("--inclusion light needs --rpc-primary")
		case len(c.RPCWitnesses) == 0:
			return cfgErr("--inclusion light needs at least one --rpc-witness")
		case c.TrustHeight == 0:
			return cfgErr("--inclusion light needs --trust-height")
		case !isHexLen(c.TrustHash, 32):
			return cfgErr("--inclusion light needs --trust-hash of 64 hex characters")
		case c.TrustPeriod <= 0:
			return cfgErr("--trust-period must be positive")
		}
	case "crosscheck":
		if len(c.CrossBridges) < 2 {
			return cfgErr("--inclusion crosscheck needs at least two --crosscheck-bridge")
		}
		own, err := bridgeID(c.BridgeAddr, c.BridgeTLS)
		if err != nil {
			return cfgErr("--bridge-addr: %v", err)
		}
		urls := make([]string, 0, len(c.CrossBridges))
		for _, a := range c.CrossBridges {
			u, err := node.BridgeURL(a, c.CrossTLS)
			if err != nil {
				return cfgErr("--crosscheck-bridge %s: %v", a, err)
			}
			urls = append(urls, u)
		}
		if err := inclusion.CheckDistinctSources(urls); err != nil {
			return cfgErr("--crosscheck-bridge: %v", err)
		}
		independent := 0
		for _, a := range c.CrossBridges {
			id, err := bridgeID(a, c.CrossTLS)
			if err != nil {
				return cfgErr("--crosscheck-bridge %s: %v", a, err)
			}
			if id != own {
				independent++
			}
		}
		if independent < 2 {
			return cfgErr("--inclusion crosscheck needs at least two --crosscheck-bridge other than --bridge-addr")
		}
		if c.CrossTokenFile != "" && !c.CrossTLS {
			for _, a := range c.CrossBridges {
				if !loopbackAddr(a) {
					return cfgErr("--crosscheck-token-file over plain HTTP to a non-loopback address is refused; set --crosscheck-tls")
				}
			}
		}
	default:
		return cfgErr("--inclusion must be self, light or crosscheck")
	}
	return nil
}

// Validate checks the configuration without touching the network or files.
func (c Config) Validate() error {
	u, err := url.Parse(c.APIURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return cfgErr("--api-url must be an absolute http or https URL")
	}
	if c.APITokenFile != "" && u.Scheme == "http" && !loopbackHost(u.Hostname()) {
		return cfgErr("--api-token-file over plain HTTP to a non-loopback host is refused; use https")
	}
	if c.RecordTokenFile != "" && u.Scheme == "http" && !loopbackHost(u.Hostname()) {
		return cfgErr("--record-token-file over plain HTTP to a non-loopback host is refused; use https")
	}
	if c.GateID != "" && !validID(c.GateID) {
		return cfgErr("--gate-id is not a valid id")
	}
	if c.GatePubKey != "" && !isHexLen(c.GatePubKey, 32) {
		return cfgErr("--gate-pubkey must be 64 hex characters")
	}
	if c.Namespace != "" && !isHexLen(c.Namespace, 29) {
		return cfgErr("--namespace must be 58 hex characters")
	}

	if c.BridgeAddr == "" {
		return cfgErr("--bridge-addr is required")
	}
	if _, err := node.BridgeURL(c.BridgeAddr, c.BridgeTLS); err != nil {
		return cfgErr("--bridge-addr: %v", err)
	}
	if c.BridgeTokenFile != "" && !c.BridgeTLS && !loopbackAddr(c.BridgeAddr) {
		return cfgErr("--bridge-token-file over plain HTTP to a non-loopback address is refused; set --bridge-tls")
	}
	if c.GRPCAddr == "" {
		return cfgErr("--grpc-addr is required")
	}
	if c.GRPCTokenFile != "" && !c.GRPCTLS && !loopbackAddr(c.GRPCAddr) {
		return cfgErr("--grpc-token-file over plain gRPC to a non-loopback address is refused; set --grpc-tls")
	}
	if c.DA != "" && c.DA != "blob" && c.DA != "fibre" {
		return cfgErr("--da must be blob or fibre")
	}
	if c.MinAppVersion != 0 && c.MaxAppVersion != 0 && c.MinAppVersion > c.MaxAppVersion {
		return cfgErr("--min-app-version above --max-app-version")
	}

	// da=fibre runs the same-operator Fibre check and reads none of the blob
	// inclusion fields.
	if c.DA != "fibre" {
		if err := c.validateInclusion(); err != nil {
			return err
		}
	} else if c.Inclusion != "" && c.Inclusion != "self" ||
		c.RPCPrimary != "" || len(c.RPCWitnesses) > 0 || c.TrustHeight != 0 || c.TrustHash != "" ||
		len(c.CrossBridges) > 0 || c.CrossTokenFile != "" || c.CrossTLS {
		return cfgErr("blob inclusion settings apply to --da blob only; da=fibre uses the same-operator Fibre check")
	}
	if c.PublishWait < 0 {
		return cfgErr("--publish-wait is negative")
	}
	if err := c.validateFast(); err != nil {
		return err
	}

	if !validID(c.AgentID) {
		return cfgErr("--agent-id is required (1..64 characters of letters, digits and . _ : / -)")
	}
	if c.AgentKeyFile == "" {
		return cfgErr("--agent-key-file is required")
	}
	if len(c.Recipients) == 0 && c.GenRecipient == "" {
		return cfgErr("give at least one --recipient or --gen-recipient-key")
	}
	for i, r := range c.Recipients {
		if _, err := parseRecipient(r); err != nil {
			return cfgErr("--recipient #%d: %v", i+1, err)
		}
	}
	if !validID(c.StrategyID) || len(c.StrategyID) > 64 {
		return cfgErr("--strategy-id is not a valid id")
	}
	if c.ThresholdBP < 1 || c.ThresholdBP > 10000 {
		return cfgErr("--threshold-bp must be 1..10000")
	}
	if c.MaxDecisions < 1 {
		return cfgErr("--max-decisions must be at least 1")
	}
	if c.PollInterval < time.Second {
		return cfgErr("--poll-interval must be at least 1s")
	}
	if c.Timeout <= 0 {
		return cfgErr("--timeout must be positive")
	}
	if c.SkewS > 300 {
		return cfgErr("--skew above 300")
	}

	switch c.PriceSource {
	case "coingecko":
	case "kraken":
		if c.KrakenPair == "" {
			return cfgErr("--price-source kraken needs --kraken-pair")
		}
	default:
		return cfgErr("--price-source must be coingecko or kraken")
	}
	if c.PriceAsset == "" {
		return cfgErr("--asset is required")
	}
	if n := len(c.PriceQuote); n < 3 || n > 5 || c.PriceQuote != strings.ToUpper(c.PriceQuote) {
		return cfgErr("--quote must be an upper-case currency code")
	}
	if c.PriceBaseURL != "" {
		pu, err := url.Parse(c.PriceBaseURL)
		if err != nil || pu.Host == "" || (pu.Scheme != "http" && pu.Scheme != "https") {
			return cfgErr("--price-base-url must be an absolute http or https URL")
		}
	}

	if c.UpAddr == "" || c.DownAddr == "" {
		return cfgErr("--up-addr and --down-addr are required")
	}
	if c.UpAmount == 0 || c.DownAmount == 0 {
		return cfgErr("--up-amount and --down-amount must be above zero")
	}
	if c.UpAmount > 1<<63-1 || c.DownAmount > 1<<63-1 {
		return cfgErr("amount above 2^63-1")
	}

	if c.ExecKeyringDir == "" || c.ExecKeyName == "" {
		return cfgErr("--executor-keyring-dir and --executor-key are required")
	}
	if (c.ExecPassFile == "") == !c.ExecPassPrompt {
		return cfgErr("give exactly one of --executor-passphrase-file and --executor-passphrase-prompt")
	}
	if !c.DryRun && c.ExecEd25519File == "" {
		return cfgErr("--executor-ed25519-file is required unless --dry-run")
	}
	if c.GasLimit == 0 {
		return cfgErr("--gas-limit must be above zero")
	}
	if c.Fee > c.MaxFee {
		return cfgErr("--fee is above --max-fee")
	}
	if _, err := parseMargin(c.FeeMargin); err != nil {
		return cfgErr("--fee-margin: %v", err)
	}
	if c.Rebroadcast <= 0 {
		return cfgErr("--rebroadcast-every must be positive")
	}
	if c.IndexerLag < 0 {
		return cfgErr("--indexer-lag-blocks is negative")
	}
	if c.ConfirmDelay < 0 {
		return cfgErr("--confirm-delay is negative")
	}
	if c.ConfirmDelay > c.Rebroadcast {
		return cfgErr("--confirm-delay is above --rebroadcast-every")
	}
	return nil
}

func isHexLen(s string, n int) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == n && s == strings.ToLower(s)
}

func validID(s string) bool {
	if len(s) < 1 || len(s) > 64 {
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

func loopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func loopbackAddr(addr string) bool { return node.LoopbackAddr(addr) }

// parseRecipient reads kid=<hex X25519 public key>.
func parseRecipient(s string) (blob.Recipient, error) {
	kid, key, ok := strings.Cut(s, "=")
	if !ok || kid == "" || len(kid) > blob.MaxKIDSize {
		return blob.Recipient{}, errors.New("want kid=<64 hex characters>")
	}
	raw, err := hex.DecodeString(key)
	if err != nil || len(raw) != 32 {
		return blob.Recipient{}, errors.New("public key must be 64 hex characters")
	}
	pk, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return blob.Recipient{}, errors.New("not an X25519 public key")
	}
	return blob.Recipient{KID: []byte(kid), PublicKey: pk}, nil
}

// parseMargin reads a non-negative decimal such as "1.2"; "" is zero, which
// means the default margin.
func parseMargin(s string) (*big.Rat, error) {
	if s == "" {
		return new(big.Rat), nil
	}
	for _, r := range s {
		if (r < '0' || r > '9') && r != '.' {
			return nil, errors.New("want a non-negative decimal such as 1.2")
		}
	}
	m, ok := new(big.Rat).SetString(s)
	if !ok {
		return nil, errors.New("want a non-negative decimal such as 1.2")
	}
	return m, nil
}

// validateFast checks the fast-mode flags. The intent check reads the run's
// own consensus and bridge nodes, a same-operator check, so it goes only with
// --inclusion self.
func (c Config) validateFast() error {
	if !c.Fast {
		if c.ArchiveURL != "" {
			return cfgErr("--archive-url applies to --fast only")
		}
		return nil
	}
	if c.ArchiveURL == "" {
		return cfgErr("--fast needs --archive-url")
	}
	u, err := url.Parse(c.ArchiveURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return cfgErr("--archive-url must be an absolute http or https URL")
	}
	if c.DA != "fibre" && c.Inclusion != "" && c.Inclusion != "self" {
		return cfgErr("--fast checks the anchor intent through the run's own nodes; use --inclusion self")
	}
	return nil
}
