package config

import (
	"errors"
	"fmt"
	"slices"
)

// Preset names. The mainnet presets are known by name only: they arrive with
// the mainnet re-pin, and asking for them is a clear error, not a guess.
const (
	CelestiaMocha         = "mocha"
	CelestiaMainnet       = "celestia-mainnet"
	SettlementBaseSepolia = "base-sepolia"
	SettlementBase        = "base"
	Custom                = "custom"
	SettlementNone        = "none"
)

// ErrPreset wraps every refusal to resolve a preset.
var ErrPreset = errors.New("config: preset")

// Endpoint is one node endpoint.
type Endpoint struct {
	Addr      string `toml:"addr"`
	TokenFile string `toml:"token_file"`
	TLS       bool   `toml:"tls"`
}

// USDC names a token contract and its EIP-712 domain.
type USDC struct {
	Address string `toml:"address"`
	Name    string `toml:"name"`
	Version string `toml:"version"`
}

// Preset is versioned data. A Celestia preset fills the chain fields, a
// settlement preset the EVM fields; the other half stays zero.
type Preset struct {
	Name string
	// Version rises whenever the data of a preset changes, so doctor can say
	// that a newer binary has changed what a config was written against.
	Version uint32

	// Celestia.
	ChainID       string
	Bridge        Endpoint
	ConsensusGRPC Endpoint
	CometRPC      []string
	FaucetURL     string
	// Fibre is true when the chain serves Fibre. A Recorder still needs its
	// own node to use it.
	Fibre bool

	// Settlement.
	EVMChainID uint64
	USDC       USDC
	RPC        []string
	// FacilitatorURL and FacilitatorNetwork name the x402 facilitator and the
	// network label it lists in its supported kinds.
	FacilitatorURL     string
	FacilitatorNetwork string
}

// Presets resolves preset names.
type Presets interface {
	Celestia(name string) (Preset, error)
	Settlement(name string) (Preset, error)
}

// Builtin is the set of presets compiled into the binary.
type Builtin struct{}

var mocha = Preset{
	Name:    CelestiaMocha,
	Version: 1,
	ChainID: "mocha-5",
	Bridge:  Endpoint{Addr: "public-endpoint.celestia-mocha.quiknode.pro", TLS: true},
	// The public gRPC endpoint of the preset speaks plain HTTP/2.
	ConsensusGRPC: Endpoint{Addr: "grpc-mocha.pops.one:9090", TLS: false},
	CometRPC:      []string{"https://rpc-mocha.pops.one", "https://rpc-1.testnet.celestia.nodes.guru"},
	FaucetURL:     "https://docs.celestia.org/operate/networks/mocha-testnet#mocha-testnet-faucet",
	Fibre:         true,
}

// The token's domain name and version are UNVERIFIED against the contract;
// the faucet link is UNVERIFIED too.
var baseSepolia = Preset{
	Name:       SettlementBaseSepolia,
	Version:    1,
	EVMChainID: 84532,
	USDC:       USDC{Address: "0x036cbd53842c5426634e7929541ec2318f3dcf7e", Name: "USDC", Version: "2"},
	// Public RPCs are rate-limited: fine for a testnet run, not for more.
	RPC:                []string{"https://sepolia.base.org", "https://base-sepolia-rpc.publicnode.com"},
	FacilitatorURL:     "https://x402.org/facilitator",
	FacilitatorNetwork: "base-sepolia",
	FaucetURL:          "https://faucet.circle.com",
}

// Celestia returns the preset of a Celestia network. "custom" carries no
// data: the config fills every field.
func (Builtin) Celestia(name string) (Preset, error) {
	switch name {
	case CelestiaMocha:
		return clonePreset(mocha), nil
	case CelestiaMainnet:
		return Preset{}, fmt.Errorf("%w: %q is not available in this build: it arrives with the mainnet re-pin; use %q or %q", ErrPreset, name, CelestiaMocha, Custom)
	case Custom:
		return Preset{Name: Custom}, nil
	}
	return Preset{}, fmt.Errorf("%w: unknown celestia network %q; use %q or %q", ErrPreset, name, CelestiaMocha, Custom)
}

// Settlement returns the preset of a settlement chain. "none" and "custom"
// carry no data.
func (Builtin) Settlement(name string) (Preset, error) {
	switch name {
	case SettlementBaseSepolia:
		return clonePreset(baseSepolia), nil
	case SettlementBase:
		return Preset{}, fmt.Errorf("%w: %q is not available in this build: it arrives with the mainnet re-pin; use %q, %q or %q", ErrPreset, name, SettlementBaseSepolia, Custom, SettlementNone)
	case Custom, SettlementNone:
		return Preset{Name: name}, nil
	}
	return Preset{}, fmt.Errorf("%w: unknown settlement %q; use %q, %q or %q", ErrPreset, name, SettlementBaseSepolia, Custom, SettlementNone)
}

func clonePreset(p Preset) Preset {
	p.CometRPC = slices.Clone(p.CometRPC)
	p.RPC = slices.Clone(p.RPC)
	return p
}
