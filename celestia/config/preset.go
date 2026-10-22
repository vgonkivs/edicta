package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"

	"github.com/vgonkivs/edicta/plugins/edenescrow"
)

// Preset names. The Base mainnet preset is known by name only: asking for it
// is a clear error, not a guess.
const (
	CelestiaMocha         = "mocha"
	CelestiaMainnet       = "celestia-mainnet"
	SettlementBaseSepolia = "base-sepolia"
	SettlementBase        = "base"
	SettlementEdenTestnet = "eden-testnet"
	SettlementEdenMainnet = "eden-mainnet"
	Custom                = "custom"
	SettlementNone        = "none"
)

// PlaceholderHost is the reserved top-level domain of a preset value the
// operator must replace. It never resolves, so an unfilled placeholder fails
// closed even if a check forgets to look for it.
const PlaceholderHost = ".invalid"

// IsPlaceholder reports whether an address, URL or OPERATOR=URL source names
// a placeholder host.
func IsPlaceholder(addr string) bool {
	if label, rest, ok := strings.Cut(addr, "="); ok && !strings.ContainsAny(label, "/:") {
		addr = rest
	}
	host := addr
	if u, err := url.Parse(addr); err == nil && u.Hostname() != "" {
		host = u.Hostname()
	} else if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	return strings.HasSuffix(strings.ToLower(strings.TrimSuffix(host, ".")), PlaceholderHost)
}

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
	// Escrow and EscrowCodeHash (0x hex) are set by the Eden presets: the
	// escrow contract of the chain and the keccak-256 of its runtime code,
	// read from the table the extractor compiles in.
	Escrow         string
	EscrowCodeHash string
	USDC           USDC
	RPC            []string
	// FacilitatorURL and FacilitatorNetwork name the x402 facilitator and the
	// network label it lists in its supported kinds.
	FacilitatorURL     string
	FacilitatorNetwork string
}

// IsEscrow reports whether the preset is an Eden escrow chain, which the
// edicta-signer file configures, not the USDC section of edicta.toml.
func (p Preset) IsEscrow() bool { return p.Escrow != "" }

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

// mainnet is the Celestia mainnet. The chain id and the Comet RPC endpoints
// are what was observed on the network; the bridge and the consensus gRPC
// endpoint are the operator's own and stay placeholders, so a config cannot
// pass validation before they are replaced. Blob and fee parameters equal
// Mocha's, so one fast-mode setup fits both.
var mainnet = Preset{
	Name:          CelestiaMainnet,
	Version:       1,
	ChainID:       "celestia",
	Bridge:        Endpoint{Addr: "bridge.operator-fills-this-in.invalid", TLS: true},
	ConsensusGRPC: Endpoint{Addr: "consensus-grpc.operator-fills-this-in.invalid:9090", TLS: false},
	CometRPC:      []string{"https://celestia-rpc.publicnode.com", "https://rpc.lunaroasis.net"},
	Fibre:         true,
}

// The Eden presets take the escrow address and code hash from the compiled
// table, so the signer, the verifier and the preset can never disagree. The
// first RPC is the operator's own node, a placeholder; the others are
// further sources under their operators' labels.
func edenPreset(name string, chainID uint64, rpc []string) Preset {
	p := Preset{Name: name, Version: 1, EVMChainID: chainID, RPC: rpc}
	if row, ok := edenescrow.Lookup(chainID); ok {
		p.Escrow = "0x" + hex.EncodeToString(row.Escrow[:])
		p.EscrowCodeHash = "0x" + hex.EncodeToString(row.CodeHash[:])
	}
	return p
}

func edenMainnet() Preset {
	return edenPreset(SettlementEdenMainnet, 714, []string{
		"own-node=https://eden-rpc.operator-fills-this-in.invalid",
		"gateway=https://rpc.eden.gateway.fm",
	})
}

func edenTestnet() Preset {
	return edenPreset(SettlementEdenTestnet, 3735928814, []string{
		"own-node=https://eden-testnet-rpc.operator-fills-this-in.invalid",
		"second-operator=https://eden-testnet-rpc-2.operator-fills-this-in.invalid",
	})
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
		return clonePreset(mainnet), nil
	case Custom:
		return Preset{Name: Custom}, nil
	}
	return Preset{}, fmt.Errorf("%w: unknown celestia network %q; use %q, %q or %q", ErrPreset, name, CelestiaMocha, CelestiaMainnet, Custom)
}

// Settlement returns the preset of a settlement chain. "none" and "custom"
// carry no data.
func (Builtin) Settlement(name string) (Preset, error) {
	switch name {
	case SettlementBaseSepolia:
		return clonePreset(baseSepolia), nil
	case SettlementEdenMainnet:
		return clonePreset(edenMainnet()), nil
	case SettlementEdenTestnet:
		return clonePreset(edenTestnet()), nil
	case SettlementBase:
		return Preset{}, fmt.Errorf("%w: %q is not available in this build; use %q, %q or %q (eden-* go in the edicta-signer file)", ErrPreset, name, SettlementBaseSepolia, Custom, SettlementNone)
	case Custom, SettlementNone:
		return Preset{Name: name}, nil
	}
	return Preset{}, fmt.Errorf("%w: unknown settlement %q; use %q, %q or %q (eden-* go in the edicta-signer file)", ErrPreset, name, SettlementBaseSepolia, Custom, SettlementNone)
}

func clonePreset(p Preset) Preset {
	p.CometRPC = slices.Clone(p.CometRPC)
	p.RPC = slices.Clone(p.RPC)
	return p
}
