package demo

import (
	"bytes"
	_ "embed"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/vgonkivs/edicta/celestia/inclusion"
)

//go:embed presets/mocha.toml
var mochaPreset []byte

// Endpoint is one node endpoint.
type Endpoint struct {
	Addr string `toml:"addr"`
	TLS  bool   `toml:"tls"`
}

// FundingPreset holds the funding limits and gas settings.
type FundingPreset struct {
	GasLimit       uint64 `toml:"gas_limit"`
	PFBGas         uint64 `toml:"pfb_gas"`
	MaxFee         uint64 `toml:"max_fee"`
	MaxAmount      uint64 `toml:"max_amount"`
	MaxTotalAmount uint64 `toml:"max_total_amount"`
	TimeoutBlocks  uint64 `toml:"timeout_blocks"`
}

// VerifyPreset holds the sources the verify step uses.
type VerifyPreset struct {
	HeadersRPC    string   `toml:"headers_rpc"`
	TxRPC         string   `toml:"tx_rpc"`
	CrossCheckRPC []string `toml:"cross_check_rpc"`
	SameOperator  []string `toml:"same_operator"`
	TrustRootAPI  string   `toml:"trust_root_api"`
	TrustRootPage string   `toml:"trust_root_page"`
	TrustRootName string   `toml:"trust_root_name"`
	TrustRootLag  uint64   `toml:"trust_root_lag"`
	TimeoutS      uint64   `toml:"timeout_s"`
}

// Preset is the network the demo runs on.
type Preset struct {
	ChainID            string        `toml:"chain_id"`
	HRP                string        `toml:"hrp"`
	Denom              string        `toml:"denom"`
	FaucetHint         string        `toml:"faucet_hint"`
	ExplorerTxURL      string        `toml:"explorer_tx_url"`
	ExplorerBlockURL   string        `toml:"explorer_block_url"`
	ExplorerAddressURL string        `toml:"explorer_address_url"`
	Bridge             Endpoint      `toml:"bridge"`
	GRPC               Endpoint      `toml:"grpc"`
	Funding            FundingPreset `toml:"funding"`
	Verify             VerifyPreset  `toml:"verify"`
}

// PresetOverrides replace preset fields from flags.
type PresetOverrides struct {
	HeadersRPC, TxRPC, TrustRootAPI, TrustRootPage string
	ExplorerTxURL, ExplorerBlockURL                string
}

// LoadPreset returns the embedded preset of a network.
func LoadPreset(name string) (Preset, error) {
	if name != "mocha" {
		return Preset{}, fmt.Errorf("%w: unknown network %q (only mocha)", ErrConfig, name)
	}
	var p Preset
	if err := toml.NewDecoder(bytes.NewReader(mochaPreset)).DisallowUnknownFields().Decode(&p); err != nil {
		return Preset{}, fmt.Errorf("%w: preset: %v", ErrConfig, err)
	}
	return p, nil
}

// Apply returns p with the overrides in place.
func (p Preset) Apply(o PresetOverrides) Preset {
	set := func(dst *string, v string) {
		if v != "" {
			*dst = v
		}
	}
	set(&p.Verify.HeadersRPC, o.HeadersRPC)
	set(&p.Verify.TxRPC, o.TxRPC)
	set(&p.Verify.TrustRootAPI, o.TrustRootAPI)
	set(&p.Verify.TrustRootPage, o.TrustRootPage)
	set(&p.ExplorerTxURL, o.ExplorerTxURL)
	set(&p.ExplorerBlockURL, o.ExplorerBlockURL)
	p.Verify.CrossCheckRPC = slices.Clone(p.Verify.CrossCheckRPC)
	p.Verify.SameOperator = slices.Clone(p.Verify.SameOperator)
	return p
}

// Timeout is the verify run's time limit.
func (v VerifyPreset) Timeout() time.Duration { return time.Duration(v.TimeoutS) * time.Second }

func urlHost(raw string) (string, error) {
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	return inclusion.SourceHost(raw)
}

// ExcludeHosts is the --exclude-host list: the gate's gRPC and bridge hosts
// and the operators that run them.
func (p Preset) ExcludeHosts() []string {
	var out []string
	for _, a := range append([]string{p.GRPC.Addr, p.Bridge.Addr}, p.Verify.SameOperator...) {
		h, err := urlHost(a)
		if err != nil {
			continue
		}
		if !slices.Contains(out, h) {
			out = append(out, h)
		}
	}
	return out
}

// ValidateBasic checks the stateless fields.
func (p Preset) ValidateBasic() error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: preset: %s", ErrConfig, fmt.Sprintf(format, a...))
	}
	f, v := p.Funding, p.Verify
	switch {
	case p.ChainID == "" || p.HRP == "" || p.Denom == "":
		return bad("chain id, hrp and denom are required")
	case p.Bridge.Addr == "" || p.GRPC.Addr == "":
		return bad("bridge and gRPC endpoints are required")
	case f.MaxAmount == 0 || f.MaxTotalAmount < f.MaxAmount || f.MaxFee == 0 || f.GasLimit == 0 || f.PFBGas == 0:
		return bad("funding limits: need MaxAmount > 0, MaxTotalAmount >= MaxAmount, MaxFee > 0 and gas")
	case !strings.Contains(v.TrustRootAPI, "{height}") || !strings.Contains(v.TrustRootPage, "{height}"):
		return bad("trust-root templates need {height}")
	case !strings.Contains(p.ExplorerTxURL, "{hash}") || !strings.Contains(p.ExplorerBlockURL, "{height}"):
		return bad("explorer templates need {hash} and {height}")
	case v.TrustRootLag == 0 || v.TimeoutS == 0:
		return bad("trust-root lag and verify timeout are required")
	}
	hh, err := urlHost(v.HeadersRPC)
	if err != nil {
		return bad("headers rpc: %v", err)
	}
	th, err := urlHost(v.TxRPC)
	if err != nil {
		return bad("tx rpc: %v", err)
	}
	if hh == th {
		return bad("the tx source and the headers source must be distinct hosts")
	}
	excl := p.ExcludeHosts()
	for _, c := range v.CrossCheckRPC {
		h, err := urlHost(c)
		if err != nil {
			return bad("cross-check rpc: %v", err)
		}
		if slices.Contains(excl, h) {
			return bad("cross-check %s is on an excluded host", h)
		}
	}
	return nil
}

// CheckTrustRootHost refuses a trust-root source whose normalized host is the
// host of any configured RPC, gRPC or bridge endpoint, with the same
// normalization --cross-check uses.
func (p Preset) CheckTrustRootHost() error {
	v := p.Verify
	root, err := urlHost(strings.ReplaceAll(v.TrustRootAPI, "{height}", "1"))
	if err != nil {
		return fmt.Errorf("%w: trust-root source: %v", ErrConfig, err)
	}
	data := append([]string{v.HeadersRPC, v.TxRPC, p.GRPC.Addr, p.Bridge.Addr}, v.CrossCheckRPC...)
	data = append(data, v.SameOperator...)
	for _, d := range data {
		h, err := urlHost(d)
		if err != nil {
			return fmt.Errorf("%w: endpoint %q: %v", ErrConfig, d, err)
		}
		if h == root {
			return fmt.Errorf("%w: %s", ErrTrustRootNotIndependent, root)
		}
	}
	if !strings.HasPrefix(v.TrustRootAPI, "https://") {
		return fmt.Errorf("%w: the trust-root source must be an https URL", ErrConfig)
	}
	return nil
}
