package demo

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// FunderConfig selects an account the user already has. All fields empty
// means the demo generates the funding account.
type FunderConfig struct {
	KeyringDir, KeyName, PassphraseFile, Address string
}

// Generated reports whether the demo creates the funder key itself.
func (f FunderConfig) Generated() bool { return f.KeyringDir == "" && f.KeyName == "" }

// Config is the demo's command line.
type Config struct {
	Network         string
	Home            string
	Funder          FunderConfig
	AmountUTIA      uint64
	MaxTotalFunding uint64 // 0 = the preset's cap
	YesFundingCap   bool   // skips only the cap confirmation
	TrustedHeader   string // "H:HASH"; empty = the trust-root source of the preset
	FundTimeout     time.Duration
	PollEvery       time.Duration
	JSON            bool
	Overrides       PresetOverrides
}

const (
	defaultAmount      = 1000
	maxDemoAmount      = 100_000
	defaultFundTimeout = 5 * time.Minute
	defaultPollEvery   = 5 * time.Second
)

// WithDefaults fills the zero fields that have defaults.
func (c Config) WithDefaults() Config {
	if c.Network == "" {
		c.Network = "mocha"
	}
	if c.AmountUTIA == 0 {
		c.AmountUTIA = defaultAmount
	}
	if c.FundTimeout == 0 {
		c.FundTimeout = defaultFundTimeout
	}
	if c.PollEvery == 0 {
		c.PollEvery = defaultPollEvery
	}
	return c
}

// ValidateBasic checks every field that needs no dependency.
func (c Config) ValidateBasic() error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrConfig, fmt.Sprintf(format, a...))
	}
	switch {
	case c.Home == "":
		return bad("no home directory")
	case c.AmountUTIA == 0 || c.AmountUTIA > maxDemoAmount:
		return bad("--amount must be 1..%d utia", maxDemoAmount)
	case c.YesFundingCap && c.MaxTotalFunding == 0:
		return bad("--yes only confirms --max-total-funding")
	case c.FundTimeout <= 0 || c.PollEvery <= 0:
		return bad("timeouts must be positive")
	case (c.Funder.KeyringDir == "") != (c.Funder.KeyName == ""):
		return bad("--funder-keyring-dir and --funder-key go together")
	case c.Funder.Generated() && (c.Funder.PassphraseFile != "" || c.Funder.Address != ""):
		return bad("--funder-passphrase-file and --address need --funder-keyring-dir and --funder-key")
	}
	if c.TrustedHeader != "" {
		if _, _, err := ParseTrustedHeader(c.TrustedHeader); err != nil {
			return bad("--trusted-header: %v", err)
		}
	}
	return nil
}

// ParseTrustedHeader parses HEIGHT:HASH with a positive decimal height and 64
// hex characters.
func ParseTrustedHeader(s string) (uint64, []byte, error) {
	h, hash, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok {
		return 0, nil, fmt.Errorf("want HEIGHT:HASH")
	}
	height, err := strconv.ParseUint(h, 10, 63)
	if err != nil || height == 0 {
		return 0, nil, fmt.Errorf("height must be a positive decimal")
	}
	b, err := hex.DecodeString(hash)
	if err != nil || len(b) != 32 {
		return 0, nil, fmt.Errorf("hash must be 64 hex characters")
	}
	return height, b, nil
}
