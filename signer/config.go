// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/vgonkivs/edicta/commitment"
)

// HourWindow is the rolling window of the per-hour caps.
const HourWindow = 3600 * time.Second

// Defaults and bounds.
const (
	DefaultSkewS         = 30
	MaxSkewS             = 300
	DefaultRetryInterval = 30 * time.Second
	MaxRetryInterval     = time.Hour
	DefaultMaxSettling   = 16
	DefaultSettleRound   = 2 * time.Minute
	MaxSettleRound       = time.Hour
	MaxAgentKeys         = 1024
)

// Caps are the operator's risk limits, in the rail's base unit.
// They hold over every chain the signer serves together.
type Caps struct {
	MaxValuePerAction *big.Int
	MaxValuePerHour   *big.Int
	// MaxFeePerHour bounds the sum of the fee bounds (max fee per gas times
	// the gas limit) in the window.
	MaxFeePerHour *big.Int
}

// Config holds the pins that do not depend on the rail. They are
// configured out of band and never taken from a request.
type Config struct {
	// GateID and GatePubKey are the one gate whose Authorizations count.
	GateID     string
	GatePubKey []byte
	// AgentKeys are the agent public keys the signer serves.
	AgentKeys [][]byte
	// SkewS is skew_s, in seconds.
	SkewS uint64
	// RefuseFast refuses Authorizations in fast mode.
	RefuseFast bool
	Caps       Caps
	// RetryInterval is how often unsettled and unrecorded decisions are
	// looked at again.
	RetryInterval time.Duration
	// MaxSettling bounds the decisions settled at once.
	MaxSettling int
	// SettleRound bounds one attempt to settle or record a decision, so a
	// long wait never keeps a slot from the others.
	SettleRound time.Duration
}

// ApplyDefaults fills the zero fields that have defaults.
func (c *Config) ApplyDefaults() {
	if c.SkewS == 0 {
		c.SkewS = DefaultSkewS
	}
	if c.RetryInterval == 0 {
		c.RetryInterval = DefaultRetryInterval
	}
	if c.MaxSettling == 0 {
		c.MaxSettling = DefaultMaxSettling
	}
	if c.SettleRound == 0 {
		c.SettleRound = DefaultSettleRound
	}
}

// ValidateBasic checks the fields alone.
func (c Config) ValidateBasic() error {
	if !validID(c.GateID) {
		return fmt.Errorf("signer: config: gate id %q is not 1..64 characters of the ID charset", c.GateID)
	}
	if err := commitment.CheckPublicKey(c.GatePubKey); err != nil {
		return fmt.Errorf("signer: config: gate key: %w", err)
	}
	if len(c.AgentKeys) == 0 {
		return errors.New("signer: config: no agent key: the signer serves no agent it was not told about")
	}
	if len(c.AgentKeys) > MaxAgentKeys {
		return fmt.Errorf("signer: config: %d agent keys, at most %d", len(c.AgentKeys), MaxAgentKeys)
	}
	for i, k := range c.AgentKeys {
		if err := commitment.CheckPublicKey(k); err != nil {
			return fmt.Errorf("signer: config: agent key %d: %w", i, err)
		}
		// The agent and the gate are two signing roles; one key in both
		// would let one party produce both signatures the signer needs.
		if bytes.Equal(k, c.GatePubKey) {
			return fmt.Errorf("signer: config: agent key %d is the gate key", i)
		}
		for j := range i {
			if bytes.Equal(k, c.AgentKeys[j]) {
				return fmt.Errorf("signer: config: agent key %d repeats key %d", i, j)
			}
		}
	}
	if c.SkewS > MaxSkewS {
		return fmt.Errorf("signer: config: skew_s %d above %d", c.SkewS, MaxSkewS)
	}
	if err := c.Caps.validate(); err != nil {
		return err
	}
	switch {
	case c.RetryInterval <= 0 || c.RetryInterval > MaxRetryInterval:
		return fmt.Errorf("signer: config: retry interval %v is not in (0, %v]", c.RetryInterval, MaxRetryInterval)
	case c.MaxSettling < 1 || c.MaxSettling > 1024:
		return fmt.Errorf("signer: config: max settling %d is not in 1..1024", c.MaxSettling)
	case c.SettleRound <= 0 || c.SettleRound > MaxSettleRound:
		return fmt.Errorf("signer: config: settle round %v is not in (0, %v]", c.SettleRound, MaxSettleRound)
	}
	return nil
}

func (c Caps) validate() error {
	for _, v := range []struct {
		name string
		x    *big.Int
	}{{"max value per action", c.MaxValuePerAction}, {"max value per hour", c.MaxValuePerHour}, {"max fee per hour", c.MaxFeePerHour}} {
		if v.x == nil || v.x.Sign() <= 0 {
			return fmt.Errorf("signer: config: %s must be above zero", v.name)
		}
		if v.x.BitLen() > 256 {
			return fmt.Errorf("signer: config: %s above 2^256", v.name)
		}
	}
	if c.MaxValuePerAction.Cmp(c.MaxValuePerHour) > 0 {
		return errors.New("signer: config: max value per action above max value per hour")
	}
	return nil
}

// validID is the charset of gate ids: 1..64 of A-Z a-z 0-9 . _ : / -.
func validID(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
			c == '.' || c == '_' || c == ':' || c == '/' || c == '-') {
			return false
		}
	}
	return true
}
