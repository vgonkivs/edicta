package gate

import (
	"time"

	"github.com/vgonkivs/prior/commitment"
)

const maxSkewS = 300

type Config struct {
	Scope          commitment.GateScope
	SkewS          uint64        // 0..300, used as given
	BlobRetentionS uint64        // local constant for da = 2
	DATimeout      time.Duration // one DA fetch
	ArchiveTimeout time.Duration // one archive fetch
	ExecTimeout    time.Duration // the whole Execute call, and one receipt signature
	ChainTimeout   time.Duration // one chain or allowlist call
	MaxFetchBytes  uint64        // budget of concurrently fetched payload bytes
	ClockTolerance uint64        // seconds the clock may step back
	PruneGrace     uint64        // seconds kept after valid_until; above ClockTolerance
	SettleS        uint64        // rail settle window for reconciliation
	OtherGateKeys  [][32]byte    // gate keys besides the signer, refused as agent keys
}

// DefaultConfig holds the defaults; the zero value of Config is not usable.
// Scope is left for the caller.
func DefaultConfig() Config {
	return Config{
		SkewS:          30,
		BlobRetentionS: 14400,
		DATimeout:      15 * time.Second,
		ArchiveTimeout: 15 * time.Second,
		ExecTimeout:    30 * time.Second,
		ChainTimeout:   10 * time.Second,
		MaxFetchBytes:  512 << 20,
		ClockTolerance: 60,
		PruneGrace:     3600,
		SettleS:        300,
	}
}
