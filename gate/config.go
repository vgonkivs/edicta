package gate

import (
	"time"

	"github.com/vgonkivs/edicta/commitment"
)

const maxSkewS = 300

type Config struct {
	Scope          commitment.GateScope
	SkewS          uint64        // 0..300, used as given
	BlobRetentionS uint64        // local constant for da = 2
	DATimeout      time.Duration // one DA fetch
	ArchiveTimeout time.Duration // one archive fetch
	SignTimeout    time.Duration // one signature, of an Authorization or a receipt
	ChainTimeout   time.Duration // one chain or allowlist call
	MaxFetchBytes  uint64        // budget of concurrently fetched payload bytes
	ClockTolerance uint64        // seconds the clock may step back
	PruneGrace     uint64        // seconds kept after valid_until; above ClockTolerance
	// MaxAuthorizationTTL bounds an Authorization's lifetime from the moment
	// it is signed, in seconds; above SkewS.
	MaxAuthorizationTTL uint64
	// AllowedDA is the set of payload_ref.da values the gate accepts; empty
	// means {1, 2}.
	AllowedDA     []commitment.DA
	OtherGateKeys [][32]byte // gate keys besides the signer, refused as agent keys
	// ExecutorKeys is the executor allowlist: the keys whose signed record
	// requests Record accepts. Disjoint from gate and agent keys.
	ExecutorKeys [][32]byte
}

// DefaultConfig holds the defaults; the zero value of Config is not usable.
// Scope is left for the caller.
func DefaultConfig() Config {
	return Config{
		SkewS:               30,
		BlobRetentionS:      14400,
		DATimeout:           15 * time.Second,
		ArchiveTimeout:      15 * time.Second,
		SignTimeout:         10 * time.Second,
		ChainTimeout:        10 * time.Second,
		MaxFetchBytes:       512 << 20,
		ClockTolerance:      60,
		PruneGrace:          3600,
		MaxAuthorizationTTL: 300,
	}
}
