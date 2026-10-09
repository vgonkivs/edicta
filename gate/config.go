package gate

import (
	"fmt"
	"math"
	"time"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/policy"
)

const (
	maxSkewS                   = 300
	defaultFibreMaxDataBytes   = 16 << 20
	defaultArchiveWriteTimeout = 10 * time.Second
	// maxFibreDataBytes is the largest blob the Fibre encoder accepts.
	maxFibreDataBytes = 1<<27 - 5
	// fibreFetchFactor is how many times a Fibre payload's size the fetch
	// budget must cover.
	fibreFetchFactor = 13
)

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
	// ArchiveWriteTimeout bounds one Archiver.Put; zero means 10s.
	ArchiveWriteTimeout time.Duration
	// AllowedDA is the set of payload_ref.da values the gate accepts; empty
	// means {1, 2}.
	AllowedDA []commitment.DA
	// FibreMaxDataBytes caps payload_size of a da = 1 commitment; zero means
	// 16 MiB. It applies only when a da = 1 committer is configured.
	FibreMaxDataBytes uint64
	OtherGateKeys     [][32]byte // gate keys besides the signer, refused as agent keys
	// ExecutorKeys is the executor allowlist: the keys whose signed record
	// requests Record accepts. Disjoint from gate and agent keys.
	ExecutorKeys [][32]byte
	// Mandate is the canonical SignedMandate; empty means no policy.
	Mandate []byte
	// AcceptV0 admits v0 commitments. It is ignored, as if false, when a
	// Mandate is configured: a v0 commitment cannot name its mandate.
	AcceptV0 bool
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
		ArchiveWriteTimeout: defaultArchiveWriteTimeout,
		// v0 stays accepted by default until the v1 format is frozen.
		AcceptV0: true,
	}
}

// withDefaults fills the fields whose zero value means a default.
func (c Config) withDefaults() Config {
	if c.ArchiveWriteTimeout == 0 {
		c.ArchiveWriteTimeout = defaultArchiveWriteTimeout
	}
	if c.FibreMaxDataBytes == 0 {
		c.FibreMaxDataBytes = defaultFibreMaxDataBytes
	}
	if len(c.AllowedDA) == 0 {
		c.AllowedDA = []commitment.DA{commitment.DAFibre, commitment.DACelestiaBlob}
	}
	return c
}

// ValidateBasic checks the fields that need no dependency. Defaults are not
// applied here.
func (c Config) ValidateBasic() error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalidConfig, fmt.Sprintf(format, a...))
	}
	switch {
	case c.SkewS > maxSkewS:
		return bad("skew_s %d above %d", c.SkewS, maxSkewS)
	case c.BlobRetentionS < 1 || c.BlobRetentionS > math.MaxInt64:
		return bad("blob_retention_s %d", c.BlobRetentionS)
	case c.DATimeout <= 0 || c.ArchiveTimeout <= 0 || c.ArchiveWriteTimeout <= 0 || c.SignTimeout <= 0 || c.ChainTimeout <= 0:
		return bad("timeouts must be positive")
	case c.MaxFetchBytes == 0:
		return bad("max_fetch_bytes is zero")
	case c.PruneGrace <= c.ClockTolerance:
		return bad("prune_grace %d must be above clock_tolerance %d", c.PruneGrace, c.ClockTolerance)
	case c.MaxAuthorizationTTL <= c.SkewS || c.MaxAuthorizationTTL > math.MaxInt64:
		return bad("max_authorization_ttl %d must be above skew_s %d", c.MaxAuthorizationTTL, c.SkewS)
	case c.FibreMaxDataBytes > maxFibreDataBytes:
		return bad("fibre_max_data_bytes %d above %d", c.FibreMaxDataBytes, uint64(maxFibreDataBytes))
	}
	if err := checkScope(c.Scope); err != nil {
		return bad("%v", err)
	}
	if len(c.Mandate) > 0 {
		sm, _, err := policy.VerifyMandate(c.Mandate)
		if err != nil {
			return bad("mandate: %v", err)
		}
		if sm.Mandate.GateID != c.Scope.GateID {
			return bad("mandate is bound to gate %q, not %q", sm.Mandate.GateID, c.Scope.GateID)
		}
	}
	if _, err := normalizeDA(c.AllowedDA); err != nil {
		return bad("%v", err)
	}
	return nil
}
