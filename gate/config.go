package gate

import (
	"fmt"
	"math"
	"slices"
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

	defaultFastWindowBlocks       = 100
	defaultMaxH0AgeBlocks         = 10
	defaultMinFastSlackBlocks     = 3
	defaultMinPromiseSlackSeconds = 15
	maxFastWindowBlocks           = 1000
	maxMinFastSlackBlocks         = 100
	maxMinPromiseSlackSeconds     = 600
	namespaceSize                 = 29
)

// Causes of ErrInvalidConfig for the fast-mode and reveal settings. They are
// stable so that operators and tests can tell the refusals apart.
const (
	CausePendingNamespaces        = "pending_namespaces"
	CauseFastWindowBlocks         = "fast_window_blocks"
	CauseMaxH0AgeBlocks           = "max_h0_age_blocks"
	CauseMinFastSlackBlocks       = "min_fast_slack_blocks"
	CauseMinPromiseSlackSeconds   = "min_promise_slack_seconds"
	CauseRevealOnExecution        = "reveal_on_execution"
	CauseRevealNotPublicExecution = "reveal_not_public_execution"
	CauseAgePlusSlack             = "age_plus_slack"
	CauseFastModeWithoutMandate   = "fast_mode_without_mandate"
	CauseFastDelayBelowSlack      = "fast_delay_below_slack"
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

	// FastMode admits pending payload references. It needs a mandate,
	// PendingNamespaces and an archive. This gate does not run stage K-fast
	// yet, so it still refuses every pending reference.
	FastMode bool
	// FastWindowBlocks bounds anchor_deadline - h0; 1..1000.
	FastWindowBlocks uint64
	// MaxH0AgeBlocks bounds head - h0 at authorization; 1..FastWindowBlocks-1.
	MaxH0AgeBlocks uint64
	// MinFastSlackBlocks is the least anchor_deadline - head; 1..100.
	MinFastSlackBlocks uint64
	// MinPromiseSlackSeconds is the least time a Fibre promise must have
	// left at authorization; 1..600.
	MinPromiseSlackSeconds uint64
	// PendingNamespaces are the namespaces a pending reference may name.
	PendingNamespaces [][]byte
	// RebroadcastIntent re-sends a Fibre anchor intent; nil means true.
	RebroadcastIntent *bool
	// RevealOnExecution lists the action types whose salt is revealed once
	// a receipt is recorded. Each must be allowlisted and registered with
	// public execution in Deps.Profiles.
	RevealOnExecution []string
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

		FastWindowBlocks:       defaultFastWindowBlocks,
		MaxH0AgeBlocks:         defaultMaxH0AgeBlocks,
		MinFastSlackBlocks:     defaultMinFastSlackBlocks,
		MinPromiseSlackSeconds: defaultMinPromiseSlackSeconds,
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

// rebroadcastIntent is RebroadcastIntent with its default applied.
func (c Config) rebroadcastIntent() bool { return c.RebroadcastIntent == nil || *c.RebroadcastIntent }

// causeErr is ErrInvalidConfig with a stable cause.
func causeErr(cause, format string, a ...any) error {
	return fmt.Errorf("%w: %s: %s", ErrInvalidConfig, cause, fmt.Sprintf(format, a...))
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
	return c.validateFast()
}

// validateFast checks the fast-mode and reveal settings in table order,
// then the cross-field rule. The bounds hold whether or not FastMode is on,
// so that turning it on never meets a bad value first.
func (c Config) validateFast() error {
	if c.FastMode && len(c.PendingNamespaces) == 0 {
		return causeErr(CausePendingNamespaces, "fast mode needs at least one pending namespace")
	}
	switch {
	case c.FastWindowBlocks < 1 || c.FastWindowBlocks > maxFastWindowBlocks:
		return causeErr(CauseFastWindowBlocks, "%d outside 1..%d", c.FastWindowBlocks, maxFastWindowBlocks)
	case c.MaxH0AgeBlocks < 1 || c.MaxH0AgeBlocks >= c.FastWindowBlocks:
		return causeErr(CauseMaxH0AgeBlocks, "%d outside 1..%d", c.MaxH0AgeBlocks, c.FastWindowBlocks-1)
	case c.MinFastSlackBlocks < 1 || c.MinFastSlackBlocks > maxMinFastSlackBlocks:
		return causeErr(CauseMinFastSlackBlocks, "%d outside 1..%d", c.MinFastSlackBlocks, maxMinFastSlackBlocks)
	case c.MinPromiseSlackSeconds < 1 || c.MinPromiseSlackSeconds > maxMinPromiseSlackSeconds:
		return causeErr(CauseMinPromiseSlackSeconds, "%d outside 1..%d", c.MinPromiseSlackSeconds, maxMinPromiseSlackSeconds)
	}
	for i, ns := range c.PendingNamespaces {
		if !validPendingNamespace(ns) {
			return causeErr(CausePendingNamespaces, "namespace %d is not a user blob namespace", i)
		}
	}
	for _, t := range c.RevealOnExecution {
		if !slices.Contains(c.Scope.ActionTypes, t) {
			return causeErr(CauseRevealOnExecution, "%q is not an allowed action type", t)
		}
	}
	if c.MaxH0AgeBlocks+c.MinFastSlackBlocks > c.FastWindowBlocks {
		return causeErr(CauseAgePlusSlack, "max_h0_age_blocks %d + min_fast_slack_blocks %d above fast_window_blocks %d",
			c.MaxH0AgeBlocks, c.MinFastSlackBlocks, c.FastWindowBlocks)
	}
	return nil
}

// validPendingNamespace is the user blob namespace rule of the commitment.
func validPendingNamespace(ns []byte) bool {
	if len(ns) != namespaceSize || ns[0] != 0 {
		return false
	}
	for _, b := range ns[1:19] {
		if b != 0 {
			return false
		}
	}
	for _, b := range ns[19:28] {
		if b != 0 {
			return true
		}
	}
	return false
}
