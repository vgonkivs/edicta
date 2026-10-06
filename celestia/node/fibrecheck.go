package node

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"runtime/debug"
	"time"

	"github.com/vgonkivs/edicta/celestia/heightcheck"
	"github.com/vgonkivs/edicta/fibre/fibrecommit"
)

// Facts a da = 1 instance requires of the chain.
const (
	// FibreAppVersion is the only app version the Fibre pins were built for.
	FibreAppVersion = 10
	// DefaultFibreChainID is the one chain validated for v0.
	DefaultFibreChainID = "mocha-5"
	// NMTModule and NMTVersion are the namespace Merkle tree module and the
	// version the anchor proof was built against: the completeness check of a
	// namespace proof needs v0.24.3 or later, and the pin is the version the
	// bridge node resolves.
	NMTModule  = "github.com/celestiaorg/nmt"
	NMTVersion = "v0.24.5"
	// maxPromiseChainIDLen is the length limit of a payment promise chain id.
	maxPromiseChainIDLen = 20

	minFibreRetention = 10 * time.Minute
	maxFibreRetention = 168 * time.Hour
)

// FibreExpect is what CheckFibre requires. Embedded Expect fields keep their
// meaning, except that the app version is always FibreAppVersion.
type FibreExpect struct {
	Expect
	// ChainIDs is the da = 1 chain allowlist; WithDefaults sets mocha-5.
	ChainIDs []string
	// SelfTest and CheckBuild are the committer's known-answer and build-pin
	// checks; WithDefaults sets the fibrecommit ones.
	SelfTest   func() error
	CheckBuild func() error
	// CheckNMT checks the linked nmt module; WithDefaults sets CheckNMTBuild.
	CheckNMT func() error
	// BridgeVersion reads the version of the bridge node. Nil means the
	// version is not read and there is no download fallback.
	BridgeVersion       func(ctx context.Context) (string, error)
	PinnedBridgeVersion string
	// Log receives the startup lines; nil is slog.Default.
	Log *slog.Logger
}

// WithDefaults fills the zero fields that have defaults.
func (e FibreExpect) WithDefaults() FibreExpect {
	if len(e.ChainIDs) == 0 {
		e.ChainIDs = []string{DefaultFibreChainID}
	} else {
		e.ChainIDs = append([]string(nil), e.ChainIDs...)
	}
	if e.SelfTest == nil {
		e.SelfTest = fibrecommit.SelfTest
	}
	if e.CheckBuild == nil {
		e.CheckBuild = fibrecommit.CheckBuild
	}
	if e.CheckNMT == nil {
		e.CheckNMT = CheckNMTBuild
	}
	return e
}

// CheckNMTBuild requires the linked nmt module to be exactly NMTVersion, with
// no replace.
func CheckNMTBuild() error {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return errors.New("build info unavailable")
	}
	return checkNMTBuildInfo(bi)
}

func checkNMTBuildInfo(bi *debug.BuildInfo) error {
	if bi == nil {
		return errors.New("build info unavailable")
	}
	for _, d := range bi.Deps {
		if d == nil || d.Path != NMTModule {
			continue
		}
		switch {
		case d.Version != NMTVersion:
			return fmt.Errorf("%s is %s, want %s", NMTModule, d.Version, NMTVersion)
		case d.Replace != nil:
			return fmt.Errorf("%s is replaced by %s", NMTModule, d.Replace.Path)
		}
		return nil
	}
	return fmt.Errorf("%s is not linked", NMTModule)
}

// ValidateBasic checks the stateless fields.
func (e FibreExpect) ValidateBasic() error {
	if len(e.ChainIDs) == 0 {
		return fmt.Errorf("%w: no chain id in the allowlist", ErrInvalidConfig)
	}
	seen := map[string]bool{}
	for _, id := range e.ChainIDs {
		switch {
		case id == "":
			return fmt.Errorf("%w: empty chain id", ErrInvalidConfig)
		case len(id) > maxPromiseChainIDLen:
			return fmt.Errorf("%w: chain id %q longer than %d bytes", ErrInvalidConfig, id, maxPromiseChainIDLen)
		case seen[id]:
			return fmt.Errorf("%w: duplicate chain id %q", ErrInvalidConfig, id)
		}
		seen[id] = true
	}
	if e.BridgeVersion != nil && e.PinnedBridgeVersion == "" {
		return fmt.Errorf("%w: bridge version check without a pinned version", ErrInvalidConfig)
	}
	return nil
}

// isNil reports a nil interface or one that holds a nil pointer, map, slice,
// func or channel.
func isNil(v any) bool {
	if v == nil {
		return true
	}
	switch rv := reflect.ValueOf(v); rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.Interface:
		return rv.IsNil()
	}
	return false
}

// FibreStart is what CheckFibre learned.
type FibreStart struct {
	// Head is the latest header the generic check validated.
	Head Header
	// BridgeFallback is true when the download fallback node may be used.
	BridgeFallback bool
	// ObservationsOnly is true when a consensus endpoint ignores heights.
	ObservationsOnly bool
}

// CheckFibre refuses a setup that cannot serve da = 1: r is the bridge the
// anchor proof reads from and is required, and the consensus node must index
// transactions for the result codes. Every refusal wraps ErrUnsupported (a bad
// config wraps ErrInvalidConfig). A bridge whose version differs from the pin
// only loses the download fallback, because its anchor answers are verified
// here. It runs one height canary per endpoint.
func CheckFibre(ctx context.Context, r Reader, c Consensus, e FibreExpect) (FibreStart, error) {
	e = e.WithDefaults()
	if err := e.ValidateBasic(); err != nil {
		return FibreStart{}, err
	}
	log := e.Log
	if log == nil {
		log = slog.Default()
	}
	if isNil(r) {
		return FibreStart{}, fmt.Errorf("%w: a fibre gate needs a bridge for the anchor proof", ErrUnsupported)
	}
	if isNil(c) {
		return FibreStart{}, fmt.Errorf("%w: reader and consensus are required", ErrUnsupported)
	}
	if err := e.CheckBuild(); err != nil {
		return FibreStart{}, fmt.Errorf("%w: fibre build pin: %w", ErrUnsupported, err)
	}
	if err := e.CheckNMT(); err != nil {
		return FibreStart{}, fmt.Errorf("%w: nmt build pin: %w", ErrUnsupported, err)
	}
	if err := e.SelfTest(); err != nil {
		return FibreStart{}, fmt.Errorf("%w: fibre known answers: %w", ErrUnsupported, err)
	}
	ex := e.Expect
	ex.MinAppVersion, ex.MaxAppVersion = FibreAppVersion, FibreAppVersion
	head, err := Check(ctx, r, c, ex)
	if err != nil {
		return FibreStart{}, err
	}
	allowed := false
	for _, id := range e.ChainIDs {
		allowed = allowed || id == head.ChainID
	}
	if !allowed {
		return FibreStart{}, fmt.Errorf("%w: chain %q is not in the da = 1 allowlist %v", ErrUnsupported, head.ChainID, e.ChainIDs)
	}
	fp, err := c.FibreParams(ctx)
	if err != nil {
		return FibreStart{}, fmt.Errorf("%w: x/fibre params: %w", ErrUnsupported, err)
	}
	if ret := time.Duration(fp.RetentionS) * time.Second; fp.RetentionS > uint64(maxFibreRetention/time.Second) || ret < minFibreRetention {
		return FibreStart{}, fmt.Errorf("%w: x/fibre retention %ds outside %s..%s", ErrUnsupported, fp.RetentionS, minFibreRetention, maxFibreRetention)
	}

	if err := c.TxIndex(ctx); err != nil {
		return FibreStart{}, fmt.Errorf("%w: result codes need the consensus tx index: %w", ErrUnsupported, err)
	}

	obs, err := heightcheck.Startup(ctx, log, ConsensusEndpoint("consensus", c), BridgeEndpoint("bridge", r))
	if err != nil {
		return FibreStart{}, fmt.Errorf("%w: height canary: %w", ErrUnsupported, err)
	}
	st := FibreStart{Head: head, ObservationsOnly: obs}
	if e.BridgeVersion == nil {
		return st, nil
	}
	v, err := e.BridgeVersion(ctx)
	switch {
	case err != nil:
		log.Warn("bridge download fallback disabled: version unreadable", "err", err)
	case v != e.PinnedBridgeVersion:
		log.Warn("bridge download fallback disabled: version differs from the pin", "version", v, "pinned", e.PinnedBridgeVersion)
	default:
		log.Info("bridge version matches the pin", "version", v)
		st.BridgeFallback = true
	}
	return st, nil
}
