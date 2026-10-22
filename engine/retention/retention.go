// Package retention records the x/fibre shard retention seen over time and
// answers what it was at a past height, never substituting the latest value.
package retention

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var (
	// ErrNotCovered means no recorded sample brackets the height.
	ErrNotCovered = errors.New("retention: height not covered by the recorded samples")
	// ErrChainMismatch means the store is bound to another chain id.
	ErrChainMismatch = errors.New("retention: store is bound to another chain")
	// ErrStoreCorrupt means the persisted history cannot be read back.
	ErrStoreCorrupt = errors.New("retention: stored history is corrupt")
	// ErrBadSample means a sample whose lower height is above its upper one.
	ErrBadSample = errors.New("retention: sample brackets no height")
	// ErrBadPolicy means a Policy that cannot give sound coverage.
	ErrBadPolicy = errors.New("retention: invalid policy")
)

type Clock interface{ Now() time.Time }

// Sample records that the value was in force at some height in
// [FromHeight, ToHeight].
type Sample struct {
	// ChainID is the chain the source read this from. A store bound to
	// another chain refuses the sample; empty skips that check.
	ChainID    string
	FromHeight uint64
	ToHeight   uint64
	RetentionS uint64
	// ObservedAt is the local clock in Unix seconds. It only drives gaps and
	// pruning, never the at-height value.
	ObservedAt uint64
}

// Run is a stretch of consecutive samples of one segment with the same value.
type Run struct {
	Segment                              uint64
	FirstFrom, FirstTo, LastFrom, LastTo uint64
	RetentionS                           uint64
	FirstAt, LastAt                      uint64
}

// Validate rejects a sample that brackets no height.
func (s Sample) Validate() error {
	if s.FromHeight > s.ToHeight {
		return fmt.Errorf("%w: [%d, %d]", ErrBadSample, s.FromHeight, s.ToHeight)
	}
	return nil
}

const (
	DefaultMaxGapBlocks = 100
	DefaultMaxGapS      = 300
	DefaultKeepS        = 8 * 24 * 3600
	DefaultSampleTO     = 30 * time.Second
	DefaultMaxSampleAge = 5

	maxGapBlocksCap = 1000
	maxGapSCap      = 900
	maxSampleAgeCap = 60
)

// Policy zero values mean the defaults.
type Policy struct {
	// AssumedLagBlocks widens each sample by this many blocks at both ends: 0
	// for an own node, more for a load-balanced endpoint whose backends may
	// trail or lead each other.
	AssumedLagBlocks uint64
	MaxGapBlocks     uint64
	MaxGapS          uint64
	// KeepS is how long runs are kept after they were last extended. It must
	// stay above the 168 h governance maximum.
	KeepS uint64
	// SampleTimeout bounds one scheduled sample or canary.
	SampleTimeout time.Duration
	// MaxSampleAge, in seconds, is how old a sample may be and still answer a
	// read of the latest value.
	MaxSampleAge uint64
}

// Normalize fills defaults and rejects values that make coverage unsound or
// useless.
func (p Policy) Normalize() (Policy, error) {
	if p.MaxGapBlocks == 0 {
		p.MaxGapBlocks = DefaultMaxGapBlocks
	}
	if p.MaxGapS == 0 {
		p.MaxGapS = DefaultMaxGapS
	}
	if p.KeepS == 0 {
		p.KeepS = DefaultKeepS
	}
	if p.SampleTimeout == 0 {
		p.SampleTimeout = DefaultSampleTO
	}
	if p.MaxSampleAge == 0 {
		p.MaxSampleAge = DefaultMaxSampleAge
	}
	switch {
	case p.MaxGapBlocks > maxGapBlocksCap:
		return p, fmt.Errorf("%w: max gap %d blocks is above %d", ErrBadPolicy, p.MaxGapBlocks, maxGapBlocksCap)
	case p.MaxGapS > maxGapSCap:
		return p, fmt.Errorf("%w: max gap %d s is above %d", ErrBadPolicy, p.MaxGapS, maxGapSCap)
	case p.MaxSampleAge > maxSampleAgeCap:
		return p, fmt.Errorf("%w: max sample age %d s is above %d", ErrBadPolicy, p.MaxSampleAge, maxSampleAgeCap)
	case p.KeepS < DefaultKeepS:
		return p, fmt.Errorf("%w: keep %d s is below %d", ErrBadPolicy, p.KeepS, DefaultKeepS)
	case p.SampleTimeout < 0:
		return p, fmt.Errorf("%w: negative timeout", ErrBadPolicy)
	}
	return p, nil
}

type LatestSource interface {
	ChainID(ctx context.Context) (string, error)
	// LatestSample reads the head, the latest value, then the head again.
	// ChainID is the chain id the endpoint reported with this read.
	// ObservedAt is filled by the caller.
	LatestSample(ctx context.Context) (Sample, error)
}

// AtHeightSource is a direct read of the value at a height. Params cannot
// check either requirement below, so an implementation MUST meet both.
type AtHeightSource interface {
	// RetentionAt MUST fail unless the response echoes the requested height
	// (x-cosmos-block-height equal to height).
	RetentionAt(ctx context.Context, height uint64) (uint64, error)
	// HonoursHeight is the canary: true only if the endpoint rejects heights
	// that cannot hold the state. It MUST run on the same connection as the
	// RetentionAt call it follows, so a load balancer cannot answer the two
	// from different backends.
	HonoursHeight(ctx context.Context) (bool, error)
}

type Store interface {
	// Bind ties the store to a chain id; a different id gives ErrChainMismatch
	// and an empty id is refused.
	Bind(ctx context.Context, chainID string) error
	Last(ctx context.Context) (Run, bool, error)
	// Append applies Next and persists the result durably before returning.
	// It fails with ErrChainMismatch while the store is not bound, and with
	// ErrBadSample for a sample that brackets no height.
	Append(ctx context.Context, s Sample, p Policy) error
	// Segment returns every run of each segment that covers the height.
	Segment(ctx context.Context, height uint64) ([]Run, error)
	// Prune drops runs last extended before the given Unix time, except those
	// of the newest segment.
	Prune(ctx context.Context, before uint64) (int, error)
}

func fresh(seg uint64, s Sample) Run {
	return Run{
		Segment: seg, FirstFrom: s.FromHeight, FirstTo: s.ToHeight, LastFrom: s.FromHeight, LastTo: s.ToHeight,
		RetentionS: s.RetentionS, FirstAt: s.ObservedAt, LastAt: s.ObservedAt,
	}
}

// Next folds a sample into the history. With appendNew false the returned
// run replaces last; otherwise it is a new run.
func Next(last Run, have bool, s Sample, p Policy) (updated Run, appendNew bool) {
	if !have {
		return fresh(1, s), true
	}
	regress := s.FromHeight < last.LastFrom || s.ToHeight < last.LastTo || s.ObservedAt < last.LastAt
	if regress || s.FromHeight-last.LastFrom > p.MaxGapBlocks || s.ObservedAt-last.LastAt > p.MaxGapS {
		return fresh(last.Segment+1, s), true
	}
	if s.RetentionS != last.RetentionS {
		return fresh(last.Segment, s), true
	}
	last.LastFrom, last.LastTo, last.LastAt = s.FromHeight, s.ToHeight, s.ObservedAt
	return last, false
}

// Plan is Next for stores: a new segment id is above every id in use, as the
// newest segment is never pruned, and two runs never share a storage key.
func Plan(last Run, have bool, topSegment uint64, s Sample, p Policy) (run Run, appendNew bool) {
	run, appendNew = Next(last, have, s, p)
	if !have {
		run.Segment = topSegment + 1
		return run, true
	}
	if appendNew && run.Segment == last.Segment && run.FirstFrom == last.FirstFrom {
		run.Segment = last.Segment + 1
	}
	return run, appendNew
}

// Covers reports whether a segment (its runs in order) brackets the height.
func Covers(runs []Run, height uint64) bool {
	return len(runs) > 0 && runs[0].FirstTo <= height && height <= runs[len(runs)-1].LastFrom
}

// AtHeight is the minimum retention over every run that may have been in
// force at the height. Runs must be ordered by segment, then position.
func AtHeight(runs []Run, height uint64) (uint64, error) {
	var (
		best  uint64
		found bool
	)
	for start := 0; start < len(runs); {
		end := start + 1
		for end < len(runs) && runs[end].Segment == runs[start].Segment {
			end++
		}
		seg := runs[start:end]
		start = end
		if !Covers(seg, height) {
			continue
		}
		for i, r := range seg {
			lo, hi := r.FirstTo, r.LastFrom
			if i > 0 {
				lo = seg[i-1].LastFrom
			}
			if i+1 < len(seg) {
				hi = seg[i+1].FirstTo
			}
			if lo <= height && height <= hi && (!found || r.RetentionS < best) {
				best, found = r.RetentionS, true
			}
		}
	}
	if !found {
		return 0, ErrNotCovered
	}
	return best, nil
}

// Covering returns every run of each segment that covers the height, for
// runs ordered by segment, then position.
func Covering(runs []Run, height uint64) []Run {
	var out []Run
	for start := 0; start < len(runs); {
		end := start + 1
		for end < len(runs) && runs[end].Segment == runs[start].Segment {
			end++
		}
		if seg := runs[start:end]; Covers(seg, height) {
			out = append(out, seg...)
		}
		start = end
	}
	return out
}
