package node

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"
)

// Expect is what Check requires of the node and chain. Zero fields take the
// defaults noted.
type Expect struct {
	ChainID       string // optional; empty = discover
	MinAppVersion uint64 // default 3, UNVERIFIED as the share-v1 floor
	MaxAppVersion uint64 // default 10, the highest version the pin was built against
	MaxHeadLagS   uint64 // default 120
	// Namespace is used by the API shape probe; empty uses a fixed v0 probe
	// namespace.
	Namespace []byte
	// Now is the local clock; nil is time.Now.
	Now func() time.Time
}

// Defaults for Expect.
const (
	DefaultMinAppVersion = 3
	DefaultMaxAppVersion = 10
	DefaultMaxHeadLagS   = 120
)

// Check refuses a node or chain this build cannot use. It is mandatory on
// every network and has no override. Every refusal wraps ErrUnsupported. It
// returns the head it validated.
func Check(ctx context.Context, r Reader, c Consensus, e Expect) (Header, error) {
	if r == nil || c == nil {
		return Header{}, fmt.Errorf("%w: reader and consensus are required", ErrUnsupported)
	}
	if e.MinAppVersion == 0 {
		e.MinAppVersion = DefaultMinAppVersion
	}
	if e.MaxAppVersion == 0 {
		e.MaxAppVersion = DefaultMaxAppVersion
	}
	if e.MaxHeadLagS == 0 {
		e.MaxHeadLagS = DefaultMaxHeadLagS
	}
	now := time.Now
	if e.Now != nil {
		now = e.Now
	}

	head, err := r.Head(ctx)
	if err != nil {
		return Header{}, fmt.Errorf("%w: bridge node head: %w", ErrUnsupported, err)
	}
	if head.ChainID == "" {
		return Header{}, fmt.Errorf("%w: head has no chain id", ErrUnsupported)
	}
	if e.ChainID != "" && e.ChainID != head.ChainID {
		return Header{}, fmt.Errorf("%w: chain id %q, expected %q", ErrUnsupported, head.ChainID, e.ChainID)
	}
	net, err := c.Network(ctx)
	if err != nil {
		return Header{}, fmt.Errorf("%w: consensus node info: %w", ErrUnsupported, err)
	}
	if net != head.ChainID {
		return Header{}, fmt.Errorf("%w: consensus node on %q, bridge node on %q", ErrUnsupported, net, head.ChainID)
	}
	ids, err := c.ProviderChainIDs(ctx)
	if err != nil {
		return Header{}, fmt.Errorf("%w: consensus providers: %w", ErrUnsupported, err)
	}
	for i, id := range ids {
		if id != head.ChainID {
			return Header{}, fmt.Errorf("%w: consensus provider %d on %q, bridge node on %q", ErrUnsupported, i, id, head.ChainID)
		}
	}
	if head.AppVersion < e.MinAppVersion || head.AppVersion > e.MaxAppVersion {
		return Header{}, fmt.Errorf("%w: app version %d outside %d..%d",
			ErrUnsupported, head.AppVersion, e.MinAppVersion, e.MaxAppVersion)
	}
	lag := now().Sub(head.Time)
	if lag < 0 {
		lag = -lag
	}
	if lag > time.Duration(e.MaxHeadLagS)*time.Second {
		return Header{}, fmt.Errorf("%w: head time %s off the local clock by %s", ErrUnsupported, head.Time.UTC().Format(time.RFC3339), lag.Round(time.Second))
	}

	ns := e.Namespace
	if len(ns) == 0 {
		ns = probeNamespace()
	}
	probe := make([]byte, 32)
	if _, err := rand.Read(probe); err != nil {
		return Header{}, fmt.Errorf("%w: probe randomness: %w", ErrUnsupported, err)
	}
	if _, err := r.Blob(ctx, head.Height, ns, probe); !errors.Is(err, ErrNotFound) {
		return Header{}, fmt.Errorf("%w: blob probe did not classify as not found: %w", ErrUnsupported, errOrNil(err))
	}
	if _, err := r.CommitmentProof(ctx, head.Height, ns, probe); !errors.Is(err, ErrNotFound) {
		return Header{}, fmt.Errorf("%w: commitment proof probe did not classify as not found: %w", ErrUnsupported, errOrNil(err))
	}
	return head, nil
}

func errOrNil(err error) error {
	if err == nil {
		return errors.New("no error")
	}
	return err
}

// probeNamespace is a version-0 namespace: version byte 0, 18 zero bytes and 10
// id bytes, 29 bytes in all.
func probeNamespace() []byte {
	ns := make([]byte, 29)
	copy(ns[19:], "edictaprob")
	return ns
}
