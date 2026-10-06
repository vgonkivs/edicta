package heightcheck

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync/atomic"

	"google.golang.org/grpc/metadata"
)

// HeightHeader is the response header a Cosmos SDK node sets to the height it
// answered at.
const HeightHeader = "x-cosmos-block-height"

// ErrHeightIgnored means a response is not for the requested height, or the
// endpoint does not honour pinned heights.
var ErrHeightIgnored = errors.New("heightcheck: endpoint ignored the requested height")

// Status is the outcome of an endpoint canary.
type Status int

const (
	// Honoured: the endpoint echoed a recent past height and answered nothing
	// at a height before the module existed.
	Honoured Status = iota + 1
	// Ignoring: the endpoint answered without the requested height, or answered
	// a height that cannot hold the state.
	Ignoring
	// Inconclusive: the canary could not tell, for example on a transport error.
	Inconclusive
)

// EchoHeight requires exactly one x-cosmos-block-height value equal to want.
func EchoHeight(md metadata.MD, want uint64) error {
	v := md.Get(HeightHeader)
	if len(v) != 1 {
		return fmt.Errorf("%w: %d %s values, want one", ErrHeightIgnored, len(v), HeightHeader)
	}
	got, err := strconv.ParseUint(v[0], 10, 64)
	if err != nil {
		return fmt.Errorf("%w: %s %q is not a height", ErrHeightIgnored, HeightHeader, v[0])
	}
	if v[0] != strconv.FormatUint(got, 10) {
		return fmt.Errorf("%w: %s %q is not a canonical height", ErrHeightIgnored, HeightHeader, v[0])
	}
	if got != want {
		return fmt.Errorf("%w: answered at height %d, asked %d", ErrHeightIgnored, got, want)
	}
	return nil
}

// HeaderHeight requires the height of a returned header to be the requested one.
func HeaderHeight(got, want uint64) error {
	if got != want {
		return fmt.Errorf("%w: header at height %d, asked %d", ErrHeightIgnored, got, want)
	}
	return nil
}

// Flag records that a consensus endpoint was seen ignoring heights. The canary
// and the block readers share one; a passing canary clears it. The zero value
// is ready and a nil Flag is never set.
type Flag struct{ ignoring atomic.Bool }

// Mark sets the flag.
func (f *Flag) Mark() {
	if f != nil {
		f.ignoring.Store(true)
	}
}

// Clear resets the flag.
func (f *Flag) Clear() {
	if f != nil {
		f.ignoring.Store(false)
	}
}

// Ignoring reports whether the endpoint is marked height-ignoring.
func (f *Flag) Ignoring() bool { return f != nil && f.ignoring.Load() }

// Role tells Startup what an endpoint's canary decides.
type Role int

const (
	// RoleConsensus endpoints serve state reads; their result drives
	// observations-only mode.
	RoleConsensus Role = iota + 1
	// RoleBridge endpoints serve headers and blobs; their result is only logged.
	RoleBridge
)

// Endpoint is one at-height reader with a canary.
type Endpoint interface {
	Name() string
	Role() Role
	Canary(ctx context.Context) (Status, error)
}

// Startup runs every canary and logs one line per endpoint. It reports
// observations-only mode when any consensus endpoint did not pass; bridge
// endpoints are logged only. A canary never makes it fail.
func Startup(ctx context.Context, log *slog.Logger, eps ...Endpoint) (observationsOnly bool, err error) {
	if log == nil {
		log = slog.Default()
	}
	for _, ep := range eps {
		st, cerr := ep.Canary(ctx)
		consensus := ep.Role() == RoleConsensus
		switch {
		case st == Honoured && cerr == nil:
			log.Info(ep.Name() + ": height honoured")
		case st == Ignoring && consensus:
			observationsOnly = true
			log.Warn(ep.Name() + ": height-ignoring, observations-only mode")
		case st == Ignoring:
			log.Warn(ep.Name() + ": height-ignoring")
		case consensus:
			observationsOnly = true
			log.Warn(ep.Name()+": height check inconclusive, observations-only mode", "err", cerr)
		default:
			log.Warn(ep.Name()+": height check inconclusive", "err", cerr)
		}
	}
	return observationsOnly, nil
}
