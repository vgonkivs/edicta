package heightcheck

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"

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
// and the at-height readers share one; a passing canary clears it unless a mark
// landed after the canary began. The zero value is ready and a nil Flag is
// never set.
type Flag struct {
	mu      sync.Mutex
	ignored bool
	gen     uint64
}

// Mark sets the flag.
func (f *Flag) Mark() {
	if f == nil {
		return
	}
	f.mu.Lock()
	f.ignored = true
	f.gen++
	f.mu.Unlock()
}

// Generation counts the marks so far. Read it before a canary starts and pass it
// to ClearIf.
func (f *Flag) Generation() uint64 {
	if f == nil {
		return 0
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gen
}

// ClearIf resets the flag unless it was marked after gen was read.
func (f *Flag) ClearIf(gen uint64) {
	if f == nil {
		return
	}
	f.mu.Lock()
	if f.gen == gen {
		f.ignored = false
	}
	f.mu.Unlock()
}

// Clear resets the flag unconditionally.
func (f *Flag) Clear() {
	if f == nil {
		return
	}
	f.mu.Lock()
	f.ignored = false
	f.mu.Unlock()
}

// Ignoring reports whether the endpoint is marked height-ignoring.
func (f *Flag) Ignoring() bool {
	if f == nil {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ignored
}

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

// Described is an optional Endpoint extension. Details returns slog key-value
// pairs, valid after Canary ran, that Startup adds to the endpoint's log line.
type Described interface {
	Details() []any
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
		var details []any
		if d, ok := ep.(Described); ok {
			details = d.Details()
		}
		switch {
		case st == Honoured && cerr == nil:
			log.Info(ep.Name()+": height honoured", details...)
		case st == Ignoring && consensus:
			observationsOnly = true
			log.Warn(ep.Name()+": height-ignoring, observations-only mode", details...)
		case st == Ignoring:
			log.Warn(ep.Name()+": height-ignoring", details...)
		case consensus:
			observationsOnly = true
			log.Warn(ep.Name()+": height check inconclusive, observations-only mode", append([]any{"err", cerr}, details...)...)
		default:
			log.Warn(ep.Name()+": height check inconclusive", append([]any{"err", cerr}, details...)...)
		}
	}
	return observationsOnly, nil
}
