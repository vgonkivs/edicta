package heightcheck

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
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
	// Honoured: the endpoint rejects heights that cannot hold the state.
	Honoured Status = iota + 1
	// Ignoring: the endpoint answered a height it cannot have answered.
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

// ClassifyGRPC reads the result of a query pinned to a height that cannot
// hold the state. Success proves the height was dropped; an error from the
// node itself proves it was looked at; anything else proves nothing.
func ClassifyGRPC(err error) Status {
	if err == nil {
		return Ignoring
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return Inconclusive
	}
	st, ok := status.FromError(err)
	if !ok {
		return Inconclusive
	}
	switch st.Code() {
	case codes.Internal, codes.NotFound, codes.InvalidArgument:
		return Honoured
	}
	return Inconclusive
}

// Endpoint is one at-height reader with a canary.
type Endpoint interface {
	Name() string
	Canary(ctx context.Context) (Status, error)
}

// Startup runs every canary and logs one line per endpoint. It reports
// observations-only mode when any endpoint did not pass; a canary never makes
// it fail.
func Startup(ctx context.Context, log *slog.Logger, eps ...Endpoint) (observationsOnly bool, err error) {
	if log == nil {
		log = slog.Default()
	}
	for _, ep := range eps {
		st, cerr := ep.Canary(ctx)
		switch {
		case st == Honoured && cerr == nil:
			log.Info(ep.Name() + ": height honoured")
		case st == Ignoring:
			observationsOnly = true
			log.Warn(ep.Name() + ": height-ignoring, observations-only mode")
		default:
			observationsOnly = true
			log.Warn(ep.Name()+": height check inconclusive, observations-only mode", "err", cerr)
		}
	}
	return observationsOnly, nil
}
