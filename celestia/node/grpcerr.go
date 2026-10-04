package node

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// classifyGRPC maps a gRPC error onto the package sentinels. A finished
// context is decided first: a cancelled call must never read as "not found".
func classifyGRPC(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if cerr := ctx.Err(); cerr != nil {
		return fmt.Errorf("%w: %w", ErrUnavailable, errors.Join(cerr, err))
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	st, ok := status.FromError(err)
	if !ok {
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	switch st.Code() {
	case codes.NotFound:
		return fmt.Errorf("%w: %s", ErrNotFound, st.Message())
	case codes.Unimplemented:
		return fmt.Errorf("%w: %s", ErrUnsupported, st.Message())
	default:
		return fmt.Errorf("%w: %s: %s", ErrUnavailable, st.Code(), st.Message())
	}
}
