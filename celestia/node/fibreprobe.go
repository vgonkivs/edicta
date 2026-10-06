package node

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/filecoin-project/go-jsonrpc"

	appfibre "github.com/celestiaorg/celestia-app/v10/fibre"
)

// ErrBridgeShape means a bridge answer does not have the shape this build
// expects, which is how an incompatible bridge shows itself.
var ErrBridgeShape = errors.New("node: bridge answer has an unexpected shape")

// ParseDownloadResult decodes the raw JSON-RPC result of fibre.Download. The
// struct decoder would read a renamed or missing member as an empty blob, so
// the result must be one object with exactly one member, data, holding a
// standard padded base64 string.
func ParseDownloadResult(raw []byte) ([]byte, error) {
	shape := func(format string, a ...any) ([]byte, error) {
		return nil, fmt.Errorf("%w: %s", ErrBridgeShape, fmt.Sprintf(format, a...))
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return shape("result is not an object")
	}
	key, err := dec.Token()
	if err != nil || key != "data" {
		return shape("result has no data member first")
	}
	val, err := dec.Token()
	s, ok := val.(string)
	if err != nil || !ok {
		return shape("data is not a string")
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return shape("result has more than one member")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return shape("data after the result object")
	}
	// The decoder skips line breaks; a strict reader must not.
	if strings.ContainsAny(s, "\r\n") {
		return shape("data is not base64")
	}
	out, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return shape("data is not base64")
	}
	return out, nil
}

// rawFibre calls fibre.Download and keeps the result undecoded.
type rawFibre struct {
	Download func(ctx context.Context, id appfibre.BlobID) (json.RawMessage, error)
}

// DownloadRaw is fibre.Download on the bridge with the raw JSON-RPC result
// returned, for the capability probe. It is read up to what maxSize bytes need
// on the wire.
func (b *FibreBridge) DownloadRaw(ctx context.Context, id [33]byte, maxSize uint64) ([]byte, error) {
	if b.raw.Download == nil {
		return nil, fmt.Errorf("%w: bridge has no raw download client", ErrUnavailable)
	}
	r, err := b.raw.Download(withBodyLimit(ctx, wireSize(maxSize)), appfibre.BlobID(id[:]))
	if err != nil {
		if ctx.Err() == nil && incompatibleAnswer(err) {
			return nil, fmt.Errorf("%w: %w", ErrBridgeIncompatible, err)
		}
		return nil, wrapCtx(ctx, err)
	}
	return r, nil
}

// incompatibleAnswer tells a bridge that refused the call (no permission, no
// such method, wrong parameters, undecodable parameters, HTTP 401) from a
// transport failure.
func incompatibleAnswer(err error) bool {
	var je *jsonrpc.JSONRPCError
	if errors.As(err, &je) {
		switch je.Code {
		case -32601, -32602, -32700:
			return true
		}
		return strings.Contains(je.Message, "missing permission")
	}
	return strings.Contains(err.Error(), "http status 401")
}

// ErrBridgeIncompatible means a bridge answered the capability probe in a way
// this build cannot use: an authorization or method error, or an answer of the
// wrong shape or content.
var ErrBridgeIncompatible = errors.New("node: bridge is not compatible with the download fallback")
