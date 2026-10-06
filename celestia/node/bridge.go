package node

import (
	"context"
	"errors"
	"fmt"

	libshare "github.com/celestiaorg/go-square/v4/share"

	"github.com/celestiaorg/celestia-node/api/client"
	"github.com/celestiaorg/celestia-node/blob"

	"github.com/vgonkivs/edicta/celestia/heightcheck"
)

// bridge adapts a celestia-node ReadClient to Reader.
type bridge struct{ rc *client.ReadClient }

// NewReader wraps the read side of an api/client. The caller keeps ownership
// of rc and closes it.
func NewReader(rc *client.ReadClient) (Reader, error) {
	if rc == nil {
		return nil, errors.New("node: nil read client")
	}
	return bridge{rc: rc}, nil
}

func (b bridge) Head(ctx context.Context) (Header, error) {
	h, err := b.rc.Header.NetworkHead(ctx)
	if err != nil {
		return Header{}, wrapCtx(ctx, err)
	}
	return Header{
		ChainID: h.ChainID(), Height: uint64(h.Height()), Time: h.Time(),
		AppVersion: h.Version.App, DataRoot: append([]byte(nil), h.DataHash...),
	}, nil
}

func (b bridge) HeaderAt(ctx context.Context, height uint64) (Header, error) {
	h, err := b.rc.Header.GetByHeight(ctx, height)
	if err != nil {
		return Header{}, wrapCtx(ctx, err)
	}
	if err := heightcheck.HeaderHeight(uint64(h.Height()), height); err != nil {
		return Header{}, heightIgnored(err)
	}
	return Header{
		ChainID: h.ChainID(), Height: uint64(h.Height()), Time: h.Time(),
		AppVersion: h.Version.App, DataRoot: append([]byte(nil), h.DataHash...),
	}, nil
}

// canaryAhead is how far above the head the bridge canary asks; no header
// exists there.
const canaryAhead = 1_000_000

type bridgeEndpoint struct {
	name string
	r    Reader
}

// BridgeEndpoint exposes the height canary of r to heightcheck.Startup.
func BridgeEndpoint(name string, r Reader) heightcheck.Endpoint {
	return bridgeEndpoint{name: name, r: r}
}

func (e bridgeEndpoint) Name() string { return e.name }

// Canary asks for a header far above the head: an honest bridge says not
// found, one that ignores the height answers some other header.
func (e bridgeEndpoint) Canary(ctx context.Context) (heightcheck.Status, error) {
	head, err := e.r.Head(ctx)
	if err != nil {
		return heightcheck.Inconclusive, fmt.Errorf("height canary: head: %w", err)
	}
	_, err = e.r.HeaderAt(ctx, head.Height+canaryAhead)
	switch {
	case err == nil, errors.Is(err, heightcheck.ErrHeightIgnored):
		return heightcheck.Ignoring, nil
	case errors.Is(err, ErrNotFound):
		return heightcheck.Honoured, nil
	}
	return heightcheck.Inconclusive, fmt.Errorf("height canary: %w", err)
}

func (b bridge) Blob(ctx context.Context, height uint64, namespace, commitment []byte) (Blob, error) {
	ns, err := libshare.NewNamespaceFromBytes(namespace)
	if err != nil {
		return Blob{}, fmt.Errorf("node: namespace: %w", err)
	}
	bl, err := b.rc.Blob.Get(ctx, height, ns, commitment)
	if err != nil {
		return Blob{}, wrapCtx(ctx, err)
	}
	if bl == nil || bl.Blob == nil {
		return Blob{}, ErrNotFound
	}
	return Blob{
		Namespace: bl.Namespace().Bytes(), Data: bl.Data(),
		ShareVersion: bl.ShareVersion(), Signer: bl.Signer(), Commitment: []byte(bl.Commitment),
	}, nil
}

func (b bridge) CommitmentProof(ctx context.Context, height uint64, namespace, commitment []byte) (CommitmentProof, error) {
	ns, err := libshare.NewNamespaceFromBytes(namespace)
	if err != nil {
		return nil, fmt.Errorf("node: namespace: %w", err)
	}
	p, err := b.rc.Blob.GetCommitmentProof(ctx, height, ns, commitment)
	if err != nil {
		return nil, wrapCtx(ctx, err)
	}
	if p == nil {
		return nil, ErrNotFound
	}
	return proof{p: p}, nil
}

type proof struct{ p *blob.CommitmentProof }

func (p proof) Verify(dataRoot, commitment []byte) error { return p.p.Verify(dataRoot, commitment) }

// wrapCtx classifies err, but a finished context always wins: a cancelled
// call whose error text happens to say "not found" is unavailable, never absent.
func wrapCtx(ctx context.Context, err error) error {
	if cerr := ctx.Err(); cerr != nil {
		return fmt.Errorf("%w: %w", ErrUnavailable, errors.Join(cerr, err))
	}
	return wrap(err)
}

// wrap classifies a library error by its text, since the JSON-RPC client
// returns plain errors, and never lets the original text hide the class.
func wrap(err error) error {
	msg := err.Error()
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	case containsAny(msg, "not found", "blob: not found", "no blob"):
		return fmt.Errorf("%w: %v", ErrNotFound, err)
	}
	return fmt.Errorf("%w: %v", ErrUnavailable, err)
}

func containsAny(s string, subs ...string) bool {
	for _, x := range subs {
		for i := 0; i+len(x) <= len(s); i++ {
			if s[i:i+len(x)] == x {
				return true
			}
		}
	}
	return false
}
