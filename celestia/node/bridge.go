package node

import (
	"context"
	"errors"
	"fmt"

	libshare "github.com/celestiaorg/go-square/v4/share"

	"github.com/celestiaorg/celestia-node/api/client"
	"github.com/celestiaorg/celestia-node/blob"
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
		return Header{}, wrap(err)
	}
	return Header{
		ChainID: h.ChainID(), Height: uint64(h.Height()), Time: h.Time(),
		AppVersion: h.Version.App, DataRoot: append([]byte(nil), h.DataHash...),
	}, nil
}

func (b bridge) HeaderAt(ctx context.Context, height uint64) (Header, error) {
	h, err := b.rc.Header.GetByHeight(ctx, height)
	if err != nil {
		return Header{}, wrap(err)
	}
	return Header{
		ChainID: h.ChainID(), Height: uint64(h.Height()), Time: h.Time(),
		AppVersion: h.Version.App, DataRoot: append([]byte(nil), h.DataHash...),
	}, nil
}

func (b bridge) Blob(ctx context.Context, height uint64, namespace, commitment []byte) (Blob, error) {
	ns, err := libshare.NewNamespaceFromBytes(namespace)
	if err != nil {
		return Blob{}, fmt.Errorf("node: namespace: %w", err)
	}
	bl, err := b.rc.Blob.Get(ctx, height, ns, commitment)
	if err != nil {
		return Blob{}, wrap(err)
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
		return nil, wrap(err)
	}
	if p == nil {
		return nil, ErrNotFound
	}
	return proof{p: p}, nil
}

type proof struct{ p *blob.CommitmentProof }

func (p proof) Verify(dataRoot, commitment []byte) error { return p.p.Verify(dataRoot, commitment) }

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
