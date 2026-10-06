package node

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	libshare "github.com/celestiaorg/go-square/v4/share"

	"github.com/celestiaorg/celestia-node/api/client"
	"github.com/celestiaorg/celestia-node/blob"
)

// blobSubmitter is the part of api/client the Submitter uses; tests fake it.
type blobSubmitter interface {
	Submit(ctx context.Context, blobs []*blob.Blob, opts *blob.SubmitOptions) (uint64, error)
	// Address is the signer address of the client's key.
	Address(ctx context.Context) ([]byte, error)
}

type clientSubmitter struct{ s blobSubmitter }

// newSubmitter submits share v1 blobs through c, signed client-side with the
// keyring key c was built with (its DefaultKeyName) and broadcast to the
// consensus gRPC endpoint. The caller keeps ownership of c and closes it.
func newSubmitter(c *client.Client) (Submitter, error) {
	if c == nil || c.State == nil || c.Blob == nil {
		return nil, errors.New("node: client has no submit side")
	}
	return clientSubmitter{s: apiClient{c: c}}, nil
}

type apiClient struct{ c *client.Client }

func (a apiClient) Submit(ctx context.Context, b []*blob.Blob, o *blob.SubmitOptions) (uint64, error) {
	return a.c.Blob.Submit(ctx, b, o)
}

func (a apiClient) Address(ctx context.Context) ([]byte, error) {
	ad, err := a.c.State.AccountAddress(ctx)
	if err != nil {
		return nil, err
	}
	return ad.Bytes(), nil
}

func (s clientSubmitter) Address(ctx context.Context) ([]byte, error) {
	a, err := s.s.Address(ctx)
	if err != nil {
		return nil, wrapCtx(ctx, err)
	}
	if len(a) != 20 {
		return nil, fmt.Errorf("%w: signer address is %d bytes", ErrUnsupported, len(a))
	}
	return bytes.Clone(a), nil
}

func (s clientSubmitter) SubmitBlob(ctx context.Context, namespace, data []byte) (uint64, error) {
	ns, err := libshare.NewNamespaceFromBytes(namespace)
	if err != nil {
		return 0, fmt.Errorf("node: namespace: %w", err)
	}
	signer, err := s.Address(ctx)
	if err != nil {
		return 0, err
	}
	b, err := blob.NewBlobV1(ns, data, signer)
	if err != nil {
		return 0, fmt.Errorf("node: building blob: %w", err)
	}
	h, err := s.s.Submit(ctx, []*blob.Blob{b}, nil)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return 0, fmt.Errorf("%w: %w", ErrUnavailable, errors.Join(cerr, err))
		}
		if strings.Contains(err.Error(), "account sequence mismatch") {
			return 0, fmt.Errorf("%w: %v", ErrSequenceMismatch, err)
		}
		return 0, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return h, nil
}
