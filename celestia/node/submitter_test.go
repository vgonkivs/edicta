package node

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	libshare "github.com/celestiaorg/go-square/v4/share"

	"github.com/celestiaorg/celestia-node/blob"
)

type fakeBlobSubmitter struct {
	addr []byte
	got  []*blob.Blob
	opts *blob.SubmitOptions
	h    uint64
	err  error
}

func (f *fakeBlobSubmitter) Submit(_ context.Context, b []*blob.Blob, o *blob.SubmitOptions) (uint64, error) {
	f.got, f.opts = b, o
	return f.h, f.err
}
func (f *fakeBlobSubmitter) Address(context.Context) ([]byte, error) { return f.addr, nil }

func testNS() []byte {
	ns := make([]byte, 29)
	copy(ns[19:], "edictatest")
	return ns
}

func TestSubmitBlobIsShareV1SignedByKey(t *testing.T) {
	f := &fakeBlobSubmitter{addr: bytes.Repeat([]byte{7}, 20), h: 1234}
	s := clientSubmitter{s: f}
	h, err := s.SubmitBlob(context.Background(), testNS(), []byte("payload"))
	require.NoError(t, err)
	require.EqualValues(t, 1234, h)
	require.Len(t, f.got, 1)
	b := f.got[0]
	require.Equal(t, uint8(libshare.ShareVersionOne), b.ShareVersion())
	require.Equal(t, f.addr, b.Signer())
	require.Equal(t, []byte("payload"), b.Data())
	require.Equal(t, testNS(), b.Namespace().Bytes())

	a, err := s.Address(context.Background())
	require.NoError(t, err)
	require.Equal(t, f.addr, a)
}

func TestSubmitBlobErrors(t *testing.T) {
	f := &fakeBlobSubmitter{addr: bytes.Repeat([]byte{7}, 20)}
	s := clientSubmitter{s: f}

	_, err := s.SubmitBlob(context.Background(), []byte("short"), []byte("x"))
	require.Error(t, err)

	f.err = errors.New("rpc error: account sequence mismatch, expected 3, got 2")
	_, err = s.SubmitBlob(context.Background(), testNS(), []byte("x"))
	require.ErrorIs(t, err, ErrSequenceMismatch)

	f.err = errors.New("boom not found")
	_, err = s.SubmitBlob(context.Background(), testNS(), []byte("x"))
	require.ErrorIs(t, err, ErrUnavailable, "a failed submit is never 'not found'")
	require.NotErrorIs(t, err, ErrNotFound)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f.err = errors.New("blob not found")
	_, err = s.SubmitBlob(ctx, testNS(), []byte("x"))
	require.ErrorIs(t, err, ErrUnavailable)
	require.NotErrorIs(t, err, ErrNotFound)

	bad := clientSubmitter{s: &fakeBlobSubmitter{addr: []byte{1, 2}}}
	_, err = bad.SubmitBlob(context.Background(), testNS(), []byte("x"))
	require.ErrorIs(t, err, ErrUnsupported)
}

func TestWrapCtxContextBeatsNotFound(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := wrapCtx(ctx, errors.New("blob: not found"))
	require.ErrorIs(t, err, ErrUnavailable)
	require.NotErrorIs(t, err, ErrNotFound)
	require.ErrorIs(t, wrapCtx(context.Background(), errors.New("blob: not found")), ErrNotFound)
}
