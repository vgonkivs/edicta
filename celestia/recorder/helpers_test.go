package recorder_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
	"github.com/vgonkivs/edicta/celestia/recorder"
	"github.com/vgonkivs/edicta/dacommit/sharev1"
)

var (
	bg      = context.Background()
	ns      = append(append([]byte{0}, make([]byte, 18)...), bytes.Repeat([]byte{7}, 10)...)
	signer  = bytes.Repeat([]byte{9}, 20)
	other   = bytes.Repeat([]byte{4}, 20)
	genesis = uint64(100)
	// The sub-second part checks that block time is floored.
	t0 = time.Date(2026, 10, 4, 12, 0, 0, 700_000_000, time.UTC)
)

func blockAt(h uint64) node.Header {
	return node.Header{ChainID: "devnet-1", Height: h, Time: t0.Add(time.Duration(h) * 6 * time.Second),
		AppVersion: 8, DataRoot: bytes.Repeat([]byte{byte(h)}, 32)}
}

func newChain() *nodefake.Chain {
	c := nodefake.NewChain(signer)
	c.AddHeader(blockAt(genesis))
	return c
}

func realCommitment(t testing.TB, ns, signer, data []byte) []byte {
	t.Helper()
	c, err := sharev1.Commitment(ns, signer, data)
	require.NoError(t, err)
	return c
}

// landing is a Submitter fake that writes the blob into a nodefake.Chain with
// the REAL share commitment (nodefake.SubmitBlob uses a stand-in), and can be
// bent. It implements recorder.Submitter.
type landing struct {
	mu    sync.Mutex
	chain *nodefake.Chain
	addr  []byte

	Calls int
	// Bend knobs.
	BlobSigner   []byte // signer stored on chain; nil = addr
	ShareV       *uint8 // share version stored on chain; nil = 1
	DataTamper   bool   // store different data than submitted
	ClaimOffset  uint64 // claimed height = real + offset
	NoLand       bool   // do not put the blob on chain
	Err          error  // returned from Submit
	ErrAfterLand bool   // with Err: the blob still lands (ambiguous outcome)
	OnSubmit     func()
}

func newLanding(c *nodefake.Chain) *landing { return &landing{chain: c, addr: signer} }

func (l *landing) Signer(context.Context) ([]byte, error) { return bytes.Clone(l.addr), nil }

func (l *landing) Submit(ctx context.Context, namespace, data []byte) (recorder.SubmitResult, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.Calls++
	if l.OnSubmit != nil {
		l.OnSubmit()
	}
	if l.Err != nil && !l.ErrAfterLand {
		return recorder.SubmitResult{}, l.Err
	}
	head, _ := l.chain.Head(ctx)
	h := head.Height + 1
	l.chain.AddHeader(blockAt(h))
	if !l.NoLand {
		s := l.addr
		if l.BlobSigner != nil {
			s = l.BlobSigner
		}
		v := uint8(1)
		if l.ShareV != nil {
			v = *l.ShareV
		}
		stored := bytes.Clone(data)
		if l.DataTamper {
			stored = append(stored, 0xff)
		}
		l.chain.AddBlob(h, node.Blob{Namespace: bytes.Clone(namespace), Data: stored, ShareVersion: v,
			Signer: bytes.Clone(s), Commitment: realCommitmentNoT(namespace, l.addr, data)}, nil)
	}
	if l.Err != nil {
		return recorder.SubmitResult{}, l.Err
	}
	return recorder.SubmitResult{Height: h + l.ClaimOffset}, nil
}

func realCommitmentNoT(ns, signer, data []byte) []byte {
	c, err := sharev1.Commitment(ns, signer, data)
	if err != nil {
		panic(err)
	}
	return c
}

// lagReader hides header/blob at the first n calls (node not yet synced).
type lagReader struct {
	node.Reader
	mu        sync.Mutex
	hdrMiss   int
	blobMiss  int
	hdrCalls  int
	blobCalls int
	onCall    func()
	// err replaces ErrNotFound while missing, if set.
	err error
}

func (r *lagReader) miss() error {
	if r.err != nil {
		return r.err
	}
	return node.ErrNotFound
}

func (r *lagReader) HeaderAt(ctx context.Context, h uint64) (node.Header, error) {
	r.mu.Lock()
	r.hdrCalls++
	miss := r.hdrCalls <= r.hdrMiss
	cb := r.onCall
	r.mu.Unlock()
	if cb != nil {
		cb()
	}
	if miss {
		return node.Header{}, r.miss()
	}
	return r.Reader.HeaderAt(ctx, h)
}

func (r *lagReader) Blob(ctx context.Context, h uint64, n, c []byte) (node.Blob, error) {
	r.mu.Lock()
	r.blobCalls++
	miss := r.blobCalls <= r.blobMiss
	r.mu.Unlock()
	if miss {
		return node.Blob{}, r.miss()
	}
	return r.Reader.Blob(ctx, h, n, c)
}

var errBoom = errors.New("boom")
