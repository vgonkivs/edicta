package recorder

import (
	"bytes"
	"context"

	"github.com/vgonkivs/edicta/celestia/node"
)

// Submitter puts one share version 1 blob on chain under its own account. It
// is trusted for liveness only: the Recorder re-verifies everything it claims.
//
// Submit may return node.ErrUnsupported only before anything was broadcast:
// the Recorder then treats the call as never made and may submit again. Any
// error after a broadcast started must be another error, which the Recorder
// treats as an unknown outcome and only searches the chain for.
type Submitter interface {
	// Signer is the 20-byte address embedded in every blob it submits.
	Signer(ctx context.Context) ([]byte, error)
	Submit(ctx context.Context, namespace, data []byte) (SubmitResult, error)
}

// SubmitResult is what a Submitter claims about a submission.
type SubmitResult struct {
	// Height is the claimed inclusion height; unverified.
	Height uint64
	// TxHash is nil when the backend does not expose it.
	TxHash []byte
}

type localSubmitter struct{ s node.Submitter }

// localKeySubmitter also shows the public key of the submitting account.
type localKeySubmitter struct {
	localSubmitter
	node.AnchorPublicKey
}

// NewLocalSubmitter submits with the node's local keyring key. When s shows
// its public key (node.AnchorPublicKey), the result shows it too.
func NewLocalSubmitter(s node.Submitter) Submitter {
	if pk, ok := s.(node.AnchorPublicKey); ok {
		return localKeySubmitter{localSubmitter: localSubmitter{s: s}, AnchorPublicKey: pk}
	}
	return localSubmitter{s: s}
}

func (l localSubmitter) Signer(ctx context.Context) ([]byte, error) {
	a, err := l.s.Address(ctx)
	if err != nil {
		return nil, err
	}
	return bytes.Clone(a), nil
}

func (l localSubmitter) Submit(ctx context.Context, namespace, data []byte) (SubmitResult, error) {
	h, err := l.s.SubmitBlob(ctx, namespace, data)
	if err != nil {
		return SubmitResult{}, err
	}
	return SubmitResult{Height: h}, nil
}
