package nodefake

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	"github.com/vgonkivs/edicta/celestia/node"
)

var _ node.FibreSubmitter = (*FibreSubmitter)(nil)

// SubmitPlan decides one SubmitFibre call.
type SubmitPlan struct {
	// Land, when set, goes onto Chain once Block (if any) is released.
	Land   *LandedPFF
	Result node.FibreResult
	Err    error
	// Block, when set, makes the call wait for it to close, or for its ctx.
	Block chan struct{}
}

// FibreSubmitter fakes the own-node Fibre submit path. Plan is called when a
// call starts, with the 1-based call number; a nil Plan fails every call.
type FibreSubmitter struct {
	Addr      []byte
	EscrowVal node.Escrow
	EscrowErr error
	Endpt     string
	// Chain receives the PFFs of Land plans.
	Chain *FibreNode
	Plan  func(call int, ns, data []byte) SubmitPlan

	mu          sync.Mutex
	calls       int
	escrowReads int
	uctx        []context.Context
}

// Address returns Addr.
func (f *FibreSubmitter) Address(context.Context) ([]byte, error) { return bytes.Clone(f.Addr), nil }

// Endpoint returns Endpt.
func (f *FibreSubmitter) Endpoint() string { return f.Endpt }

// Escrow returns EscrowVal or EscrowErr and counts the read.
func (f *FibreSubmitter) Escrow(context.Context) (node.Escrow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.escrowReads++
	return f.EscrowVal, f.EscrowErr
}

// SetEscrow replaces the escrow state between calls.
func (f *FibreSubmitter) SetEscrow(e node.Escrow) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.EscrowVal = e
}

func (f *FibreSubmitter) SubmitFibre(ctx context.Context, namespace, data []byte) (node.FibreResult, error) {
	f.mu.Lock()
	f.calls++
	call := f.calls
	f.uctx = append(f.uctx, ctx)
	plan := f.Plan
	f.mu.Unlock()
	if plan == nil {
		return node.FibreResult{}, fmt.Errorf("%w: no plan", node.ErrUnavailable)
	}
	p := plan(call, bytes.Clone(namespace), bytes.Clone(data))
	if p.Block != nil {
		select {
		case <-p.Block:
		case <-ctx.Done():
			return node.FibreResult{}, fmt.Errorf("%w: %w", node.ErrUnavailable, ctx.Err())
		}
	}
	if p.Land != nil && f.Chain != nil {
		f.Chain.Land(*p.Land)
	}
	return p.Result, p.Err
}

// Calls counts SubmitFibre calls.
func (f *FibreSubmitter) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// EscrowReads counts Escrow calls.
func (f *FibreSubmitter) EscrowReads() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.escrowReads
}

// UploadCtx is the ctx call number call (1-based) was given.
func (f *FibreSubmitter) UploadCtx(call int) context.Context {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.uctx[call-1]
}
