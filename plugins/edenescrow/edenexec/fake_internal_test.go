// SPDX-License-Identifier: Apache-2.0

package edenexec

import (
	"context"
	"sync"
)

// FakeSource is a scripted Source. A nil map entry is ErrNotFound; a set
// error field fails that method. Calls counts every method call by name.
type FakeSource struct {
	SrcName  string
	SrcClass SourceClass

	Chain     uint64
	HeadNum   uint64
	Code      [32]byte
	Txs       map[[32]byte]TxView
	Receipts  map[[32]byte]ReceiptView
	Headers   map[[32]byte]HeaderView
	BlockTxs  map[[32]byte][][]byte
	BlockRcpt map[[32]byte][][]byte

	ChainErr, HeadErr, CodeErr, TxErr, ReceiptErr, HeaderErr, BlockTxsErr, BlockRcptErr error

	// OnTransaction, when set, replaces the transaction lookup; n counts its
	// calls from 1.
	OnTransaction func(n int, hash [32]byte) (TxView, error)

	mu    sync.Mutex
	Calls map[string]int
}

var _ Source = (*FakeSource)(nil)

func (f *FakeSource) count(m string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Calls == nil {
		f.Calls = map[string]int{}
	}
	f.Calls[m]++
	return f.Calls[m]
}

// CallCount is the number of calls of method m.
func (f *FakeSource) CallCount(m string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Calls[m]
}

// TotalCalls is the number of calls of every method.
func (f *FakeSource) TotalCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.Calls {
		n += c
	}
	return n
}

func (f *FakeSource) Name() string       { return f.SrcName }
func (f *FakeSource) Class() SourceClass { return f.SrcClass }

func (f *FakeSource) ChainID(context.Context) (uint64, error) {
	f.count("ChainID")
	return f.Chain, f.ChainErr
}

func (f *FakeSource) Head(context.Context) (uint64, error) {
	f.count("Head")
	return f.HeadNum, f.HeadErr
}

func (f *FakeSource) Transaction(_ context.Context, h [32]byte) (TxView, error) {
	n := f.count("Transaction")
	if f.OnTransaction != nil {
		return f.OnTransaction(n, h)
	}
	if f.TxErr != nil {
		return TxView{}, f.TxErr
	}
	tx, ok := f.Txs[h]
	if !ok {
		return TxView{}, ErrNotFound
	}
	return tx, nil
}

func (f *FakeSource) Receipt(_ context.Context, h [32]byte) (ReceiptView, error) {
	f.count("Receipt")
	if f.ReceiptErr != nil {
		return ReceiptView{}, f.ReceiptErr
	}
	rc, ok := f.Receipts[h]
	if !ok {
		return ReceiptView{}, ErrNotFound
	}
	return rc, nil
}

func (f *FakeSource) Header(_ context.Context, h [32]byte) (HeaderView, error) {
	f.count("Header")
	if f.HeaderErr != nil {
		return HeaderView{}, f.HeaderErr
	}
	hd, ok := f.Headers[h]
	if !ok {
		return HeaderView{}, ErrNotFound
	}
	return hd, nil
}

func (f *FakeSource) BlockTransactions(_ context.Context, h [32]byte) ([][]byte, error) {
	f.count("BlockTransactions")
	if f.BlockTxsErr != nil {
		return nil, f.BlockTxsErr
	}
	b, ok := f.BlockTxs[h]
	if !ok {
		return nil, ErrNotFound
	}
	return b, nil
}

func (f *FakeSource) BlockReceipts(_ context.Context, h [32]byte) ([][]byte, error) {
	f.count("BlockReceipts")
	if f.BlockRcptErr != nil {
		return nil, f.BlockRcptErr
	}
	b, ok := f.BlockRcpt[h]
	if !ok {
		return nil, ErrNotFound
	}
	return b, nil
}

func (f *FakeSource) CodeHash(context.Context, [20]byte) ([32]byte, error) {
	f.count("CodeHash")
	return f.Code, f.CodeErr
}

// FakeDA is a scripted DAStatus.
type FakeDA struct {
	Height   uint64
	Included bool
	Err      error
	Asked    []uint64
}

func (d *FakeDA) Name() string { return "own-ev-node" }

func (d *FakeDA) DataDAHeight(_ context.Context, height uint64) (uint64, bool, error) {
	d.Asked = append(d.Asked, height)
	return d.Height, d.Included, d.Err
}
