package demo

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"sync"
	"time"

	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/railtx"
	"github.com/vgonkivs/edicta/celestia/recorder"
	"github.com/vgonkivs/edicta/celestia/secret"
)

type fakeChain struct {
	mu       sync.Mutex
	balances map[string]uint64
	log      *[]string
	minSeen  []uint64
}

func (c *fakeChain) ChainID(context.Context) (string, error) { return "mocha-5", nil }
func (c *fakeChain) Head(context.Context) (uint64, time.Time, error) {
	return 1000, time.Now(), nil
}
func (c *fakeChain) MinGasPrice(context.Context) (*big.Rat, error) { return big.NewRat(4, 1000), nil }
func (c *fakeChain) TxIndex(context.Context) error                 { return nil }

func (c *fakeChain) BalanceAt(_ context.Context, addr, _ string, minHeight uint64) (uint64, uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.log != nil {
		*c.log = append(*c.log, "read")
	}
	c.minSeen = append(c.minSeen, minHeight)
	return c.balances[addr], max(1000, minHeight), nil
}

type sendCall struct {
	to     string
	amount uint64
}

type fakeFunding struct {
	mu      sync.Mutex
	addr    string
	log     *[]string
	sends   []sendCall
	settle  []func() (bool, error)
	send    []func() ([32]byte, uint64, error)
	pending bool
	status  node.TxStatus
	binding *uint64
	closed  bool
	consent *railtx.Consent
	armed   []bool
}

func (f *fakeFunding) event(s string) {
	if f.log != nil {
		*f.log = append(*f.log, s)
	}
}

func (f *fakeFunding) Address() string { return f.addr }

func (f *fakeFunding) Settle(context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.event("settle")
	if len(f.settle) == 0 {
		return false, nil
	}
	fn := f.settle[0]
	f.settle = f.settle[1:]
	return fn()
}

func (f *fakeFunding) Send(_ context.Context, to string, amount uint64) ([32]byte, uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.event("send")
	f.sends = append(f.sends, sendCall{to, amount})
	if f.consent != nil {
		f.armed = append(f.armed, f.consent.Check() == nil)
	}
	if len(f.send) == 0 {
		return [32]byte{1}, 1100, nil
	}
	fn := f.send[0]
	f.send = f.send[1:]
	return fn()
}

func (f *fakeFunding) Status(context.Context, [32]byte) (node.TxStatus, error) { return f.status, nil }
func (f *fakeFunding) Pending() ([32]byte, uint64, bool)                       { return [32]byte{9}, 1100, f.pending }
func (f *fakeFunding) Guards() (*uint64, *uint64)                              { return nil, f.binding }
func (f *fakeFunding) Close() error                                            { f.closed = true; return nil }

type fakeAbandoner struct {
	hashes   [][32]byte
	bindings []uint64
}

func (a *fakeAbandoner) Abandon(_ context.Context, h [32]byte) error {
	a.hashes = append(a.hashes, h)
	return nil
}

func (a *fakeAbandoner) AbandonBinding(_ context.Context, s uint64) error {
	a.bindings = append(a.bindings, s)
	return nil
}

type fakeConsole struct {
	enters   []Answer
	lines    []string
	confirms []bool
	prompts  []string
	pass     secret.Secret
	// stale are Enters typed before the prompt; Flush drops them.
	stale   []Answer
	flushed int
}

func (c *fakeConsole) Flush() error { c.stale, c.flushed = nil, c.flushed+1; return nil }

func (c *fakeConsole) WaitEnter(_ context.Context, p string) (Answer, error) {
	if len(c.stale) > 0 {
		a := c.stale[0]
		c.stale = c.stale[1:]
		return a, nil
	}
	c.prompts = append(c.prompts, p)
	if len(c.enters) == 0 {
		return 0, errors.New("fakeConsole: nobody answers")
	}
	a := c.enters[0]
	c.enters = c.enters[1:]
	return a, nil
}

func (c *fakeConsole) Passphrase(string) (secret.Secret, error) { return c.pass, nil }

func (c *fakeConsole) Confirm(_ context.Context, p, _ string) (bool, error) {
	c.prompts = append(c.prompts, p)
	if len(c.confirms) == 0 {
		return false, nil
	}
	v := c.confirms[0]
	c.confirms = c.confirms[1:]
	return v, nil
}

func (c *fakeConsole) ReadLine(_ context.Context, p string) (string, error) {
	c.prompts = append(c.prompts, p)
	if len(c.lines) == 0 {
		return "", errors.New("fakeConsole: no line")
	}
	l := c.lines[0]
	c.lines = c.lines[1:]
	return l, nil
}

type fakeSubmitter struct {
	mu    sync.Mutex
	calls int
}

func (s *fakeSubmitter) Signer(context.Context) ([]byte, error) { return make([]byte, 20), nil }
func (s *fakeSubmitter) Submit(context.Context, []byte, []byte) (recorder.SubmitResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	return recorder.SubmitResult{Height: 1}, nil
}

type fakeTrustRoot struct {
	err   error
	hash  []byte
	calls int
}

func (t *fakeTrustRoot) Name() string { return "Celenium" }
func (t *fakeTrustRoot) Link(h uint64) string {
	return "https://example.invalid/block/" + string(rune('0'+h%10))
}
func (t *fakeTrustRoot) HeaderHash(context.Context, uint64) ([]byte, error) {
	t.calls++
	return bytes.Clone(t.hash), t.err
}

func noSleep(context.Context, time.Duration) error { return nil }

var _ = railtx.ErrNotStarted
