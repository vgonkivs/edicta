// Package sdktest has in-memory fakes for testing code that uses the SDK.
package sdktest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"sync"
	"time"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/dacommit/sharev1"
	"github.com/vgonkivs/edicta/sdk"
)

var (
	namespace = append(make([]byte, 19), []byte("sdktest-01")...)
	signer    = []byte("edicta-sdktest-fake1")
)

// Publisher records every blob and returns a reference with the real share
// commitment for da = 2, and a hash-based stand-in for da = 1.
type Publisher struct {
	mu             sync.Mutex
	da             commitment.DA
	blockTime      uint64
	retentionStart uint64
	height         uint64
	corrupt        bool
	hang           bool
	err            error
	blobs          [][]byte
	published      []sdk.Published
}

func NewPublisher(da commitment.DA) *Publisher {
	return &Publisher{da: da, blockTime: 1_700_000_000, height: 1}
}

func (p *Publisher) SetBlockTime(t uint64)      { p.mu.Lock(); p.blockTime = t; p.mu.Unlock() }
func (p *Publisher) SetHeight(h uint64)         { p.mu.Lock(); p.height = h; p.mu.Unlock() }
func (p *Publisher) SetRetentionStart(t uint64) { p.mu.Lock(); p.retentionStart = t; p.mu.Unlock() }
func (p *Publisher) Fail(err error)             { p.mu.Lock(); p.err = err; p.mu.Unlock() }
func (p *Publisher) Hang()                      { p.mu.Lock(); p.hang = true; p.mu.Unlock() }

// CorruptCommitment makes later results carry a commitment that does not match
// the blob, as a faulty Recorder would.
func (p *Publisher) CorruptCommitment() { p.mu.Lock(); p.corrupt = true; p.mu.Unlock() }

// Blobs returns copies of every blob received.
func (p *Publisher) Blobs() [][]byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([][]byte, len(p.blobs))
	for i, b := range p.blobs {
		out[i] = bytes.Clone(b)
	}
	return out
}

// Published returns every result handed out.
func (p *Publisher) Published() []sdk.Published {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]sdk.Published(nil), p.published...)
}

func (p *Publisher) Publish(ctx context.Context, blob []byte) (sdk.Published, error) {
	p.mu.Lock()
	hang, err := p.hang, p.err
	p.blobs = append(p.blobs, bytes.Clone(blob))
	p.mu.Unlock()
	if hang {
		<-ctx.Done()
		return sdk.Published{}, ctx.Err()
	}
	if err != nil {
		return sdk.Published{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	ref := commitment.PayloadRef{DA: p.da, Namespace: bytes.Clone(namespace), Height: p.height}
	if p.da == commitment.DACelestiaBlob {
		cm, err := sharev1.Commitment(ref.Namespace, signer, blob)
		if err != nil {
			return sdk.Published{}, err
		}
		ref.Commitment, ref.Signer = cm, bytes.Clone(signer)
	} else {
		sum := sha256.Sum256(append([]byte("sdktest fibre commitment "), blob...))
		ref.Commitment = sum[:]
	}
	if p.corrupt {
		ref.Commitment[0] ^= 1
	}
	out := sdk.Published{Ref: ref, BlockTime: p.blockTime, RetentionStart: p.retentionStart}
	if p.da == commitment.DAFibre && out.RetentionStart == 0 {
		out.RetentionStart = p.blockTime
	}
	p.published = append(p.published, out)
	return out, nil
}

// Clock is a settable clock.
type Clock struct {
	mu sync.Mutex
	t  time.Time
}

func NewClock(unix int64) *Clock { return &Clock{t: time.Unix(unix, 0)} }

func (c *Clock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *Clock) Set(unix int64)          { c.mu.Lock(); c.t = time.Unix(unix, 0); c.mu.Unlock() }
func (c *Clock) Advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }
