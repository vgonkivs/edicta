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
	defaultNamespace = append(make([]byte, 19), []byte("sdktest-01")...)
	defaultSigner    = []byte("edicta-sdktest-fake1")
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
	hangNext       int
	namespace      []byte
	signer         []byte
	err            error
	blobs          [][]byte
	published      []sdk.Published
}

func NewPublisher(da commitment.DA) *Publisher {
	return &Publisher{
		da: da, blockTime: 1_700_000_000, height: 1,
		namespace: bytes.Clone(defaultNamespace), signer: bytes.Clone(defaultSigner),
	}
}

func (p *Publisher) SetBlockTime(t uint64)      { p.mu.Lock(); p.blockTime = t; p.mu.Unlock() }
func (p *Publisher) SetHeight(h uint64)         { p.mu.Lock(); p.height = h; p.mu.Unlock() }
func (p *Publisher) SetRetentionStart(t uint64) { p.mu.Lock(); p.retentionStart = t; p.mu.Unlock() }
func (p *Publisher) Fail(err error)             { p.mu.Lock(); p.err = err; p.mu.Unlock() }
func (p *Publisher) Hang()                      { p.mu.Lock(); p.hang = true; p.mu.Unlock() }

// SetNamespace and SetSigner change what later results carry.
func (p *Publisher) SetNamespace(ns []byte) {
	p.mu.Lock()
	p.namespace = bytes.Clone(ns)
	p.mu.Unlock()
}
func (p *Publisher) SetSigner(s []byte) { p.mu.Lock(); p.signer = bytes.Clone(s); p.mu.Unlock() }

// Namespace and Signer return copies of what results carry now.
func (p *Publisher) Namespace() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return bytes.Clone(p.namespace)
}
func (p *Publisher) Signer() []byte { p.mu.Lock(); defer p.mu.Unlock(); return bytes.Clone(p.signer) }

// HangNext makes the next n publishes hang until their context ends.
func (p *Publisher) HangNext(n int) { p.mu.Lock(); p.hangNext = n; p.mu.Unlock() }

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
	if p.hangNext > 0 {
		hang = true
		p.hangNext--
	}
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
	ref := commitment.PayloadRef{DA: p.da, Namespace: bytes.Clone(p.namespace), Height: p.height}
	if p.da == commitment.DACelestiaBlob {
		cm, err := sharev1.Commitment(ref.Namespace, p.signer, blob)
		if err != nil {
			return sdk.Published{}, err
		}
		ref.Commitment, ref.Signer = cm, bytes.Clone(p.signer)
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

// InclusionVerifier confirms references that its Publisher handed out, as an
// independent chain view would, and rejects any other.
type InclusionVerifier struct {
	mu          sync.Mutex
	pub         *Publisher
	independent bool
	blockTime   uint64
	override    bool
	err         error
	panics      bool
	hang        bool
	calls       int
}

// NewInclusionVerifier is independent by default.
func NewInclusionVerifier(p *Publisher) *InclusionVerifier {
	return &InclusionVerifier{pub: p, independent: true}
}

// SetBlockTime makes later calls report t instead of the published time.
func (v *InclusionVerifier) SetBlockTime(t uint64) {
	v.mu.Lock()
	v.blockTime, v.override = t, true
	v.mu.Unlock()
}
func (v *InclusionVerifier) SetIndependent(b bool) { v.mu.Lock(); v.independent = b; v.mu.Unlock() }
func (v *InclusionVerifier) Fail(err error)        { v.mu.Lock(); v.err = err; v.mu.Unlock() }
func (v *InclusionVerifier) Panic()                { v.mu.Lock(); v.panics = true; v.mu.Unlock() }
func (v *InclusionVerifier) Hang()                 { v.mu.Lock(); v.hang = true; v.mu.Unlock() }

func (v *InclusionVerifier) Independent() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.independent
}

// Calls is the number of VerifyInclusion calls.
func (v *InclusionVerifier) Calls() int { v.mu.Lock(); defer v.mu.Unlock(); return v.calls }

func (v *InclusionVerifier) VerifyInclusion(ctx context.Context, ref commitment.PayloadRef) (uint64, error) {
	v.mu.Lock()
	v.calls++
	hang, err, panics, override, bt := v.hang, v.err, v.panics, v.override, v.blockTime
	v.mu.Unlock()
	if panics {
		panic("sdktest: inclusion verifier panic")
	}
	if hang {
		<-ctx.Done()
		return 0, ctx.Err()
	}
	if err != nil {
		return 0, err
	}
	for _, pub := range v.pub.Published() {
		r := pub.Ref
		if r.DA == ref.DA && r.Height == ref.Height && bytes.Equal(r.Namespace, ref.Namespace) &&
			bytes.Equal(r.Commitment, ref.Commitment) && bytes.Equal(r.Signer, ref.Signer) {
			if override {
				return bt, nil
			}
			return pub.BlockTime, nil
		}
	}
	return 0, sdk.ErrInclusionUnverified
}
