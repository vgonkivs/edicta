package sdk_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/sdk"
	"github.com/vgonkivs/edicta/test/gatefix"
)

// lostSigner signs every call, leaks the signature, and fails the first n calls
// after signing.
type lostSigner struct {
	inner  sdk.Signer
	fail   int
	hashes []commitment.Hash
	sigs   [][]byte
}

func (s *lostSigner) PublicKey() ed25519.PublicKey { return s.inner.PublicKey() }
func (s *lostSigner) SignCommitment(ctx context.Context, h commitment.Hash) ([]byte, error) {
	sig, err := s.inner.SignCommitment(ctx, h)
	if err != nil {
		return nil, err
	}
	s.hashes = append(s.hashes, h)
	s.sigs = append(s.sigs, sig)
	if s.fail > 0 {
		s.fail--
		return nil, errors.New("kms: response lost after signing")
	}
	return sig, nil
}

func lostRig(t *testing.T, fail int) (*rig, *lostSigner) {
	t.Helper()
	r := newRig(t)
	ls := &lostSigner{inner: r.signer.inner, fail: fail}
	r.deps.Signer = ls
	return r, ls
}

func (r *rig) builderWith(ls *lostSigner) *sdk.Builder {
	r.t.Helper()
	b, err := sdk.New(r.cfg, sdk.Deps{Publisher: r.rec, Signer: ls, Clock: r.clock, Chain: r.chain})
	require.NoError(r.t, err)
	return b
}

func sealPublish(t *testing.T, b *sdk.Builder, r *rig) (*sdk.Sealed, sdk.Published) {
	t.Helper()
	s, err := b.Seal(bg, r.payload())
	require.NoError(t, err)
	pub, err := b.Publish(bg, s)
	require.NoError(t, err)
	return s, pub
}

// After the signer has been called once for a Sealed, every retry signs the
// same commitment: same times, same nonce, same bytes.
func TestRetryResignsTheFirstWindow(t *testing.T) {
	r, ls := lostRig(t, 2)
	b := r.builderWith(ls)
	s, pub := sealPublish(t, b, r)

	_, err := b.Finalize(bg, s, pub)
	require.Error(t, err)
	r.clock.unix += 5
	_, err = b.Finalize(bg, s, pub)
	require.Error(t, err)
	r.clock.unix += 5
	res, err := b.Finalize(bg, s, pub)
	require.NoError(t, err)

	require.Len(t, ls.hashes, 3)
	assert.Equal(t, ls.hashes[0], ls.hashes[1])
	assert.Equal(t, ls.hashes[0], ls.hashes[2])
	assert.Equal(t, ls.hashes[0], res.CommitmentHash)
	assert.EqualValues(t, now, res.Commitment.IssuedAt, "issued_at of the first attempt")
	assert.EqualValues(t, now+900, res.Commitment.ValidUntil, "valid_until of the first attempt")
	assert.Equal(t, res.Validity.IssuedAt, res.Commitment.IssuedAt)
	assert.Equal(t, res.Validity.ValidUntil, res.Commitment.ValidUntil)

	// Ed25519 is deterministic: the signature that leaked is the retry's.
	leaked, err := commitment.EncodeSigned(&commitment.SignedCommitment{Commitment: res.Commitment, Signature: ls.sigs[0]})
	require.NoError(t, err)
	assert.Equal(t, res.Envelope, leaked)
	requireValidAtGate(t, res, now+10)
}

func TestRetryBoundaryAtTheFloor(t *testing.T) {
	for _, tt := range []struct {
		name    string
		advance uint64
		ok      bool
	}{
		{"just inside", 840, true},
		{"one second past the floor", 841, false},
		{"near the end", 890, false},
		{"after expiry", 1000, false},
		{"much later", 5000, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, ls := lostRig(t, 1)
			b := r.builderWith(ls)
			s, pub := sealPublish(t, b, r)
			_, err := b.Finalize(bg, s, pub)
			require.Error(t, err)

			r.clock.unix += tt.advance
			res, err := b.Finalize(bg, s, pub)
			if tt.ok {
				require.NoError(t, err)
				assert.Equal(t, ls.hashes[0], res.CommitmentHash)
				return
			}
			require.ErrorIs(t, err, sdk.ErrValidityWindow)
			assert.Nil(t, res)
			assert.Len(t, ls.hashes, 1, "refused before the signer is called again")

			// A new Seal starts a new decision with a new nonce.
			s2, pub2 := sealPublish(t, b, r)
			res2, err := b.Finalize(bg, s2, pub2)
			require.NoError(t, err)
			assert.NotEqual(t, ls.hashes[0], res2.CommitmentHash)
			assert.GreaterOrEqual(t, res2.Commitment.IssuedAt, r.clock.unix)
		})
	}
}

// A failure before the signer was reached pins nothing: the next attempt picks
// its window from the clock as usual.
func TestFailureBeforeSigningDoesNotPinTheWindow(t *testing.T) {
	r, ls := lostRig(t, 0)
	b := r.builderWith(ls)
	s, pub := sealPublish(t, b, r)

	bad := pub
	bad.Ref.Commitment = bytes.Clone(pub.Ref.Commitment)
	bad.Ref.Commitment[0] ^= 1
	_, err := b.Finalize(bg, s, bad)
	require.ErrorIs(t, err, sdk.ErrDACommitmentMismatch)
	assert.Empty(t, ls.hashes)

	r.clock.unix += 3000
	r.rec.blockTime = r.clock.unix - 100
	pub.BlockTime = r.rec.blockTime
	res, err := b.Finalize(bg, s, pub)
	require.NoError(t, err)
	assert.EqualValues(t, r.clock.unix, res.Commitment.IssuedAt)
}

// The regression against the real gate: a leaked signature executes, the clock
// moves on, the nonce record is pruned, and only then does the agent retry. At
// most one execution may result.
func TestLateRetryAfterPruneNeverExecutesTwice(t *testing.T) {
	e := newE2E(t)
	var leakedSig []byte
	failed := false
	e.sign.override = func(h commitment.Hash) ([]byte, error) {
		sig, err := e.sign.inner.SignCommitment(bg, h)
		require.NoError(t, err)
		if !failed {
			failed, leakedSig = true, sig
			return nil, errors.New("kms: response lost after signing")
		}
		return sig, nil
	}
	t0 := uint64(e.env.Clock.Now().Unix())
	s, err := e.b.Seal(bg, e.rig.payload())
	require.NoError(t, err)
	pub, err := e.b.Publish(bg, s)
	require.NoError(t, err)
	_, err = e.b.Finalize(bg, s, pub)
	require.Error(t, err)
	require.NotNil(t, leakedSig)

	e.env.Clock.Set(t0 + 5000)
	res, err := e.b.Finalize(bg, s, pub)
	if err != nil {
		// Refused: nothing more can be signed for this decision.
		require.ErrorIs(t, err, sdk.ErrValidityWindow)
		assert.Nil(t, res)
		assert.Equal(t, 0, e.env.Exec.Calls())
		return
	}

	// Signed: the retry and the leaked signature are the same commitment, or
	// the gate refuses the second.
	c := gatefix.Clone(&res.Commitment)
	c.IssuedAt, c.ValidUntil = t0, t0+900
	leaked, err := commitment.EncodeSigned(&commitment.SignedCommitment{Commitment: *c, Signature: leakedSig})
	require.NoError(t, err)
	e.stage(res)

	e.env.Clock.Set(t0 + 5)
	_, err = e.env.Admit(leaked)
	require.NoError(t, err, "the leaked signature executes")

	e.env.Clock.Set(t0 + 5000)
	e.sign.override = nil
	s2, err := e.b.Seal(bg, e.rig.payload())
	require.NoError(t, err)
	pub2, err := e.b.Publish(bg, s2)
	require.NoError(t, err)
	res2, err := e.b.Finalize(bg, s2, pub2)
	require.NoError(t, err)
	e.stage(res2)
	_, err = e.env.Admit(res2.Envelope)
	require.NoError(t, err)
	_, err = e.env.Gate.Prune(bg)
	require.NoError(t, err)

	_, err = e.env.Admit(res.Envelope)
	require.Truef(t, errors.Is(err, gate.ErrNonceUsed) || errors.Is(err, commitment.ErrExpired), "the retry was admitted or failed oddly: %v", err)
	assert.Equal(t, 2, e.env.Exec.Calls(), "the leaked order and the unrelated order, never the retry")
}

// A panic in any dependency is an error: no signature, and only the panic's
// type in the message.
type secretPanic struct{}

func (secretPanic) String() string { return "panic-value-secret-4242" }
func (secretPanic) Error() string  { return "panic-value-secret-4242" }

type panickyPublisher struct{}

func (panickyPublisher) Publish(context.Context, []byte) (sdk.Published, error) { panic(secretPanic{}) }

type panickyChain struct{}

func (panickyChain) FibreRetention(context.Context, uint64) (uint64, error) { panic(secretPanic{}) }

func TestDependencyPanicsAreErrors(t *testing.T) {
	check := func(t *testing.T, r *rig, run func() error) {
		t.Helper()
		var err error
		require.NotPanics(t, func() { err = run() })
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "panic-value-secret-4242", "the panic value stays out of the message")
		assert.Contains(t, err.Error(), "secretPanic", "the panic type is named")
		assert.Zero(t, r.signer.calls())
	}
	t.Run("publisher", func(t *testing.T) {
		r := newRig(t)
		b, err := sdk.New(r.cfg, sdk.Deps{Publisher: panickyPublisher{}, Signer: r.signer, Clock: r.clock, Chain: r.chain})
		require.NoError(t, err)
		check(t, r, func() error { _, err := b.Commit(bg, r.payload()); return err })
	})
	t.Run("chain parameters", func(t *testing.T) {
		r := fibreRig(t)
		r.deps.Chain = panickyChain{}
		b := r.builder()
		check(t, r, func() error { _, err := b.Commit(bg, r.payload()); return err })
	})
	t.Run("clock", func(t *testing.T) {
		r := newRig(t)
		pc := &panickyClock{}
		b, err := sdk.New(r.cfg, sdk.Deps{Publisher: r.rec, Signer: r.signer, Clock: pc, Chain: r.chain})
		require.NoError(t, err)
		pc.armed = true
		check(t, r, func() error { _, err := b.Commit(bg, r.payload()); return err })
	})
	t.Run("a panic leaves the sealed payload usable", func(t *testing.T) {
		r := newRig(t)
		pc := &panickyClock{}
		b, err := sdk.New(r.cfg, sdk.Deps{Publisher: r.rec, Signer: r.signer, Clock: pc, Chain: r.chain})
		require.NoError(t, err)
		s, pub := sealPublish(t, b, r)
		pc.armed = true
		require.NotPanics(t, func() { _, err = b.Finalize(bg, s, pub) })
		require.Error(t, err)
		pc.armed = false
		pc.inner = r.clock
		res, err := b.Finalize(bg, s, pub)
		require.NoError(t, err)
		assert.NotNil(t, res)
	})
}

type panickyClock struct {
	armed bool
	inner *clock
}

func (c *panickyClock) Now() time.Time {
	if c.armed {
		panic(secretPanic{})
	}
	if c.inner != nil {
		return c.inner.Now()
	}
	return (&clock{unix: now}).Now()
}

// The committer's context is named once in its errors.
func TestCommitterErrorPrefixIsNotRepeated(t *testing.T) {
	const prefix = "DA commitment check"
	for name, c := range map[string]sdk.Committer{
		"panic": panickyCommitter{"boom"},
		"error": committerFn(func(context.Context, commitment.PayloadRef, []byte) error { return errors.New("refused") }),
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.deps.Committers = map[commitment.DA]sdk.Committer{commitment.DAFibre: c}
			r.rec.da = commitment.DAFibre
			r.rec.retentionStart = now - 150
			_, err := r.builder().Commit(bg, r.payload())
			require.Error(t, err)
			assert.LessOrEqualf(t, strings.Count(err.Error(), prefix), 1, "prefix repeated in %q", err)
		})
	}
	t.Run("built-in mismatch", func(t *testing.T) {
		r := newRig(t)
		r.rec.other = []byte("other")
		_, err := r.builder().Commit(bg, r.payload())
		require.Error(t, err)
		assert.LessOrEqual(t, strings.Count(err.Error(), "DA commitment"), 2, fmt.Sprint(err))
	})
}

// The commitment assembler takes a nonce and a plaintext hash from its caller,
// so it must not be exported; the builder alone draws them.
func TestAssemblerIsNotExported(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	require.NoError(t, err)
	for _, p := range pkgs {
		for _, f := range p.Files {
			for _, d := range f.Decls {
				switch d := d.(type) {
				case *ast.FuncDecl:
					if d.Recv == nil {
						assert.NotEqual(t, "BuildCommitment", d.Name.Name, "BuildCommitment must not be exported")
					}
				case *ast.GenDecl:
					for _, sp := range d.Specs {
						ts, ok := sp.(*ast.TypeSpec)
						if !ok || !ts.Name.IsExported() {
							continue
						}
						st, ok := ts.Type.(*ast.StructType)
						if !ok {
							continue
						}
						for _, fl := range st.Fields.List {
							for _, n := range fl.Names {
								if n.Name == "Nonce" || n.Name == "PlaintextHash" {
									t.Errorf("exported type %s has a caller-chosen field %s", ts.Name.Name, n.Name)
								}
							}
						}
					}
				}
			}
		}
	}
}
