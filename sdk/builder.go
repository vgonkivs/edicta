package sdk

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/dacommit/sharev1"
	"github.com/vgonkivs/edicta/sdk/blob"
	"github.com/vgonkivs/edicta/sdk/payload"
)

// Builder turns decisions into signed commitments. It is safe for concurrent
// use; each Sealed value belongs to one Commit flow.
type Builder struct {
	cfg        Config
	deps       Deps
	committers map[commitment.DA]Committer
	skip       map[commitment.DA]bool
}

// String names the builder without printing its configuration or signer.
func (b *Builder) String() string { return "sdk.Builder" }

// Format makes every fmt verb print the String form.
func (b *Builder) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(b.String())) }

func (b *Builder) GoString() string { return b.String() }

func (b *Builder) LogValue() slog.Value { return slog.StringValue(b.String()) }

// New validates the configuration and the signer key.
func New(cfg Config, d Deps) (*Builder, error) {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalidConfig, fmt.Sprintf(format, a...))
	}
	if d.Publisher == nil || d.Signer == nil || d.Clock == nil {
		return nil, bad("publisher, signer and clock are required")
	}
	if n := len(cfg.Recipients); n < blob.MinRecipients || n > blob.MaxRecipients {
		return nil, bad("%d recipients", n)
	}
	seen := map[string]bool{}
	for i, r := range cfg.Recipients {
		if len(r.KID) < 1 || len(r.KID) > blob.MaxKIDSize || r.PublicKey == nil {
			return nil, bad("recipient %d", i)
		}
		if seen[string(r.KID)] {
			return nil, bad("duplicate recipient kid at %d", i)
		}
		seen[string(r.KID)] = true
	}
	if err := (commitment.Params{FibreRetentionS: 1, BlobRetentionS: cfg.BlobRetentionS, SkewS: cfg.SkewS}).Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	if cfg.MaxBlobSize == 0 || cfg.MaxBlobSize > blob.MaxSealSize {
		return nil, bad("max blob size %d", cfg.MaxBlobSize)
	}
	switch {
	case cfg.MinValidityS == 0:
		cfg.MinValidityS = minValidityFloorS
	case cfg.MinValidityS < minValidityFloorS:
		return nil, bad("min validity %d is below %d", cfg.MinValidityS, minValidityFloorS)
	}
	switch {
	case cfg.CallTimeout == 0:
		cfg.CallTimeout = defaultCallTimeout
	case cfg.CallTimeout < 0:
		return nil, bad("call timeout %s", cfg.CallTimeout)
	}
	switch {
	case cfg.MaxPublishWait == 0:
		cfg.MaxPublishWait = defaultMaxPublishWait
	case cfg.MaxPublishWait < 0:
		return nil, bad("max publish wait %s", cfg.MaxPublishWait)
	}
	if cfg.MaxReissues < 0 {
		return nil, bad("max reissues %d", cfg.MaxReissues)
	}
	switch cfg.SubmitterTrust {
	case SubmitterSameOperator:
	case SubmitterUntrusted:
		if d.Inclusion == nil {
			return nil, bad("an untrusted submitter needs an inclusion verifier")
		}
		rep, ok := d.Inclusion.(IndependenceReporter)
		if !ok {
			return nil, bad("an untrusted submitter needs a verifier that reports its independence")
		}
		independent := false
		if err := guard("independence report", func() error { independent = rep.Independent(); return nil }); err != nil || !independent {
			return nil, bad("an untrusted submitter needs a verifier independent of it")
		}
	default:
		return nil, bad("submitter trust %d", cfg.SubmitterTrust)
	}
	if n := len(cfg.ExpectNamespace); n != 0 && n != 29 {
		return nil, bad("expected namespace of %d bytes", n)
	}
	for i, s := range cfg.ExpectSigners {
		if len(s) != 20 {
			return nil, bad("expected signer %d of %d bytes", i, len(s))
		}
	}
	skip := map[commitment.DA]bool{}
	for _, da := range cfg.UnsafeSkipDACheck {
		if da != commitment.DAFibre && da != commitment.DACelestiaBlob || skip[da] {
			return nil, bad("skip list entry %d", da)
		}
		skip[da] = true
	}
	committers := map[commitment.DA]Committer{}
	for da, c := range d.Committers {
		if c == nil {
			return nil, bad("nil committer for da %d", da)
		}
		committers[da] = c
	}
	if err := commitment.CheckPublicKey(d.Signer.PublicKey()); err != nil {
		return nil, err
	}
	cfg.Recipients = slices.Clone(cfg.Recipients)
	cfg.ExpectNamespace = bytes.Clone(cfg.ExpectNamespace)
	cfg.ExpectSigners = slices.Clone(cfg.ExpectSigners)
	for i, s := range cfg.ExpectSigners {
		cfg.ExpectSigners[i] = bytes.Clone(s)
	}
	cfg.UnsafeSkipDACheck = slices.Clone(cfg.UnsafeSkipDACheck)
	return &Builder{cfg: cfg, deps: d, committers: committers, skip: skip}, nil
}

// Sealed is an encrypted payload ready to publish, with the decision it holds.
type Sealed struct {
	blob           []byte
	nonce          [16]byte
	pinned         bool     // the signer has been called: the window below is fixed
	window         Validity // issued_at and valid_until of that first attempt
	ciphertextHash commitment.Hash
	plaintextHash  commitment.Hash
	actionType     string
	action         []byte
	actionHash     commitment.Hash

	mu   sync.Mutex
	done bool
}

func (s *Sealed) Blob() []byte                    { return bytes.Clone(s.blob) }
func (s *Sealed) CiphertextHash() commitment.Hash { return s.ciphertextHash }
func (s *Sealed) PlaintextHash() commitment.Hash  { return s.plaintextHash }

// Result is a signed commitment and everything needed to send it.
type Result struct {
	Envelope       []byte
	CommitmentHash commitment.Hash
	Commitment     commitment.Commitment
	// Action is the exact action bytes the gate and the executor must be
	// given; ActionHash is the hash the commitment carries for them.
	Action     []byte
	ActionHash commitment.Hash
	Blob       []byte
	Published  Published
	Validity   Validity
	DAChecked  bool // false only when the da was in UnsafeSkipDACheck
}

// Commit is Seal, Publish and Finalize, bounded by MaxPublishWait per attempt.
// An attempt that times out, fails to publish or is not verified on chain is
// dropped unsigned and the payload is sealed anew, with a new nonce, up to
// MaxReissues times. A refusal of the published content, a block time that
// differs from the verified header and the caller's own cancellation end the
// call at once.
func (b *Builder) Commit(ctx context.Context, p *payload.Payload) (*Result, error) {
	var last error
	for attempt := 0; attempt <= b.cfg.MaxReissues; attempt++ {
		res, retry, err := b.attempt(ctx, p)
		if err == nil {
			return res, nil
		}
		if cerr := ctx.Err(); cerr != nil {
			return nil, fmt.Errorf("%w: %w", cerr, err)
		}
		if !retry {
			return nil, err
		}
		last = err
	}
	return nil, fmt.Errorf("%w after %d attempts: %w", ErrPublishTimeout, b.cfg.MaxReissues+1, last)
}

// attempt runs one seal, publish and finalize. retry reports whether the
// failure is one a fresh seal may cure.
func (b *Builder) attempt(ctx context.Context, p *payload.Payload) (res *Result, retry bool, err error) {
	s, err := b.Seal(ctx, p)
	if err != nil {
		return nil, false, err
	}
	actx, cancel := context.WithTimeout(ctx, b.cfg.MaxPublishWait)
	defer cancel()
	pub, err := b.Publish(actx, s)
	if err != nil {
		return nil, true, err
	}
	res, err = b.Finalize(actx, s, pub)
	if err == nil {
		return res, false, nil
	}
	if errors.Is(err, ErrInclusionUnverified) {
		return nil, true, err
	}
	if actx.Err() != nil && ctx.Err() == nil {
		// The attempt's own deadline ended it. After the signer was reached the
		// window is pinned and the failure is not a delay.
		s.mu.Lock()
		pinned := s.pinned
		s.mu.Unlock()
		return nil, !pinned, err
	}
	return nil, false, err
}

func (b *Builder) now() (now uint64, err error) {
	defer recoverTo("clock", &err)
	t := b.deps.Clock.Now().Unix()
	if t <= 0 {
		return 0, fmt.Errorf("%w: clock reads %d", ErrInvalidConfig, t)
	}
	return uint64(t), nil
}

// probeParams are permissive on retention: the probe checks the content of the
// decision, not the time window.
var probeParams = commitment.Params{FibreRetentionS: 14400, BlobRetentionS: 14400}

// Seal encodes and encrypts the payload. Nothing is published, and a decision
// the gate would refuse statically is refused here.
func (b *Builder) Seal(ctx context.Context, p *payload.Payload) (*Sealed, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	plaintext, err := payload.Encode(p)
	if err != nil {
		return nil, err
	}
	if uint64(len(plaintext))+blob.SaltSize+chacha20poly1305.Overhead > b.cfg.MaxBlobSize {
		return nil, fmt.Errorf("%w: plaintext of %d bytes", payload.ErrTooLarge, len(plaintext))
	}
	action := bytes.Clone(p.Action.Data)
	ah, err := commitment.ActionHash(p.Action.Type, action)
	if err != nil {
		return nil, err
	}
	if err := b.probe(commitment.Action{Type: p.Action.Type, Hash: ah[:]}); err != nil {
		return nil, err
	}

	raw, salt, err := blob.Seal(plaintext, b.cfg.Recipients)
	if err != nil {
		clear(plaintext)
		return nil, err
	}
	ph := commitment.PlaintextHash(salt, plaintext)
	clear(plaintext)
	clear(salt[:])
	if uint64(len(raw)) > b.cfg.MaxBlobSize {
		return nil, fmt.Errorf("%w: blob of %d bytes", payload.ErrTooLarge, len(raw))
	}
	sealed := &Sealed{
		blob: raw, ciphertextHash: sha256.Sum256(raw), plaintextHash: ph,
		actionType: p.Action.Type, action: action, actionHash: ah,
	}
	rand.Read(sealed.nonce[:])
	return sealed, nil
}

// probe runs the decode and static checks on a commitment with placeholder
// anchor and times, before any DA fee is paid.
func (b *Builder) probe(a commitment.Action) error {
	now, err := b.now()
	if err != nil {
		return err
	}
	ns := make([]byte, 29)
	ns[27] = 1
	in := input{
		AgentID:     b.cfg.AgentID,
		AgentPubKey: b.deps.Signer.PublicKey(),
		IssuedAt:    now,
		ValidUntil:  now + min(b.cfg.TTLS, 3600),
		Scope:       b.cfg.Scope,
		Action:      a,
		Ref: commitment.PayloadRef{
			DA: commitment.DACelestiaBlob, Namespace: ns, Commitment: make([]byte, 32),
			Height: 1, Signer: make([]byte, 20),
		},
		PayloadSize: 1,
	}
	if in.ValidUntil <= in.IssuedAt {
		in.ValidUntil = in.IssuedAt + 1
	}
	p := probeParams
	p.SkewS = b.cfg.SkewS
	_, err = buildCommitment(in, p)
	return err
}

// Publish hands the sealed bytes to the publisher. It may be retried with the
// same Sealed.
func (b *Builder) Publish(ctx context.Context, s *Sealed) (Published, error) {
	if s == nil {
		return Published{}, errors.New("sdk: nil sealed payload")
	}
	if err := ctx.Err(); err != nil {
		return Published{}, err
	}
	cctx, cancel := context.WithTimeout(ctx, b.cfg.CallTimeout)
	defer cancel()
	var pub Published
	err := guard("publisher", func() (err error) {
		pub, err = b.deps.Publisher.Publish(cctx, bytes.Clone(s.blob))
		return err
	})
	if err != nil {
		return Published{}, fmt.Errorf("sdk: publish: %w", err)
	}
	pub.Ref = cloneRef(pub.Ref)
	return pub, nil
}

// Finalize checks the publish result, recomputes the DA commitment, chooses
// the validity window, signs and self-checks. It succeeds at most once per
// Sealed.
func (b *Builder) Finalize(ctx context.Context, s *Sealed, pub Published) (*Result, error) {
	if s == nil {
		return nil, errors.New("sdk: nil sealed payload")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return nil, ErrAlreadyFinalized
	}
	res, err := b.finalize(ctx, s, pub)
	if err != nil {
		return nil, err
	}
	s.done = true
	return res, nil
}

func (b *Builder) finalize(ctx context.Context, s *Sealed, pub Published) (*Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ref := cloneRef(pub.Ref)
	if ref.DA != commitment.DAFibre && ref.DA != commitment.DACelestiaBlob {
		return nil, fmt.Errorf("%w: da %d", ErrPublishResult, ref.DA)
	}
	if ref.Height == 0 {
		return nil, fmt.Errorf("%w: no height", ErrPublishResult)
	}
	if err := b.checkExpected(ref); err != nil {
		return nil, err
	}
	checked, err := b.checkDA(ref, s.blob)
	if err != nil {
		return nil, err
	}
	if b.deps.Inclusion != nil {
		t, err := b.verifyInclusion(ctx, ref)
		if err != nil {
			return nil, err
		}
		if t != pub.BlockTime {
			return nil, fmt.Errorf("%w: header time %d, published %d", ErrBlockTimeMismatch, t, pub.BlockTime)
		}
	}

	now, err := b.now()
	if err != nil {
		return nil, err
	}
	w := Window{
		Now: now, BlockTime: pub.BlockTime, RetentionStart: pub.RetentionStart, DA: ref.DA,
		BlobRetentionS: b.cfg.BlobRetentionS, SkewS: b.cfg.SkewS, TTLS: b.cfg.TTLS,
		MinValidityS: b.cfg.MinValidityS,
	}
	params := commitment.Params{FibreRetentionS: b.cfg.BlobRetentionS, BlobRetentionS: b.cfg.BlobRetentionS, SkewS: b.cfg.SkewS}
	if ref.DA == commitment.DAFibre {
		if b.deps.Chain == nil {
			return nil, fmt.Errorf("%w: no chain parameters for da 1", ErrInvalidConfig)
		}
		cctx, cancel := context.WithTimeout(ctx, b.cfg.CallTimeout)
		defer cancel()
		if w.FibreLatestS, err = b.retention(cctx, 0); err != nil {
			return nil, fmt.Errorf("sdk: fibre retention: %w", err)
		}
		if w.FibreAtHeightS, err = b.retention(cctx, ref.Height); err != nil {
			return nil, fmt.Errorf("sdk: fibre retention at height %d: %w", ref.Height, err)
		}
		params.FibreRetentionS = w.FibreLatestS
	}
	if err := params.Validate(); err != nil {
		return nil, err
	}
	var v Validity
	if s.pinned {
		// A retry signs the same commitment as the attempt that reached the
		// signer, or none at all.
		v = s.window
		if err := b.checkRemaining(v.ValidUntil, "on retry"); err != nil {
			return nil, err
		}
	} else if v, err = ChooseValidity(w); err != nil {
		return nil, err
	}

	agentPub := b.deps.Signer.PublicKey()
	if err := commitment.CheckPublicKey(agentPub); err != nil {
		return nil, err
	}
	in := input{
		AgentID: b.cfg.AgentID, AgentPubKey: agentPub, IssuedAt: v.IssuedAt, ValidUntil: v.ValidUntil,
		Scope: b.cfg.Scope, Action: commitment.Action{Type: s.actionType, Hash: s.actionHash[:]}, Ref: ref,
		CiphertextHash: s.ciphertextHash, PlaintextHash: s.plaintextHash, PayloadSize: uint64(len(s.blob)),
	}
	in.Nonce = s.nonce
	c, err := buildCommitment(in, params)
	if err != nil {
		return nil, err
	}
	if err := commitment.CheckTime(c, now, params); err != nil {
		return nil, err
	}
	if err := commitment.CheckPayload(c, s.blob); err != nil {
		return nil, err
	}
	if err := commitment.CheckAnchorTime(c, pub.BlockTime, params); err != nil {
		return nil, err
	}
	start, retention := pub.BlockTime, b.cfg.BlobRetentionS
	if ref.DA == commitment.DAFibre {
		start, retention = min(pub.BlockTime, pub.RetentionStart), min(w.FibreLatestS, w.FibreAtHeightS)
	}
	if !commitment.WithinRetention(c, start, retention) {
		return nil, fmt.Errorf("%w: valid_until outside the retention window", ErrValidityWindow)
	}

	// The chain reads may have been slow; do not sign into a closed window.
	if err := b.checkRemaining(v.ValidUntil, "before signing"); err != nil {
		return nil, err
	}
	h, err := commitment.HashOf(c)
	if err != nil {
		return nil, err
	}
	s.pinned, s.window = true, v
	sig, err := b.sign(ctx, h)
	if err != nil {
		return nil, err
	}
	if err := b.checkRemaining(v.ValidUntil, "after signing"); err != nil {
		return nil, err
	}
	if now, err = b.now(); err != nil {
		return nil, err
	}
	env, err := commitment.EncodeSigned(&commitment.SignedCommitment{Commitment: *c, Signature: sig})
	if err != nil {
		return nil, err
	}
	gs := commitment.GateScope{GateID: b.cfg.Scope.GateID, ActionTypes: []string{s.actionType}}
	sc, h2, err := commitment.VerifyForGate(env, now, gs, params)
	if err != nil {
		return nil, err
	}
	if h2 != h {
		return nil, fmt.Errorf("%w: hash changed after signing", commitment.ErrSignatureInvalid)
	}
	return &Result{
		Envelope: env, CommitmentHash: h, Commitment: sc.Commitment, Blob: bytes.Clone(s.blob),
		Action: bytes.Clone(s.action), ActionHash: s.actionHash,
		Published: Published{Ref: ref, BlockTime: pub.BlockTime, RetentionStart: pub.RetentionStart},
		Validity:  v, DAChecked: checked,
	}, nil
}

// checkExpected refuses a reference outside the configured namespace and
// signer allowlist.
func (b *Builder) checkExpected(ref commitment.PayloadRef) error {
	if len(b.cfg.ExpectNamespace) != 0 && !bytes.Equal(ref.Namespace, b.cfg.ExpectNamespace) {
		return fmt.Errorf("%w: namespace", ErrUnexpectedRef)
	}
	if len(b.cfg.ExpectSigners) != 0 && !slices.ContainsFunc(b.cfg.ExpectSigners, func(s []byte) bool { return bytes.Equal(s, ref.Signer) }) {
		return fmt.Errorf("%w: signer", ErrUnexpectedRef)
	}
	return nil
}

// verifyInclusion asks the verifier about ref and returns the time of the
// header it verified. Every failure, including a panic, is ErrInclusionUnverified.
func (b *Builder) verifyInclusion(ctx context.Context, ref commitment.PayloadRef) (t uint64, err error) {
	cctx, cancel := context.WithTimeout(ctx, b.cfg.CallTimeout)
	defer cancel()
	err = guard("inclusion verifier", func() (err error) {
		t, err = b.deps.Inclusion.VerifyInclusion(cctx, cloneRef(ref))
		return err
	})
	if err != nil {
		if errors.Is(err, ErrInclusionUnverified) {
			return 0, err
		}
		return 0, fmt.Errorf("%w: %w", ErrInclusionUnverified, err)
	}
	return t, nil
}

// checkDA recomputes the DA commitment unless the da is explicitly opted out.
func (b *Builder) checkDA(ref commitment.PayloadRef, raw []byte) (bool, error) {
	if b.skip[ref.DA] {
		return false, nil
	}
	var checks []Committer
	if ref.DA == commitment.DACelestiaBlob {
		// The built-in recompute always runs for da 2; a caller's committer adds to it.
		checks = append(checks, ShareV1Committer())
	}
	if c, ok := b.committers[ref.DA]; ok {
		checks = append(checks, c)
	}
	if len(checks) == 0 {
		return false, fmt.Errorf("%w: da %d", ErrDACheckUnavailable, ref.DA)
	}
	for _, c := range checks {
		if err := b.runCommitter(c, ref, raw); err != nil {
			if errors.Is(err, ErrDACommitmentMismatch) || errors.Is(err, sharev1.ErrMismatch) {
				return false, fmt.Errorf("%w: %w", ErrDACommitmentMismatch, err)
			}
			return false, fmt.Errorf("sdk: DA commitment check: %w", err)
		}
	}
	return true, nil
}

// checkRemaining refuses a commitment whose valid_until is closer than the floor
// by the current clock.
func (b *Builder) checkRemaining(expiry uint64, when string) error {
	now, err := b.now()
	if err != nil {
		return err
	}
	if expiry < satAdd(now, b.cfg.MinValidityS) || expiry <= satAdd(now, b.cfg.SkewS) {
		return fmt.Errorf("%w: expiry %d is too close to now %d %s", ErrValidityWindow, expiry, now, when)
	}
	return nil
}

// recoverTo turns a panic into an error that carries only the panic's type:
// the value may hold anything, including key material.
func recoverTo(what string, err *error) {
	if r := recover(); r != nil {
		*err = fmt.Errorf("sdk: %s panicked (%T)", what, r)
	}
}

func guard(what string, f func() error) (err error) {
	defer recoverTo(what, &err)
	return f()
}

func (b *Builder) retention(ctx context.Context, height uint64) (v uint64, err error) {
	defer recoverTo("chain parameters", &err)
	return b.deps.Chain.FibreRetention(ctx, height)
}

// runCommitter calls a committer. Check is a pure computation, so there is
// no timeout; a panic is still recovered.
func (b *Builder) runCommitter(c Committer, ref commitment.PayloadRef, raw []byte) error {
	return guard("committer", func() error { return c.Check(ref, raw) })
}

// sign calls the signer with the call timeout.
func (b *Builder) sign(ctx context.Context, h commitment.Hash) (sig []byte, err error) {
	cctx, cancel := context.WithTimeout(ctx, b.cfg.CallTimeout)
	defer cancel()
	err = guard("signer", func() (err error) {
		sig, err = b.deps.Signer.SignCommitment(cctx, h)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("sdk: sign: %w", err)
	}
	return sig, nil
}
