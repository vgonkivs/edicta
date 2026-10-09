package verifier_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/gate/dacommit/blobv1"
	"github.com/vgonkivs/edicta/test/archivefix"
	"github.com/vgonkivs/edicta/test/gatefix"
	"github.com/vgonkivs/edicta/verifier"
)

const (
	anchorHeight = uint64(4200000)
	checkpointH  = uint64(4200100)
	blockTime    = uint64(1790999950)
	authorizedAt = uint64(1791000060)
	authExpires  = uint64(1791000360)
)

var (
	errFakeHeader = errors.New("fake anchor: header does not decode")
	errFakeProof  = errors.New("fake anchor: blob proof does not verify against the header")
	errFakeTrust  = errors.New("fake trust: header hash is not on the trusted chain")
)

func goodHeader() []byte { return []byte("hdr:4200000") }

func proofFor(header []byte) []byte { return append([]byte("proof-for:"), header...) }

// fakeAnchor stands in for the da-specific anchor verifier: a header must
// carry the "hdr:" prefix and the proof must be derived from the header.
type fakeAnchor struct {
	blockTime  uint64
	settlement string
	signed     int64
	total      int64
	precision  string
	proofForm  int
	earlier    int
	calls      int

	payloadSize   uint64
	creations     []uint64
	promiseHeight func(ev *archive.EvidenceRecord) uint64
	blobSize      *uint64
	promiseHash   []byte
}

// uploadSize is the paid upload size of a blob of n payload bytes.
func uploadSize(n uint64) uint64 {
	rows := (n + 5 + 4095) / 4096
	rows = (rows + 63) / 64 * 64
	return rows * 4096
}

func (f *fakeAnchor) VerifyAnchor(ref commitment.PayloadRef, ev *archive.EvidenceRecord) (verifier.AnchorFacts, error) {
	f.calls++
	if !bytes.HasPrefix(ev.Header, []byte("hdr:")) {
		return verifier.AnchorFacts{}, errFakeHeader
	}
	if ref.DA == commitment.DACelestiaBlob && !bytes.Equal(ev.BlobProof, proofFor(ev.Header)) {
		return verifier.AnchorFacts{}, errFakeProof
	}
	if ref.DA == commitment.DAFibre && !bytes.Equal(ev.SystemBlobProof, proofFor(ev.Header)) {
		return verifier.AnchorFacts{}, errFakeProof
	}
	h := sha256.Sum256(ev.Header)
	facts := verifier.AnchorFacts{
		BlockTime:          f.blockTime,
		RetentionStart:     f.blockTime,
		AnchorHeaderHash:   h[:],
		EarlierCreations:   f.creations,
		Settlement:         f.settlement,
		CertSignedPower:    f.signed,
		CertTotalPower:     f.total,
		CertTokenPrecision: f.precision,
		ProofForm:          f.proofForm,
		CandidatesEarlier:  f.earlier,
	}
	if ref.DA == commitment.DAFibre {
		ph := sha256.Sum256([]byte("promise-header"))
		facts.PromiseHeaderHash = ph[:]
		if f.promiseHash != nil {
			facts.PromiseHeaderHash = f.promiseHash
		}
		facts.PromiseHeight = ev.PromiseHeight
		if f.promiseHeight != nil {
			facts.PromiseHeight = f.promiseHeight(ev)
		}
		facts.PromiseBlobSize = uploadSize(f.payloadSize)
		if f.blobSize != nil {
			facts.PromiseBlobSize = *f.blobSize
		}
		facts.CertValsetHeader = "next_validators_hash@promise"
	}
	return facts, nil
}

// fakeTrust accepts exactly the hashes it was given.
type fakeTrust struct {
	hashes map[uint64][]byte
	res    verifier.TrustResult
	err    error
	asked  []uint64
}

func (f *fakeTrust) Trusted(_ context.Context, height uint64, hash []byte) (verifier.TrustResult, error) {
	f.asked = append(f.asked, height)
	if f.err != nil {
		return verifier.TrustResult{}, f.err
	}
	if want, ok := f.hashes[height]; !ok || !bytes.Equal(want, hash) {
		return verifier.TrustResult{}, errFakeTrust
	}
	return f.res, nil
}

type acceptAll struct{}

func (acceptAll) Check(commitment.PayloadRef, []byte) error { return nil }

// fibreBlobCommitter accepts the one da = 1 blob of the fixtures.
type fibreBlobCommitter struct{}

func (fibreBlobCommitter) Check(_ commitment.PayloadRef, blob []byte) error {
	if !bytes.Equal(blob, gatefix.FibreBlob()) {
		return gate.ErrDACommitmentMismatch
	}
	return nil
}

// parts are the records of one decision, before they are written. Tests
// change them, then write them.
type parts struct {
	da         commitment.DA
	c          *commitment.Commitment
	hash       commitment.Hash
	env        []byte
	action     []byte
	salt       []byte
	blob       []byte
	payloadRef []byte
	ev         *archive.EvidenceRecord
	auth       []byte // nil: pending
	k2         *archive.K2Inputs
	// authAt overrides the recorded issue time.
	authAt  uint64
	markers []string
	// permissive stores the payload without the DA check, as a store that
	// was damaged after the write would hold it.
	permissive bool
}

func gateKey(t testing.TB) ed25519.PrivateKey { return gatefix.Key(t, "gate1") }

func gatePub(t testing.TB) ed25519.PublicKey { return gateKey(t).Public().(ed25519.PublicKey) }

func signAuth(t testing.TB, key ed25519.PrivateKey, h commitment.Hash, c *commitment.Commitment, path commitment.PayloadPath, expires uint64) []byte {
	t.Helper()
	a := commitment.Authorization{
		Version:        commitment.Version,
		CommitmentHash: h[:],
		ActionHash:     c.Action.Hash,
		GateID:         gatefix.GateID,
		Expires:        expires,
		Path:           path,
		Mode:           commitment.ModeStrict,
	}
	if c.PayloadRef.Pending() {
		a.Mode = commitment.ModeFast
	}
	return signAuthorization(t, key, a)
}

// signAuthorization signs a under the Authorization tags.
func signAuthorization(t testing.TB, key ed25519.PrivateKey, a commitment.Authorization) []byte {
	t.Helper()
	canon, err := commitment.EncodeAuthorization(&a)
	require.NoError(t, err)
	ah := commitment.HashAuthorization(canon)
	b, err := commitment.EncodeSignedAuthorization(&commitment.SignedAuthorization{
		Authorization: a,
		Signature:     ed25519.Sign(key, commitment.AuthorizationSigningMessage(ah)),
	})
	require.NoError(t, err)
	return b
}

// newParts is a complete authorized da = 2 decision: the minimal_lmt
// template with its real blob and share commitment.
func newParts(t testing.TB) *parts {
	t.Helper()
	c := gatefix.Template(t)
	env, h := gatefix.Sign(t, "agent1", c)
	p := &parts{
		da: commitment.DACelestiaBlob, c: c, hash: h, env: env,
		action:     gatefix.Action(t),
		salt:       gatefix.Salt(t),
		blob:       gatefix.Blob(t),
		payloadRef: c.PayloadRef.Commitment,
		ev: &archive.EvidenceRecord{
			DA: commitment.DACelestiaBlob, Commitment: c.PayloadRef.Commitment, Namespace: c.PayloadRef.Namespace,
			Height: anchorHeight, Header: goodHeader(), BlobProof: proofFor(goodHeader()),
		},
		k2: &archive.K2Inputs{DA: commitment.DACelestiaBlob, CheckedAt: authorizedAt, BlockTime: blockTime, BlobRetentionS: 14400},
	}
	p.auth = signAuth(t, gateKey(t), h, c, commitment.PathDA, authExpires)
	return p
}

// newFibreParts is a da = 1 decision. The evidence fields come from the
// archive vectors; the anchor verifier is a fake.
func newFibreParts(t testing.TB) *parts {
	t.Helper()
	c := gatefix.FibreTemplate(t)
	env, h := gatefix.Sign(t, "agent1", c)
	action := gatefix.Action(t)
	ah, err := commitment.ActionHash(c.Action.Type, gatefix.Salt(t), action)
	require.NoError(t, err)
	if !bytes.Equal(ah[:], c.Action.Hash) {
		c = gatefix.WithAction(t, c, gatefix.ActionType, action)
		env, h = gatefix.Sign(t, "agent1", c)
	}
	src, ok := archivefix.Load(t).Cases["evidence_da1_live"].Record.(*archive.EvidenceRecord)
	require.True(t, ok)
	ev := *src
	ev.Commitment = c.PayloadRef.Commitment
	ev.Header = goodHeader()
	ev.SystemBlobProof = proofFor(goodHeader())
	p := &parts{
		da: commitment.DAFibre, c: c, hash: h, env: env, action: action, salt: gatefix.Salt(t),
		blob: gatefix.FibreBlob(), payloadRef: c.PayloadRef.Commitment, ev: &ev,
		k2: &archive.K2Inputs{
			DA: commitment.DAFibre, CheckedAt: authorizedAt, BlockTime: blockTime,
			RetentionLatestS: 14400, RetentionAtHeightS: 14400, RetentionSource: archive.RetentionBoth,
			PromiseCreated: blockTime,
		},
	}
	p.ev.Height = c.PayloadRef.Height
	p.auth = signAuth(t, gateKey(t), h, c, commitment.PathDA, authExpires)
	return p
}

func (p *parts) committers() map[commitment.DA]gate.DACommitter {
	return map[commitment.DA]gate.DACommitter{
		commitment.DACelestiaBlob: blobv1.New(),
		commitment.DAFibre:        fibreBlobCommitter{},
	}
}

func (p *parts) write(t testing.TB) *fsarchive.Store {
	t.Helper()
	cm := p.committers()
	if p.permissive {
		cm = map[commitment.DA]gate.DACommitter{commitment.DACelestiaBlob: acceptAll{}, commitment.DAFibre: acceptAll{}}
	}
	s, err := fsarchive.Open(t.TempDir(), cm)
	require.NoError(t, err)
	ctx := context.Background()
	put := func(r archive.Record) {
		t.Helper()
		_, err := s.Put(ctx, r)
		require.NoError(t, err)
	}
	if p.blob != nil {
		pr := &archive.PayloadRecord{DA: p.da, Commitment: p.payloadRef, Blob: p.blob, IntentHeight: 1}
		if p.da == commitment.DACelestiaBlob {
			pr.Namespace, pr.Signer = p.c.PayloadRef.Namespace, p.c.PayloadRef.Signer
		}
		put(pr)
	}
	if p.ev != nil && p.blob != nil {
		put(p.ev)
	}
	put(&archive.DecisionRecord{Envelope: p.env, Form: archive.FormPublic, Action: p.action, ActionSalt: p.salt})
	for _, m := range p.markers {
		put(&archive.RejectionRecord{CommitmentHash: p.hash, Error: m, GateID: gatefix.GateID, RejectedAt: authorizedAt - 10})
	}
	if p.auth != nil {
		issued := authorizedAt
		if p.authAt != 0 {
			issued = p.authAt
		}
		put(&archive.AuthorizationRecord{SignedAuthorization: p.auth, AuthorizedAt: issued, K2: p.k2})
	}
	return s
}

// rig is a verifier over a written archive with fakes for the anchor and
// header trust.
type rig struct {
	p      *parts
	store  *fsarchive.Store
	anchor *fakeAnchor
	trust  *fakeTrust
	deps   verifier.Deps
}

func newRig(t testing.TB, p *parts) *rig {
	t.Helper()
	r := &rig{p: p, store: p.write(t), anchor: &fakeAnchor{blockTime: blockTime, payloadSize: p.c.PayloadSize, proofForm: 1}}
	h := sha256.Sum256(goodHeader())
	hashes := map[uint64][]byte{p.ev.Height: h[:]}
	if p.da == commitment.DAFibre {
		ph := sha256.Sum256([]byte("promise-header"))
		hashes[p.ev.PromiseHeight] = ph[:]
		r.anchor.settlement, r.anchor.signed, r.anchor.total = "node-attested", 3, 4
		r.anchor.precision = "robust"
	}
	r.trust = &fakeTrust{
		hashes: hashes,
		res:    verifier.TrustResult{Checked: true, CheckpointH: checkpointH, CheckpointHash: bytes.Repeat([]byte{0xcc}, 32), CrossCheck: "pass"},
	}
	r.deps = verifier.Deps{
		Config:     verifier.Config{Params: commitment.DefaultParams(), GateKeys: []ed25519.PublicKey{gatePub(t)}},
		Archive:    r.store,
		Committers: p.committers(),
		Anchors:    map[commitment.DA]verifier.AnchorVerifier{p.da: r.anchor},
		Trust:      r.trust,
	}
	return r
}

func (r *rig) verifier(t testing.TB) *verifier.Verifier {
	t.Helper()
	v, err := verifier.New(r.deps)
	require.NoError(t, err)
	return v
}

func (r *rig) verify(t testing.TB, opts ...verifier.Option) verifier.Report {
	t.Helper()
	rep, err := r.verifier(t).Verify(context.Background(), r.p.hash, opts...)
	require.NoError(t, err)
	return rep
}

func failed(t testing.TB, rep verifier.Report, name verifier.CheckName) verifier.Check {
	t.Helper()
	c, ok := rep.Check(name)
	require.Truef(t, ok, "report has no check %q", name)
	require.Equalf(t, verifier.StatusFail, c.Status, "check %q: %v", name, c.Err)
	require.Error(t, c.Err)
	return c
}

// unchecked requires the check to be unchecked with this reason: a source
// problem, never a finding about the decision.
func unchecked(t testing.TB, rep verifier.Report, name verifier.CheckName, reason verifier.Reason) verifier.Check {
	t.Helper()
	c, ok := rep.Check(name)
	require.Truef(t, ok, "report has no check %q", name)
	require.Equalf(t, verifier.StatusUnchecked, c.Status, "check %q: %v", name, c.Err)
	require.Equalf(t, reason, c.Reason, "check %q: %v", name, c.Err)
	require.Error(t, c.Err)
	return c
}

func passed(t testing.TB, rep verifier.Report, name verifier.CheckName) {
	t.Helper()
	c, ok := rep.Check(name)
	require.Truef(t, ok, "report has no check %q", name)
	require.Equalf(t, verifier.StatusPass, c.Status, "check %q: %v", name, c.Err)
}

// named lists every named failure of the verifier.
var named = []error{
	verifier.ErrDecisionNotFound, verifier.ErrEnvelopeInvalid, verifier.ErrActionInvalid,
	verifier.ErrAuthorizationInvalid, verifier.ErrGateKeyNotTrusted, verifier.ErrPayloadInvalid,
	verifier.ErrAnchorInvalid, verifier.ErrArchiveIncomplete, verifier.ErrHeaderTrust,
	verifier.ErrReceiptInvalid, verifier.ErrAnchorUnsupported,
}

// requireOnly requires err to match want and no other named failure.
func requireOnly(t testing.TB, err, want error) {
	t.Helper()
	require.ErrorIs(t, err, want)
	for _, other := range named {
		if other != want {
			require.NotErrorIsf(t, err, other, "also matches %v", other)
		}
	}
}
