package inclusion_test

import (
	"bytes"
	"context"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/celestiaorg/celestia-app/v10/app"
	"github.com/celestiaorg/celestia-app/v10/app/encoding"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/celestia/gatechain"
	"github.com/vgonkivs/edicta/celestia/inclusion"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/celestia/nodefake"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/dacommit/sharev1"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/sdk"
)

var pns = append(append([]byte{0}, make([]byte, 18)...), bytes.Repeat([]byte{5}, 10)...)

// intents is an in-memory archive.IntentReader.
type intents map[string]*archive.AnchorIntentRecord

func intentKey(da commitment.DA, c []byte, h uint64) string { return fmt.Sprintf("%d/%x/%d", da, c, h) }

func (m intents) Intent(_ context.Context, da commitment.DA, c []byte, h uint64) (*archive.AnchorIntentRecord, error) {
	r, ok := m[intentKey(da, c, h)]
	if !ok {
		return nil, archive.ErrNotFound
	}
	return r, nil
}

type pendingWorld struct {
	ch   *nodefake.Chain
	in   intents
	sig  node.AnchorSigner
	addr []byte
	h0   uint64
}

func newPendingWorld(t *testing.T) *pendingWorld {
	t.Helper()
	kr := keyring.NewInMemory(encoding.MakeConfig(app.ModuleEncodingRegisters...).Codec)
	_, _, err := kr.NewMnemonic("r", keyring.English, "m/44'/118'/0'/0/0", keyring.DefaultBIP39Passphrase, hd.Secp256k1)
	require.NoError(t, err)
	s, err := node.NewAnchorSigner(kr, "r", chainID)
	require.NoError(t, err)
	addr, err := s.Address(bg)
	require.NoError(t, err)
	w := &pendingWorld{ch: nodefake.NewChain(addr), in: intents{}, sig: s, addr: addr, h0: 50}
	for h := uint64(48); h <= 53; h++ {
		w.ch.AddHeader(node.Header{ChainID: chainID, Height: h, Time: base.Add(timeOf(h)), DataRoot: sum("root")})
	}
	return w
}

// put archives the intent of a PFB for data signed at h0, and returns the
// reference to data.
func (w *pendingWorld) put(t *testing.T, signed, data []byte) commitment.PayloadRef {
	t.Helper()
	tx, err := w.sig.SignPFB(bg, pns, signed, node.TxParams{AccountNumber: 1, Sequence: 2, GasPrice: big.NewRat(1, 250), TimeoutHeight: w.h0 + 20})
	require.NoError(t, err)
	c, err := sharev1.Commitment(pns, w.addr, data)
	require.NoError(t, err)
	w.in[intentKey(commitment.DACelestiaBlob, c, w.h0)] = &archive.AnchorIntentRecord{
		DA: commitment.DACelestiaBlob, Commitment: c, Namespace: pns, RefHeight: w.h0, Tx: tx, Signer: w.addr, CreatedAt: 1,
	}
	return commitment.PayloadRef{DA: commitment.DACelestiaBlob, Namespace: pns, Commitment: c, Height: w.h0,
		Signer: w.addr, Anchor: commitment.AnchorPending}
}

func (w *pendingWorld) verifier(t *testing.T, v gate.IntentVerifier) *inclusion.Pending {
	t.Helper()
	if v == nil {
		var err error
		v, err = gatechain.NewBlobIntents(w.ch)
		require.NoError(t, err)
	}
	p, err := inclusion.NewPending(inclusion.PendingConfig{Intents: w.in, Verifier: v})
	require.NoError(t, err)
	return p
}

func timeOf(h uint64) time.Duration { return time.Duration(h) * time.Second }

func TestPendingReturnsTheHeaderTimeAtH0(t *testing.T) {
	w := newPendingWorld(t)
	data := []byte("payload")
	ref := w.put(t, data, data)
	got, err := w.verifier(t, nil).VerifyPending(bg, ref, uint64(len(data)))
	require.NoError(t, err)
	assert.Equal(t, uint64(base.Add(timeOf(w.h0)).Unix()), got)
}

func TestPendingRefusesAPFBForAnotherBlob(t *testing.T) {
	w := newPendingWorld(t)
	data := []byte("payload")
	ref := w.put(t, []byte("another payload"), data)
	_, err := w.verifier(t, nil).VerifyPending(bg, ref, uint64(len(data)))
	require.ErrorIs(t, err, sdk.ErrInclusionUnverified)
	require.ErrorIs(t, err, gate.ErrAnchorIntentInvalid)
}

func TestPendingRefusesABadCertificate(t *testing.T) {
	w := newPendingWorld(t)
	data := []byte("payload")
	ref := w.put(t, data, data)
	_, err := w.verifier(t, refusing{gate.ErrCertInvalid}).VerifyPending(bg, ref, uint64(len(data)))
	require.ErrorIs(t, err, sdk.ErrInclusionUnverified)
	require.ErrorIs(t, err, gate.ErrCertInvalid)
}

func TestPendingRefusesAMissingIntentOrAnIncludedReference(t *testing.T) {
	w := newPendingWorld(t)
	data := []byte("payload")
	ref := w.put(t, data, data)
	p := w.verifier(t, nil)

	moved := ref
	moved.Height = w.h0 + 1
	_, err := p.VerifyPending(bg, moved, uint64(len(data)))
	require.ErrorIs(t, err, sdk.ErrInclusionUnverified, "no intent at another h0")

	included := ref
	included.Anchor = 0
	_, err = p.VerifyPending(bg, included, uint64(len(data)))
	require.ErrorIs(t, err, sdk.ErrInclusionUnverified)

	otherNS := ref
	otherNS.Namespace = append(bytes.Clone(pns[:28]), 6)
	w.in[intentKey(commitment.DACelestiaBlob, ref.Commitment, w.h0)].Namespace = otherNS.Namespace
	_, err = p.VerifyPending(bg, ref, uint64(len(data)))
	require.ErrorIs(t, err, sdk.ErrInclusionUnverified, "a record naming another namespace")
}

func TestPendingConfigNeedsBothParts(t *testing.T) {
	_, err := inclusion.NewPending(inclusion.PendingConfig{Intents: intents{}})
	require.ErrorIs(t, err, inclusion.ErrConfig)
	_, err = inclusion.NewPending(inclusion.PendingConfig{Verifier: refusing{}})
	require.ErrorIs(t, err, inclusion.ErrConfig)
}

type refusing struct{ err error }

func (r refusing) VerifyIntent(context.Context, commitment.PayloadRef, *gate.AnchorIntent, uint64) (gate.IntentFacts, error) {
	return gate.IntentFacts{}, r.err
}

// foreignIntents answers every key with one fixed record, as a store that
// files a record under the wrong key would.
type foreignIntents struct{ rec *archive.AnchorIntentRecord }

func (f foreignIntents) Intent(context.Context, commitment.DA, []byte, uint64) (*archive.AnchorIntentRecord, error) {
	r := *f.rec
	return &r, nil
}

func TestPendingRefusesAForeignIntent(t *testing.T) {
	w := newPendingWorld(t)
	data := []byte("payload")
	ref := w.put(t, data, data)
	good := *w.in[intentKey(commitment.DACelestiaBlob, ref.Commitment, w.h0)]
	bv, err := gatechain.NewBlobIntents(w.ch)
	require.NoError(t, err)

	for _, tc := range []struct {
		name string
		bend func(r *archive.AnchorIntentRecord)
	}{
		{"another h0", func(r *archive.AnchorIntentRecord) { r.RefHeight = w.h0 + 1 }},
		{"another commitment", func(r *archive.AnchorIntentRecord) { r.Commitment = bytes.Repeat([]byte{1}, 32) }},
		{"another signer", func(r *archive.AnchorIntentRecord) { r.Signer = bytes.Repeat([]byte{2}, 20) }},
		{"another da", func(r *archive.AnchorIntentRecord) { r.DA = commitment.DAFibre }},
		{"no signer", func(r *archive.AnchorIntentRecord) { r.Signer = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := good
			tc.bend(&rec)
			p, err := inclusion.NewPending(inclusion.PendingConfig{Intents: foreignIntents{&rec}, Verifier: bv})
			require.NoError(t, err)
			_, err = p.VerifyPending(bg, ref, uint64(len(data)))
			require.ErrorIs(t, err, sdk.ErrInclusionUnverified)
		})
	}
}

// The intent's PFB stops being valid at h0 itself: the gate's own intent
// check refuses it.
func TestPendingRefusesAPFBThatTimesOutAtH0(t *testing.T) {
	w := newPendingWorld(t)
	data := []byte("payload")
	ref := w.put(t, data, data)
	rec := w.in[intentKey(commitment.DACelestiaBlob, ref.Commitment, w.h0)]
	tx, err := w.sig.SignPFB(bg, pns, data, node.TxParams{AccountNumber: 1, Sequence: 2, GasPrice: big.NewRat(1, 250), TimeoutHeight: w.h0})
	require.NoError(t, err)
	rec.Tx = tx
	_, err = w.verifier(t, nil).VerifyPending(bg, ref, uint64(len(data)))
	require.ErrorIs(t, err, sdk.ErrInclusionUnverified)
	require.ErrorIs(t, err, gate.ErrAnchorIntentInvalid)
}

func TestPendingReportsTheOperatorsAttestation(t *testing.T) {
	for _, ind := range []bool{false, true} {
		p, err := inclusion.NewPending(inclusion.PendingConfig{Intents: intents{}, Verifier: refusing{}, Independent: ind})
		require.NoError(t, err)
		assert.Equal(t, ind, p.Independent())
	}
}
