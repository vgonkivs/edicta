package gatechain_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	blobtypes "github.com/celestiaorg/celestia-app/v10/x/blob/types"
	fibretypes "github.com/celestiaorg/celestia-app/v10/x/fibre/types"
	libshare "github.com/celestiaorg/go-square/v4/share"
	squaretx "github.com/celestiaorg/go-square/v4/tx"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/types/bech32"
	cosmostx "github.com/cosmos/cosmos-sdk/types/tx"

	"github.com/vgonkivs/edicta/celestia/gatechain"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
)

// intentChain serves the live evidence at the promise height and a head a
// few blocks later.
type intentChain struct {
	t       testing.TB
	l       live
	head    uint64
	headErr error
	hist    []byte
	params  node.FibreParams
}

func newIntentChain(t testing.TB) *intentChain {
	l := loadLive(t)
	return &intentChain{t: t, l: l, head: l.promiseH + 2, hist: l.hist,
		params: node.FibreParams{RetentionS: 14400, PromiseHeightWindow: 1000, PromiseTimeoutS: 3600}}
}

func (c *intentChain) Header(_ context.Context, height uint64) (node.FibreHeader, error) {
	if raw, ok := c.l.headers[height]; ok {
		h := c.l.header(c.t, raw)
		return node.FibreHeader{Height: uint64(h.Height), DataHash: h.DataHash, Time: h.Time, AppVersion: h.Version.App}, nil
	}
	base := c.l.header(c.t, c.l.promiseHdr)
	return node.FibreHeader{Height: height, Time: base.Time.Add(time.Duration(height-c.l.promiseH) * 6 * time.Second),
		AppVersion: node.FibreAppVersion}, nil
}

func (c *intentChain) TxCode(context.Context, uint64, [32]byte) (uint32, error) { return 0, nil }

func (c *intentChain) HistoricalInfo(_ context.Context, height uint64) ([]byte, error) {
	if height != c.l.promiseH {
		return nil, node.ErrNotFound
	}
	return c.hist, nil
}

func (c *intentChain) SignedHeader(_ context.Context, height uint64) ([]byte, error) {
	if height != c.l.promiseH {
		return nil, node.ErrNotFound
	}
	return signedHeader(c.t, c.l.promiseHdr), nil
}

func (c *intentChain) LatestHeight(context.Context) (uint64, error) { return c.head, c.headErr }

func (c *intentChain) FibreParamsAt(context.Context, uint64) (node.FibreParams, error) {
	return c.params, nil
}

func liveIntent(l live) (commitment.PayloadRef, *gate.AnchorIntent) {
	ref := refFor(l, l.ns, l.commit, l.promiseH)
	ref.Anchor = commitment.AnchorPending
	return ref, &gate.AnchorIntent{DA: commitment.DAFibre, Commitment: ref.Commitment, Namespace: ref.Namespace,
		RefHeight: l.promiseH, Tx: l.pff, CreatedAt: uint64(l.created.Unix())}
}

func TestFibreIntentFacts(t *testing.T) {
	c := newIntentChain(t)
	v, err := gatechain.NewFibreIntents(c, mochaID)
	require.NoError(t, err)
	ref, rec := liveIntent(c.l)
	f, err := v.VerifyIntent(t.Context(), ref, rec, uint64(len(c.l.payload)))
	require.NoError(t, err)
	assert.Equal(t, commitment.DAFibre, f.DA)
	assert.Equal(t, uint64(c.l.header(t, c.l.promiseHdr).Time.Unix()), f.RefTime)
	assert.Equal(t, c.head, f.Head)
	assert.Equal(t, uint64(c.l.created.Unix()), f.CreatedAt)
	assert.EqualValues(t, 3600, f.PromiseTimeout)
	assert.EqualValues(t, 1000, f.ChainWindow)
	assert.Positive(t, f.CertSigned)
	assert.GreaterOrEqual(t, f.CertTotal, f.CertSigned)
}

func TestFibreIntentRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(c *intentChain, ref *commitment.PayloadRef, rec *gate.AnchorIntent, size *uint64)
		want   error
	}{
		"promise height is not h0": {func(c *intentChain, ref *commitment.PayloadRef, _ *gate.AnchorIntent, _ *uint64) {
			ref.Height++
		}, gate.ErrAnchorIntentInvalid},
		"other namespace": {func(_ *intentChain, ref *commitment.PayloadRef, _ *gate.AnchorIntent, _ *uint64) {
			ref.Namespace = append([]byte(nil), ref.Namespace...)
			ref.Namespace[28] ^= 1
		}, gate.ErrAnchorIntentInvalid},
		"other commitment": {func(_ *intentChain, ref *commitment.PayloadRef, _ *gate.AnchorIntent, _ *uint64) {
			ref.Commitment = make([]byte, 32)
		}, gate.ErrAnchorIntentInvalid},
		"other blob size": {func(_ *intentChain, _ *commitment.PayloadRef, _ *gate.AnchorIntent, size *uint64) {
			*size = 262140
		}, gate.ErrAnchorIntentInvalid},
		"not a pff": {func(_ *intentChain, _ *commitment.PayloadRef, rec *gate.AnchorIntent, _ *uint64) {
			rec.Tx = []byte{0x0a, 0x00}
		}, gate.ErrAnchorIntentInvalid},
		"certificate without signatures": {func(c *intentChain, _ *commitment.PayloadRef, rec *gate.AnchorIntent, _ *uint64) {
			rec.Tx = mutateTx(c.t, rec.Tx, func(m *fibretypes.MsgPayForFibre) {
				for i := range m.ValidatorSignatures {
					m.ValidatorSignatures[i] = nil
				}
			})
		}, gate.ErrCertInvalid},
		"forged valset order": {func(c *intentChain, _ *commitment.PayloadRef, _ *gate.AnchorIntent, _ *uint64) {
			hi := parseHist(c.t, c.hist)
			require.GreaterOrEqual(c.t, len(hi.Valset), 2)
			hi.Valset[0], hi.Valset[1] = hi.Valset[1], hi.Valset[0]
			c.hist = marshalHist(c.t, hi)
		}, gate.ErrChainUnavailable},
		"head unreadable": {func(c *intentChain, _ *commitment.PayloadRef, _ *gate.AnchorIntent, _ *uint64) {
			c.headErr = errors.New("dial")
		}, gate.ErrChainUnavailable},
		"head below h0": {func(c *intentChain, _ *commitment.PayloadRef, _ *gate.AnchorIntent, _ *uint64) {
			c.head = c.l.promiseH - 1
		}, gate.ErrChainUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			c := newIntentChain(t)
			v, err := gatechain.NewFibreIntents(c, mochaID)
			require.NoError(t, err)
			ref, rec := liveIntent(c.l)
			size := uint64(len(c.l.payload))
			tc.mutate(c, &ref, rec, &size)
			_, err = v.VerifyIntent(t.Context(), ref, rec, size)
			require.ErrorIs(t, err, tc.want)
		})
	}
}

// pfbTx builds a signed-looking tx holding msgs, with the given timeout.
func pfbTx(t testing.TB, timeout uint64, signed bool, msgs ...*blobtypes.MsgPayForBlobs) []byte {
	t.Helper()
	body := cosmostx.TxBody{TimeoutHeight: timeout}
	for _, m := range msgs {
		v, err := m.Marshal()
		require.NoError(t, err)
		body.Messages = append(body.Messages, &codectypes.Any{TypeUrl: "/celestia.blob.v1.MsgPayForBlobs", Value: v})
	}
	bb, err := body.Marshal()
	require.NoError(t, err)
	auth := cosmostx.AuthInfo{}
	raw := cosmostx.TxRaw{BodyBytes: bb}
	if signed {
		auth.SignerInfos = []*cosmostx.SignerInfo{{Sequence: 1}}
		raw.Signatures = [][]byte{make([]byte, 64)}
	}
	if raw.AuthInfoBytes, err = auth.Marshal(); err != nil {
		require.NoError(t, err)
	}
	out, err := raw.Marshal()
	require.NoError(t, err)
	return out
}

func blobRef(t testing.TB) (commitment.PayloadRef, *blobtypes.MsgPayForBlobs) {
	t.Helper()
	ns := append(make([]byte, 19), []byte("edicta/d01")...)
	signer := make([]byte, 20)
	signer[0] = 7
	addr, err := bech32.ConvertAndEncode("celestia", signer)
	require.NoError(t, err)
	commit := sha256.Sum256([]byte("blob"))
	ref := commitment.PayloadRef{DA: commitment.DACelestiaBlob, Namespace: ns, Commitment: commit[:], Signer: signer,
		Height: 100, Anchor: commitment.AnchorPending}
	other := sha256.Sum256([]byte("other"))
	msg := &blobtypes.MsgPayForBlobs{Signer: addr, Namespaces: [][]byte{ns, ns}, BlobSizes: []uint32{4, 4},
		ShareCommitments: [][]byte{other[:], commit[:]}, ShareVersions: []uint32{1, 1}}
	return ref, msg
}

type blobHeaders struct {
	head uint64
	at   map[uint64]time.Time
}

func (b blobHeaders) Head(context.Context) (node.Header, error) {
	return node.Header{Height: b.head, Time: time.Unix(1_790_997_030, 0)}, nil
}

func (b blobHeaders) HeaderAt(_ context.Context, h uint64) (node.Header, error) {
	t, ok := b.at[h]
	if !ok {
		return node.Header{}, node.ErrNotFound
	}
	return node.Header{Height: h, Time: t}, nil
}

func TestBlobIntent(t *testing.T) {
	ref, msg := blobRef(t)
	hs := blobHeaders{head: 102, at: map[uint64]time.Time{100: time.Unix(1_790_997_000, 0)}}
	v, err := gatechain.NewBlobIntents(hs)
	require.NoError(t, err)
	rec := &gate.AnchorIntent{DA: commitment.DACelestiaBlob, Tx: pfbTx(t, 150, true, msg)}
	f, err := v.VerifyIntent(t.Context(), ref, rec, 4)
	require.NoError(t, err)
	assert.Equal(t, gate.IntentFacts{DA: commitment.DACelestiaBlob, RefTime: 1_790_997_000, Head: 102,
		HeadTime: 1_790_997_030, TimeoutHeight: 150}, f)

	other := *msg
	other.Signer, err = bech32.ConvertAndEncode("celestia", make([]byte, 20))
	require.NoError(t, err)
	for name, tx := range map[string][]byte{
		"another signer":     pfbTx(t, 0, true, &other),
		"a second message":   pfbTx(t, 0, true, msg, msg),
		"timeout at h0":      pfbTx(t, 100, true, msg),
		"unsigned":           pfbTx(t, 0, false, msg),
		"another commitment": pfbTx(t, 0, true, &blobtypes.MsgPayForBlobs{Signer: msg.Signer, Namespaces: msg.Namespaces[:1], BlobSizes: msg.BlobSizes[:1], ShareCommitments: msg.ShareCommitments[:1], ShareVersions: msg.ShareVersions[:1]}),
		"share version 0":    pfbTx(t, 0, true, &blobtypes.MsgPayForBlobs{Signer: msg.Signer, Namespaces: msg.Namespaces, BlobSizes: msg.BlobSizes, ShareCommitments: msg.ShareCommitments, ShareVersions: []uint32{1, 0}}),
		"not a tx":           {0xff, 0x01},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := v.VerifyIntent(t.Context(), ref, &gate.AnchorIntent{DA: commitment.DACelestiaBlob, Tx: tx}, 4)
			require.ErrorIs(t, err, gate.ErrAnchorIntentInvalid)
		})
	}

	hs.at = map[uint64]time.Time{}
	v, err = gatechain.NewBlobIntents(hs)
	require.NoError(t, err)
	_, err = v.VerifyIntent(t.Context(), ref, rec, 4)
	require.ErrorIs(t, err, gate.ErrChainUnavailable)
}

type fakeNode struct {
	status node.TxStatus
	err    error
	sent   [][]byte
	sendFn func([]byte) error
}

func (n *fakeNode) Tx(context.Context, [32]byte) (node.TxStatus, error) { return n.status, n.err }

func (n *fakeNode) Broadcast(_ context.Context, raw []byte) ([32]byte, error) {
	n.sent = append(n.sent, raw)
	if n.sendFn != nil {
		return [32]byte{}, n.sendFn(raw)
	}
	return sha256.Sum256(raw), nil
}

func TestBroadcaster(t *testing.T) {
	ref, msg := blobRef(t)
	rec := &gate.AnchorIntent{DA: commitment.DACelestiaBlob, Namespace: ref.Namespace, Signer: ref.Signer, Tx: pfbTx(t, 0, true, msg)}

	n := &fakeNode{status: node.TxStatus{Found: true, Height: 101, Code: 0}}
	b, err := gatechain.NewBroadcaster(n)
	require.NoError(t, err)
	st, err := b.Lookup(t.Context(), rec)
	require.NoError(t, err)
	assert.Equal(t, gate.TxStatus{Included: true, Height: 101}, st)

	n.err = errors.New("dial")
	_, err = b.Lookup(t.Context(), rec)
	require.ErrorIs(t, err, gate.ErrChainUnavailable)

	require.NoError(t, b.Broadcast(t.Context(), commitment.DACelestiaBlob, rec, []byte("blob")))
	require.Len(t, n.sent, 1)
	btx, isBlob, err := squaretx.UnmarshalBlobTx(n.sent[0])
	require.NoError(t, err)
	require.True(t, isBlob)
	assert.Equal(t, rec.Tx, btx.Tx)
	require.Len(t, btx.Blobs, 1)
	assert.Equal(t, []byte("blob"), btx.Blobs[0].Data())
	assert.Equal(t, libshare.ShareVersionOne, btx.Blobs[0].ShareVersion())

	n.sendFn = func([]byte) error { return node.ErrAlreadyInMempool }
	require.NoError(t, b.Broadcast(t.Context(), commitment.DAFibre, rec, nil), "a known tx counts as sent")
	assert.Equal(t, rec.Tx, n.sent[1], "a Fibre tx goes out unchanged")

	n.sendFn = func([]byte) error { return node.ErrRejected }
	require.ErrorIs(t, b.Broadcast(t.Context(), commitment.DAFibre, rec, nil), gate.ErrAnchorIntentRejected)
	n.sendFn = func([]byte) error { return node.ErrUnavailable }
	require.ErrorIs(t, b.Broadcast(t.Context(), commitment.DAFibre, rec, nil), gate.ErrChainUnavailable)
}
