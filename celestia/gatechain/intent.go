package gatechain

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"

	blobtypes "github.com/celestiaorg/celestia-app/v10/x/blob/types"
	libshare "github.com/celestiaorg/go-square/v4/share"
	squaretx "github.com/celestiaorg/go-square/v4/tx"
	"github.com/cosmos/cosmos-sdk/types/bech32"
	cosmostx "github.com/cosmos/cosmos-sdk/types/tx"

	"github.com/vgonkivs/edicta/celestia/fibrecert"
	"github.com/vgonkivs/edicta/celestia/heightcheck"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
)

// FibreIntentChain is what the Fibre intent check reads from the consensus
// endpoint: the headers, the validator history at h0, the head and the
// x/fibre parameters at the head.
type FibreIntentChain interface {
	node.FibreChainReader
	LatestHeight(ctx context.Context) (uint64, error)
	FibreParamsAt(ctx context.Context, height uint64) (node.FibreParams, error)
}

// FibreIntents checks a da = 1 anchor intent: the PayForFibre tx and its
// binding, the headers at h0 and at the head, and the availability
// certificate against the validator set at h0.
type FibreIntents struct {
	c       FibreIntentChain
	chainID string
}

var _ gate.IntentVerifier = (*FibreIntents)(nil)

// NewFibreIntents accepts only promises for chainID.
func NewFibreIntents(c FibreIntentChain, chainID string) (*FibreIntents, error) {
	if c == nil || chainID == "" {
		return nil, fmt.Errorf("%w: fibre intents need a chain reader and a chain id", ErrInvalidConfig)
	}
	return &FibreIntents{c: c, chainID: chainID}, nil
}

func invalidIntent(format string, a ...any) error {
	return fmt.Errorf("%w: %s", gate.ErrAnchorIntentInvalid, fmt.Sprintf(format, a...))
}

func (v *FibreIntents) VerifyIntent(ctx context.Context, ref commitment.PayloadRef, rec *gate.AnchorIntent, payloadSize uint64) (gate.IntentFacts, error) {
	h0 := ref.Height
	if ref.DA != commitment.DAFibre || rec == nil {
		return gate.IntentFacts{}, invalidIntent("not a da = 1 intent")
	}
	f, ok, err := fibrecert.ParsePFF(rec.Tx)
	switch {
	case !ok:
		return gate.IntentFacts{}, invalidIntent("tx is not a PayForFibre tx")
	case err != nil:
		return gate.IntentFacts{}, invalidIntent("%v", err)
	}
	u, ok := fibreUploadSize(payloadSize)
	if !ok || u > math.MaxUint32 {
		return gate.IntentFacts{}, invalidIntent("payload size %d has no upload size", payloadSize)
	}
	b := fibrecert.Binding{ChainID: v.chainID, Namespace: ref.Namespace, BlobSize: uint32(u)}
	copy(b.Commitment[:], ref.Commitment)
	if err := fibrecert.CheckBinding(f.Promise, b); err != nil {
		return gate.IntentFacts{}, invalidIntent("%v", err)
	}
	if f.Promise.Height != h0 {
		return gate.IntentFacts{}, invalidIntent("promise height %d, reference height %d", f.Promise.Height, h0)
	}
	if err := fibrecert.VerifyOwner(f); err != nil {
		return gate.IntentFacts{}, invalidIntent("%v", err)
	}
	created := f.Promise.CreationTime.Unix()
	if created <= 0 {
		return gate.IntentFacts{}, invalidIntent("promise creation time %v", f.Promise.CreationTime)
	}
	// Checked before any chain read: a record that misstates the promise is
	// invalid whatever the endpoint or the certificate would say.
	if uint64(created) != rec.CreatedAt {
		return gate.IntentFacts{}, invalidIntent("created_at %d, promise creation %d", rec.CreatedAt, created)
	}

	refTime, err := v.headerTime(ctx, h0)
	if err != nil {
		return gate.IntentFacts{}, err
	}
	hist, err := v.c.HistoricalInfo(ctx, h0)
	if err != nil {
		return gate.IntentFacts{}, unavailable(fmt.Errorf("historical info at %d: %w", h0, err))
	}
	sh, err := v.c.SignedHeader(ctx, h0)
	if err != nil {
		return gate.IntentFacts{}, unavailable(fmt.Errorf("header at %d: %w", h0, err))
	}
	head, err := v.c.LatestHeight(ctx)
	if err != nil {
		return gate.IntentFacts{}, unavailable(fmt.Errorf("head: %w", err))
	}
	if head < h0 {
		return gate.IntentFacts{}, unavailable(fmt.Errorf("head %d below the reference height %d", head, h0))
	}
	headTime, err := v.headerTime(ctx, head)
	if err != nil {
		return gate.IntentFacts{}, err
	}
	fp, err := v.c.FibreParamsAt(ctx, head)
	if err != nil {
		return gate.IntentFacts{}, unavailable(fmt.Errorf("x/fibre params at %d: %w", head, err))
	}
	if fp.PromiseTimeoutS == 0 {
		return gate.IntentFacts{}, unavailable(fmt.Errorf("x/fibre params at %d have no promise timeout", head))
	}

	rep, err := certify(rec.Tx, b, hist, sh, h0)
	if err != nil {
		return gate.IntentFacts{}, err
	}
	return gate.IntentFacts{
		DA: commitment.DAFibre, RefTime: refTime, Head: head, HeadTime: headTime,
		CreatedAt: uint64(created), PromiseTimeout: fp.PromiseTimeoutS, ChainWindow: fp.PromiseHeightWindow,
		CertSigned: rep.SignedPower, CertTotal: rep.TotalPower,
	}, nil
}

// certify applies the network quorum rule against the validator set the
// chain recorded at h0. Evidence that is missing, for another height or does
// not bind to the header is the endpoint's failure, not the certificate's.
func certify(tx []byte, b fibrecert.Binding, hist, signedHeader []byte, h0 uint64) (fibrecert.Report, error) {
	hdr, err := evidenceHeights(hist, signedHeader, h0)
	if err != nil {
		return fibrecert.Report{}, unavailable(err)
	}
	ev := fibrecert.ValsetEvidence{PromiseHeader: hdr}
	f, _, err := fibrecert.ParsePFF(tx)
	if err != nil {
		return fibrecert.Report{}, invalidIntent("%v", err)
	}
	if _, _, err := fibrecert.ValidatorsFor(hist, f.Promise, ev); err != nil {
		return fibrecert.Report{}, unavailable(fmt.Errorf("validator list at %d: %w", h0, err))
	}
	rep, _, err := fibrecert.Verify(tx, b, hist, ev)
	switch {
	case errors.Is(err, fibrecert.ErrValsetMismatch):
		return fibrecert.Report{}, unavailable(err)
	case err != nil:
		return fibrecert.Report{}, fmt.Errorf("%w: %w", gate.ErrCertInvalid, err)
	}
	return rep, nil
}

func (v *FibreIntents) headerTime(ctx context.Context, height uint64) (uint64, error) {
	hd, err := v.c.Header(ctx, height)
	if err != nil {
		return 0, unavailable(fmt.Errorf("header at %d: %w", height, err))
	}
	if err := heightcheck.HeaderHeight(hd.Height, height); err != nil {
		return 0, unavailable(err)
	}
	if hd.AppVersion != node.FibreAppVersion {
		return 0, unavailable(fmt.Errorf("header at %d has app version %d, want %d", height, hd.AppVersion, node.FibreAppVersion))
	}
	t := blockUnix(hd.Time)
	if t == 0 {
		return 0, unavailable(fmt.Errorf("header at %d has no time", height))
	}
	return t, nil
}

// fibreUploadSize is the padded upload size the promise must state for a
// payload of n bytes: whole rows of 4096 bytes, the row count rounded up to
// a multiple of 64.
func fibreUploadSize(n uint64) (uint64, bool) {
	const rowBytes, rowAlign = 4096, 64
	if n == 0 || n > math.MaxUint64-rowBytes-5 {
		return 0, false
	}
	rows := (n + 5 + rowBytes - 1) / rowBytes
	rowSize := rowAlign * ((rows + rowAlign - 1) / rowAlign)
	if rowSize > math.MaxUint64/rowBytes {
		return 0, false
	}
	return rowBytes * rowSize, true
}

// BlobHeaders is what the blob intent check reads: the header at h0 and the
// head, from the same endpoint.
type BlobHeaders interface {
	Head(ctx context.Context) (node.Header, error)
	HeaderAt(ctx context.Context, height uint64) (node.Header, error)
}

// BlobIntents checks a da = 2 anchor intent: the PFB binding and the header
// at h0. The tx's signature, fee and sequence are left to the node's CheckTx
// at the broadcast.
type BlobIntents struct{ r BlobHeaders }

var _ gate.IntentVerifier = (*BlobIntents)(nil)

func NewBlobIntents(r BlobHeaders) (*BlobIntents, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: blob intents need a header reader", ErrInvalidConfig)
	}
	return &BlobIntents{r: r}, nil
}

func (v *BlobIntents) VerifyIntent(ctx context.Context, ref commitment.PayloadRef, rec *gate.AnchorIntent, _ uint64) (gate.IntentFacts, error) {
	h0 := ref.Height
	if ref.DA != commitment.DACelestiaBlob || rec == nil {
		return gate.IntentFacts{}, invalidIntent("not a da = 2 intent")
	}
	timeout, err := CheckPFB(rec.Tx, ref)
	if err != nil {
		return gate.IntentFacts{}, err
	}
	hd, err := v.r.HeaderAt(ctx, h0)
	if err != nil {
		return gate.IntentFacts{}, unavailable(fmt.Errorf("header at %d: %w", h0, err))
	}
	if err := heightcheck.HeaderHeight(hd.Height, h0); err != nil {
		return gate.IntentFacts{}, unavailable(err)
	}
	refTime := blockUnix(hd.Time)
	if refTime == 0 {
		return gate.IntentFacts{}, unavailable(fmt.Errorf("header at %d has no time", h0))
	}
	head, err := v.r.Head(ctx)
	if err != nil {
		return gate.IntentFacts{}, unavailable(fmt.Errorf("head: %w", err))
	}
	if head.Height < h0 {
		return gate.IntentFacts{}, unavailable(fmt.Errorf("head %d below the reference height %d", head.Height, h0))
	}
	return gate.IntentFacts{
		DA: commitment.DACelestiaBlob, RefTime: refTime, Head: head.Height, HeadTime: blockUnix(head.Time),
		TimeoutHeight: timeout,
	}, nil
}

const pfbTypeURL = "/celestia.blob.v1.MsgPayForBlobs"

// CheckPFB requires tx to be a signed Cosmos tx with exactly one message, a
// MsgPayForBlobs that pays for the reference's blob (namespace, share
// commitment, share version 1) with the reference's signer, and a
// timeout_height of 0 or above h0. It returns the timeout_height.
func CheckPFB(tx []byte, ref commitment.PayloadRef) (uint64, error) {
	if _, isBlob, _ := squaretx.UnmarshalBlobTx(tx); isBlob {
		return 0, invalidIntent("the intent holds a BlobTx, not the bare tx")
	}
	var raw cosmostx.TxRaw
	if err := raw.Unmarshal(tx); err != nil {
		return 0, invalidIntent("tx: %v", err)
	}
	var body cosmostx.TxBody
	if err := body.Unmarshal(raw.BodyBytes); err != nil {
		return 0, invalidIntent("tx body: %v", err)
	}
	if len(body.Messages) != 1 || body.Messages[0] == nil || body.Messages[0].TypeUrl != pfbTypeURL {
		return 0, invalidIntent("tx must hold exactly one MsgPayForBlobs")
	}
	var msg blobtypes.MsgPayForBlobs
	if err := msg.Unmarshal(body.Messages[0].Value); err != nil {
		return 0, invalidIntent("MsgPayForBlobs: %v", err)
	}
	found := false
	for i := range msg.Namespaces {
		if i < len(msg.ShareCommitments) && i < len(msg.ShareVersions) &&
			bytes.Equal(msg.Namespaces[i], ref.Namespace) && bytes.Equal(msg.ShareCommitments[i], ref.Commitment) &&
			msg.ShareVersions[i] == uint32(libshare.ShareVersionOne) {
			found = true
			break
		}
	}
	if !found {
		return 0, invalidIntent("MsgPayForBlobs pays for no blob of the reference")
	}
	_, signer, err := bech32.DecodeAndConvert(msg.Signer)
	if err != nil || !bytes.Equal(signer, ref.Signer) {
		return 0, invalidIntent("MsgPayForBlobs signer is not the reference's signer")
	}
	if body.TimeoutHeight != 0 && body.TimeoutHeight <= ref.Height {
		return 0, invalidIntent("timeout_height %d at or below h0 %d", body.TimeoutHeight, ref.Height)
	}
	var auth cosmostx.AuthInfo
	if err := auth.Unmarshal(raw.AuthInfoBytes); err != nil {
		return 0, invalidIntent("auth info: %v", err)
	}
	if len(auth.SignerInfos) == 0 || len(raw.Signatures) == 0 {
		return 0, invalidIntent("tx is not signed")
	}
	return body.TimeoutHeight, nil
}

// IntentNode is the gate's own consensus node: the tx lookup and the
// broadcast.
type IntentNode interface {
	Tx(ctx context.Context, hash [32]byte) (node.TxStatus, error)
	Broadcast(ctx context.Context, txRaw []byte) ([32]byte, error)
}

// Broadcaster looks intents up and broadcasts them on the gate's own node.
type Broadcaster struct{ n IntentNode }

var _ gate.IntentBroadcaster = (*Broadcaster)(nil)

func NewBroadcaster(n IntentNode) (*Broadcaster, error) {
	if n == nil {
		return nil, fmt.Errorf("%w: the broadcaster needs a node", ErrInvalidConfig)
	}
	return &Broadcaster{n: n}, nil
}

// Lookup reads the intent tx by SHA-256 of its bytes, which for a PFB is
// also the hash of the BlobTx that carries it.
func (b *Broadcaster) Lookup(ctx context.Context, rec *gate.AnchorIntent) (gate.TxStatus, error) {
	st, err := b.n.Tx(ctx, sha256.Sum256(rec.Tx))
	if err != nil {
		return gate.TxStatus{}, unavailable(err)
	}
	if !st.Found {
		return gate.TxStatus{}, nil
	}
	return gate.TxStatus{Included: true, Height: st.Height, Code: st.Code}, nil
}

// Broadcast sends the tx, for da = 2 wrapped with the blob as a BlobTx. A tx
// the node already holds counts as sent.
func (b *Broadcaster) Broadcast(ctx context.Context, da commitment.DA, rec *gate.AnchorIntent, blob []byte) error {
	raw := rec.Tx
	if da == commitment.DACelestiaBlob {
		ns, err := libshare.NewNamespaceFromBytes(rec.Namespace)
		if err != nil {
			return fmt.Errorf("%w: namespace: %w", gate.ErrAnchorIntentRejected, err)
		}
		bl, err := libshare.NewV1Blob(ns, blob, rec.Signer)
		if err != nil {
			return fmt.Errorf("%w: blob: %w", gate.ErrAnchorIntentRejected, err)
		}
		if raw, err = squaretx.MarshalBlobTx(rec.Tx, bl); err != nil {
			return fmt.Errorf("%w: blob tx: %w", gate.ErrAnchorIntentRejected, err)
		}
	}
	_, err := b.n.Broadcast(ctx, raw)
	switch {
	case err == nil, errors.Is(err, node.ErrAlreadyInMempool):
		return nil
	case errors.Is(err, node.ErrRejected), errors.Is(err, node.ErrSequenceMismatch), errors.Is(err, node.ErrMempoolFull):
		return fmt.Errorf("%w: %w", gate.ErrAnchorIntentRejected, err)
	}
	return unavailable(err)
}
