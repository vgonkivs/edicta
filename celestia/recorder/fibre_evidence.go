package recorder

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/celestiaorg/celestia-app/v10/pkg/da"
	daproto "github.com/celestiaorg/celestia-app/v10/proto/celestia/core/v1/da"
	fibretypes "github.com/celestiaorg/celestia-app/v10/x/fibre/types"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmttypes "github.com/cometbft/cometbft/types"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/celestia/anchorverify"
	"github.com/vgonkivs/edicta/celestia/fibreproof"
	"github.com/vgonkivs/edicta/celestia/gatechain"
	"github.com/vgonkivs/edicta/celestia/node"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/sdk"
)

// maxAnchorProofBytes is the archive's field limit for the anchor proof.
const maxAnchorProofBytes = 1 << 22

func unavailable(what string, err error) error {
	return fmt.Errorf("%w: %s: %w", ErrNodeUnavailable, what, err)
}

// bindSignedHeader decodes a SignedHeader and requires its commit to be for
// the header it carries, at height h.
func bindSignedHeader(raw []byte, h uint64) (*cmtproto.Header, error) {
	var sh cmtproto.SignedHeader
	if err := sh.Unmarshal(raw); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if sh.Header == nil || sh.Commit == nil {
		return nil, errors.New("no header or no commit")
	}
	if sh.Header.Height < 0 || uint64(sh.Header.Height) != h || sh.Commit.Height != sh.Header.Height {
		return nil, fmt.Errorf("header at height %d, commit at %d, want %d", sh.Header.Height, sh.Commit.Height, h)
	}
	ch, err := cmttypes.HeaderFromProto(sh.Header)
	if err != nil {
		return nil, fmt.Errorf("header: %w", err)
	}
	if want := ch.Hash(); len(want) != sha256.Size || !bytes.Equal(want, sh.Commit.BlockID.Hash) {
		return nil, errors.New("commit is for another block than the header")
	}
	return sh.Header, nil
}

// buildEvidence assembles the evidence record of the anchor fa from reads of
// the own node, checks every part against its header, and runs the verifier's
// own anchor check on the result before anything is written: records are
// write-once, so a bad one could not be repaired.
func (r *FibreRecorder) buildEvidence(ctx context.Context, ref commitment.PayloadRef, fa gatechain.FibreAnchor) (sdk.Published, *archive.EvidenceRecord, error) {
	h := ref.Height
	c := r.d.Chain

	rawH, err := c.SignedHeader(ctx, h)
	if err != nil {
		return sdk.Published{}, nil, unavailable("signed header", err)
	}
	hdr, err := bindSignedHeader(rawH, h)
	if err != nil {
		return sdk.Published{}, nil, unavailable("signed header", err)
	}
	if hdr.Time.Unix() < 0 || uint64(hdr.Time.Unix()) != fa.BlockTime {
		return sdk.Published{}, nil, unavailable("signed header", errors.New("time differs from the anchor block time"))
	}

	if len(fa.Proof) > maxAnchorProofBytes {
		return sdk.Published{}, nil, archiveFault("anchor proof", errors.New("above the archive field limit; publish a new blob"))
	}
	anchorTx, err := anchorTxOf(fa, hdr.DataHash)
	if err != nil {
		return sdk.Published{}, nil, unavailable("anchor proof", err)
	}
	ftx, ok, err := fibretypes.TryParseFibreTx(anchorTx)
	if err != nil || !ok {
		return sdk.Published{}, nil, unavailable("anchor tx", errors.Join(err, errors.New("not a pay-for-fibre tx")))
	}
	sysBlob, err := ftx.SystemBlob.Marshal()
	if err != nil {
		return sdk.Published{}, nil, unavailable("system blob", err)
	}

	pl, err := c.TxPlace(ctx, fa.TxHash)
	if err != nil {
		return sdk.Published{}, nil, unavailable("tx placement", err)
	}
	if pl.Status != "COMMITTED" || pl.Height != h || pl.Code != 0 {
		return sdk.Published{}, nil, unavailable("tx placement", fmt.Errorf("status %q at height %d with code %d, want committed at %d with code 0", pl.Status, pl.Height, pl.Code, h))
	}

	ph := fa.Promise.Height
	rawP, err := c.SignedHeader(ctx, ph)
	if err != nil {
		return sdk.Published{}, nil, unavailable("promise header", err)
	}
	phdr, err := bindSignedHeader(rawP, ph)
	if err != nil {
		return sdk.Published{}, nil, unavailable("promise header", err)
	}
	hist, err := c.HistoricalInfo(ctx, ph)
	if err != nil {
		return sdk.Published{}, nil, unavailable("historical info", err)
	}
	// The set behind the promise header's next validators hash is the one at
	// the promise height plus one.
	vset, err := c.ValidatorSet(ctx, ph+1)
	if err != nil {
		return sdk.Published{}, nil, unavailable("validator set", err)
	}
	if err := checkValset(vset, phdr.NextValidatorsHash); err != nil {
		return sdk.Published{}, nil, unavailable("validator set", err)
	}

	ev := &archive.EvidenceRecord{
		DA: commitment.DAFibre, Commitment: bytes.Clone(ref.Commitment), Namespace: bytes.Clone(r.cfg.Namespace), Height: h,
		Header: rawH, AnchorTx: anchorTx, AnchorTxIndex: uint64(pl.Index), TxCode: 0,
		SystemBlob: sysBlob, SystemBlobProof: bytes.Clone(fa.Proof),
		PromiseHeight: ph, PromiseHeader: rawP, HistoricalInfo: hist,
	}
	facts, err := anchorverify.Fibre().VerifyAnchor(ref, ev)
	if err != nil {
		return sdk.Published{}, nil, unavailable("evidence self-check", err)
	}
	var start uint64
	if s := fa.Promise.CreationTime.Unix(); s > 0 {
		start = uint64(s)
	}
	if facts.RetentionStart != start || facts.BlockTime != fa.BlockTime {
		return sdk.Published{}, nil, unavailable("evidence self-check", errors.New("verifier facts differ from the anchor"))
	}
	return sdk.Published{Ref: ref, BlockTime: fa.BlockTime, RetentionStart: start}, ev, nil
}

// anchorTxOf returns the tx of the anchor from the namespace data, after
// checking the data against the block's data hash.
func anchorTxOf(fa gatechain.FibreAnchor, dataHash []byte) ([]byte, error) {
	dahProto, stream, err := fibreproof.DecodeProof(fa.Proof)
	if err != nil {
		return nil, err
	}
	var dp daproto.DataAvailabilityHeader
	if err := dp.Unmarshal(dahProto); err != nil {
		return nil, err
	}
	dah := &da.DataAvailabilityHeader{RowRoots: dp.RowRoots, ColumnRoots: dp.ColumnRoots}
	if err := fibreproof.CheckDAH(dah, dataHash); err != nil {
		return nil, err
	}
	txs, err := fibreproof.VerifyNamespaceData(dah, stream)
	if err != nil {
		return nil, err
	}
	for _, tx := range txs {
		if sha256.Sum256(tx) == fa.TxHash {
			return tx, nil
		}
	}
	return nil, errors.New("anchor tx is not in the block's namespace data")
}

func checkValset(raw, nextValidatorsHash []byte) error {
	var vp cmtproto.ValidatorSet
	if err := vp.Unmarshal(raw); err != nil {
		return err
	}
	vs, err := cmttypes.ValidatorSetFromProto(&vp)
	if err != nil {
		return err
	}
	if !bytes.Equal(vs.Hash(), nextValidatorsHash) {
		return errors.New("hash differs from the promise header's next validators hash")
	}
	return nil
}

// fromEvidence answers from archived evidence without reading the blob, which
// Fibre no longer serves after retention. If the own node still has the
// header at the anchor height, it must be the archived one.
func (r *FibreRecorder) fromEvidence(ctx context.Context, comm, _ []byte, ev *archive.EvidenceRecord) (sdk.Published, error) {
	if ev.Height == 0 || !bytes.Equal(ev.Namespace, r.cfg.Namespace) {
		return sdk.Published{}, archiveFault("evidence record", archive.ErrConflict)
	}
	ref := r.ref(comm, ev.Height)
	facts, err := anchorverify.Fibre().VerifyAnchor(ref, ev)
	if err != nil {
		return sdk.Published{}, archiveFault("evidence record", err)
	}
	raw, err := r.d.Chain.SignedHeader(ctx, ev.Height)
	switch {
	case err == nil:
		hdr, err := bindSignedHeader(raw, ev.Height)
		if err != nil {
			return sdk.Published{}, archiveFault("node header", err)
		}
		ch, err := cmttypes.HeaderFromProto(hdr)
		if err != nil || !bytes.Equal(ch.Hash(), facts.AnchorHeaderHash) {
			return sdk.Published{}, archiveFault("node header", errors.New("differs from the archived header"))
		}
	case errors.Is(err, node.ErrNotFound):
	default:
		return sdk.Published{}, unavailable("signed header", err)
	}
	return sdk.Published{Ref: ref, BlockTime: facts.BlockTime, RetentionStart: facts.RetentionStart}, nil
}
