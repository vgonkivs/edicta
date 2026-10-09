// Package anchorverify checks archived anchor evidence offline: the header
// and the proof that the blob was in that block. Whether the header belongs
// to the chain is header trust's question, not this package's.
package anchorverify

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/celestiaorg/celestia-app/v10/pkg/da"
	daproto "github.com/celestiaorg/celestia-app/v10/proto/celestia/core/v1/da"
	fibretypes "github.com/celestiaorg/celestia-app/v10/x/fibre/types"
	"github.com/celestiaorg/celestia-node/blob"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	core "github.com/cometbft/cometbft/types"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/celestia/fibrecert"
	"github.com/vgonkivs/edicta/celestia/fibreproof"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/verifier"
)

type blobAnchor struct{}

// Blob verifies da = 2 evidence: the commitment proof of the share-version-1
// blob against the data root of the archived header.
func Blob() verifier.AnchorVerifier { return blobAnchor{} }

func (blobAnchor) VerifyAnchor(ref commitment.PayloadRef, ev *archive.EvidenceRecord) (facts verifier.AnchorFacts, err error) {
	if ref.DA != commitment.DACelestiaBlob {
		return verifier.AnchorFacts{}, fmt.Errorf("%w: da %d", verifier.ErrAnchorUnsupported, ref.DA)
	}
	defer func() {
		if r := recover(); r != nil {
			facts, err = verifier.AnchorFacts{}, fmt.Errorf("panic: %v", r)
		}
	}()
	hd, err := decodeSignedHeader(ev.Header)
	if err != nil {
		return verifier.AnchorFacts{}, fmt.Errorf("header: %w", err)
	}
	if uint64(hd.Height) != ref.Height {
		return verifier.AnchorFacts{}, fmt.Errorf("header is for height %d, the reference names %d", hd.Height, ref.Height)
	}
	if len(hd.DataHash) == 0 {
		return verifier.AnchorFacts{}, errors.New("header has no data root")
	}
	hash := hd.Hash()
	if len(hash) != 32 {
		return verifier.AnchorFacts{}, errors.New("header has no hash")
	}
	if len(ev.BlobProof) == 0 {
		return verifier.AnchorFacts{}, errors.New("evidence has no commitment proof")
	}
	if err := verifyProof(ev.BlobProof, hd.DataHash, ref.Commitment); err != nil {
		return verifier.AnchorFacts{}, fmt.Errorf("commitment proof against data root at height %d: %w", ref.Height, err)
	}
	if hd.Time.Unix() < 0 {
		return verifier.AnchorFacts{}, fmt.Errorf("header time %s is before 1970", hd.Time.UTC().Format(time.RFC3339))
	}
	ts := uint64(hd.Time.Unix())
	return verifier.AnchorFacts{
		BlockTime:        ts,
		RetentionStart:   ts,
		AnchorHeaderHash: hash,
	}, nil
}

// verifyProof decodes and checks the proof. A panic in the proof library
// becomes an error: the proof is attacker-supplied archive data, and decoding
// it is as exposed as verifying it.
func verifyProof(raw, dataRoot, commit []byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	var p blob.CommitmentProof
	if err := p.UnmarshalJSON(raw); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	return p.Verify(dataRoot, commit)
}

// decodeSignedHeader reads the header of a protobuf SignedHeader. The commit
// is not checked: v0 trusts headers through the hash chain.
func decodeSignedHeader(b []byte) (core.Header, error) {
	var sh cmtproto.SignedHeader
	if err := sh.Unmarshal(b); err != nil {
		return core.Header{}, err
	}
	if sh.Header == nil {
		return core.Header{}, errors.New("signed header has no header")
	}
	return core.HeaderFromProto(sh.Header)
}

type fibreAnchor struct{}

// Fibre verifies da = 1 evidence offline: the form-1 anchor proof (DAH and
// namespace data) against the data hash of the archived header, the archived
// PayForFibre tx among the reassembled txs, and the validator certificate
// against the archived validator list and promise header. Records written
// before the form-1 proof are unchecked, not valid.
func Fibre() verifier.AnchorVerifier { return fibreAnchor{} }

func (fibreAnchor) VerifyAnchor(ref commitment.PayloadRef, ev *archive.EvidenceRecord) (facts verifier.AnchorFacts, err error) {
	if ref.DA != commitment.DAFibre {
		return verifier.AnchorFacts{}, fmt.Errorf("%w: da %d", verifier.ErrAnchorUnsupported, ref.DA)
	}
	// The evidence is attacker-supplied archive data, and the decoders of the
	// upstream libraries are as exposed as their verifiers.
	defer func() {
		if r := recover(); r != nil {
			facts, err = verifier.AnchorFacts{}, fmt.Errorf("panic: %v", r)
		}
	}()
	switch {
	case len(ref.Commitment) != 32:
		return verifier.AnchorFacts{}, fmt.Errorf("commitment is %d bytes", len(ref.Commitment))
	case len(ev.SystemBlobProof) == 0:
		return verifier.AnchorFacts{}, errors.New("evidence has no anchor proof")
	case ev.SystemBlobProof[0] != 0xa3:
		return verifier.AnchorFacts{}, errors.New("the anchor proof is not the deterministic CBOR map of the namespace data form")
	}
	hd, err := decodeSignedHeader(ev.Header)
	if err != nil {
		return verifier.AnchorFacts{}, fmt.Errorf("header: %w", err)
	}
	if uint64(hd.Height) != ref.Height {
		return verifier.AnchorFacts{}, fmt.Errorf("header is for height %d, the reference names %d", hd.Height, ref.Height)
	}
	if len(hd.DataHash) == 0 {
		return verifier.AnchorFacts{}, errors.New("header has no data root")
	}
	hash := hd.Hash()
	if len(hash) != 32 {
		return verifier.AnchorFacts{}, errors.New("header has no hash")
	}
	if hd.Time.Unix() < 0 {
		return verifier.AnchorFacts{}, fmt.Errorf("header time %s is before 1970", hd.Time.UTC().Format(time.RFC3339))
	}

	txs, err := verifyBlockProof(ev.SystemBlobProof, hd.DataHash)
	if err != nil {
		return verifier.AnchorFacts{}, fmt.Errorf("anchor proof at height %d: %w", ref.Height, err)
	}
	if len(ev.AnchorTx) == 0 {
		return verifier.AnchorFacts{}, errors.New("evidence has no anchor tx")
	}
	if ev.TxCode != 0 {
		return verifier.AnchorFacts{}, fmt.Errorf("the anchor tx has result code %d", ev.TxCode)
	}
	if err := checkSystemBlob(ev); err != nil {
		return verifier.AnchorFacts{}, err
	}

	b := fibrecert.Binding{ChainID: hd.ChainID, Namespace: ref.Namespace, Commitment: [32]byte(ref.Commitment)}
	earlier, err := candidatesEarlier(txs, ev.AnchorTx, b)
	if err != nil {
		return verifier.AnchorFacts{}, err
	}

	pff, ok, err := fibrecert.ParsePFF(ev.AnchorTx)
	if err != nil || !ok {
		return verifier.AnchorFacts{}, fmt.Errorf("anchor tx: %w", errors.Join(err, errNotFibre(ok)))
	}
	if ev.PromiseHeight != pff.Promise.Height {
		return verifier.AnchorFacts{}, fmt.Errorf("evidence promise height %d, the promise names %d", ev.PromiseHeight, pff.Promise.Height)
	}
	if ev.PromiseHeight > ref.Height {
		return verifier.AnchorFacts{}, fmt.Errorf("promise height %d is above the anchor height %d", ev.PromiseHeight, ref.Height)
	}
	promiseHeader, ph, err := decodePromiseHeader(ev.PromiseHeader)
	if err != nil {
		return verifier.AnchorFacts{}, err
	}
	if ev.PromiseHeight == ref.Height && !bytes.Equal(ph, hash) {
		return verifier.AnchorFacts{}, fmt.Errorf("the promise header and the anchor header at height %d differ", ref.Height)
	}
	b.BlobSize = pff.Promise.BlobSize
	rep, matched, err := fibrecert.Verify(ev.AnchorTx, b, ev.HistoricalInfo, fibrecert.ValsetEvidence{PromiseHeader: promiseHeader})
	if err != nil {
		return verifier.AnchorFacts{}, fmt.Errorf("certificate: %w", err)
	}
	vals, err := fibrecert.ParseHistoricalInfo(ev.HistoricalInfo)
	if err != nil {
		return verifier.AnchorFacts{}, fmt.Errorf("certificate: %w", err)
	}
	robust, err := fibrecert.TokensRobust(pff, vals)
	if err != nil {
		return verifier.AnchorFacts{}, fmt.Errorf("certificate: %w", err)
	}
	precision := "bucket-dependent"
	if robust {
		precision = "robust"
	}
	start := pff.Promise.CreationTime.Unix()
	if start <= 0 {
		return verifier.AnchorFacts{}, fmt.Errorf("promise creation time %s is not after 1970", pff.Promise.CreationTime.UTC().Format(time.RFC3339))
	}
	ts := uint64(hd.Time.Unix())
	return verifier.AnchorFacts{
		BlockTime:          ts,
		RetentionStart:     uint64(start),
		AnchorHeaderHash:   hash,
		PromiseHeaderHash:  ph,
		PromiseHeight:      ev.PromiseHeight,
		PromiseBlobSize:    uint64(pff.Promise.BlobSize),
		CertSignedPower:    rep.SignedPower,
		CertTotalPower:     rep.TotalPower,
		CertTokenPrecision: precision,
		CertValsetHeader:   matched,
		Settlement:         "node-attested",
		ProofForm:          1,
		CandidatesEarlier:  len(earlier),
		EarlierCreations:   earlier,
	}, nil
}

func errNotFibre(ok bool) error {
	if ok {
		return nil
	}
	return errors.New("not a Fibre tx")
}

// verifyBlockProof checks the form-1 proof against the data hash of the
// archived header and returns the txs of the PayForFibre namespace.
func verifyBlockProof(raw, dataHash []byte) ([][]byte, error) {
	dahProto, stream, err := fibreproof.DecodeProof(raw)
	if err != nil {
		return nil, err
	}
	var dp daproto.DataAvailabilityHeader
	if err := dp.Unmarshal(dahProto); err != nil {
		return nil, fmt.Errorf("dah: %w", err)
	}
	dah := &da.DataAvailabilityHeader{RowRoots: dp.RowRoots, ColumnRoots: dp.ColumnRoots}
	if err := fibreproof.CheckDAH(dah, dataHash); err != nil {
		return nil, fmt.Errorf("dah: %w", err)
	}
	txs, err := fibreproof.VerifyNamespaceData(dah, stream)
	if err != nil {
		return nil, fmt.Errorf("namespace data: %w", err)
	}
	return txs, nil
}

// candidatesEarlier requires the archived tx to be a candidate among txs and
// returns the promise creation times of the candidates created earlier.
func candidatesEarlier(txs [][]byte, anchor []byte, b fibrecert.Binding) ([]uint64, error) {
	var (
		found     bool
		anchorAt  time.Time
		creations []time.Time
	)
	for _, raw := range txs {
		pff, ok, err := fibrecert.ParsePFF(raw)
		if !ok || err != nil {
			continue
		}
		cb := b
		cb.BlobSize = pff.Promise.BlobSize
		if fibrecert.CheckBinding(pff.Promise, cb) != nil {
			continue
		}
		creations = append(creations, pff.Promise.CreationTime)
		if !found && bytes.Equal(raw, anchor) {
			found, anchorAt = true, pff.Promise.CreationTime
		}
	}
	if !found {
		return nil, errors.New("the anchor tx is not a candidate among the PayForFibre txs of the block")
	}
	var earlier []uint64
	for _, t := range creations {
		if t.Before(anchorAt) && t.Unix() > 0 {
			earlier = append(earlier, uint64(t.Unix()))
		}
	}
	return earlier, nil
}

// checkSystemBlob requires the archived system blob to be the one the
// archived tx stands for in the square.
func checkSystemBlob(ev *archive.EvidenceRecord) error {
	ftx, ok, err := fibretypes.TryParseFibreTx(ev.AnchorTx)
	if err != nil || !ok {
		return fmt.Errorf("anchor tx: %w", errors.Join(err, errNotFibre(ok)))
	}
	want, err := ftx.SystemBlob.Marshal()
	if err != nil {
		return fmt.Errorf("system blob: %w", err)
	}
	if !bytes.Equal(want, ev.SystemBlob) {
		return errors.New("the archived system blob is not the one of the anchor tx")
	}
	return nil
}

// decodePromiseHeader reads the protobuf SignedHeader the archive keeps for
// the promise height. It returns the inner header, marshalled for the
// certificate check, and its hash.
func decodePromiseHeader(raw []byte) ([]byte, []byte, error) {
	var sh cmtproto.SignedHeader
	if err := sh.Unmarshal(raw); err != nil {
		return nil, nil, fmt.Errorf("promise header: %w", err)
	}
	if sh.Header == nil {
		return nil, nil, errors.New("promise header: signed header has no header")
	}
	ch, err := core.HeaderFromProto(sh.Header)
	if err != nil {
		return nil, nil, fmt.Errorf("promise header: %w", err)
	}
	hash := ch.Hash()
	if len(hash) != 32 {
		return nil, nil, errors.New("promise header has no hash")
	}
	inner, err := sh.Header.Marshal()
	if err != nil {
		return nil, nil, fmt.Errorf("promise header: %w", err)
	}
	return inner, hash, nil
}
