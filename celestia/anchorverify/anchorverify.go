// Package anchorverify checks archived anchor evidence offline: the header
// and the proof that the blob was in that block. Whether the header belongs
// to the chain is header trust's question, not this package's.
package anchorverify

import (
	"errors"
	"fmt"
	"time"

	"github.com/celestiaorg/celestia-node/blob"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	core "github.com/cometbft/cometbft/types"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/verifier"
)

type blobAnchor struct{}

// Blob verifies da = 2 evidence: the commitment proof of the share-version-1
// blob against the data root of the archived header.
func Blob() verifier.AnchorVerifier { return blobAnchor{} }

func (blobAnchor) VerifyAnchor(ref commitment.PayloadRef, ev *archive.EvidenceRecord) (verifier.AnchorFacts, error) {
	if ref.DA != commitment.DACelestiaBlob {
		return verifier.AnchorFacts{}, fmt.Errorf("%w: da %d", verifier.ErrAnchorUnsupported, ref.DA)
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
		BlockTime:      ts,
		RetentionStart: ts,
		HeaderHashes:   map[uint64][]byte{ref.Height: hash},
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

// Fibre is the da = 1 anchor verifier slot. It refuses every record until
// the form-1 anchor proof exists.
func Fibre() verifier.AnchorVerifier { return fibreAnchor{} }

func (fibreAnchor) VerifyAnchor(commitment.PayloadRef, *archive.EvidenceRecord) (verifier.AnchorFacts, error) {
	return verifier.AnchorFacts{}, fmt.Errorf("%w: the da = 1 anchor proof is not implemented", verifier.ErrAnchorUnsupported)
}
