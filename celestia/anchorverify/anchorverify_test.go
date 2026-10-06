package anchorverify_test

import (
	"testing"
	"time"

	"github.com/celestiaorg/celestia-app/v10/pkg/da"
	"github.com/celestiaorg/celestia-node/blob"
	libshare "github.com/celestiaorg/go-square/v4/share"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmtversion "github.com/cometbft/cometbft/proto/tendermint/version"
	core "github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/celestia/anchorverify"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/test/gatefix"
	"github.com/vgonkivs/edicta/verifier"
)

const height = uint64(4200000)

var blockTime = time.Unix(1790999950, 0).UTC()

type fixture struct {
	ref      commitment.PayloadRef
	ev       *archive.EvidenceRecord
	proof    *blob.CommitmentProof
	header   core.Header
	dataRoot []byte
}

// newFixture builds a 2x2 square holding the vector blob as a share-version-1
// blob, a header whose data hash is the square's data root, and the node's
// commitment proof for the blob.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	c := gatefix.Template(t)
	ns, err := libshare.NewNamespaceFromBytes(c.PayloadRef.Namespace)
	require.NoError(t, err)
	b, err := libshare.NewV1Blob(ns, gatefix.Blob(t), c.PayloadRef.Signer)
	require.NoError(t, err)
	shares, err := b.ToShares()
	require.NoError(t, err)
	ods := append(append([]libshare.Share{}, shares...), libshare.TailPaddingShares(4-len(shares))...)
	raw := make([][]byte, len(ods))
	for i, s := range ods {
		raw[i] = s.ToBytes()
	}
	eds, err := da.ExtendShares(raw)
	require.NoError(t, err)
	dah, err := da.NewDataAvailabilityHeader(eds)
	require.NoError(t, err)
	proof, err := blob.ProveCommitment(eds, ns, shares)
	require.NoError(t, err)

	f := &fixture{
		ref:      c.PayloadRef,
		proof:    proof,
		dataRoot: dah.Hash(),
	}
	f.header = core.Header{
		Version: cmtversion.Consensus{Block: 11, App: 6}, ChainID: "test-1", Height: int64(height),
		Time:           blockTime,
		DataHash:       f.dataRoot,
		ValidatorsHash: make([]byte, 32), NextValidatorsHash: make([]byte, 32),
		ProposerAddress: make([]byte, 20),
	}
	f.ev = &archive.EvidenceRecord{
		DA: commitment.DACelestiaBlob, Commitment: c.PayloadRef.Commitment, Namespace: c.PayloadRef.Namespace,
		Height: height, Header: signedHeader(t, f.header), BlobProof: proofJSON(t, proof),
	}
	return f
}

func signedHeader(t *testing.T, h core.Header) []byte {
	t.Helper()
	hp := h.ToProto()
	b, err := (&cmtproto.SignedHeader{Header: hp, Commit: &cmtproto.Commit{}}).Marshal()
	require.NoError(t, err)
	return b
}

func proofJSON(t *testing.T, p *blob.CommitmentProof) []byte {
	t.Helper()
	b, err := p.MarshalJSON()
	require.NoError(t, err)
	return b
}

func TestBlobAcceptsARealCommitmentProof(t *testing.T) {
	f := newFixture(t)
	facts, err := anchorverify.Blob().VerifyAnchor(f.ref, f.ev)
	require.NoError(t, err)
	assert.Equal(t, uint64(blockTime.Unix()), facts.BlockTime)
	assert.Equal(t, uint64(blockTime.Unix()), facts.RetentionStart)
	assert.Equal(t, f.header.Hash().Bytes(), facts.HeaderHashes[height])
	assert.Empty(t, facts.Settlement)
}

func TestBlobRefusals(t *testing.T) {
	tests := []struct {
		name string
		mod  func(t *testing.T, f *fixture)
	}{
		{"wrong height in the reference", func(t *testing.T, f *fixture) { f.ref.Height++ }},
		{"header of another height", func(t *testing.T, f *fixture) {
			f.header.Height++
			f.ev.Header = signedHeader(t, f.header)
		}},
		{"proof is for another data root", func(t *testing.T, f *fixture) {
			f.header.DataHash = append([]byte(nil), f.header.DataHash...)
			f.header.DataHash[0] ^= 1
			f.ev.Header = signedHeader(t, f.header)
		}},
		{"header without a data root", func(t *testing.T, f *fixture) {
			f.header.DataHash = nil
			f.ev.Header = signedHeader(t, f.header)
		}},
		{"commitment of the reference differs", func(t *testing.T, f *fixture) {
			f.ref.Commitment = append([]byte(nil), f.ref.Commitment...)
			f.ref.Commitment[0] ^= 1
		}},
		{"tampered subtree root", func(t *testing.T, f *fixture) {
			f.proof.SubtreeRoots[0][len(f.proof.SubtreeRoots[0])-1] ^= 1
			f.ev.BlobProof = proofJSON(t, f.proof)
		}},
		{"tampered row root", func(t *testing.T, f *fixture) {
			f.proof.RowProof.RowRoots[0][0] ^= 1
			f.ev.BlobProof = proofJSON(t, f.proof)
		}},
		{"proof bytes cut", func(t *testing.T, f *fixture) { f.ev.BlobProof = f.ev.BlobProof[:len(f.ev.BlobProof)/2] }},
		{"proof is not JSON", func(t *testing.T, f *fixture) { f.ev.BlobProof = []byte("not json") }},
		{"proof absent", func(t *testing.T, f *fixture) { f.ev.BlobProof = nil }},
		{"empty proof object", func(t *testing.T, f *fixture) { f.ev.BlobProof = []byte("{}") }},
		{"header is not a signed header", func(t *testing.T, f *fixture) { f.ev.Header = []byte{0xff, 0xff} }},
		{"signed header without a header", func(t *testing.T, f *fixture) {
			b, err := (&cmtproto.SignedHeader{}).Marshal()
			require.NoError(t, err)
			f.ev.Header = b
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			tc.mod(t, f)
			facts, err := anchorverify.Blob().VerifyAnchor(f.ref, f.ev)
			require.Error(t, err)
			assert.Empty(t, facts.HeaderHashes)
		})
	}
}

func TestBlobRefusesOtherDA(t *testing.T) {
	f := newFixture(t)
	f.ref.DA = commitment.DAFibre
	_, err := anchorverify.Blob().VerifyAnchor(f.ref, f.ev)
	require.ErrorIs(t, err, verifier.ErrAnchorUnsupported)
}

// A nil entry in the proof makes the upstream verifier dereference nil; the
// proof comes from the archive, so the panic must become an error.
func TestBlobPanicGuard(t *testing.T) {
	tests := []struct {
		name string
		mod  func(p *blob.CommitmentProof)
	}{
		{"nil subtree root proof", func(p *blob.CommitmentProof) { p.SubtreeRootProofs[0] = nil }},
		{"nil row proof", func(p *blob.CommitmentProof) { p.RowProof.Proofs[0] = nil }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			tc.mod(f.proof)
			f.ev.BlobProof = proofJSON(t, f.proof)
			require.NotPanics(t, func() {
				_, err := anchorverify.Blob().VerifyAnchor(f.ref, f.ev)
				require.Error(t, err)
			})
		})
	}
}

func TestFibreSlotRefuses(t *testing.T) {
	_, err := anchorverify.Fibre().VerifyAnchor(commitment.PayloadRef{DA: commitment.DAFibre}, &archive.EvidenceRecord{})
	require.ErrorIs(t, err, verifier.ErrAnchorUnsupported)
}
