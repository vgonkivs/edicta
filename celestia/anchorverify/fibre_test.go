package anchorverify_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	fibretypes "github.com/celestiaorg/celestia-app/v10/x/fibre/types"
	libshare "github.com/celestiaorg/go-square/v4/share"
	cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	core "github.com/cometbft/cometbft/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/archive/fsarchive"
	"github.com/vgonkivs/edicta/celestia/anchorverify"
	"github.com/vgonkivs/edicta/celestia/fibrecert"
	"github.com/vgonkivs/edicta/celestia/fibreproof"
	"github.com/vgonkivs/edicta/celestia/test/fibrefix"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/test/gatefix"
	"github.com/vgonkivs/edicta/verifier"
)

func verifyFibre(l *fibrefix.Live, ev *archive.EvidenceRecord) (verifier.AnchorFacts, error) {
	return anchorverify.Fibre().VerifyAnchor(l.Ref, ev)
}

func TestFibreSlotRefuses(t *testing.T) {
	_, err := anchorverify.Fibre().VerifyAnchor(commitment.PayloadRef{DA: commitment.DAFibre}, &archive.EvidenceRecord{})
	require.Error(t, err)
	require.NotErrorIs(t, err, verifier.ErrAnchorUnsupported, "empty evidence is a failure, not an unchecked anchor")
	assert.ErrorContains(t, err, "commitment")
}

func TestFibreRefusesOtherDA(t *testing.T) {
	l := fibrefix.LoadLive(t)
	ref := l.Ref
	ref.DA = commitment.DACelestiaBlob
	_, err := anchorverify.Fibre().VerifyAnchor(ref, l.Evidence(t))
	require.ErrorIs(t, err, verifier.ErrAnchorUnsupported)
}

func TestFibreLiveEvidenceVerifies(t *testing.T) {
	l := fibrefix.LoadLive(t)
	facts, err := verifyFibre(l, l.Evidence(t))
	require.NoError(t, err)

	assert.Equal(t, "node-attested", facts.Settlement)
	assert.Equal(t, 1, facts.ProofForm)
	assert.Equal(t, 0, facts.CandidatesEarlier)
	assert.Equal(t, "robust", facts.CertTokenPrecision)
	assert.Equal(t, uint64(l.Header.Time.Unix()), facts.BlockTime)
	assert.Equal(t, uint64(l.Created.Unix()), facts.RetentionStart, "floor of the promise creation time")
	assert.Equal(t, uint64(1791196769), facts.RetentionStart)
	assert.Equal(t, l.HeaderHashes[l.Height], facts.HeaderHashes[l.Height])
	assert.Equal(t, l.HeaderHashes[l.PromiseHeight], facts.HeaderHashes[l.PromiseHeight])
	assert.Equal(t, int64(282969545202534), facts.CertSignedPower)
	assert.Equal(t, int64(371550350184936), facts.CertTotalPower)
	assert.Equal(t, "next_validators_hash@1402813", facts.CertValsetHeader)
}

func TestFibreForm0ProofIsUnchecked(t *testing.T) {
	l := fibrefix.LoadLive(t)
	for name, proof := range map[string][]byte{
		"json object": []byte(`{"row_proof":{}}`),
		"bare brace":  []byte(`{`),
	} {
		t.Run(name, func(t *testing.T) {
			ev := l.Evidence(t)
			ev.SystemBlobProof = proof
			facts, err := verifyFibre(l, ev)
			require.ErrorIs(t, err, verifier.ErrAnchorUnsupported)
			assert.ErrorContains(t, err, "form-0")
			assert.Empty(t, facts.Settlement)
			assert.Empty(t, facts.HeaderHashes)
		})
	}
}

func TestFibreProofRefusals(t *testing.T) {
	l := fibrefix.LoadLive(t)
	form1 := l.Proof
	tests := []struct {
		name  string
		proof []byte
	}{
		{"absent", nil},
		{"empty", []byte{}},
		{"unknown first byte", []byte{0x00, 0x01}},
		{"cbor of another shape", []byte{0xa2, 0x01, 0x01, 0x02, 0x40}},
		{"trailing byte", append(bytes.Clone(form1), 0)},
		{"cut", form1[:len(form1)-1]},
		{"half", form1[:len(form1)/2]},
		{"head only", form1[:4]},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := l.Evidence(t)
			ev.SystemBlobProof = tc.proof
			facts, err := verifyFibre(l, ev)
			require.Error(t, err)
			require.NotErrorIs(t, err, verifier.ErrAnchorUnsupported)
			assert.Empty(t, facts.HeaderHashes)
			assert.Empty(t, facts.Settlement)
		})
	}
}

// A form-1 proof of the vector block whose parts are tampered one at a time.
func TestFibreBlockProofTampering(t *testing.T) {
	l := fibrefix.LoadLive(t)
	blk := fibrefix.VectorBlock(t, l.Case)
	tests := []struct {
		name string
		mod  func(t *testing.T, ev *archive.EvidenceRecord)
		want string
	}{
		{"dah row root", func(t *testing.T, ev *archive.EvidenceRecord) {
			b := blk.Clone()
			b.Rows[0][70] ^= 1
			ev.SystemBlobProof = fibreproof.EncodeProof(b.DAHProto(t), blk.Stream(t))
		}, "dah"},
		{"dah column root", func(t *testing.T, ev *archive.EvidenceRecord) {
			b := blk.Clone()
			b.Cols[0][70] ^= 1
			ev.SystemBlobProof = fibreproof.EncodeProof(b.DAHProto(t), blk.Stream(t))
		}, "dah"},
		{"dah of another block", func(t *testing.T, ev *archive.EvidenceRecord) {
			other := fibrefix.VectorBlock(t, fibrefix.LoadAnchorVector(t).Live.Cases[1])
			ev.SystemBlobProof = fibreproof.EncodeProof(other.DAHProto(t), blk.Stream(t))
		}, "dah"},
		{"dah is not a protobuf", func(t *testing.T, ev *archive.EvidenceRecord) {
			ev.SystemBlobProof = fibreproof.EncodeProof([]byte{0xff, 0xff, 0xff}, blk.Stream(t))
		}, "dah"},
		{"namespace data share", func(t *testing.T, ev *archive.EvidenceRecord) {
			b := blk.Clone()
			s, err := libshare.NewShare(append(append([]byte{}, b.ND[0].Shares[0].ToBytes()[:100]...), append([]byte{b.ND[0].Shares[0].ToBytes()[100] ^ 1}, b.ND[0].Shares[0].ToBytes()[101:]...)...))
			require.NoError(t, err)
			b.ND[0].Shares[0] = s
			ev.SystemBlobProof = fibreproof.EncodeProof(blk.DAHProto(t), b.Stream(t))
		}, "namespace data"},
		{"namespace data stream cut", func(t *testing.T, ev *archive.EvidenceRecord) {
			s := blk.Stream(t)
			ev.SystemBlobProof = fibreproof.EncodeProof(blk.DAHProto(t), s[:len(s)-1])
		}, "namespace data"},
		{"namespace data empty", func(t *testing.T, ev *archive.EvidenceRecord) {
			ev.SystemBlobProof = fibreproof.EncodeProof(blk.DAHProto(t), nil)
		}, "namespace data"},
		{"namespace data of another block", func(t *testing.T, ev *archive.EvidenceRecord) {
			other := fibrefix.VectorBlock(t, fibrefix.LoadAnchorVector(t).Live.Cases[1])
			ev.SystemBlobProof = fibreproof.EncodeProof(blk.DAHProto(t), other.Stream(t))
		}, "namespace data"},
		{"header data hash", func(t *testing.T, ev *archive.EvidenceRecord) {
			h := l.Header
			h.DataHash = bytes.Clone(h.DataHash)
			h.DataHash[0] ^= 1
			ev.Header = fibrefix.SignedHeader(t, h)
		}, "dah"},
		{"header without data hash", func(t *testing.T, ev *archive.EvidenceRecord) {
			h := l.Header
			h.DataHash = nil
			ev.Header = fibrefix.SignedHeader(t, h)
		}, "data root"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := l.Evidence(t)
			tc.mod(t, ev)
			facts, err := verifyFibre(l, ev)
			require.Error(t, err)
			assert.ErrorContains(t, err, tc.want)
			assert.Empty(t, facts.HeaderHashes)
		})
	}
}

func TestFibreEvidenceRefusals(t *testing.T) {
	l := fibrefix.LoadLive(t)
	tests := []struct {
		name string
		mod  func(t *testing.T, ref *commitment.PayloadRef, ev *archive.EvidenceRecord)
		want string
		is   error
	}{
		{"no anchor tx", func(_ *testing.T, _ *commitment.PayloadRef, ev *archive.EvidenceRecord) { ev.AnchorTx = nil }, "anchor tx", nil},
		{"tx code is not zero", func(_ *testing.T, _ *commitment.PayloadRef, ev *archive.EvidenceRecord) { ev.TxCode = 11 }, "result code 11", nil},
		{"system blob byte flipped", func(_ *testing.T, _ *commitment.PayloadRef, ev *archive.EvidenceRecord) {
			ev.SystemBlob[len(ev.SystemBlob)-1] ^= 1
		}, "system blob", nil},
		{"system blob absent", func(_ *testing.T, _ *commitment.PayloadRef, ev *archive.EvidenceRecord) { ev.SystemBlob = nil }, "system blob", nil},
		{"system blob of another tx", func(t *testing.T, _ *commitment.PayloadRef, ev *archive.EvidenceRecord) {
			other := fibrefix.MutateTx(t, l.PFFTx, func(m *fibretypes.MsgPayForFibre) { m.PaymentPromise.Commitment = bytes.Repeat([]byte{4}, 32) })
			ev.SystemBlob = fibrefix.SystemBlobOf(t, other)
		}, "system blob", nil},
		{"anchor tx is not a tx", func(_ *testing.T, _ *commitment.PayloadRef, ev *archive.EvidenceRecord) {
			ev.AnchorTx = []byte{1, 2, 3}
		}, "anchor tx", nil},
		{"promise height off by one", func(_ *testing.T, _ *commitment.PayloadRef, ev *archive.EvidenceRecord) { ev.PromiseHeight++ }, "promise height", nil},
		{"promise height zero", func(_ *testing.T, _ *commitment.PayloadRef, ev *archive.EvidenceRecord) { ev.PromiseHeight = 0 }, "promise height", nil},
		{"header at another height", func(t *testing.T, _ *commitment.PayloadRef, ev *archive.EvidenceRecord) {
			h := l.Header
			h.Height++
			ev.Header = fibrefix.SignedHeader(t, h)
		}, "header is for height", nil},
		{"reference at another height", func(_ *testing.T, ref *commitment.PayloadRef, _ *archive.EvidenceRecord) { ref.Height++ }, "header is for height", nil},
		{"header is not a signed header", func(_ *testing.T, _ *commitment.PayloadRef, ev *archive.EvidenceRecord) {
			ev.Header = []byte{0xff, 0xff}
		}, "header", nil},
		{"header time before the epoch", func(t *testing.T, _ *commitment.PayloadRef, ev *archive.EvidenceRecord) {
			h := l.Header
			h.Time = time.Unix(-5, 0).UTC()
			ev.Header = fibrefix.SignedHeader(t, h)
		}, "before 1970", nil},
		{"commitment of the reference", func(_ *testing.T, ref *commitment.PayloadRef, _ *archive.EvidenceRecord) {
			ref.Commitment = bytes.Clone(ref.Commitment)
			ref.Commitment[0] ^= 1
		}, "not a candidate", nil},
		{"commitment of the wrong length", func(_ *testing.T, ref *commitment.PayloadRef, _ *archive.EvidenceRecord) {
			ref.Commitment = ref.Commitment[:31]
		}, "commitment is 31 bytes", nil},
		{"namespace of the reference", func(_ *testing.T, ref *commitment.PayloadRef, _ *archive.EvidenceRecord) {
			ref.Namespace = bytes.Clone(ref.Namespace)
			ref.Namespace[len(ref.Namespace)-1] ^= 1
		}, "", nil},
		{"chain of the header", func(t *testing.T, _ *commitment.PayloadRef, ev *archive.EvidenceRecord) {
			h := l.Header
			h.ChainID = "mocha-4"
			ev.Header = fibrefix.SignedHeader(t, h)
		}, "", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ref, ev := l.Ref, l.Evidence(t)
			ref.Commitment, ref.Namespace = bytes.Clone(ref.Commitment), bytes.Clone(ref.Namespace)
			tc.mod(t, &ref, ev)
			facts, err := anchorverify.Fibre().VerifyAnchor(ref, ev)
			require.Error(t, err)
			require.NotErrorIs(t, err, verifier.ErrAnchorUnsupported)
			if tc.want != "" {
				assert.ErrorContains(t, err, tc.want)
			}
			if tc.is != nil {
				require.ErrorIs(t, err, tc.is)
			}
			assert.Empty(t, facts.HeaderHashes)
			assert.Empty(t, facts.Settlement)
		})
	}
}

// withBlock puts the txs in a synthetic block with real proofs and returns
// the live evidence pointed at that block and the given anchor tx.
func withBlock(t *testing.T, l *fibrefix.Live, anchor []byte, txs ...[]byte) *archive.EvidenceRecord {
	t.Helper()
	return l.EvidenceFor(t, fibrefix.BuildBlock(t, txs...), anchor)
}

func setCreated(t *testing.T, tx []byte, at time.Time) []byte {
	t.Helper()
	return fibrefix.MutateTx(t, tx, func(m *fibretypes.MsgPayForFibre) { m.PaymentPromise.CreationTimestamp = at })
}

func TestFibreAnchorMustBeACandidate(t *testing.T) {
	l := fibrefix.LoadLive(t)
	other := fibrefix.MutateTx(t, l.PFFTx, func(m *fibretypes.MsgPayForFibre) { m.Signer = "celestia1other" })
	noPromiseMatch := fibrefix.MutateTx(t, l.PFFTx, func(m *fibretypes.MsgPayForFibre) { m.PaymentPromise.Commitment = bytes.Repeat([]byte{9}, 32) })

	t.Run("block holds the anchor tx", func(t *testing.T) {
		facts, err := verifyFibre(l, withBlock(t, l, l.PFFTx, l.PFFTx))
		require.NoError(t, err)
		assert.Equal(t, 0, facts.CandidatesEarlier)
	})
	t.Run("block holds another tx with the same promise", func(t *testing.T) {
		_, err := verifyFibre(l, withBlock(t, l, l.PFFTx, other))
		require.ErrorContains(t, err, "not a candidate")
	})
	t.Run("block holds txs of other promises only", func(t *testing.T) {
		_, err := verifyFibre(l, withBlock(t, l, l.PFFTx, noPromiseMatch))
		require.ErrorContains(t, err, "not a candidate")
	})
	t.Run("block has no PayForFibre txs", func(t *testing.T) {
		_, err := verifyFibre(l, withBlock(t, l, l.PFFTx))
		require.ErrorContains(t, err, "not a candidate")
	})
	t.Run("the anchor tx is bytes the block does not hold", func(t *testing.T) {
		ev := withBlock(t, l, l.PFFTx, l.PFFTx)
		ev.AnchorTx = append(bytes.Clone(l.PFFTx), 0)
		_, err := verifyFibre(l, ev)
		require.Error(t, err)
	})
}

func TestFibreCandidatesEarlier(t *testing.T) {
	l := fibrefix.LoadLive(t)
	at := func(d time.Duration) []byte { return setCreated(t, l.PFFTx, l.Created.Add(d)) }
	earlier1, earlier2, later := at(-time.Second), at(-time.Minute), at(time.Second)
	same := fibrefix.MutateTx(t, l.PFFTx, func(m *fibretypes.MsgPayForFibre) { m.Signer = "celestia1other" })

	tests := []struct {
		name string
		txs  [][]byte
		want int
	}{
		{"alone", [][]byte{l.PFFTx}, 0},
		{"one earlier", [][]byte{earlier1, l.PFFTx}, 1},
		{"two earlier, listed after the anchor", [][]byte{l.PFFTx, earlier1, earlier2}, 2},
		{"only later ones", [][]byte{l.PFFTx, later}, 0},
		{"mixed", [][]byte{earlier1, later, l.PFFTx, earlier2}, 2},
		{"same timestamp is not earlier", [][]byte{same, l.PFFTx}, 0},
		{"earlier by a sub-second", [][]byte{at(-time.Nanosecond), l.PFFTx}, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			facts, err := verifyFibre(l, withBlock(t, l, l.PFFTx, tc.txs...))
			require.NoError(t, err)
			assert.Equal(t, tc.want, facts.CandidatesEarlier)
			assert.Equal(t, uint64(l.Created.Unix()), facts.RetentionStart, "the start is the anchor's, not the earliest")
		})
	}
}

func TestFibreCandidatesOfOtherBindingsDoNotCount(t *testing.T) {
	l := fibrefix.LoadLive(t)
	earlier := func(mod func(*fibretypes.MsgPayForFibre)) []byte {
		return fibrefix.MutateTx(t, l.PFFTx, func(m *fibretypes.MsgPayForFibre) {
			m.PaymentPromise.CreationTimestamp = l.Created.Add(-time.Hour)
			mod(m)
		})
	}
	for name, tx := range map[string][]byte{
		"other commitment": earlier(func(m *fibretypes.MsgPayForFibre) { m.PaymentPromise.Commitment = bytes.Repeat([]byte{3}, 32) }),
		"other chain":      earlier(func(m *fibretypes.MsgPayForFibre) { m.PaymentPromise.ChainId = "mocha-4" }),
		"other namespace":  earlier(func(m *fibretypes.MsgPayForFibre) { m.PaymentPromise.Namespace = bytes.Repeat([]byte{3}, 29) }),
	} {
		t.Run(name, func(t *testing.T) {
			facts, err := verifyFibre(l, withBlock(t, l, l.PFFTx, tx, l.PFFTx))
			require.NoError(t, err)
			assert.Equal(t, 0, facts.CandidatesEarlier)
		})
	}
	t.Run("a non-Fibre tx in the namespace is skipped", func(t *testing.T) {
		facts, err := verifyFibre(l, withBlock(t, l, l.PFFTx, []byte("not a tx"), l.PFFTx))
		require.NoError(t, err)
		assert.Equal(t, 0, facts.CandidatesEarlier)
	})
}

func TestFibreReassemblyAttacksInASignedBlock(t *testing.T) {
	l := fibrefix.LoadLive(t)
	filler := bytes.Repeat([]byte{5}, 900)
	good := fibrefix.SplitTxs(t, filler, l.PFFTx)
	require.GreaterOrEqual(t, len(good), 4)
	tests := []struct {
		name   string
		shares []libshare.Share
		ok     bool
	}{
		{"complete", good, true},
		{"cut", good[:len(good)-1], false},
		{"padded", append(append([]libshare.Share{}, good...), good[len(good)-1]), false},
		{"reordered", append([]libshare.Share{good[1], good[0]}, good[2:]...), false},
		{"first share dropped", good[1:], false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			blk := fibrefix.BuildBlockFromShares(t, tc.shares)
			facts, err := verifyFibre(l, l.EvidenceFor(t, blk, l.PFFTx))
			if tc.ok {
				require.NoError(t, err)
				assert.Equal(t, 1, facts.ProofForm)
				return
			}
			require.Error(t, err)
			assert.ErrorContains(t, err, "namespace data")
			assert.Empty(t, facts.HeaderHashes)
		})
	}
}

func TestFibreCertificateFailures(t *testing.T) {
	l := fibrefix.LoadLive(t)
	pff, ok, err := fibrecert.ParsePFF(l.PFFTx)
	require.NoError(t, err)
	require.True(t, ok)
	sigs := pff.Signatures

	tests := []struct {
		name string
		sigs func() [][]byte
		is   error
	}{
		{"below the threshold", func() [][]byte {
			out := make([][]byte, len(sigs))
			for i := 1; i < 40; i++ {
				out[i] = sigs[i]
			}
			return out
		}, fibrecert.ErrCertificateInsufficient},
		{"no signatures", func() [][]byte { return nil }, fibrecert.ErrCertificateInsufficient},
		{"bad signature before the stop point", func() [][]byte {
			out := append([][]byte(nil), sigs...)
			out[1] = bytes.Clone(out[1])
			out[1][0] ^= 1
			return out
		}, fibrecert.ErrCertificateInvalid},
		{"more signatures than validators", func() [][]byte {
			return append(append([][]byte(nil), sigs...), bytes.Repeat([]byte{1}, 64))
		}, fibrecert.ErrCertificateMalformed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tx := fibrefix.MutateTx(t, l.PFFTx, func(m *fibretypes.MsgPayForFibre) { m.ValidatorSignatures = tc.sigs() })
			facts, err := verifyFibre(l, withBlock(t, l, tx, tx))
			require.ErrorIs(t, err, tc.is)
			assert.Empty(t, facts.HeaderHashes)
		})
	}

	t.Run("bad signature after the stop point is only counted", func(t *testing.T) {
		out := append([][]byte(nil), sigs...)
		last := len(out) - 1
		for len(out[last]) == 0 {
			last--
		}
		out[last] = bytes.Clone(out[last])
		out[last][0] ^= 1
		tx := fibrefix.MutateTx(t, l.PFFTx, func(m *fibretypes.MsgPayForFibre) { m.ValidatorSignatures = out })
		facts, err := verifyFibre(l, withBlock(t, l, tx, tx))
		require.NoError(t, err)
		assert.Equal(t, "robust", facts.CertTokenPrecision)
	})
}

func TestFibreOwnerSignatureIsChecked(t *testing.T) {
	l := fibrefix.LoadLive(t)
	tx := fibrefix.MutateTx(t, l.PFFTx, func(m *fibretypes.MsgPayForFibre) {
		m.PaymentPromise.BlobSize++
	})
	_, err := verifyFibre(l, withBlock(t, l, tx, tx))
	require.Error(t, err, "the promise no longer matches the signatures")
}

func TestFibreValidatorListFailures(t *testing.T) {
	l := fibrefix.LoadLive(t)
	var hi stakingtypes.HistoricalInfo
	require.NoError(t, hi.Unmarshal(l.Hist))
	marshal := func(h stakingtypes.HistoricalInfo) []byte {
		b, err := h.Marshal()
		require.NoError(t, err)
		return b
	}
	clone := func() stakingtypes.HistoricalInfo {
		var h stakingtypes.HistoricalInfo
		require.NoError(t, h.Unmarshal(l.Hist))
		return h
	}
	tests := []struct {
		name string
		mod  func(ev *archive.EvidenceRecord)
		is   error
	}{
		{"two validators swapped", func(ev *archive.EvidenceRecord) {
			h := clone()
			h.Valset[3], h.Valset[4] = h.Valset[4], h.Valset[3]
			ev.HistoricalInfo = marshal(h)
		}, fibrecert.ErrCertificateInvalid},
		{"power of a validator changed by one bucket", func(ev *archive.EvidenceRecord) {
			h := clone()
			h.Valset[10].Tokens = h.Valset[10].Tokens.AddRaw(1_000_000)
			ev.HistoricalInfo = marshal(h)
		}, fibrecert.ErrValsetMismatch},
		{"validator dropped", func(ev *archive.EvidenceRecord) {
			h := clone()
			h.Valset = h.Valset[:len(h.Valset)-1]
			ev.HistoricalInfo = marshal(h)
		}, fibrecert.ErrCertificateMalformed},
		{"promise header of another height", func(ev *archive.EvidenceRecord) { ev.PromiseHeader = l.Headers[l.PromiseHeight+1] }, fibrecert.ErrValsetMismatch},
		{"promise header with another valset hash", func(ev *archive.EvidenceRecord) {
			var h cmtproto.Header
			require.NoError(t, h.Unmarshal(l.PromiseHeader))
			h.NextValidatorsHash = bytes.Clone(h.NextValidatorsHash)
			h.NextValidatorsHash[0] ^= 1
			b, err := h.Marshal()
			require.NoError(t, err)
			ev.PromiseHeader = b
		}, fibrecert.ErrValsetMismatch},
		{"promise header absent", func(ev *archive.EvidenceRecord) { ev.PromiseHeader = nil }, nil},
		{"historical info absent", func(ev *archive.EvidenceRecord) { ev.HistoricalInfo = nil }, nil},
		{"historical info garbage", func(ev *archive.EvidenceRecord) { ev.HistoricalInfo = []byte{0xff, 0xfe} }, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := l.Evidence(t)
			tc.mod(ev)
			facts, err := verifyFibre(l, ev)
			require.Error(t, err)
			if tc.is != nil {
				require.ErrorIs(t, err, tc.is)
			}
			assert.Empty(t, facts.HeaderHashes)
		})
	}
}

// The first validator holds the most power and signed nothing. Raising its
// tokens by whole buckets moves the signed share down to exactly the
// threshold, where the verdict depends on the tokens inside the buckets. The
// promise header is rebuilt for the new set; header trust is not in play.
func TestFibreTokenPrecisionBucketDependent(t *testing.T) {
	l := fibrefix.LoadLive(t)
	pff, _, err := fibrecert.ParsePFF(l.PFFTx)
	require.NoError(t, err)
	vals, err := fibrecert.ParseHistoricalInfo(l.Hist)
	require.NoError(t, err)
	require.Empty(t, pff.Signatures[0])

	var signed, total int64
	for i, v := range vals {
		total += v.Power
		if len(pff.Signatures[i]) != 0 {
			signed += v.Power
		}
	}
	const bucket = int64(1_000_000)
	delta := (3*signed - 2*total) / 2 / bucket * bucket
	require.Positive(t, delta)

	var hi stakingtypes.HistoricalInfo
	require.NoError(t, hi.Unmarshal(l.Hist))
	hi.Valset[0].Tokens = hi.Valset[0].Tokens.AddRaw(delta)
	hist, err := hi.Marshal()
	require.NoError(t, err)

	cv := make([]*core.Validator, 0, len(hi.Valset))
	vals[0].Power += delta
	for _, v := range vals {
		cv = append(cv, core.NewValidator(cmted25519.PubKey(v.PubKey), v.Power/bucket))
	}
	var ph cmtproto.Header
	require.NoError(t, ph.Unmarshal(l.PromiseHeader))
	ph.NextValidatorsHash = core.NewValidatorSet(cv).Hash()
	promiseHdr, err := ph.Marshal()
	require.NoError(t, err)

	ev := l.Evidence(t)
	ev.HistoricalInfo, ev.PromiseHeader = hist, promiseHdr
	facts, err := verifyFibre(l, ev)
	require.NoError(t, err, "still accepted at the archived tokens")
	assert.Equal(t, "bucket-dependent", facts.CertTokenPrecision)
	required, _, _ := fibrecert.Threshold(0, facts.CertTotalPower)
	assert.Less(t, facts.CertSignedPower-required, 10*bucket, "the signed power sits within a few buckets of the threshold")
}

func TestFibrePanicGuard(t *testing.T) {
	l := fibrefix.LoadLive(t)
	rnd := func(n int) []byte {
		b := make([]byte, n)
		_, err := rand.Read(b)
		require.NoError(t, err)
		return b
	}
	for name, mod := range map[string]func(ev *archive.EvidenceRecord){
		"random proof body": func(ev *archive.EvidenceRecord) {
			ev.SystemBlobProof = fibreproof.EncodeProof(rnd(1472), rnd(2000))
		},
		"empty dah and stream": func(ev *archive.EvidenceRecord) { ev.SystemBlobProof = fibreproof.EncodeProof(nil, nil) },
		"nil dah roots": func(ev *archive.EvidenceRecord) {
			ev.SystemBlobProof = fibreproof.EncodeProof([]byte{0x0a, 0x00, 0x12, 0x00}, nil)
		},
		"random header":     func(ev *archive.EvidenceRecord) { ev.Header = rnd(300) },
		"empty signed hdr":  func(ev *archive.EvidenceRecord) { ev.Header = []byte{0x0a, 0x00} },
		"random anchor tx":  func(ev *archive.EvidenceRecord) { ev.AnchorTx = rnd(500) },
		"random hist info":  func(ev *archive.EvidenceRecord) { ev.HistoricalInfo = rnd(500) },
		"random promise hd": func(ev *archive.EvidenceRecord) { ev.PromiseHeader = rnd(300) },
		"random sys blob":   func(ev *archive.EvidenceRecord) { ev.SystemBlob = rnd(100) },
		"nested garbage": func(ev *archive.EvidenceRecord) {
			ev.AnchorTx = []byte{0x0a, 0x05, 0x0a, 0x03, 0x0a, 0x01, 0x0a, 0x12, 0x00}
		},
	} {
		t.Run(name, func(t *testing.T) {
			ev := l.Evidence(t)
			mod(ev)
			require.NotPanics(t, func() {
				facts, err := verifyFibre(l, ev)
				require.Error(t, err)
				assert.Empty(t, facts.HeaderHashes)
			})
		})
	}
}

func FuzzFibreVerifyAnchor(f *testing.F) {
	l := fibrefix.LoadLive(f)
	ev := l.Evidence(f)
	f.Add(ev.SystemBlobProof, ev.AnchorTx, ev.Header, ev.HistoricalInfo, ev.PromiseHeader)
	f.Add([]byte(`{"a":1}`), ev.AnchorTx, ev.Header, ev.HistoricalInfo, ev.PromiseHeader)
	f.Add([]byte{}, []byte{}, []byte{}, []byte{}, []byte{})
	f.Fuzz(func(t *testing.T, proof, tx, header, hist, promise []byte) {
		e := l.Evidence(t)
		e.SystemBlobProof, e.AnchorTx, e.Header, e.HistoricalInfo, e.PromiseHeader = proof, tx, header, hist, promise
		facts, err := verifyFibre(l, e)
		if err == nil {
			assert.Equal(t, "node-attested", facts.Settlement)
			assert.Equal(t, 1, facts.ProofForm)
		}
	})
}

type mapTrust map[uint64][]byte

func (m mapTrust) Trusted(_ context.Context, h uint64, hash []byte) (verifier.TrustResult, error) {
	if want, ok := m[h]; !ok || !bytes.Equal(want, hash) {
		return verifier.TrustResult{}, verifier.ErrHeaderTrust
	}
	return verifier.TrustResult{Checked: true, CheckpointH: 1402819, CheckpointHash: bytes.Repeat([]byte{0xcc}, 32), CrossCheck: "off"}, nil
}

func fibreVerifier(t *testing.T, l *fibrefix.Live, ev *archive.EvidenceRecord, trust verifier.HeaderTrust) (*verifier.Verifier, fibrefix.Decision) {
	t.Helper()
	d := l.WriteDecision(t, ev)
	cm := fibrefix.Committers(t)
	store, err := openStore(t, d.Dir, cm)
	require.NoError(t, err)
	v, err := verifier.New(verifier.Deps{
		Config:     verifier.Config{Params: commitment.DefaultParams(), GateKeys: []ed25519.PublicKey{gatefix.Key(t, "gate1").Public().(ed25519.PublicKey)}},
		Archive:    store,
		Committers: cm,
		Anchors:    map[commitment.DA]verifier.AnchorVerifier{commitment.DAFibre: anchorverify.Fibre()},
		Trust:      trust,
	})
	require.NoError(t, err)
	return v, d
}

func TestFibreThroughTheVerifier(t *testing.T) {
	l := fibrefix.LoadLive(t)
	v, d := fibreVerifier(t, l, l.Evidence(t), mapTrust(l.HeaderHashes))
	rep, err := v.Verify(context.Background(), d.Hash)
	require.NoError(t, err)

	assert.Equal(t, verifier.VerdictValid, rep.Verdict, "%+v", rep.Checks)
	assert.Equal(t, "node-attested", rep.Settlement)
	assert.Equal(t, 1, rep.AnchorProofForm)
	assert.Equal(t, 0, rep.AnchorCandidatesEarlier)
	require.NotNil(t, rep.Cert)
	assert.Equal(t, "robust", rep.Cert.TokenPrecision)
	assert.Equal(t, "next_validators_hash@1402813", rep.Cert.ValsetHeader)
	assert.InDelta(t, 0.7616, rep.Cert.SignedShare, 1e-3)
	assert.False(t, rep.Cert.QuorumWarning)
	assert.Equal(t, uint64(1791196769), rep.RetentionStart)
}

func TestFibreThroughTheVerifierWarnsAboutEarlierCandidates(t *testing.T) {
	l := fibrefix.LoadLive(t)
	earlier := setCreated(t, l.PFFTx, l.Created.Add(-time.Minute))
	ev := withBlock(t, l, l.PFFTx, earlier, l.PFFTx)
	facts, err := verifyFibre(l, ev)
	require.NoError(t, err)
	v, d := fibreVerifier(t, l, ev, mapTrust(facts.HeaderHashes))
	rep, err := v.Verify(context.Background(), d.Hash)
	require.NoError(t, err)
	assert.Equal(t, verifier.VerdictValid, rep.Verdict, "a warning never changes the verdict")
	assert.Equal(t, 1, rep.AnchorCandidatesEarlier)
	assert.NotEmpty(t, rep.Warnings)
}

func TestFibreForm0ThroughTheVerifierIsNeverValid(t *testing.T) {
	l := fibrefix.LoadLive(t)
	ev := l.Evidence(t)
	ev.SystemBlobProof = []byte(`{"form":0}`)
	v, d := fibreVerifier(t, l, ev, mapTrust(l.HeaderHashes))
	rep, err := v.Verify(context.Background(), d.Hash)
	require.NoError(t, err)

	assert.Equal(t, verifier.VerdictUnchecked, rep.Verdict)
	c, ok := rep.Check(verifier.CheckAnchor)
	require.True(t, ok)
	assert.Equal(t, verifier.StatusUnchecked, c.Status)
	require.ErrorIs(t, c.Err, verifier.ErrAnchorUnsupported)
	assert.NotEmpty(t, c.Err.Error(), "the reason is given")
	assert.Empty(t, rep.Settlement)
}

func TestFibreTamperedEvidenceThroughTheVerifierIsInvalid(t *testing.T) {
	l := fibrefix.LoadLive(t)
	ev := l.Evidence(t)
	ev.SystemBlob[0] ^= 1
	v, d := fibreVerifier(t, l, ev, mapTrust(l.HeaderHashes))
	rep, err := v.Verify(context.Background(), d.Hash)
	require.NoError(t, err)
	assert.Equal(t, verifier.VerdictInvalid, rep.Verdict)
	c, _ := rep.Check(verifier.CheckAnchor)
	assert.Equal(t, verifier.StatusFail, c.Status)
	require.ErrorIs(t, c.Err, verifier.ErrAnchorInvalid)
}

func openStore(t *testing.T, dir string, cm map[commitment.DA]gate.DACommitter) (*fsarchive.Store, error) {
	t.Helper()
	return fsarchive.Open(dir, cm)
}
