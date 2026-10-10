package archive

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"

	"github.com/vgonkivs/edicta/commitment"
)

// Kinds of the fast-mode records.
const (
	KindAnchorIntent Kind = 13
	KindAbsenceProof Kind = 14
)

const (
	maxIntentSize   = 65600
	maxAbsenceSize  = 1 << 24
	maxIntentTx     = 1 << 16
	maxNamespaceDat = 1 << 24
)

// AnchorIntentRecord is the signed anchor tx of a pending reference, archived
// before it is broadcast. Signer is set for da = 2 only. CreatedAt is the
// promise creation time, floored, for da = 1 and the Recorder clock for
// da = 2.
type AnchorIntentRecord struct {
	DA         commitment.DA
	Commitment []byte
	Namespace  []byte
	RefHeight  uint64
	Tx         []byte
	Signer     []byte
	CreatedAt  uint64
}

// AbsenceProofRecord is what one height contributes to an absence proof.
// Results and NextHeader are set together, for da = 1 only. An empty
// NamespaceData means no row holds the namespace.
type AbsenceProofRecord struct {
	DA            commitment.DA
	Commitment    []byte
	Namespace     []byte
	Height        uint64
	Header        []byte
	DAH           []byte
	NamespaceData []byte
	Results       []byte
	NextHeader    []byte
}

func (*AnchorIntentRecord) Kind() Kind { return KindAnchorIntent }
func (*AbsenceProofRecord) Kind() Kind { return KindAbsenceProof }

// IntentReader is the optional read side of the anchor intent record. It
// returns ErrNotFound for an absent key and an ErrCorrupt error for a stored
// record that does not decode or does not carry its key.
type IntentReader interface {
	Intent(ctx context.Context, da commitment.DA, commit []byte, refHeight uint64) (*AnchorIntentRecord, error)
}

// AbsenceReader is the optional read side of the absence proof record, with
// the error rules of IntentReader.
type AbsenceReader interface {
	Absence(ctx context.Context, da commitment.DA, commit []byte, height uint64) (*AbsenceProofRecord, error)
}

func intentSchema() []fdef {
	return []fdef{
		{3, "da", tUint, pReq, 0, 0, nil},
		{4, "commitment", tBstr, pReq, 32, 32, nil},
		{5, "namespace", tBstr, pReq, 29, 29, nil},
		{6, "ref_height", tUint, pReq, 0, 0, nil},
		{7, "tx", tBstr, pReq, 1, maxIntentTx, nil},
		{8, "signer", tBstr, pReq2, 20, 20, nil},
		{9, "created_at", tUint, pReq, 0, 0, nil},
	}
}

func absenceSchema() []fdef {
	return []fdef{
		{3, "da", tUint, pReq, 0, 0, nil},
		{4, "commitment", tBstr, pReq, 32, 32, nil},
		{5, "namespace", tBstr, pReq, 29, 29, nil},
		{6, "height", tUint, pReq, 0, 0, nil},
		{7, "header", tBstr, pReq, 1, maxOpaque, nil},
		{8, "dah", tBstr, pReq, 1, maxOpaque, nil},
		{9, "namespace_data", tBstr, pReq, 0, maxNamespaceDat, nil},
		{10, "results", tBstr, pOpt1, 1, maxOpaque, nil},
		{11, "next_header", tBstr, pWithResults, 1, maxOpaque, nil},
	}
}

func buildFast(pm *pmap, kind Kind, bs func(*pmap, uint64) []byte, u func(*pmap, uint64) uint64) Record {
	if kind == KindAnchorIntent {
		return &AnchorIntentRecord{
			DA: commitment.DA(u(pm, 3)), Commitment: bs(pm, 4), Namespace: bs(pm, 5), RefHeight: u(pm, 6),
			Tx: bs(pm, 7), Signer: bs(pm, 8), CreatedAt: u(pm, 9),
		}
	}
	r := &AbsenceProofRecord{
		DA: commitment.DA(u(pm, 3)), Commitment: bs(pm, 4), Namespace: bs(pm, 5), Height: u(pm, 6),
		Header: bs(pm, 7), DAH: bs(pm, 8), NamespaceData: bs(pm, 9), Results: bs(pm, 10), NextHeader: bs(pm, 11),
	}
	// Key 9 is required and may be empty; a decoded record always holds it.
	if r.NamespaceData == nil {
		r.NamespaceData = []byte{}
	}
	return r
}

func encodeIntent(w *mapWriter, r *AnchorIntentRecord) {
	w.uint(2, uint64(KindAnchorIntent))
	w.uint(3, uint64(r.DA))
	w.bytes(4, r.Commitment)
	w.bytes(5, r.Namespace)
	w.uint(6, r.RefHeight)
	w.bytes(7, r.Tx)
	w.opt(8, r.Signer)
	w.uint(9, r.CreatedAt)
}

func encodeAbsence(w *mapWriter, r *AbsenceProofRecord) {
	w.uint(2, uint64(KindAbsenceProof))
	w.uint(3, uint64(r.DA))
	w.bytes(4, r.Commitment)
	w.bytes(5, r.Namespace)
	w.uint(6, r.Height)
	w.bytes(7, r.Header)
	w.bytes(8, r.DAH)
	w.bytes(9, r.NamespaceData)
	w.opt(10, r.Results)
	w.opt(11, r.NextHeader)
}

// IntentPath is the path of an anchor intent record.
func IntentPath(da commitment.DA, commit []byte, refHeight uint64) (string, error) {
	return heightPath("intent", da, commit, refHeight)
}

// AbsencePath is the path of an absence proof record.
func AbsencePath(da commitment.DA, commit []byte, height uint64) (string, error) {
	return heightPath("absence", da, commit, height)
}

func heightPath(dir string, da commitment.DA, commit []byte, height uint64) (string, error) {
	if da != commitment.DAFibre && da != commitment.DACelestiaBlob {
		return "", fmt.Errorf("archive: da %d: %w", da, commitment.ErrInvalidEnum)
	}
	if len(commit) != 32 {
		return "", fmt.Errorf("archive: commitment of %d bytes: %w", len(commit), commitment.ErrFieldSize)
	}
	if height == 0 || height > math.MaxInt64 {
		return "", fmt.Errorf("archive: height %d: %w", height, commitment.ErrIntRange)
	}
	return dir + "/" + strconv.FormatUint(uint64(da), 10) + "/" + hex.EncodeToString(commit) + "/" +
		strconv.FormatUint(height, 10), nil
}

// parseHeightKey accepts exactly the paths heightPath produces.
func parseHeightKey(parts []string) bool {
	if len(parts) != 4 || (parts[1] != "1" && parts[1] != "2") || !isLowerHex32(parts[2]) {
		return false
	}
	h, err := strconv.ParseUint(parts[3], 10, 64)
	return err == nil && h > 0 && h <= math.MaxInt64 && strconv.FormatUint(h, 10) == parts[3]
}

func fastKeyPath(r Record) (string, bool, error) {
	switch r := r.(type) {
	case *AnchorIntentRecord:
		if r == nil {
			return "", false, nil
		}
		p, err := IntentPath(r.DA, r.Commitment, r.RefHeight)
		return p, true, err
	case *AbsenceProofRecord:
		if r == nil {
			return "", false, nil
		}
		p, err := AbsencePath(r.DA, r.Commitment, r.Height)
		return p, true, err
	}
	return "", false, nil
}

// hasNamespace reports the kinds whose key 5 is a namespace, which must be
// a valid user blob namespace.
func hasNamespace(k Kind) bool {
	return k == KindPayload || k == KindEvidence || k == KindAnchorIntent || k == KindAbsenceProof
}

// fastSameIdentity: an intent is identified by the whole record, so two
// different txs under one reference conflict; an absence proof by its key,
// since honest tools may serialize the same proof differently.
func fastSameIdentity(a, b Record) (same, ok bool) {
	switch a := a.(type) {
	case *AnchorIntentRecord:
		b, isB := b.(*AnchorIntentRecord)
		return isB && a.DA == b.DA && bytes.Equal(a.Commitment, b.Commitment) &&
			bytes.Equal(a.Namespace, b.Namespace) && a.RefHeight == b.RefHeight && bytes.Equal(a.Tx, b.Tx) &&
			bytes.Equal(a.Signer, b.Signer) && a.CreatedAt == b.CreatedAt, true
	case *AbsenceProofRecord:
		b, isB := b.(*AbsenceProofRecord)
		return isB && a.DA == b.DA && bytes.Equal(a.Commitment, b.Commitment) && a.Height == b.Height, true
	}
	return false, false
}
