package fsarchive

import (
	"bytes"
	"context"
	"errors"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
)

var (
	_ archive.IntentReader  = (*Store)(nil)
	_ archive.AbsenceReader = (*Store)(nil)
)

func (s *Store) Intent(_ context.Context, da commitment.DA, commit []byte, refHeight uint64) (*archive.AnchorIntentRecord, error) {
	rel, err := archive.IntentPath(da, commit, refHeight)
	if err != nil {
		return nil, notFound(err)
	}
	rec, err := s.read(rel)
	if err != nil {
		return nil, err
	}
	r, ok := rec.(*archive.AnchorIntentRecord)
	if !ok {
		return nil, corruptType(rel)
	}
	return r, nil
}

func (s *Store) Absence(_ context.Context, da commitment.DA, commit []byte, height uint64) (*archive.AbsenceProofRecord, error) {
	rel, err := archive.AbsencePath(da, commit, height)
	if err != nil {
		return nil, notFound(err)
	}
	rec, err := s.read(rel)
	if err != nil {
		return nil, err
	}
	r, ok := rec.(*archive.AbsenceProofRecord)
	if !ok {
		return nil, corruptType(rel)
	}
	return r, nil
}

// ReplaceAbsence stores rec over the absence proof archived under its key,
// if any. Absence proofs are checked against the chain on every read, so a
// copy that does not verify carries nothing; the caller replaces it only
// with a record it has verified and only after the archived one failed.
func (s *Store) ReplaceAbsence(_ context.Context, rec *archive.AbsenceProofRecord) (archive.Outcome, error) {
	if s.readOnly {
		return 0, ErrReadOnly
	}
	b, err := archive.Encode(rec)
	if err != nil {
		return 0, err
	}
	rel, err := archive.KeyPath(rec)
	if err != nil {
		return 0, err
	}
	final := s.path(rel)
	// Write-once identity of an absence proof is its key, so the bytes
	// decide whether this is the record already there.
	old, err := s.read(rel)
	switch {
	case err == nil:
		if ob, err := archive.Encode(old); err == nil && bytes.Equal(ob, b) {
			if err := s.syncExisting(final); err != nil {
				return 0, err
			}
			return archive.Unchanged, nil
		}
	case !errors.Is(err, archive.ErrNotFound) && !errors.Is(err, archive.ErrCorrupt):
		return 0, err
	}
	if err := s.write(final, b, true); err != nil {
		return 0, err
	}
	return archive.Written, nil
}
