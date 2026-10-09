package fsarchive

import (
	"context"

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
