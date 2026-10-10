package fsarchive

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
)

var (
	_ archive.IntentReader  = (*Store)(nil)
	_ archive.IntentLister  = (*Store)(nil)
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

// Intents walks the intent directory of da. Names that are not canonical
// keys, such as temp files of a write in progress, are skipped.
func (s *Store) Intents(ctx context.Context, da commitment.DA, from uint64) ([]*archive.AnchorIntentRecord, error) {
	if da != commitment.DAFibre && da != commitment.DACelestiaBlob {
		return nil, nil
	}
	root := s.path("intent/" + strconv.FormatUint(uint64(da), 10))
	dirs, err := os.ReadDir(root)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("fsarchive: %w", err)
	}
	var out []*archive.AnchorIntentRecord
	for _, d := range dirs {
		commit, err := hex.DecodeString(d.Name())
		if !d.IsDir() || err != nil || len(commit) != 32 || hex.EncodeToString(commit) != d.Name() {
			continue
		}
		files, err := os.ReadDir(filepath.Join(root, d.Name()))
		if err != nil {
			return nil, fmt.Errorf("fsarchive: %w", err)
		}
		for _, f := range files {
			h, err := strconv.ParseUint(f.Name(), 10, 64)
			if err != nil || h < from || strconv.FormatUint(h, 10) != f.Name() {
				continue
			}
			rec, err := s.Intent(ctx, da, commit, h)
			if err != nil {
				return nil, err
			}
			out = append(out, rec)
		}
	}
	return out, nil
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
