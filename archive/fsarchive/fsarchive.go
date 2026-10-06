// Package fsarchive stores archive records as files under one directory.
// Every record is written to a temp file, synced and then linked to its
// final path, so a record is either fully present or absent and a second
// writer of the same key cannot replace it, also from another process.
package fsarchive

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
)

const tempPrefix = ".tmp-"

// Option configures a Store.
type Option func(*Store)

// WithBeforeRename sets a hook that runs after the temp file is written and
// synced, right before it is published. An error aborts the write. It exists
// to simulate crashes.
func WithBeforeRename(f func(finalPath string) error) Option {
	return func(s *Store) { s.before = f }
}

type Store struct {
	dir        string
	committers map[commitment.DA]gate.DACommitter
	before     func(string) error
	// mu serializes marker and Authorization writes in this process; lockDir
	// does it across processes.
	mu sync.Mutex
}

var _ archive.Store = (*Store)(nil)

// Open uses dir as the archive, creating it if needed. A payload is accepted
// only for a da that has a committer.
func Open(dir string, committers map[commitment.DA]gate.DACommitter, opts ...Option) (*Store, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("fsarchive: %w", err)
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return nil, fmt.Errorf("fsarchive: %w", err)
	}
	s := &Store{dir: abs, committers: make(map[commitment.DA]gate.DACommitter, len(committers))}
	for da, c := range committers {
		s.committers[da] = c
	}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

func (s *Store) path(rel string) string { return filepath.Join(s.dir, filepath.FromSlash(rel)) }

func (s *Store) Put(_ context.Context, r archive.Record) (archive.Outcome, error) {
	b, err := archive.Encode(r)
	if err != nil {
		return 0, err
	}
	rel, err := archive.KeyPath(r)
	if err != nil {
		return 0, err
	}
	switch r := r.(type) {
	case *archive.PayloadRecord:
		if err := s.checkDA(r); err != nil {
			return 0, err
		}
	case *archive.EvidenceRecord:
		need, err := archive.DataPath(archive.KindPayload, r.DA, r.Commitment)
		if err != nil {
			return 0, err
		}
		if err := s.require(need); err != nil {
			return 0, err
		}
	case *archive.AuthorizationRecord, *archive.RejectionRecord:
		return s.putDependent(r, rel, b)
	}
	return s.create(rel, r, b)
}

func (s *Store) putDependent(r archive.Record, rel string, b []byte) (archive.Outcome, error) {
	var h commitment.Hash
	switch r := r.(type) {
	case *archive.RejectionRecord:
		h = r.CommitmentHash
	case *archive.AuthorizationRecord:
		sa, _, err := commitment.DecodeSignedAuthorization(r.SignedAuthorization)
		if err != nil {
			return 0, fmt.Errorf("fsarchive: %w", err)
		}
		copy(h[:], sa.Authorization.CommitmentHash)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := lockDir(s.dir)
	if err != nil {
		return 0, err
	}
	defer unlock()

	if err := s.require(archive.HashPath(archive.KindDecision, h)); err != nil {
		return 0, err
	}
	if r.Kind() == archive.KindRejection {
		ok, err := s.exists(archive.HashPath(archive.KindAuthorization, h))
		if err != nil {
			return 0, err
		}
		if ok {
			return archive.Unchanged, nil
		}
	}
	return s.create(rel, r, b)
}

func (s *Store) checkDA(p *archive.PayloadRecord) error {
	c, ok := s.committers[p.DA]
	if !ok {
		return fmt.Errorf("%w: da %d", gate.ErrArchiveRecomputeUnsupported, p.DA)
	}
	ref := commitment.PayloadRef{DA: p.DA, Namespace: p.Namespace, Commitment: p.Commitment, Signer: p.Signer}
	if err := c.Check(ref, p.Blob); err != nil {
		return fmt.Errorf("fsarchive: payload %x: %w", p.Commitment, err)
	}
	return nil
}

func (s *Store) exists(rel string) (bool, error) {
	_, err := os.Stat(s.path(rel))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	}
	return false, fmt.Errorf("fsarchive: %w", err)
}

func (s *Store) require(rel string) error {
	ok, err := s.exists(rel)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: %s", archive.ErrNotFound, rel)
	}
	return nil
}

// create stores b under rel unless the key is taken. A taken key is compared
// by identity; a corrupt record there is reported and never replaced.
func (s *Store) create(rel string, r archive.Record, b []byte) (archive.Outcome, error) {
	final := s.path(rel)
	for range 3 {
		old, err := s.read(rel)
		switch {
		case err == nil:
			if archive.SameIdentity(old, r) {
				return archive.Unchanged, nil
			}
			return 0, fmt.Errorf("%w: %s", archive.ErrConflict, rel)
		case !errors.Is(err, archive.ErrNotFound):
			return 0, err
		}
		err = s.publish(final, b)
		if err == nil {
			return archive.Written, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return 0, err
		}
	}
	return 0, fmt.Errorf("fsarchive: %s keeps changing under the writer", rel)
}

func (s *Store) publish(final string, b []byte) (err error) {
	dir := filepath.Dir(final)
	if err := s.ensureDir(dir); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, tempPrefix+"*")
	if err != nil {
		return fmt.Errorf("fsarchive: %w", err)
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return fmt.Errorf("fsarchive: write: %w", err)
	}
	if err := f.Chmod(0o644); err != nil {
		_ = f.Close()
		return fmt.Errorf("fsarchive: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("fsarchive: sync: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("fsarchive: %w", err)
	}
	if s.before != nil {
		if err := s.before(final); err != nil {
			return fmt.Errorf("fsarchive: before rename: %w", err)
		}
	}
	// A hard link fails when the final path exists, where a rename would
	// replace it.
	if err := os.Link(tmp, final); err != nil {
		return fmt.Errorf("fsarchive: publish: %w", err)
	}
	return syncDir(dir)
}

func (s *Store) ensureDir(dir string) error {
	rel, err := filepath.Rel(s.dir, dir)
	if err != nil {
		return fmt.Errorf("fsarchive: %w", err)
	}
	cur := s.dir
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "." {
			continue
		}
		next := filepath.Join(cur, part)
		switch err := os.Mkdir(next, 0o755); {
		case err == nil:
			if err := syncDir(cur); err != nil {
				return err
			}
		case !errors.Is(err, fs.ErrExist):
			return fmt.Errorf("fsarchive: %w", err)
		}
		cur = next
	}
	return nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("fsarchive: %w", err)
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return fmt.Errorf("fsarchive: sync dir: %w", err)
	}
	if err := d.Close(); err != nil {
		return fmt.Errorf("fsarchive: %w", err)
	}
	return nil
}

// read loads the record stored under rel and checks that it carries that key.
func (s *Store) read(rel string) (archive.Record, error) {
	f, err := os.Open(s.path(rel))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", archive.ErrNotFound, rel)
		}
		return nil, fmt.Errorf("fsarchive: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, archive.MaxRecordSize+1))
	if err != nil {
		return nil, fmt.Errorf("fsarchive: read %s: %w", rel, err)
	}
	rec, err := archive.Decode(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", rel, err)
	}
	got, err := archive.KeyPath(rec)
	if err != nil || got != rel {
		return nil, fmt.Errorf("%w: %s carries key %s", archive.ErrCorrupt, rel, got)
	}
	return rec, nil
}

func notFound(err error) error { return fmt.Errorf("%w: %w", archive.ErrNotFound, err) }

func corruptType(rel string) error {
	return fmt.Errorf("%w: %s holds a record of another kind", archive.ErrCorrupt, rel)
}

func (s *Store) Payload(_ context.Context, da commitment.DA, commit []byte) (*archive.PayloadRecord, error) {
	rel, err := archive.DataPath(archive.KindPayload, da, commit)
	if err != nil {
		return nil, notFound(err)
	}
	rec, err := s.read(rel)
	if err != nil {
		return nil, err
	}
	p, ok := rec.(*archive.PayloadRecord)
	if !ok {
		return nil, corruptType(rel)
	}
	return p, nil
}

func (s *Store) Evidence(_ context.Context, da commitment.DA, commit []byte) (*archive.EvidenceRecord, error) {
	rel, err := archive.DataPath(archive.KindEvidence, da, commit)
	if err != nil {
		return nil, notFound(err)
	}
	rec, err := s.read(rel)
	if err != nil {
		return nil, err
	}
	e, ok := rec.(*archive.EvidenceRecord)
	if !ok {
		return nil, corruptType(rel)
	}
	return e, nil
}

func (s *Store) Decision(_ context.Context, h commitment.Hash) (*archive.DecisionRecord, error) {
	rel := archive.HashPath(archive.KindDecision, h)
	rec, err := s.read(rel)
	if err != nil {
		return nil, err
	}
	d, ok := rec.(*archive.DecisionRecord)
	if !ok {
		return nil, corruptType(rel)
	}
	return d, nil
}

func (s *Store) Authorization(_ context.Context, h commitment.Hash) (*archive.AuthorizationRecord, error) {
	rel := archive.HashPath(archive.KindAuthorization, h)
	rec, err := s.read(rel)
	if err != nil {
		return nil, err
	}
	a, ok := rec.(*archive.AuthorizationRecord)
	if !ok {
		return nil, corruptType(rel)
	}
	return a, nil
}

func (s *Store) Rejection(_ context.Context, h commitment.Hash, name string) (*archive.RejectionRecord, error) {
	rel, err := archive.RejectionPath(h, name)
	if err != nil {
		return nil, notFound(err)
	}
	rec, err := s.read(rel)
	if err != nil {
		return nil, err
	}
	m, ok := rec.(*archive.RejectionRecord)
	if !ok {
		return nil, corruptType(rel)
	}
	return m, nil
}

func (s *Store) State(ctx context.Context, h commitment.Hash) (archive.DecisionState, error) {
	if _, err := s.Decision(ctx, h); err != nil {
		if errors.Is(err, archive.ErrNotFound) {
			return archive.DecisionState{State: archive.StateAbsent}, nil
		}
		return archive.DecisionState{}, err
	}
	// Markers first: one written after this read is skipped, and an
	// Authorization seen afterwards still makes the state authorized.
	marks, err := s.markers(ctx, h)
	if err != nil {
		return archive.DecisionState{}, err
	}
	st := archive.DecisionState{Rejections: marks}
	_, err = s.Authorization(ctx, h)
	switch {
	case err == nil:
		st.State = archive.StateAuthorized
	case !errors.Is(err, archive.ErrNotFound):
		return archive.DecisionState{}, err
	case len(marks) > 0:
		st.State = archive.StateRejected
	default:
		st.State = archive.StatePending
	}
	return st, nil
}

func (s *Store) markers(ctx context.Context, h commitment.Hash) ([]string, error) {
	dir := s.path("rejection/" + hex.EncodeToString(h[:]))
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("fsarchive: %w", err)
	}
	var marks []*archive.RejectionRecord
	for _, e := range entries {
		name := e.Name()
		if !archive.IsVerdict(name) {
			continue
		}
		m, err := s.Rejection(ctx, h, name)
		if errors.Is(err, archive.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		marks = append(marks, m)
	}
	sort.Slice(marks, func(i, j int) bool {
		if marks[i].RejectedAt != marks[j].RejectedAt {
			return marks[i].RejectedAt < marks[j].RejectedAt
		}
		return marks[i].Error < marks[j].Error
	})
	names := make([]string, len(marks))
	for i, m := range marks {
		names[i] = m.Error
	}
	return names, nil
}
