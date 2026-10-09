// Package fsarchive stores archive records as files under one directory.
// Every record is written to a temp file, synced and then linked to its
// final path, so a record is either fully present or absent and a second
// writer of the same key cannot replace it, also from another process.
package fsarchive

import (
	"bytes"
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
	"time"

	"github.com/vgonkivs/edicta/archive"
	"github.com/vgonkivs/edicta/commitment"
	"github.com/vgonkivs/edicta/gate"
	"github.com/vgonkivs/edicta/policy"
)

const tempPrefix = ".tmp-"

// ErrReadOnly is returned by a write on a store opened with OpenReadOnly.
var ErrReadOnly = errors.New("fsarchive: store is read-only")

// Option configures a Store.
type Option func(*Store)

// WithBeforePublish sets a hook that runs after the temp file is written and
// synced, right before it is published. An error aborts the write. It exists
// to simulate crashes.
func WithBeforePublish(f func(finalPath string) error) Option {
	return func(s *Store) { s.before = f }
}

// WithSyncHook sets a hook that runs after each file fsync with the final
// path of the record, including the re-sync of a record that already exists.
// It exists for tests; the hook runs on the write path, so a slow one slows
// every write.
func WithSyncHook(f func(path string)) Option {
	return func(s *Store) { s.syncHook = f }
}

// WithStaleAge sets how old a temp file must be before Open removes it. The
// default is one hour; a younger file may belong to a live writer.
func WithStaleAge(d time.Duration) Option {
	return func(s *Store) { s.staleAge = d }
}

type Store struct {
	staleAge   time.Duration
	dir        string
	committers map[commitment.DA]gate.DACommitter
	before     func(string) error
	readOnly   bool
	syncHook   func(string)
	// mu serializes marker and Authorization writes in this process; lockDir
	// does it across processes.
	mu sync.Mutex
}

var (
	_ archive.Store           = (*Store)(nil)
	_ archive.PayloadStreamer = (*Store)(nil)
	_ archive.PolicyReader    = (*Store)(nil)
)

// Open uses dir as the archive, creating it if needed. A payload is accepted
// only for a da that has a committer. Temp files left by a crashed writer
// are removed once older than the stale age. Open fails on a platform without directory locks.
func Open(dir string, committers map[commitment.DA]gate.DACommitter, opts ...Option) (*Store, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("fsarchive: %w", err)
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return nil, fmt.Errorf("fsarchive: %w", err)
	}
	if err := checkPlatform(); err != nil {
		return nil, err
	}
	s := &Store{staleAge: time.Hour, dir: abs, committers: make(map[commitment.DA]gate.DACommitter, len(committers))}
	for da, c := range committers {
		s.committers[da] = c
	}
	for _, o := range opts {
		o(s)
	}
	if err := s.removeStale(); err != nil {
		return nil, err
	}
	return s, nil
}

// OpenReadOnly uses an existing dir for reading only. It never creates,
// locks, writes or deletes anything, so it works on a read-only mount and
// beside a live writer; Put fails with ErrReadOnly. Readers need no lock
// because a record is published whole by a hard link.
func OpenReadOnly(dir string, committers map[commitment.DA]gate.DACommitter) (*Store, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("fsarchive: %w", err)
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("fsarchive: %w", err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("fsarchive: %s is not a directory", abs)
	}
	s := &Store{dir: abs, readOnly: true, committers: make(map[commitment.DA]gate.DACommitter, len(committers))}
	for da, c := range committers {
		s.committers[da] = c
	}
	return s, nil
}

// removeStale deletes old temp files a crashed writer left behind. They are never
// linked to a key, so no reader can see them. Young ones are kept: payload
// writes take no lock, so they may belong to a live writer.
func (s *Store) removeStale() error {
	unlock, err := lockDir(context.Background(), s.dir)
	if err != nil {
		return err
	}
	defer unlock()
	err = filepath.WalkDir(s.dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if !d.IsDir() && strings.HasPrefix(d.Name(), tempPrefix) {
			info, err := d.Info()
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return err
			}
			if time.Since(info.ModTime()) < s.staleAge {
				return nil
			}
			if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("fsarchive: clean temp files: %w", err)
	}
	return nil
}

func (s *Store) path(rel string) string { return filepath.Join(s.dir, filepath.FromSlash(rel)) }

func (s *Store) Put(ctx context.Context, r archive.Record) (archive.Outcome, error) {
	if s.readOnly {
		return 0, ErrReadOnly
	}
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
	case *archive.DecisionRecord:
		// A private decision needs the encrypted action record first, which
		// this store does not hold yet.
		if r.Form == archive.FormPrivate {
			return 0, fmt.Errorf("%w: private action record of a private decision", archive.ErrNotFound)
		}
	case *archive.AuthorizationRecord, *archive.RejectionRecord, *archive.RevealRecord:
		return s.putDependent(ctx, r, rel, b)
	case *archive.PolicyAllowRecord, *archive.PolicyDenyRecord, *archive.PolicySuccessorRecord:
		if err := s.checkPolicyDeps(r); err != nil {
			return 0, err
		}
	}
	return s.create(rel, r, b)
}

func (s *Store) putDependent(ctx context.Context, r archive.Record, rel string, b []byte) (archive.Outcome, error) {
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
	case *archive.RevealRecord:
		sr, _, err := commitment.DecodeSignedReceipt(r.SignedReceipt)
		if err != nil {
			return 0, fmt.Errorf("fsarchive: %w", err)
		}
		copy(h[:], sr.Receipt.CommitmentHash)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := lockDir(ctx, s.dir)
	if err != nil {
		return 0, err
	}
	defer unlock()

	if err := s.require(archive.HashPath(archive.KindDecision, h)); err != nil {
		return 0, err
	}
	if a, ok := r.(*archive.AuthorizationRecord); ok {
		if err := s.checkK2(h, a); err != nil {
			return 0, err
		}
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

// checkK2 compares the da of the K2 inputs with the da of the stored
// decision. An absent decision is not checked here.
func (s *Store) checkK2(h commitment.Hash, a *archive.AuthorizationRecord) error {
	if a.K2 == nil {
		return nil
	}
	rel := archive.HashPath(archive.KindDecision, h)
	rec, err := s.read(rel)
	if err != nil {
		if errors.Is(err, archive.ErrNotFound) {
			return nil
		}
		return err
	}
	d, ok := rec.(*archive.DecisionRecord)
	if !ok {
		return corruptType(rel)
	}
	sc, err := commitment.DecodeSigned(d.Envelope)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", archive.ErrCorrupt, rel, err)
	}
	if sc.Commitment.PayloadRef.DA != a.K2.DA {
		return fmt.Errorf("%w: k2 da %d differs from the decision's da %d", archive.ErrCorrupt, a.K2.DA, sc.Commitment.PayloadRef.DA)
	}
	return nil
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
				// The earlier writer may have died between link and fsync.
				if err := s.syncExisting(final); err != nil {
					return 0, err
				}
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

func (s *Store) synced(path string) {
	if s.syncHook != nil {
		s.syncHook(path)
	}
}

func (s *Store) syncExisting(final string) error {
	f, err := os.Open(final)
	if err != nil {
		return fmt.Errorf("fsarchive: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("fsarchive: sync: %w", err)
	}
	s.synced(final)
	if err := f.Close(); err != nil {
		return fmt.Errorf("fsarchive: %w", err)
	}
	return syncDir(filepath.Dir(final))
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
	s.synced(final)
	if err := f.Close(); err != nil {
		return fmt.Errorf("fsarchive: %w", err)
	}
	if s.before != nil {
		if err := s.before(final); err != nil {
			return fmt.Errorf("fsarchive: before publish: %w", err)
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
		case errors.Is(err, fs.ErrExist):
			// A crashed writer may have created it without syncing the parent.
			if err := syncDir(cur); err != nil {
				return err
			}
		default:
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

// PayloadReader opens the encoded payload record for streaming. The caller
// must validate the bytes.
func (s *Store) PayloadReader(ctx context.Context, da commitment.DA, commit []byte) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rel, err := archive.DataPath(archive.KindPayload, da, commit)
	if err != nil {
		return nil, notFound(err)
	}
	f, err := os.Open(s.path(rel))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", archive.ErrNotFound, rel)
		}
		return nil, fmt.Errorf("fsarchive: %w", err)
	}
	return f, nil
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

func (s *Store) Reveal(_ context.Context, h commitment.Hash) (*archive.RevealRecord, error) {
	rel := archive.HashPath(archive.KindReveal, h)
	rec, err := s.read(rel)
	if err != nil {
		return nil, err
	}
	r, ok := rec.(*archive.RevealRecord)
	if !ok {
		return nil, corruptType(rel)
	}
	return r, nil
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
	if err := s.checkK2(h, a); err != nil {
		return nil, err
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

// Raw opens the stored bytes of the record under a canonical key without
// decoding them. Anything that is not a canonical key is absent, and a
// link or other non-regular file is refused so the tree cannot be left.
func (s *Store) Raw(_ context.Context, key string) (io.ReadCloser, error) {
	if _, err := archive.ParseKey(key); err != nil {
		return nil, notFound(err)
	}
	p := s.path(key)
	before, err := os.Lstat(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", archive.ErrNotFound, key)
		}
		return nil, fmt.Errorf("fsarchive: %w", err)
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("fsarchive: %s is not a regular file", key)
	}
	f, err := os.Open(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", archive.ErrNotFound, key)
		}
		return nil, fmt.Errorf("fsarchive: %w", err)
	}
	after, err := f.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		f.Close()
		return nil, fmt.Errorf("fsarchive: %s is not a regular file", key)
	}
	return f, nil
}

// checkPolicyDeps enforces the write preconditions of the policy records
// that depend on others. The records they need are immutable once written,
// so no lock is needed.
func (s *Store) checkPolicyDeps(r archive.Record) error {
	switch r := r.(type) {
	case *archive.PolicyAllowRecord:
		sv, _, err := policy.DecodeSignedVerdict(r.SignedVerdict)
		if err != nil {
			return fmt.Errorf("fsarchive: %w", err)
		}
		if err := s.require(archive.HashPath(archive.KindDecision, commitment.Hash(sv.Verdict.CommitmentHash))); err != nil {
			return err
		}
		return s.require(archive.PolicyHashPath(archive.KindMandate, commitment.Hash(sv.Verdict.MandateHash)))
	case *archive.PolicyDenyRecord:
		sv, _, err := policy.DecodeSignedVerdict(r.SignedVerdict)
		if err != nil {
			return fmt.Errorf("fsarchive: %w", err)
		}
		return s.require(archive.HashPath(archive.KindDecision, commitment.Hash(sv.Verdict.CommitmentHash)))
	case *archive.PolicySuccessorRecord:
		return s.checkSuccessor(r)
	}
	return nil
}

// checkSuccessor requires the allow record the successor names, and that the
// allow belongs to the gate and counter and consumed the state.
func (s *Store) checkSuccessor(r *archive.PolicySuccessorRecord) error {
	if len(r.CommitmentHash) != 32 {
		return fmt.Errorf("fsarchive: successor commitment hash: %w", commitment.ErrFieldSize)
	}
	allow, err := s.PolicyAllow(context.Background(), commitment.Hash(r.CommitmentHash))
	if err != nil {
		return err
	}
	sv, _, err := policy.DecodeSignedVerdict(allow.SignedVerdict)
	if err != nil {
		return fmt.Errorf("%w: %w", archive.ErrCorrupt, err)
	}
	v := &sv.Verdict
	prev, ok := v.PrevStateHash()
	if !ok || v.GateID != r.GateID || !bytes.Equal(prev[:], r.StateHash) {
		return fmt.Errorf("%w: the allow does not match the successor", archive.ErrCorrupt)
	}
	m, err := s.Mandate(context.Background(), commitment.Hash(v.MandateHash))
	if err != nil {
		return err
	}
	sm, _, err := policy.DecodeSignedMandate(m.SignedMandate)
	if err != nil {
		return fmt.Errorf("%w: %w", archive.ErrCorrupt, err)
	}
	if ck := sm.Mandate.CounterKey(); !bytes.Equal(ck[:], r.CounterKey) {
		return fmt.Errorf("%w: the allow's mandate has another counter key", archive.ErrCorrupt)
	}
	return nil
}

func readAs[T archive.Record](s *Store, rel string) (T, error) {
	var zero T
	rec, err := s.read(rel)
	if err != nil {
		return zero, err
	}
	t, ok := rec.(T)
	if !ok {
		return zero, corruptType(rel)
	}
	return t, nil
}

func (s *Store) Mandate(_ context.Context, h commitment.Hash) (*archive.MandateRecord, error) {
	return readAs[*archive.MandateRecord](s, archive.PolicyHashPath(archive.KindMandate, h))
}

func (s *Store) PolicyAllow(_ context.Context, h commitment.Hash) (*archive.PolicyAllowRecord, error) {
	return readAs[*archive.PolicyAllowRecord](s, archive.PolicyHashPath(archive.KindPolicyAllow, h))
}

func (s *Store) PolicyDeny(_ context.Context, h commitment.Hash, reason string) (*archive.PolicyDenyRecord, error) {
	rel, err := archive.PolicyDenyPath(h, reason)
	if err != nil {
		return nil, notFound(err)
	}
	return readAs[*archive.PolicyDenyRecord](s, rel)
}

func (s *Store) PolicyBucket(_ context.Context, h commitment.Hash) (*archive.PolicyBucketRecord, error) {
	return readAs[*archive.PolicyBucketRecord](s, archive.PolicyHashPath(archive.KindPolicyBucket, h))
}

func (s *Store) PolicyClosed(_ context.Context, h commitment.Hash) (*archive.PolicyClosedRecord, error) {
	return readAs[*archive.PolicyClosedRecord](s, archive.PolicyHashPath(archive.KindPolicyClosed, h))
}

func (s *Store) PolicySuccessor(_ context.Context, key commitment.Hash) (*archive.PolicySuccessorRecord, error) {
	return readAs[*archive.PolicySuccessorRecord](s, archive.PolicyHashPath(archive.KindPolicySuccessor, key))
}
