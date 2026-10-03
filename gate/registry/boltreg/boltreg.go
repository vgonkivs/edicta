// Package boltreg is the durable registry on bbolt. Every state change is
// one transaction, fsynced before the call returns, and the file lock admits
// one process per file.
package boltreg

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/fxamacker/cbor/v2"
	bolt "go.etcd.io/bbolt"

	"github.com/vgonkivs/edicta/gate/registry"
)

var (
	bucketEntries = []byte("entries")
	bucketMeta    = []byte("meta")
	keyEpoch      = []byte("epoch")
	keyWatermark  = []byte("watermark")
	keyCutoff     = []byte("prune_cutoff")
)

const lockTimeout = time.Second

type Registry struct {
	db      *bolt.DB
	claimed atomic.Bool
}

var _ registry.Registry = (*Registry)(nil)

// Open opens or creates the registry file. On creation the epoch is set to
// now in the same transaction that creates the buckets; on reopen it is
// never rewritten.
func Open(path string, now uint64) (*Registry, error) {
	if now == 0 {
		return nil, errors.New("boltreg: epoch must be set")
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: lockTimeout})
	if err != nil {
		return nil, fmt.Errorf("boltreg: open %s: %w", path, err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(bucketEntries); err != nil {
			return err
		}
		m, err := tx.CreateBucketIfNotExists(bucketMeta)
		if err != nil {
			return err
		}
		if m.Get(keyEpoch) != nil {
			_, err := readMeta(m)
			return err
		}
		if err := m.Put(keyEpoch, u64(now)); err != nil {
			return err
		}
		return m.Put(keyWatermark, u64(now))
	})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("boltreg: init %s: %w", path, err)
	}
	return &Registry{db: db}, nil
}

func (r *Registry) Close() error { return r.db.Close() }

// Claim marks the registry as owned by one gate.
func (r *Registry) Claim() (func(), error) {
	if !r.claimed.CompareAndSwap(false, true) {
		return nil, registry.ErrInUse
	}
	return func() { r.claimed.Store(false) }, nil
}

// readMeta decodes the metadata strictly. The epoch and the watermark must be
// present with exactly 8 bytes. The prune cutoff may be absent, which is the
// initial state of a new store and of one created before the field existed,
// and then reads as 0; a present value of any other length is an error.
func readMeta(m *bolt.Bucket) (registry.Meta, error) {
	var out registry.Meta
	for _, f := range []struct {
		key      []byte
		dst      *uint64
		optional bool
	}{{keyEpoch, &out.Epoch, false}, {keyWatermark, &out.Watermark, false}, {keyCutoff, &out.PruneCutoff, true}} {
		v := m.Get(f.key)
		if v == nil && f.optional {
			continue
		}
		if len(v) != 8 {
			return registry.Meta{}, fmt.Errorf("%w: %s has %d bytes", registry.ErrCorruptMeta, f.key, len(v))
		}
		*f.dst = binary.BigEndian.Uint64(v)
	}
	return out, nil
}

func u64(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

func dbKey(k registry.Key) []byte {
	b := make([]byte, 0, 48)
	b = append(b, k.PubKey[:]...)
	return append(b, k.Nonce[:]...)
}

func encode(e registry.Entry) ([]byte, error) { return cbor.Marshal(e) }

func decode(b []byte) (registry.Entry, error) {
	var e registry.Entry
	if err := cbor.Unmarshal(b, &e); err != nil {
		return registry.Entry{}, fmt.Errorf("boltreg: corrupt entry: %w", err)
	}
	return e, nil
}

func (r *Registry) Reserve(_ context.Context, e registry.Entry, tolerance uint64) error {
	if err := registry.CheckReserve(e); err != nil {
		return err
	}
	val, err := encode(e)
	if err != nil {
		return err
	}
	return r.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketEntries)
		if old := b.Get(dbKey(e.Key)); old != nil {
			existing, err := decode(old)
			if err != nil {
				return err
			}
			return &registry.ExistsError{Existing: existing}
		}
		m := tx.Bucket(bucketMeta)
		meta, err := readMeta(m)
		if err != nil {
			return err
		}
		w := meta.Watermark
		if c := meta.PruneCutoff; e.ValidUntil < c {
			return fmt.Errorf("%w: valid_until %d, cutoff %d", registry.ErrPrunedWindow, e.ValidUntil, c)
		}
		if registry.BelowWatermark(e.ReservedAt, tolerance, w) {
			return fmt.Errorf("%w: reserved_at %d, watermark %d", registry.ErrBelowWatermark, e.ReservedAt, w)
		}
		if err := b.Put(dbKey(e.Key), val); err != nil {
			return err
		}
		if e.ReservedAt > w {
			return m.Put(keyWatermark, u64(e.ReservedAt))
		}
		return nil
	})
}

func (r *Registry) Resolve(_ context.Context, k registry.Key, from registry.State, upd registry.Entry) error {
	return r.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketEntries)
		raw := b.Get(dbKey(k))
		if raw == nil {
			return registry.ErrNotFound
		}
		stored, err := decode(raw)
		if err != nil {
			return err
		}
		next, err := registry.Transition(stored, from, upd)
		if err != nil {
			return err
		}
		val, err := encode(next)
		if err != nil {
			return err
		}
		return b.Put(dbKey(k), val)
	})
}

func (r *Registry) Get(_ context.Context, k registry.Key) (registry.Entry, error) {
	var out registry.Entry
	err := r.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketEntries).Get(dbKey(k))
		if raw == nil {
			return registry.ErrNotFound
		}
		var err error
		out, err = decode(raw)
		return err
	})
	return out, err
}

func (r *Registry) Pending(_ context.Context) ([]registry.Entry, error) {
	var out []registry.Entry
	err := r.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketEntries).ForEach(func(_, v []byte) error {
			e, err := decode(v)
			if err != nil {
				return err
			}
			if registry.NeedsAttention(e) {
				out = append(out, e)
			}
			return nil
		})
	})
	return out, err
}

func (r *Registry) Recover(_ context.Context, now uint64) (int, error) {
	n := 0
	err := r.db.Update(func(tx *bolt.Tx) error {
		n = 0
		b := tx.Bucket(bucketEntries)
		type change struct {
			key, val []byte
		}
		var changes []change
		err := b.ForEach(func(k, v []byte) error {
			e, err := decode(v)
			if err != nil {
				return err
			}
			if e.State != registry.StateReserved {
				return nil
			}
			val, err := encode(registry.RecoverEntry(e, now))
			if err != nil {
				return err
			}
			changes = append(changes, change{append([]byte(nil), k...), val})
			return nil
		})
		if err != nil {
			return err
		}
		for _, c := range changes {
			if err := b.Put(c.key, c.val); err != nil {
				return err
			}
		}
		n = len(changes)
		return nil
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (r *Registry) Meta(_ context.Context) (registry.Meta, error) {
	var m registry.Meta
	err := r.db.View(func(tx *bolt.Tx) error {
		var err error
		m, err = readMeta(tx.Bucket(bucketMeta))
		return err
	})
	return m, err
}

func (r *Registry) Prune(_ context.Context, cutoff uint64) (int, error) {
	n := 0
	err := r.db.Update(func(tx *bolt.Tx) error {
		n = 0
		m := tx.Bucket(bucketMeta)
		meta, err := readMeta(m)
		if err != nil {
			return err
		}
		if cutoff > meta.PruneCutoff {
			if err := m.Put(keyCutoff, u64(cutoff)); err != nil {
				return err
			}
		}
		b := tx.Bucket(bucketEntries)
		var doomed [][]byte
		err = b.ForEach(func(k, v []byte) error {
			e, err := decode(v)
			if err != nil {
				return err
			}
			if registry.Prunable(e, cutoff) {
				doomed = append(doomed, append([]byte(nil), k...))
			}
			return nil
		})
		if err != nil {
			return err
		}
		for _, k := range doomed {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		n = len(doomed)
		return nil
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}
