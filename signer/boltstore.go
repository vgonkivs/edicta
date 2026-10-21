// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/vgonkivs/edicta/commitment"
)

var (
	bucketEntries = []byte("entries")
	// bucketWindow indexes the counted amounts by reservation time:
	// reserved_at (8 bytes, big-endian) || commitment_hash -> value, fee.
	bucketWindow = []byte("window")
	// bucketState indexes the entries by state: state || 0x00 ||
	// commitment_hash -> nothing, so the worker reads the open ones only.
	bucketState = []byte("state")
	// bucketSlot names the last decision that reserved each slot: slot ->
	// commitment_hash.
	bucketSlot = []byte("slot")
)

func stateKey(st State, h commitment.Hash) []byte {
	k := make([]byte, 0, len(st)+1+len(h))
	k = append(k, st...)
	k = append(k, 0)
	return append(k, h[:]...)
}

const lockTimeout = time.Second

// BoltStore is the Store on one bbolt file. A second process cannot open the
// same file.
type BoltStore struct{ db *bolt.DB }

var _ Store = (*BoltStore)(nil)

// OpenBoltStore opens or creates the store file, mode 0600.
func OpenBoltStore(path string) (*BoltStore, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: lockTimeout})
	if err != nil {
		return nil, fmt.Errorf("signer: open store: %w", err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketEntries, bucketWindow, bucketState, bucketSlot} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("signer: open store: %w", err)
	}
	return &BoltStore{db: db}, nil
}

func (s *BoltStore) Close() error { return s.db.Close() }

func unavailable(op string, err error) error {
	return fmt.Errorf("%w: store %s: %w", ErrUnavailable, op, err)
}

func windowKey(at int64, h commitment.Hash) []byte {
	k := make([]byte, 8+len(h))
	binary.BigEndian.PutUint64(k, uint64(max(at, 0)))
	copy(k[8:], h[:])
	return k
}

type windowVal struct {
	Value []byte `json:"v"`
	Fee   []byte `json:"f"`
}

func (s *BoltStore) Reserve(_ context.Context, e Entry, windowStart int64, admit func(Totals) error) (Entry, bool, error) {
	var stored Entry
	var existing bool
	var refused error
	err := s.db.Update(func(tx *bolt.Tx) error {
		entries, win := tx.Bucket(bucketEntries), tx.Bucket(bucketWindow)
		if raw := entries.Get(e.CommitmentHash[:]); raw != nil {
			existing = true
			return json.Unmarshal(raw, &stored)
		}
		t := Totals{Value: new(big.Int), Fee: new(big.Int)}
		c := win.Cursor()
		var old [][]byte
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if int64(binary.BigEndian.Uint64(k[:8])) < windowStart {
				old = append(old, bytes.Clone(k))
				continue
			}
			var w windowVal
			if err := json.Unmarshal(v, &w); err != nil {
				return err
			}
			t.Value.Add(t.Value, new(big.Int).SetBytes(w.Value))
			t.Fee.Add(t.Fee, new(big.Int).SetBytes(w.Fee))
		}
		slots := tx.Bucket(bucketSlot)
		if e.Slot != "" {
			if h := slots.Get([]byte(e.Slot)); h != nil {
				raw := entries.Get(h)
				if raw == nil {
					return fmt.Errorf("signer: store: slot index names a missing entry %x", h)
				}
				var holder Entry
				if err := json.Unmarshal(raw, &holder); err != nil {
					return err
				}
				t.SlotHolder = &holder
			}
		}
		if refused = admit(t); refused != nil {
			return refused
		}
		// Amounts out of the window no longer count; their entries stay.
		for _, k := range old {
			if err := win.Delete(k); err != nil {
				return err
			}
		}
		wv, err := json.Marshal(windowVal{Value: e.Value, Fee: e.Fee})
		if err != nil {
			return err
		}
		if err := win.Put(windowKey(e.ReservedAt, e.CommitmentHash), wv); err != nil {
			return err
		}
		raw, err := json.Marshal(e)
		if err != nil {
			return err
		}
		stored = e
		if err := tx.Bucket(bucketState).Put(stateKey(e.State, e.CommitmentHash), nil); err != nil {
			return err
		}
		if e.Slot != "" {
			if err := slots.Put([]byte(e.Slot), bytes.Clone(e.CommitmentHash[:])); err != nil {
				return err
			}
		}
		return entries.Put(e.CommitmentHash[:], raw)
	})
	switch {
	case refused != nil:
		return Entry{}, false, refused
	case err != nil:
		return Entry{}, false, unavailable("reserve", err)
	}
	return stored, existing, nil
}

func (s *BoltStore) Get(_ context.Context, h commitment.Hash) (Entry, bool, error) {
	var e Entry
	var found bool
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketEntries).Get(h[:])
		if raw == nil {
			return nil
		}
		found = true
		return json.Unmarshal(raw, &e)
	})
	if err != nil {
		return Entry{}, false, unavailable("get", err)
	}
	return e, found, nil
}

// errImmutable marks an update that would change what may not change.
var errImmutable = errors.New("signer: store: update changes an immutable field")

func (s *BoltStore) Update(_ context.Context, h commitment.Hash, fn func(*Entry) error) (Entry, error) {
	var out Entry
	var fnErr error
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketEntries)
		raw := b.Get(h[:])
		if raw == nil {
			fnErr = fmt.Errorf("%w: %x", ErrUnknownDecision, h)
			return fnErr
		}
		// Two decodings share no slice, so fn cannot change before in place.
		var before, e Entry
		if err := json.Unmarshal(raw, &before); err != nil {
			return err
		}
		if err := json.Unmarshal(raw, &e); err != nil {
			return err
		}
		if fnErr = fn(&e); fnErr != nil {
			return fnErr
		}
		if err := checkImmutable(before, e); err != nil {
			fnErr = err
			return err
		}
		enc, err := json.Marshal(e)
		if err != nil {
			return err
		}
		out = e
		if e.State != before.State {
			idx := tx.Bucket(bucketState)
			if err := idx.Delete(stateKey(before.State, h)); err != nil {
				return err
			}
			if err := idx.Put(stateKey(e.State, h), nil); err != nil {
				return err
			}
		}
		return b.Put(h[:], enc)
	})
	switch {
	case fnErr != nil:
		return Entry{}, fnErr
	case err != nil:
		return Entry{}, unavailable("update", err)
	}
	return out, nil
}

func checkImmutable(a, b Entry) error {
	same := a.CommitmentHash == b.CommitmentHash && a.Digest == b.Digest && a.ActionType == b.ActionType &&
		a.Key == b.Key && a.Payer == b.Payer && bytes.Equal(a.Value, b.Value) && bytes.Equal(a.Fee, b.Fee) &&
		a.ReservedAt == b.ReservedAt && a.Until == b.Until && bytes.Equal(a.Envelope, b.Envelope) &&
		bytes.Equal(a.Action, b.Action) && bytes.Equal(a.Salt, b.Salt) && bytes.Equal(a.Authorization, b.Authorization) &&
		a.AuthExpires == b.AuthExpires && a.Mode == b.Mode && bytes.Equal(a.Requirements, b.Requirements) && a.Slot == b.Slot
	if !same {
		return errImmutable
	}
	if len(a.Signed) > 0 && (!bytes.Equal(a.Signed, b.Signed) || a.RailRef != b.RailRef) {
		return fmt.Errorf("%w: signed bytes", errImmutable)
	}
	if len(a.PaymentProof) > 0 && !bytes.Equal(a.PaymentProof, b.PaymentProof) {
		return fmt.Errorf("%w: payment proof", errImmutable)
	}
	if a.Seen && !b.Seen {
		return fmt.Errorf("%w: seen", errImmutable)
	}
	return nil
}

func (s *BoltStore) IndexSlot(_ context.Context, h commitment.Hash, slot string) error {
	if slot == "" {
		return errors.New("signer: store: empty slot")
	}
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketEntries)
		raw := b.Get(h[:])
		if raw == nil {
			return fmt.Errorf("%w: %x", ErrUnknownDecision, h)
		}
		var e Entry
		if err := json.Unmarshal(raw, &e); err != nil {
			return err
		}
		if e.Slot != "" {
			return nil
		}
		e.Slot = slot
		enc, err := json.Marshal(e)
		if err != nil {
			return err
		}
		if err := b.Put(h[:], enc); err != nil {
			return err
		}
		slots := tx.Bucket(bucketSlot)
		if slots.Get([]byte(slot)) != nil {
			return nil
		}
		return slots.Put([]byte(slot), bytes.Clone(h[:]))
	})
	if err != nil {
		if errors.Is(err, ErrUnknownDecision) {
			return err
		}
		return unavailable("index slot", err)
	}
	return nil
}

func (s *BoltStore) Unfinished(_ context.Context, states ...State) ([]Entry, error) {
	var out []Entry
	err := s.db.View(func(tx *bolt.Tx) error {
		entries, c := tx.Bucket(bucketEntries), tx.Bucket(bucketState).Cursor()
		for _, st := range slices.Compact(slices.Sorted(slices.Values(states))) {
			prefix := stateKey(st, commitment.Hash{})[:len(st)+1]
			for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
				raw := entries.Get(k[len(prefix):])
				if raw == nil {
					return fmt.Errorf("signer: store: state index names a missing entry %x", k[len(prefix):])
				}
				var e Entry
				if err := json.Unmarshal(raw, &e); err != nil {
					return err
				}
				out = append(out, e)
			}
		}
		return nil
	})
	if err != nil {
		return nil, unavailable("list", err)
	}
	return out, nil
}
