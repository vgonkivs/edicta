package boltreg

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	bolt "go.etcd.io/bbolt"

	"github.com/vgonkivs/edicta/retention"
)

var (
	bucketRetention = []byte("fibre_retention")
	bucketRetMeta   = []byte("meta")
	bucketRetRuns   = []byte("runs")
	keyRetSchema    = []byte("schema")
	keyRetChain     = []byte("chain_id")
	keyRetSegment   = []byte("segment")
)

const retentionSchema = uint64(1)

var (
	retEnc, _ = cbor.CoreDetEncOptions().EncMode()
	retDec, _ = cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF, ExtraReturnErrors: cbor.ExtraDecErrorUnknownField}.DecMode()
)

type runWire struct {
	Segment    uint64 `cbor:"1,keyasint"`
	FirstFrom  uint64 `cbor:"2,keyasint"`
	FirstTo    uint64 `cbor:"3,keyasint"`
	LastFrom   uint64 `cbor:"4,keyasint"`
	LastTo     uint64 `cbor:"5,keyasint"`
	RetentionS uint64 `cbor:"6,keyasint"`
	FirstAt    uint64 `cbor:"7,keyasint"`
	LastAt     uint64 `cbor:"8,keyasint"`
}

func corrupt(format string, a ...any) error {
	return fmt.Errorf("%w: %s", retention.ErrStoreCorrupt, fmt.Sprintf(format, a...))
}

func runKey(r retention.Run) []byte {
	k := make([]byte, 16)
	binary.BigEndian.PutUint64(k, r.Segment)
	binary.BigEndian.PutUint64(k[8:], r.FirstFrom)
	return k
}

func encodeRun(r retention.Run) ([]byte, error) {
	return retEnc.Marshal(runWire(r))
}

func decodeRun(k, v []byte) (retention.Run, error) {
	if len(k) != 16 {
		return retention.Run{}, corrupt("run key has %d bytes", len(k))
	}
	var w runWire
	if err := retDec.Unmarshal(v, &w); err != nil {
		return retention.Run{}, corrupt("run %x: %v", k, err)
	}
	r := retention.Run(w)
	if string(runKey(r)) != string(k) {
		return retention.Run{}, corrupt("run %x does not match its key", k)
	}
	return r, nil
}

// retentionStore keeps the observation history in its own top-level bucket,
// so nothing here can touch the nonce buckets.
type retentionStore struct{ r *Registry }

var _ retention.Store = retentionStore{}

// RetentionStore returns the retention history kept in the same file. Every
// Append is one fsynced transaction.
func (r *Registry) RetentionStore() retention.Store { return retentionStore{r: r} }

// buckets returns the retention sub-buckets after checking the schema; with
// create false a missing bucket gives nil sub-buckets and no error.
func buckets(tx *bolt.Tx, create bool) (meta, runs *bolt.Bucket, err error) {
	top := tx.Bucket(bucketRetention)
	if top == nil {
		if !create {
			return nil, nil, nil
		}
		if top, err = tx.CreateBucket(bucketRetention); err != nil {
			return nil, nil, err
		}
		if meta, err = top.CreateBucket(bucketRetMeta); err != nil {
			return nil, nil, err
		}
		if runs, err = top.CreateBucket(bucketRetRuns); err != nil {
			return nil, nil, err
		}
		return meta, runs, meta.Put(keyRetSchema, u64(retentionSchema))
	}
	meta, runs = top.Bucket(bucketRetMeta), top.Bucket(bucketRetRuns)
	if meta == nil || runs == nil {
		return nil, nil, corrupt("sub-bucket missing")
	}
	if v := meta.Get(keyRetSchema); len(v) != 8 || binary.BigEndian.Uint64(v) != retentionSchema {
		return nil, nil, corrupt("schema is missing or not %d", retentionSchema)
	}
	if v := meta.Get(keyRetSegment); v != nil && len(v) != 8 {
		return nil, nil, corrupt("segment has %d bytes", len(v))
	}
	return meta, runs, nil
}

func lastRun(runs *bolt.Bucket) (retention.Run, bool, error) {
	k, v := runs.Cursor().Last()
	if k == nil {
		return retention.Run{}, false, nil
	}
	r, err := decodeRun(k, v)
	return r, err == nil, err
}

func (s retentionStore) Bind(_ context.Context, chainID string) error {
	return s.r.db.Update(func(tx *bolt.Tx) error {
		meta, _, err := buckets(tx, true)
		if err != nil {
			return err
		}
		if cur := meta.Get(keyRetChain); cur != nil {
			if string(cur) != chainID {
				return fmt.Errorf("%w: bound to %q, asked for %q", retention.ErrChainMismatch, cur, chainID)
			}
			return nil
		}
		return meta.Put(keyRetChain, []byte(chainID))
	})
}

func (s retentionStore) Last(_ context.Context) (retention.Run, bool, error) {
	var (
		out  retention.Run
		have bool
	)
	err := s.r.db.View(func(tx *bolt.Tx) error {
		_, runs, err := buckets(tx, false)
		if err != nil || runs == nil {
			return err
		}
		out, have, err = lastRun(runs)
		return err
	})
	return out, have, err
}

func (s retentionStore) Append(_ context.Context, smp retention.Sample, p retention.Policy) error {
	return s.r.db.Update(func(tx *bolt.Tx) error {
		meta, runs, err := buckets(tx, true)
		if err != nil {
			return err
		}
		last, have, err := lastRun(runs)
		if err != nil {
			return err
		}
		var top uint64
		if v := meta.Get(keyRetSegment); v != nil {
			top = binary.BigEndian.Uint64(v)
		}
		top = max(top, last.Segment)
		run, appendNew := retention.Plan(last, have, top, smp, p)
		if !appendNew {
			// Same key as the last run; its position never changes.
			return putRun(runs, run)
		}
		if err := putRun(runs, run); err != nil {
			return err
		}
		return meta.Put(keyRetSegment, u64(max(top, run.Segment)))
	})
}

func putRun(runs *bolt.Bucket, r retention.Run) error {
	v, err := encodeRun(r)
	if err != nil {
		return fmt.Errorf("boltreg: encode run: %w", err)
	}
	return runs.Put(runKey(r), v)
}

func (s retentionStore) Segment(_ context.Context, height uint64) ([]retention.Run, error) {
	var out []retention.Run
	err := s.r.db.View(func(tx *bolt.Tx) error {
		_, runs, err := buckets(tx, false)
		if err != nil || runs == nil {
			return err
		}
		all, err := readRuns(runs)
		out = retention.Covering(all, height)
		return err
	})
	return out, err
}

func readRuns(runs *bolt.Bucket) ([]retention.Run, error) {
	var all []retention.Run
	err := runs.ForEach(func(k, v []byte) error {
		r, err := decodeRun(k, v)
		all = append(all, r)
		return err
	})
	return all, err
}

func (s retentionStore) Prune(_ context.Context, before uint64) (int, error) {
	n := 0
	err := s.r.db.Update(func(tx *bolt.Tx) error {
		_, runs, err := buckets(tx, false)
		if err != nil || runs == nil {
			return err
		}
		all, err := readRuns(runs)
		if err != nil {
			return err
		}
		for _, r := range all {
			if r.LastAt < before {
				if err := runs.Delete(runKey(r)); err != nil {
					return err
				}
				n++
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}
