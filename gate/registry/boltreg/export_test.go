package boltreg

import bolt "go.etcd.io/bbolt"

// NoSync reports the bbolt NoSync flag of the underlying database. The
// registry keeps its handle in the unexported field db.
func (r *Registry) NoSync() bool { return r.db.NoSync }

// SetMetaRaw writes a raw value under a key of the meta bucket, bypassing all
// validation, so tests can simulate a damaged file.
func (r *Registry) SetMetaRaw(key string, val []byte) error {
	return r.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketMeta).Put([]byte(key), val)
	})
}

// DeleteMetaRaw removes a key of the meta bucket, so tests can build a file
// of the previous layout.
func (r *Registry) DeleteMetaRaw(key string) error {
	return r.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketMeta).Delete([]byte(key))
	})
}

// SetRetentionRaw writes a raw value into a sub-bucket of the retention
// bucket, creating the sub-bucket if needed.
func (r *Registry) SetRetentionRaw(sub, key string, val []byte) error {
	return r.db.Update(func(tx *bolt.Tx) error {
		top, err := tx.CreateBucketIfNotExists([]byte("fibre_retention"))
		if err != nil {
			return err
		}
		b, err := top.CreateBucketIfNotExists([]byte(sub))
		if err != nil {
			return err
		}
		return b.Put([]byte(key), val)
	})
}

// CorruptRetentionRuns replaces every stored run with garbage and reports how
// many it touched.
func (r *Registry) CorruptRetentionRuns() (int, error) {
	n := 0
	err := r.db.Update(func(tx *bolt.Tx) error {
		top := tx.Bucket([]byte("fibre_retention"))
		if top == nil {
			return nil
		}
		runs := top.Bucket([]byte("runs"))
		if runs == nil {
			return nil
		}
		var keys [][]byte
		_ = runs.ForEach(func(k, _ []byte) error { keys = append(keys, append([]byte(nil), k...)); return nil })
		for _, k := range keys {
			if err := runs.Put(k, []byte{0xff, 0xfe, 0xfd}); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}

// DumpTop returns the top-level bucket names and, for the nonce buckets, a
// flat dump of their keys and values.
func (r *Registry) DumpTop() (names []string, nonce map[string]string) {
	nonce = map[string]string{}
	_ = r.db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, b *bolt.Bucket) error {
			names = append(names, string(name))
			if string(name) == "entries" || string(name) == "meta" {
				_ = b.ForEach(func(k, v []byte) error {
					nonce[string(name)+"/"+string(k)] = string(v)
					return nil
				})
			}
			return nil
		})
	})
	return names, nonce
}
