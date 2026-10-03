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
