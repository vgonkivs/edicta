package edictad

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/vgonkivs/edicta/archive"
)

// Under a private mandate a clear mandate, bucket or closed set never reaches
// the store, and the writer drops it instead of retrying.
func TestClearPolicyRecordsAreRefusedUnderAPrivateMandate(t *testing.T) {
	st := &memStore{}
	io := newArchiveIO(st)
	io.private = true
	w := &writer{io: io, q: &retryQueue{}, log: discard, timeout: time.Second}
	for _, r := range []archive.Record{&archive.MandateRecord{}, &archive.PolicyBucketRecord{}, &archive.PolicyClosedRecord{}} {
		_, err := io.put(t.Context(), r)
		assert.ErrorIs(t, err, errClearInPrivate)
		assert.Equal(t, writeStop, w.writeOne(t.Context(), r))
	}
	assert.Zero(t, st.putCount())
	assert.Zero(t, w.q.len())

	io.private = false
	_, err := io.put(t.Context(), &archive.MandateRecord{})
	assert.NoError(t, err)
	assert.Equal(t, 1, st.putCount())
}
