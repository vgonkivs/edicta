package edictad

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vgonkivs/edicta/commitment"
)

func TestDenyIndexReservesOnce(t *testing.T) {
	x := newDenyIndex()
	k := denyKey{h: commitment.Hash{1}, reason: "ErrMinSpacing"}
	var won atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if x.reserve(k, 100, 10) {
				won.Add(1)
			}
		}()
	}
	wg.Wait()
	assert.EqualValues(t, 1, won.Load(), "concurrent retries write one deny")

	x.release(k)
	assert.True(t, x.reserve(k, 100, 10), "a failed write frees the key")
	x.commit(k)
	x.release(k)
	assert.False(t, x.reserve(k, 100, 10), "an acknowledged deny stays")

	other := denyKey{h: commitment.Hash{1}, reason: "ErrPeriodLimit"}
	assert.True(t, x.reserve(other, 100, 10), "another reason is another record")
}

func TestDenyIndexIsBounded(t *testing.T) {
	x := newDenyIndex()
	for i := range maxDenyIndex {
		var h commitment.Hash
		h[0], h[1], h[2] = byte(i), byte(i>>8), byte(i>>16)
		assert.True(t, x.reserve(denyKey{h: h}, 5, 1))
	}
	assert.True(t, x.reserve(denyKey{h: commitment.Hash{9, 9, 9, 9}}, 50, 10), "expired entries make room")
	assert.Len(t, x.m, 1)
}

func TestDenyIndexNeverEvictsAReservationInFlight(t *testing.T) {
	x := newDenyIndex()
	for i := range maxDenyIndex {
		var h commitment.Hash
		h[0], h[1], h[2] = byte(i), byte(i>>8), byte(i>>16)
		assert.True(t, x.reserve(denyKey{h: h}, 100, 10))
	}
	assert.True(t, x.reserve(denyKey{h: commitment.Hash{9, 9, 9, 9}}, 100, 10))
	assert.Len(t, x.m, maxDenyIndex+1, "a full index of reservations keeps them all")
	assert.False(t, x.reserve(denyKey{h: commitment.Hash{}}, 100, 10), "the first reservation still holds")

	settled := denyKey{h: commitment.Hash{1}}
	x.commit(settled)
	assert.True(t, x.reserve(denyKey{h: commitment.Hash{8, 8, 8, 8}}, 100, 10))
	_, ok := x.m[settled]
	assert.False(t, ok, "a settled entry makes room")
	assert.Len(t, x.m, maxDenyIndex+1)
}
