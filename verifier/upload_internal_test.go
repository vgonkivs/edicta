package verifier

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUploadSize(t *testing.T) {
	tests := []struct {
		payload uint64
		want    uint64
		ok      bool
	}{
		{0, 0, false},
		{1, 262144, true},
		{262139, 262144, true},
		{262140, 524288, true},
		{1 << 27, 1<<27 + 262144, true},
		{1<<27 - 5, 1 << 27, true},
		{1<<27 + 1, 0, false},
	}
	for _, tc := range tests {
		got, ok := uploadSize(tc.payload)
		assert.Equal(t, tc.ok, ok, tc.payload)
		assert.Equal(t, tc.want, got, tc.payload)
	}
}
