// SPDX-License-Identifier: Apache-2.0

package gate_test

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/engine/dasource"
	"github.com/vgonkivs/edicta/engine/gate"
)

// The gate's names for the DA source sentinels are part of its refusal
// vocabulary: they must stay the very values the archive, the verifier and
// the committers return, with the texts clients already match.
func TestDASourceSentinelsAreTheGateSentinels(t *testing.T) {
	for _, tc := range []struct {
		name     string
		gate     error
		dasource error
		text     string
	}{
		{"ErrArchiveUnavailable", gate.ErrArchiveUnavailable, dasource.ErrArchiveUnavailable, "gate: archive unavailable"},
		{"ErrBlobNotFound", gate.ErrBlobNotFound, dasource.ErrBlobNotFound, "gate: blob not found"},
		{"ErrArchiveRecomputeUnsupported", gate.ErrArchiveRecomputeUnsupported, dasource.ErrArchiveRecomputeUnsupported, "gate: archive path needs a DA commitment recompute that is not available"},
		{"ErrDACommitmentMismatch", gate.ErrDACommitmentMismatch, dasource.ErrDACommitmentMismatch, "gate: DA commitment mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NotNil(t, tc.dasource)
			assert.Same(t, tc.dasource, tc.gate)
			require.ErrorIs(t, tc.gate, tc.dasource)
			require.ErrorIs(t, tc.dasource, tc.gate)
			assert.EqualError(t, tc.gate, tc.text)
		})
	}
}

func TestDASourceSentinelsStayDistinct(t *testing.T) {
	all := []error{dasource.ErrArchiveUnavailable, dasource.ErrBlobNotFound, dasource.ErrArchiveRecomputeUnsupported, dasource.ErrDACommitmentMismatch}
	for i, a := range all {
		for j, b := range all {
			if i != j {
				assert.NotErrorIs(t, a, b)
			}
		}
	}
	assert.NotErrorIs(t, dasource.ErrBlobNotFound, gate.ErrPayloadUnavailable)
}

func TestDASourceTypesAreTheGateTypes(t *testing.T) {
	assert.Equal(t, reflect.TypeFor[dasource.BlobSource](), reflect.TypeFor[gate.BlobSource]())
	assert.Equal(t, reflect.TypeFor[dasource.DACommitter](), reflect.TypeFor[gate.DACommitter]())
	assert.Equal(t, reflect.TypeFor[dasource.IntentSource](), reflect.TypeFor[gate.IntentSource]())
	assert.Equal(t, reflect.TypeFor[dasource.AnchorIntent](), reflect.TypeFor[gate.AnchorIntent]())
}
