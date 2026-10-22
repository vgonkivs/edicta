// SPDX-License-Identifier: Apache-2.0

package edictad

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/edenescrow"
)

func TestRefuseDevIDs(t *testing.T) {
	for _, id := range []string{edenescrow.DevExtractorID, "x/y-dev", "x-dev/v2"} {
		require.True(t, devMarked(id), id)
		require.Error(t, refuseDevIDs(false, []string{"ok/v1", id}), id)
		require.NoError(t, refuseDevIDs(true, []string{id}), "an edictadev build accepts %s", id)
	}
	for _, id := range []string{edenescrow.ExtractorID, edenescrow.ActionType, "device/v1", "x/devx"} {
		assert.False(t, devMarked(id), id)
		require.NoError(t, refuseDevIDs(false, []string{id}), id)
	}
}

// Each build registers only the ids it may: production never the dev one.
func TestPolicyExtractorsMatchTheBuild(t *testing.T) {
	_, err := policyExtractors()
	require.NoError(t, err)
	assert.Equal(t, isDevBuild(), devMarked(edenescrow.RegisteredExtractorID()))
}
