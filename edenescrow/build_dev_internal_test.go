// SPDX-License-Identifier: Apache-2.0

//go:build edictadev

package edenescrow

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const buildName = "edictadev"

// tablesInBuild are the extractor tables this build can construct.
var tablesInBuild = map[string]table{ExtractorID: productionTable, DevExtractorID: devTable}

func TestDevBuildRegistersDevID(t *testing.T) {
	assert.Equal(t, DevExtractorID, RegisteredExtractorID())
	assert.Equal(t, DevExtractorID, New().ID())
	r, ok := Lookup(31337)
	require.True(t, ok)
	assert.Equal(t, escrowCreate2, r.Escrow)
	assert.Len(t, Rows(), 3)
	// The production ID keeps its rows in a dev build.
	_, ok = productionTable.lookup(31337)
	assert.False(t, ok)
}
