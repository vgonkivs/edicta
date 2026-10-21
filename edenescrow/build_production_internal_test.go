// SPDX-License-Identifier: Apache-2.0

//go:build !edictadev

package edenescrow

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const buildName = "production"

// tablesInBuild are the extractor tables this build can construct.
var tablesInBuild = map[string]table{ExtractorID: productionTable}

func TestProductionBuildRegistersNoDevRow(t *testing.T) {
	assert.Equal(t, ExtractorID, RegisteredExtractorID())
	assert.Equal(t, ExtractorID, New().ID())
	_, ok := Lookup(31337)
	assert.False(t, ok, "the dev chain is no row of a production build")
	assert.Len(t, Rows(), 2)
}
