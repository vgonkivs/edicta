// SPDX-License-Identifier: Apache-2.0

package gatechain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInvalidConfigNamesGatechainAndMatchesTheSentinel(t *testing.T) {
	err := invalidConfig("no consensus reader")
	require.ErrorIs(t, err, ErrInvalidConfig)
	assert.EqualError(t, err, "gatechain: invalid config: no consensus reader")
}
