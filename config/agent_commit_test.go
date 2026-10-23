// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAgentCommitSettingsAreValidated(t *testing.T) {
	ok := Agent{ID: "a1", KeyFile: "k", SubmitterTrust: SubmitterSameOperator, GateKeys: []string{strings.Repeat("ab", 32)}}
	require.NoError(t, ok.ValidateBasic())
	require.NoError(t, Agent{ID: "a1", KeyFile: "k"}.ValidateBasic(), "the keys are optional in the file; commit refuses to run without them")

	bad := ok
	bad.SubmitterTrust = "friendly"
	assert.Error(t, bad.ValidateBasic())
	bad = ok
	bad.GateKeys = []string{"zz"}
	assert.Error(t, bad.ValidateBasic())
}
