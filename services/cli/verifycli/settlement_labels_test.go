// SPDX-License-Identifier: Apache-2.0

package verifycli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSettlementOperatorLabels(t *testing.T) {
	h := strings.Repeat("ab", 32)
	base := []string{"verify", h, "--gate-key", gatePubHex(t), "--archive", t.TempDir(), "--settlement", "--receipt", "r"}
	with := func(extra ...string) []string { return append(append([]string(nil), base...), extra...) }

	_, err := parseFlags(with("--settlement-rpc", "gw=https://a.example", "--settlement-own-rpc", "own=http://b.example:8545",
		"--settlement-level", "L1"), &bytes.Buffer{})
	require.NoError(t, err, "two labels, two operators")

	_, err = parseFlags(with("--settlement-rpc", "gw=https://a.example", "--settlement-rpc", "gw=https://b.example",
		"--settlement-level", "L1"), &bytes.Buffer{})
	assert.ErrorContains(t, err, "distinct operators", "one label on two hosts is one operator")

	_, err = parseFlags(with("--settlement-rpc", "bad label=https://a.example"), &bytes.Buffer{})
	assert.Error(t, err)

	_, err = parseFlags(with("--settlement-rpc", "gw=https://gate.example/rpc", "--exclude-host", "gate.example"), &bytes.Buffer{})
	assert.ErrorContains(t, err, "excluded host", "a label never hides the host")
}
