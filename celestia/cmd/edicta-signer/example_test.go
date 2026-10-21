// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/signerd"
)

func TestExampleConfigIsValid(t *testing.T) {
	b, err := os.ReadFile("signer.example.toml")
	require.NoError(t, err)
	cfg, err := signerd.ParseConfig(b)
	require.NoError(t, err)
	cfg.ApplyDefaults()
	require.NoError(t, cfg.ValidateBasic())
}
