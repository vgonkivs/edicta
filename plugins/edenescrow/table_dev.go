// SPDX-License-Identifier: Apache-2.0

//go:build edictadev

package edenescrow

import "slices"

// devTable adds the compose dev chain. 31337 is every local Hardhat or Anvil
// chain's id, so the row exists only in dev builds, and under its own
// extractor ID: a production verifier then reports a dev decision as having
// no extractor instead of a facts mismatch.
var devTable = table{id: DevExtractorID, rows: append(slices.Clone(productionRows),
	Row{ChainID: 31337, Escrow: escrowCreate2, CodeHash: escrowCodeHash})}

// builtTable is the table this build registers.
var builtTable = devTable
