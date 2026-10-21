// SPDX-License-Identifier: Apache-2.0

package edenescrow

import "slices"

// Row binds one chain to its escrow address and the keccak-256 hash of the
// escrow's runtime code.
type Row struct {
	ChainID  uint64
	Escrow   [20]byte
	CodeHash [32]byte
}

var (
	// escrowCodeHash is the keccak-256 of the NativeEscrow runtime code. The
	// contract has no immutables and its constructor writes no storage, so
	// every copy of the runtime code has this hash.
	escrowCodeHash = [32]byte{
		0x28, 0x1a, 0x5e, 0xc0, 0x49, 0x4b, 0x3c, 0x25, 0xba, 0x7d, 0x7e, 0x36, 0x64, 0x8a, 0x4f, 0x00,
		0xf9, 0xf9, 0x10, 0xd3, 0x88, 0x9c, 0xc0, 0x9d, 0x70, 0x67, 0x55, 0xbd, 0x89, 0x43, 0x00, 0xe5,
	}
	// escrowMainnet is the verified deployment on Eden mainnet, a plain
	// CREATE from an EOA.
	escrowMainnet = [20]byte{
		0x65, 0xd7, 0x7c, 0x98, 0xe7, 0x3d, 0xfb, 0xea, 0x91, 0xec,
		0xb7, 0x2b, 0x27, 0xc9, 0x75, 0x3e, 0x18, 0x6a, 0x94, 0xc8,
	}
	// escrowCreate2 is the CREATE2 address of the same creation code through
	// the deterministic deployer with a zero salt. The mainnet address cannot
	// be reproduced on another chain; this one can, by anyone.
	escrowCreate2 = [20]byte{
		0xe8, 0x51, 0xa9, 0xb2, 0x2d, 0x94, 0x9a, 0xe0, 0x05, 0xf6,
		0x5e, 0x1b, 0xa9, 0x7c, 0x9b, 0x0c, 0x18, 0x35, 0x4e, 0x5d,
	}
)

// productionRows are the rows of ExtractorID, the same in every build so
// that the extractor's output never depends on how it was built.
var productionRows = []Row{
	{ChainID: 714, Escrow: escrowMainnet, CodeHash: escrowCodeHash},        // Eden mainnet
	{ChainID: 3735928814, Escrow: escrowCreate2, CodeHash: escrowCodeHash}, // Eden testnet
}

// table is the compiled escrow table of one extractor ID.
type table struct {
	id   string
	rows []Row
}

var productionTable = table{id: ExtractorID, rows: productionRows}

func (t table) lookup(chainID uint64) (Row, bool) {
	for _, r := range t.rows {
		if r.ChainID == chainID {
			return r, true
		}
	}
	return Row{}, false
}

// Lookup returns the row of chainID in this build's table.
func Lookup(chainID uint64) (Row, bool) { return builtTable.lookup(chainID) }

// Rows returns a copy of this build's table.
func Rows() []Row { return slices.Clone(builtTable.rows) }

// RegisteredExtractorID is the extractor ID this build registers for
// ActionType: ExtractorID, or DevExtractorID in an edictadev build.
func RegisteredExtractorID() string { return builtTable.id }
