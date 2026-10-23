// SPDX-License-Identifier: Apache-2.0

//go:build edictadev

package devinitcmd

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

// Balances of the dev Eden accounts, in wei: 1000 TIA for the payer and 10 TIA
// for the facilitator.
const (
	payerWei       = "1000000000000000000000"
	facilitatorWei = "10000000000000000000"
	// gasLimit is the mainnet block gas limit.
	gasLimit = "0x2faf080"
)

var addrRE = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)

// edenGenesis is the dev chainspec for ev-reth: Prague and Osaka active from
// genesis as on the public chain.
type edenGenesis struct {
	Config     map[string]any    `json:"config"`
	Nonce      string            `json:"nonce"`
	Timestamp  string            `json:"timestamp"`
	ExtraData  string            `json:"extraData"`
	GasLimit   string            `json:"gasLimit"`
	Difficulty string            `json:"difficulty"`
	MixHash    string            `json:"mixHash"`
	Coinbase   string            `json:"coinbase"`
	Alloc      map[string]allocE `json:"alloc"`
}

type allocE struct {
	Balance string `json:"balance"`
	Code    string `json:"code,omitempty"`
}

// escrowSlot is the NativeEscrow runtime code at its CREATE2 address. Both
// empty means the slot is still a placeholder.
type escrowSlot struct {
	Address string
	Code    []byte
}

// buildEdenGenesis returns the chainspec JSON. The escrow code is included
// only when given: the real bytecode arrives with the escrow work, and until
// then the slot is absent.
func buildEdenGenesis(chainID uint64, payer, facilitator string, escrow escrowSlot) ([]byte, error) {
	if chainID == 0 {
		return nil, errors.New("eden chain id is zero")
	}
	for name, a := range map[string]string{"payer": payer, "facilitator": facilitator} {
		if !addrRE.MatchString(a) {
			return nil, fmt.Errorf("%s address %q is not a 0x address", name, a)
		}
	}
	if (escrow.Address == "") != (len(escrow.Code) == 0) {
		return nil, errors.New("escrow address and code go together")
	}
	alloc := map[string]allocE{
		key(payer):       {Balance: hexWei(payerWei)},
		key(facilitator): {Balance: hexWei(facilitatorWei)},
	}
	if escrow.Address != "" {
		if !addrRE.MatchString(escrow.Address) {
			return nil, fmt.Errorf("escrow address %q is not a 0x address", escrow.Address)
		}
		if _, dup := alloc[key(escrow.Address)]; dup {
			return nil, errors.New("escrow address collides with a funded account")
		}
		alloc[key(escrow.Address)] = allocE{Balance: "0x0", Code: "0x" + hex.EncodeToString(escrow.Code)}
	}
	zero := uint64(0)
	cfg := map[string]any{
		"chainId": chainID, "homesteadBlock": zero, "eip150Block": zero, "eip155Block": zero, "eip158Block": zero,
		"byzantiumBlock": zero, "constantinopleBlock": zero, "petersburgBlock": zero, "istanbulBlock": zero,
		"berlinBlock": zero, "londonBlock": zero, "shanghaiTime": zero, "cancunTime": zero, "pragueTime": zero,
		"osakaTime": zero, "terminalTotalDifficulty": zero, "terminalTotalDifficultyPassed": true,
		"blobSchedule": map[string]any{
			"cancun": map[string]any{"target": 3, "max": 6, "baseFeeUpdateFraction": 3338477},
			"prague": map[string]any{"target": 6, "max": 9, "baseFeeUpdateFraction": 5007716},
			"osaka":  map[string]any{"target": 6, "max": 9, "baseFeeUpdateFraction": 5007716},
		},
	}
	g := edenGenesis{
		Config: cfg, Nonce: "0x0", Timestamp: "0x0", ExtraData: "0x", GasLimit: gasLimit, Difficulty: "0x1",
		MixHash: "0x" + strings.Repeat("00", 32), Coinbase: "0x" + strings.Repeat("00", 20), Alloc: alloc,
	}
	return json.MarshalIndent(g, "", "  ")
}

// key is the alloc key: lower case without the 0x prefix, as geth writes it.
func key(addr string) string { return strings.ToLower(strings.TrimPrefix(addr, "0x")) }

// hexWei writes a decimal wei amount as the 0x hex a genesis balance takes.
func hexWei(s string) string {
	n, _ := new(big.Int).SetString(s, 10)
	return "0x" + n.Text(16)
}
