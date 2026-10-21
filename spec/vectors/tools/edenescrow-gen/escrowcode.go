// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	mainRPC = "https://rpc.eden.gateway.fm/"
	testRPC = "https://rpc.testnet.eden.gateway.fm/"
)

var deployer = common.HexToAddress("0x4e59b44847b379578588920ca78fbf26c0b4956c")

type escrowCode struct {
	Blockscout struct {
		Creator          string `json:"creator_address_hash"`
		CreationTx       string `json:"creation_transaction_hash"`
		CreationBytecode string `json:"creation_bytecode"`
		DeployedBytecode string `json:"deployed_bytecode"`
		ConstructorArgs  any    `json:"constructor_args"`
	} `json:"blockscout"`
	CreationTx struct {
		RPCTx struct {
			From  string  `json:"from"`
			To    *string `json:"to"`
			Nonce string  `json:"nonce"`
			Input string  `json:"input"`
			Hash  string  `json:"hash"`
		} `json:"rpc_tx"`
	} `json:"creation_tx"`
	RPCReads []struct {
		URL    string  `json:"url"`
		Method string  `json:"method"`
		Params []any   `json:"params"`
		Result *string `json:"result"`
	} `json:"rpc_reads"`
}

func (ec *escrowCode) read(url, method, addr string) string {
	for _, r := range ec.RPCReads {
		if r.URL != url || r.Method != method || r.Result == nil {
			continue
		}
		if addr == "" || (len(r.Params) > 0 && strings.EqualFold(fmt.Sprint(r.Params[0]), addr)) {
			return *r.Result
		}
	}
	panic(fmt.Sprintf("no recorded %s %s %s", url, method, addr))
}

// hasOpcode walks EVM code, skipping PUSH data, and reports whether op occurs.
func hasOpcode(code []byte, op byte) bool {
	for i := 0; i < len(code); i++ {
		c := code[i]
		if c == op {
			return true
		}
		if c >= 0x60 && c <= 0x7f {
			i += int(c - 0x5f)
		}
	}
	return false
}

var (
	escrowCopy common.Address
	codeHash   []byte
)

// loadEscrowCode checks the recorded deployment and fixes the table
// constants: the runtime code hash, and the CREATE2 address of the same
// creation code through the deterministic deployer with salt zero.
func loadEscrowCode(ec *escrowCode) obj {
	bs := ec.Blockscout
	runtime := unhex(ec.read(mainRPC, "eth_getCode", strings.ToLower(escrow714.Hex())))
	if !bytes.Equal(runtime, unhex(bs.DeployedBytecode)) {
		panic("eth_getCode differs from the verified deployed bytecode")
	}
	initCode := unhex(bs.CreationBytecode)
	prefix := initCode[:len(initCode)-len(runtime)]
	if !bytes.Equal(initCode[len(prefix):], runtime) || bs.ConstructorArgs != nil {
		panic("creation code is not constructor prefix plus the runtime code")
	}
	if hasOpcode(prefix, 0x55) {
		panic("constructor writes storage")
	}
	tx := ec.CreationTx.RPCTx
	if tx.To != nil || tx.Input != bs.CreationBytecode || tx.Hash != bs.CreationTx || !strings.EqualFold(tx.From, bs.Creator) {
		panic("creation tx does not match the explorer record")
	}
	nonce, ok := new(big.Int).SetString(strings.TrimPrefix(tx.Nonce, "0x"), 16)
	if !ok {
		panic("nonce")
	}
	creator := common.HexToAddress(bs.Creator)
	if crypto.CreateAddress(creator, nonce.Uint64()) != escrow714 {
		panic("CREATE address differs from the escrow")
	}
	initHash := crypto.Keccak256(initCode)
	var salt [32]byte
	escrowCopy = crypto.CreateAddress2(deployer, salt, initHash)
	codeHash = crypto.Keccak256(runtime)
	if ec.read(testRPC, "eth_chainId", "") != "0xdeadbfee" || ec.read(mainRPC, "eth_chainId", "") != "0x2ca" {
		panic("recorded chain ids")
	}
	low := func(a common.Address) string { return strings.ToLower(a.Hex()) }
	table = []tableRow{
		{714, escrow714, "all"},
		{3735928814, escrowCopy, "all"},
		{31337, escrowCopy, "edictadev"},
	}
	return obj{
		{"live_input", "spec/vectors/profiles/eden-escrow/live/escrow-code.json"},
		{"runtime_code_size", dec(uint64(len(runtime)))},
		{"runtime_code_hash", hx(codeHash)},
		{"constructor_prefix_hex", hx(prefix)},
		{"constructor_writes_storage", false},
		{"init_code_hash", hx(initHash)},
		{"create", obj{{"creator", low(creator)}, {"nonce", nonce.String()}, {"address", low(escrow714)}}},
		{"create2", obj{{"deployer", low(deployer)}, {"salt_hex", hx(salt[:])}, {"address", low(escrowCopy)}}},
		{"recorded_code", obj{
			{"mainnet_escrow_size", dec(uint64(len(runtime)))},
			{"mainnet_create2", ec.read(mainRPC, "eth_getCode", low(escrowCopy))},
			{"testnet_create2", ec.read(testRPC, "eth_getCode", low(escrowCopy))},
			{"testnet_mainnet_address", ec.read(testRPC, "eth_getCode", low(escrow714))},
			{"testnet_deployer", ec.read(testRPC, "eth_getCode", low(deployer))},
		}},
	}
}
