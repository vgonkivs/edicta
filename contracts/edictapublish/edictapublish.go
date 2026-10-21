// Package edictapublish carries the build artifacts of the EdictaPublish
// publication sink and the constants derived from them. It does no I/O.
package edictapublish

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"

	"golang.org/x/crypto/sha3"
)

//go:embed runtime.hex
var runtimeHex string

//go:embed init.hex
var initHex string

// DeterministicDeployer is the widely deployed CREATE2 factory; its call data
// is salt (32 bytes) followed by the init code.
const DeterministicDeployer = "4e59b44847b379578588920cA78FbF26c0B4956C"

// SaltLabel is hashed into the fixed salt, so the address depends only on the
// init code.
const SaltLabel = "edicta/v1/edicta-publish"

// PublishSelector is the first four bytes of keccak256("publish(bytes)").
var PublishSelector = [4]byte{0x7f, 0xd2, 0x83, 0x46}

// RuntimeCode is the runtime bytecode for a genesis alloc.
func RuntimeCode() []byte { return mustHex(runtimeHex) }

// InitCode is the creation bytecode (no constructor arguments).
func InitCode() []byte { return mustHex(initHex) }

// EventTopic is topic 0 of EdictaPayload(bytes32).
func EventTopic() [32]byte { return keccak([]byte("EdictaPayload(bytes32)")) }

// PayloadTopic is topic 1 of the event for a blob: sha256(blob).
func PayloadTopic(blob []byte) [32]byte { return sha256.Sum256(blob) }

// Salt is the fixed CREATE2 salt.
func Salt() [32]byte { return sha256.Sum256([]byte(SaltLabel)) }

// DeployCalldata is the call data for DeterministicDeployer: salt || init code.
func DeployCalldata() []byte {
	s := Salt()
	return append(s[:], InitCode()...)
}

// Create2Address is the address the deployer produces for the fixed salt and
// the checked-in init code.
func Create2Address() [20]byte {
	s := Salt()
	h := keccak(InitCode())
	buf := make([]byte, 0, 1+20+32+32)
	buf = append(buf, 0xff)
	buf = append(buf, mustHex(DeterministicDeployer)...)
	buf = append(buf, s[:]...)
	buf = append(buf, h[:]...)
	sum := keccak(buf)
	var out [20]byte
	copy(out[:], sum[12:])
	return out
}

func keccak(b []byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(b)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// The inputs are embedded files pinned by the artifact tests; an empty result
// on a decode failure makes every one of those checks fail.
func mustHex(s string) []byte {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil
	}
	return b
}
