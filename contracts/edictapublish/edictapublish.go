// Package edictapublish carries the build artifacts of the EdictaPublish
// publication sink and the constants derived from them. It does no I/O.
package edictapublish

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/vgonkivs/edicta/internal/evm"
)

//go:embed runtime.hex
var runtimeHex string

//go:embed init.hex
var initHex string

//go:embed build.json
var buildJSON []byte

// DeterministicDeployer is the widely deployed CREATE2 factory; its call data
// is salt (32 bytes) followed by the init code.
const DeterministicDeployer = "4e59b44847b379578588920cA78FbF26c0B4956C"

// SaltLabel is hashed into the fixed salt, so the address depends only on the
// init code.
const SaltLabel = "edicta/v1/edicta-publish"

const addressHex = "dedc2b65d07a4c3506dbe6fe50a04373addcdb18"

var publishSelector = [4]byte{0x7f, 0xd2, 0x83, 0x46}

// ErrArtifact reports an embedded artifact that does not match its pin.
var ErrArtifact = errors.New("edictapublish: artifact check failed")

// Address is the pinned CREATE2 address of the sink. Consumers use it instead
// of recomputing it.
func Address() [20]byte {
	var out [20]byte
	b, _ := hex.DecodeString(addressHex)
	copy(out[:], b)
	return out
}

// PublishSelector is the first four bytes of keccak256("publish(bytes)").
func PublishSelector() [4]byte { return publishSelector }

// RuntimeCode is the runtime bytecode for a genesis alloc. It is nil if the
// embedded file does not decode; Check reports that.
func RuntimeCode() []byte { return decodeHex(runtimeHex) }

// InitCode is the creation bytecode (no constructor arguments). It is nil if
// the embedded file does not decode; Check reports that.
func InitCode() []byte { return decodeHex(initHex) }

// EventTopic is topic 0 of EdictaPayload(bytes32).
func EventTopic() [32]byte { return evm.Keccak256([]byte("EdictaPayload(bytes32)")) }

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
	h := evm.Keccak256(InitCode())
	buf := make([]byte, 0, 1+20+32+32)
	buf = append(buf, 0xff)
	buf = append(buf, decodeHex(DeterministicDeployer)...)
	buf = append(buf, s[:]...)
	buf = append(buf, h[:]...)
	sum := evm.Keccak256(buf)
	var out [20]byte
	copy(out[:], sum[12:])
	return out
}

// Check verifies the embedded artifacts before they are used for a
// deployment: both files decode and are non-empty, their hashes equal the
// ones recorded in the build metadata, the init code ends with the runtime
// code, and the CREATE2 address equals the pinned Address.
func Check() error {
	var bi struct {
		RuntimeSHA256 string `json:"runtime_sha256"`
		InitSHA256    string `json:"init_sha256"`
	}
	if err := json.Unmarshal(buildJSON, &bi); err != nil {
		return fmt.Errorf("%w: build metadata: %v", ErrArtifact, err)
	}
	for _, a := range []struct{ name, text, want string }{
		{"runtime.hex", runtimeHex, bi.RuntimeSHA256},
		{"init.hex", initHex, bi.InitSHA256},
	} {
		code, err := hex.DecodeString(strings.TrimSpace(a.text))
		if err != nil {
			return fmt.Errorf("%w: %s: %v", ErrArtifact, a.name, err)
		}
		if len(code) == 0 {
			return fmt.Errorf("%w: %s is empty", ErrArtifact, a.name)
		}
		sum := sha256.Sum256([]byte(a.text))
		if hex.EncodeToString(sum[:]) != a.want {
			return fmt.Errorf("%w: %s hash differs from build metadata", ErrArtifact, a.name)
		}
	}
	rt, ini := RuntimeCode(), InitCode()
	if len(ini) < len(rt) || hex.EncodeToString(ini[len(ini)-len(rt):]) != hex.EncodeToString(rt) {
		return fmt.Errorf("%w: init code does not end with the runtime code", ErrArtifact)
	}
	if Create2Address() != Address() {
		return fmt.Errorf("%w: CREATE2 address differs from the pinned address", ErrArtifact)
	}
	return nil
}

func decodeHex(s string) []byte {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil
	}
	return b
}
