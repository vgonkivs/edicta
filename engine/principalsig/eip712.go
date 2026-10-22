package principalsig

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/sha3"
)

const (
	eip712DomainName    = "Edicta Mandate"
	eip712DomainVersion = "1"
	eip712DomainType    = "EIP712Domain(string name,string version)"
	eip712MandateType   = "Mandate(bytes32 mandateHash,bytes16 mandateId,uint64 version,string gateId)"
)

// keccak256 is Keccak-256 as Ethereum uses it, not SHA3-256.
func keccak256(parts ...[]byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	for _, p := range parts {
		h.Write(p)
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// EIP712DomainSeparator has no chainId, verifyingContract or salt: a mandate
// binds a gate, not a chain.
func EIP712DomainSeparator() [32]byte {
	t := keccak256([]byte(eip712DomainType))
	n := keccak256([]byte(eip712DomainName))
	v := keccak256([]byte(eip712DomainVersion))
	return keccak256(t[:], n[:], v[:])
}

// EIP712TypeHash is keccak256 of the Mandate type string.
func EIP712TypeHash() [32]byte { return keccak256([]byte(eip712MandateType)) }

// EIP712HashStruct is hashStruct(Mandate): bytes16 is right-padded, uint64
// left-padded to 32 bytes and the string hashed.
func EIP712HashStruct(m EIP712Message) [32]byte {
	th := EIP712TypeHash()
	var id, ver [32]byte
	copy(id[:], m.MandateID[:])
	binary.BigEndian.PutUint64(ver[24:], m.Version)
	g := keccak256([]byte(m.GateID))
	return keccak256(th[:], m.MandateHash[:], id[:], ver[:], g[:])
}

// EIP712Digest is keccak256(0x19 0x01 || domain_separator || hash_struct).
func EIP712Digest(m EIP712Message) [32]byte {
	ds := EIP712DomainSeparator()
	hs := EIP712HashStruct(m)
	return keccak256([]byte{0x19, 0x01}, ds[:], hs[:])
}

type typedField struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type typedData struct {
	Types struct {
		EIP712Domain []typedField `json:"EIP712Domain"`
		Mandate      []typedField `json:"Mandate"`
	} `json:"types"`
	PrimaryType string `json:"primaryType"`
	Domain      struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"domain"`
	Message struct {
		MandateHash string `json:"mandateHash"`
		MandateID   string `json:"mandateId"`
		Version     string `json:"version"`
		GateID      string `json:"gateId"`
	} `json:"message"`
}

// EIP712TypedDataJSON is the eth_signTypedData_v4 argument whose digest is
// EIP712Digest(m). The uint64 is a decimal string so no JSON reader rounds it.
func EIP712TypedDataJSON(m EIP712Message) ([]byte, error) {
	var td typedData
	td.Types.EIP712Domain = []typedField{{"name", "string"}, {"version", "string"}}
	td.Types.Mandate = []typedField{{"mandateHash", "bytes32"}, {"mandateId", "bytes16"}, {"version", "uint64"}, {"gateId", "string"}}
	td.PrimaryType = "Mandate"
	td.Domain.Name = eip712DomainName
	td.Domain.Version = eip712DomainVersion
	td.Message.MandateHash = "0x" + hex.EncodeToString(m.MandateHash[:])
	td.Message.MandateID = "0x" + hex.EncodeToString(m.MandateID[:])
	td.Message.Version = strconv.FormatUint(m.Version, 10)
	td.Message.GateID = m.GateID
	b, err := json.Marshal(&td)
	if err != nil {
		return nil, fmt.Errorf("principalsig: typed data: %w", err)
	}
	return b, nil
}

// EthereumAddress is the last 20 bytes of keccak256 of the uncompressed key
// without its 0x04 prefix. pub is a compressed or uncompressed secp256k1 key.
func EthereumAddress(pub []byte) ([20]byte, error) {
	k, err := secp256k1.ParsePubKey(pub)
	if err != nil {
		return [20]byte{}, fmt.Errorf("%w: %v", ErrPrincipal, err)
	}
	return ethAddress(k), nil
}

func ethAddress(k *secp256k1.PublicKey) [20]byte {
	h := keccak256(k.SerializeUncompressed()[1:])
	var a [20]byte
	copy(a[:], h[12:])
	return a
}
