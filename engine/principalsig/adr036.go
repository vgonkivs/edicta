package principalsig

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/ripemd160" //nolint:staticcheck // Cosmos addresses are RIPEMD-160 by definition.
)

const hashLinePrefix = "\nmandate hash: "

// ADR036Data is the text D a Cosmos wallet signs: the rendered mandate, then
// one last line with the mandate hash in lower-case hex, no trailing LF.
func ADR036Data(renderedMandate []byte, mandateHash [32]byte) []byte {
	out := make([]byte, 0, len(renderedMandate)+len(hashLinePrefix)+64)
	out = append(out, renderedMandate...)
	out = append(out, hashLinePrefix...)
	return hex.AppendEncode(out, mandateHash[:])
}

func hasHashLine(d []byte, mandateHash [32]byte) bool {
	return bytes.HasSuffix(d, hex.AppendEncode([]byte(hashLinePrefix), mandateHash[:]))
}

// ADR036SignDoc is the amino JSON sign document of an ADR-036 MsgSignData
// over data, as the Cosmos SDK and Keplr signArbitrary build it with an empty
// chain_id. Base64 and a bech32 address need no JSON escaping, so the
// document is a fixed template with two variable substrings.
func ADR036SignDoc(principal []byte, hrp string, data []byte) ([]byte, error) {
	signer, err := CosmosAddress(principal, hrp)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.WriteString(`{"account_number":"0","chain_id":"","fee":{"amount":[],"gas":"0"},"memo":"",`)
	b.WriteString(`"msgs":[{"type":"sign/MsgSignData","value":{"data":"`)
	b.WriteString(base64.StdEncoding.EncodeToString(data))
	b.WriteString(`","signer":"`)
	b.WriteString(signer)
	b.WriteString(`"}}],"sequence":"0"}`)
	return b.Bytes(), nil
}

// CosmosAddress is bech32(hrp, RIPEMD-160(SHA-256(principal))) of a
// compressed secp256k1 key.
func CosmosAddress(principal []byte, hrp string) (string, error) {
	if _, err := parseCompressed(principal); err != nil {
		return "", err
	}
	if !ValidHRP(hrp) {
		return "", fmt.Errorf("%w: hrp %q", ErrPrincipal, hrp)
	}
	sh := sha256.Sum256(principal)
	r := ripemd160.New()
	r.Write(sh[:])
	return bech32Encode(hrp, r.Sum(nil))
}

// ValidHRP reports whether hrp is 1..16 bytes of [a-z0-9], the mandate's
// principal_hrp charset.
func ValidHRP(hrp string) bool {
	if len(hrp) < 1 || len(hrp) > 16 {
		return false
	}
	for i := 0; i < len(hrp); i++ {
		c := hrp[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// CanonicalCosmosAddress parses a bech32 account address (BIP-173, checksum,
// no mixed case) and returns its canonical lower-case re-encoding, so pins
// compare one text per address.
func CanonicalCosmosAddress(s string) (string, error) {
	hrp, addr, err := ParseCosmosAddress(s)
	if err != nil {
		return "", err
	}
	return bech32Encode(hrp, addr[:])
}

// ParseCosmosAddress decodes a bech32 account address into its hrp and the
// 20-byte address.
func ParseCosmosAddress(s string) (string, [20]byte, error) {
	var addr [20]byte
	hrp, data, err := bech32Decode(s)
	if err != nil {
		return "", addr, err
	}
	if !ValidHRP(hrp) || len(data) != 20 {
		return "", addr, fmt.Errorf("%w: not a 20-byte account address with a [a-z0-9] hrp", ErrPrincipal)
	}
	copy(addr[:], data)
	return hrp, addr, nil
}
