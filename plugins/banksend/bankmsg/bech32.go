package bankmsg

import (
	"errors"
	"fmt"
	"strings"
)

const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var gen = [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

// addrLen is the byte length of a Cosmos account address.
const addrLen = 20

var errAddress = errors.New("bankmsg: bad address")

func polymod(values []byte) uint32 {
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if top>>uint(i)&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

func hrpExpand(hrp string) []byte {
	out := make([]byte, 0, 2*len(hrp)+1)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]&31)
	}
	return out
}

func checksum(hrp string, data []byte) []byte {
	v := append(hrpExpand(hrp), data...)
	v = append(v, 0, 0, 0, 0, 0, 0)
	mod := polymod(v) ^ 1
	out := make([]byte, 6)
	for i := range out {
		out[i] = byte(mod >> uint(5*(5-i)) & 31)
	}
	return out
}

func to5(b []byte) []byte {
	var out []byte
	acc, bits := uint32(0), 0
	for _, x := range b {
		acc = acc<<8 | uint32(x)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out = append(out, byte(acc>>uint(bits)&31))
		}
		acc &= 1<<uint(bits) - 1
	}
	if bits > 0 {
		out = append(out, byte(acc<<uint(5-bits)&31))
	}
	return out
}

// from5 is strict: leftover bits must be fewer than 5 and zero.
func from5(d []byte) ([]byte, bool) {
	var out []byte
	acc, bits := uint32(0), 0
	for _, x := range d {
		acc = acc<<5 | uint32(x)
		bits += 5
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(acc>>uint(bits)))
		}
		acc &= 1<<uint(bits) - 1
	}
	if bits >= 5 || acc != 0 {
		return nil, false
	}
	return out, true
}

// EncodeAddress returns the lower-case bech32 address of a 20-byte account.
func EncodeAddress(hrp string, raw []byte) (string, error) {
	if hrp == "" || hrp != strings.ToLower(hrp) {
		return "", fmt.Errorf("%w: prefix", errAddress)
	}
	if len(raw) != addrLen {
		return "", fmt.Errorf("%w: %d bytes", errAddress, len(raw))
	}
	d := to5(raw)
	d = append(d, checksum(hrp, d)...)
	var sb strings.Builder
	sb.WriteString(hrp)
	sb.WriteByte('1')
	for _, x := range d {
		sb.WriteByte(charset[x])
	}
	return sb.String(), nil
}

// DecodeAddress parses a lower-case bech32 (not bech32m) address with the
// given prefix into its 20 bytes.
func DecodeAddress(hrp, addr string) ([]byte, error) {
	if hrp == "" || addr == "" || len(addr) > 90 {
		return nil, fmt.Errorf("%w: length or prefix", errAddress)
	}
	pos := strings.LastIndexByte(addr, '1')
	if pos < 1 || addr[:pos] != hrp || len(addr)-pos-1 < 6 {
		return nil, fmt.Errorf("%w: prefix mismatch", errAddress)
	}
	for i := 0; i < pos; i++ {
		if addr[i] < 33 || addr[i] > 126 || addr[i] >= 'A' && addr[i] <= 'Z' {
			return nil, fmt.Errorf("%w: prefix character", errAddress)
		}
	}
	data := make([]byte, 0, len(addr)-pos-1)
	for i := pos + 1; i < len(addr); i++ {
		k := strings.IndexByte(charset, addr[i])
		if k < 0 {
			return nil, fmt.Errorf("%w: character at %d", errAddress, i)
		}
		data = append(data, byte(k))
	}
	if polymod(append(hrpExpand(hrp), data...)) != 1 {
		return nil, fmt.Errorf("%w: checksum", errAddress)
	}
	raw, ok := from5(data[:len(data)-6])
	if !ok || len(raw) != addrLen {
		return nil, fmt.Errorf("%w: payload", errAddress)
	}
	return raw, nil
}
