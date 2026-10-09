package principalsig

import (
	"fmt"
	"strings"
)

// BIP-173 bech32 (not bech32m), as Cosmos account addresses use it.

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func bech32Polymod(values []byte) uint32 {
	gen := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (top>>i)&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

func bech32HRPExpand(hrp string) []byte {
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

func convertBits(in []byte, from, to uint, pad bool) ([]byte, error) {
	var acc, bits uint
	maxv := uint(1)<<to - 1
	out := make([]byte, 0, len(in)*int(from)/int(to)+1)
	for _, v := range in {
		if uint(v)>>from != 0 {
			return nil, fmt.Errorf("%w: bech32 value out of range", ErrPrincipal)
		}
		acc = acc<<from | uint(v)
		bits += from
		for bits >= to {
			bits -= to
			out = append(out, byte(acc>>bits&maxv))
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, byte(acc<<(to-bits)&maxv))
		}
	} else if bits >= from || acc<<(to-bits)&maxv != 0 {
		return nil, fmt.Errorf("%w: bech32 padding", ErrPrincipal)
	}
	return out, nil
}

func bech32Encode(hrp string, data []byte) (string, error) {
	five, err := convertBits(data, 8, 5, true)
	if err != nil {
		return "", err
	}
	vals := append(bech32HRPExpand(hrp), five...)
	mod := bech32Polymod(append(vals, 0, 0, 0, 0, 0, 0)) ^ 1
	var sb strings.Builder
	sb.WriteString(hrp)
	sb.WriteByte('1')
	for _, v := range five {
		sb.WriteByte(bech32Charset[v])
	}
	for i := 0; i < 6; i++ {
		sb.WriteByte(bech32Charset[(mod>>(5*(5-i)))&31])
	}
	return sb.String(), nil
}

func bech32Decode(s string) (string, []byte, error) {
	bad := func(why string) (string, []byte, error) {
		return "", nil, fmt.Errorf("%w: bech32: %s", ErrPrincipal, why)
	}
	if len(s) > 90 {
		return bad("too long")
	}
	if strings.ToLower(s) != s && strings.ToUpper(s) != s {
		return bad("mixed case")
	}
	s = strings.ToLower(s)
	for i := 0; i < len(s); i++ {
		if s[i] < 33 || s[i] > 126 {
			return bad("character out of range")
		}
	}
	sep := strings.LastIndexByte(s, '1')
	if sep < 1 || sep+7 > len(s) {
		return bad("separator position")
	}
	hrp := s[:sep]
	five := make([]byte, 0, len(s)-sep-1)
	for i := sep + 1; i < len(s); i++ {
		v := strings.IndexByte(bech32Charset, s[i])
		if v < 0 {
			return bad("character outside the charset")
		}
		five = append(five, byte(v))
	}
	if bech32Polymod(append(bech32HRPExpand(hrp), five...)) != 1 {
		return bad("checksum")
	}
	data, err := convertBits(five[:len(five)-6], 5, 8, false)
	if err != nil {
		return "", nil, err
	}
	return hrp, data, nil
}
