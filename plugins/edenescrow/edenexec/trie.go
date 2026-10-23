// SPDX-License-Identifier: Apache-2.0

package edenexec

import (
	"github.com/vgonkivs/edicta/internal/evm"
	"github.com/vgonkivs/edicta/internal/evm/rlp"
)

// DeriveSha is the root of the Merkle Patricia trie that maps rlp(i) to
// items[i], as go-ethereum's types.DeriveSha computes transactionsRoot and
// receiptsRoot. The root does not depend on the insertion order, so the
// trie is built at once from all keys. Items must not be empty: go-ethereum
// stores an empty value as no value, so such a root would differ.
func DeriveSha(items [][]byte) [32]byte {
	if len(items) == 0 {
		return evm.Keccak256(rlp.AppendString(nil, nil))
	}
	kvs := make([]trieKV, len(items))
	for i, it := range items {
		kvs[i] = trieKV{key: nibbles(rlp.AppendUint64(nil, uint64(i))), value: it}
	}
	return evm.Keccak256(trieNode(kvs, 0))
}

type trieKV struct {
	key   []byte // one nibble per byte
	value []byte
}

func nibbles(b []byte) []byte {
	out := make([]byte, 0, 2*len(b))
	for _, x := range b {
		out = append(out, x>>4, x&0x0f)
	}
	return out
}

// trieNode is the RLP encoding of the node holding kvs, whose keys agree on
// their first depth nibbles. Keys are distinct.
func trieNode(kvs []trieKV, depth int) []byte {
	if len(kvs) == 1 {
		return rlp.AppendList(nil, rlp.AppendString(nil, hexPrefix(kvs[0].key[depth:], true)), rlp.AppendString(nil, kvs[0].value))
	}
	if cp := commonPrefix(kvs, depth); cp > 0 {
		path := kvs[0].key[depth : depth+cp]
		return rlp.AppendList(nil, rlp.AppendString(nil, hexPrefix(path, false)), childRef(trieNode(kvs, depth+cp)))
	}
	var groups [16][]trieKV
	var value []byte
	for _, kv := range kvs {
		if len(kv.key) == depth {
			value = kv.value
			continue
		}
		n := kv.key[depth]
		groups[n] = append(groups[n], kv)
	}
	slots := make([][]byte, 17)
	for i, g := range groups {
		if len(g) == 0 {
			slots[i] = rlp.AppendString(nil, nil)
			continue
		}
		slots[i] = childRef(trieNode(g, depth+1))
	}
	slots[16] = rlp.AppendString(nil, value)
	return rlp.AppendList(nil, slots...)
}

// commonPrefix is the number of nibbles after depth that every key shares,
// stopping at the end of the shortest key.
func commonPrefix(kvs []trieKV, depth int) int {
	n := 0
	for {
		i := depth + n
		if i >= len(kvs[0].key) {
			return n
		}
		c := kvs[0].key[i]
		for _, kv := range kvs[1:] {
			if i >= len(kv.key) || kv.key[i] != c {
				return n
			}
		}
		n++
	}
}

// childRef embeds a node shorter than 32 bytes and refers to any other by
// its hash.
func childRef(enc []byte) []byte {
	if len(enc) < 32 {
		return enc
	}
	h := evm.Keccak256(enc)
	return rlp.AppendString(nil, h[:])
}

// hexPrefix is the compact encoding of a nibble path with its leaf flag.
func hexPrefix(path []byte, leaf bool) []byte {
	flag := byte(0)
	if leaf {
		flag = 2
	}
	out := make([]byte, 0, len(path)/2+1)
	if len(path)%2 == 1 {
		out = append(out, (flag+1)<<4|path[0])
		path = path[1:]
	} else {
		out = append(out, flag<<4)
	}
	for i := 0; i < len(path); i += 2 {
		out = append(out, path[i]<<4|path[i+1])
	}
	return out
}
