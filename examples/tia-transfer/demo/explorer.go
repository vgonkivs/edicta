package demo

import (
	"fmt"
	"strings"
)

type explorer struct{ tx, block, addr string }

func newExplorer(p Preset) Explorer {
	return explorer{tx: p.ExplorerTxURL, block: p.ExplorerBlockURL, addr: p.ExplorerAddressURL}
}

func (e explorer) Tx(hash string) string { return strings.ReplaceAll(e.tx, "{hash}", hash) }

func (e explorer) Block(h uint64) string {
	return strings.ReplaceAll(e.block, "{height}", fmt.Sprint(h))
}

func (e explorer) Address(a string) string { return strings.ReplaceAll(e.addr, "{address}", a) }
