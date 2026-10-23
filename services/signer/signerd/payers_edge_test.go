// SPDX-License-Identifier: Apache-2.0

package signerd_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/services/signer/signerd"
)

func TestConfigPayerSpellingVariantsAreOnePayer(t *testing.T) {
	base, ps := twoAgentsText(t)
	require.NoError(t, validate(base))
	addr := func(n string) string { return fmt.Sprintf("%x", ps[n].addr) }
	mixed := func(h string) string {
		var b strings.Builder
		for i, c := range h {
			if i%2 == 0 {
				b.WriteString(strings.ToUpper(string(c)))
			} else {
				b.WriteRune(c)
			}
		}
		return b.String()
	}
	setAddr := func(s, n, to string) string {
		return strings.Replace(s, `address = "0x`+addr(n)+`"`, `address = "`+to+`"`, 1)
	}
	setAgent := func(s, n, to string) string {
		old := ps[n].toml()
		repl := strings.Replace(old, `agent_pubkey = "`+ps[n].agent+`"`, `agent_pubkey = "`+to+`"`, 1)
		return strings.Replace(s, old, repl, 1)
	}
	cases := map[string]struct {
		text string
		want string
	}{
		"one address for two agents, mixed case": {setAddr(base, "b714", "0x"+mixed(addr("a714"))), "share payer address"},
		"one address for two agents on two chains, upper case": {setAddr(base, "btest", "0x"+strings.ToUpper(addr("a714"))),
			"share payer address"},
		"an address with an upper-case 0X prefix": {setAddr(base, "b714", "0X"+addr("b714")), "must be 0x and 40 hex"},
		"an address without the 0x prefix":        {setAddr(base, "b714", addr("b714")), "must be 0x and 40 hex"},
		"one agent twice on a chain, its key in upper case": {setAgent(base, "b714", strings.ToUpper(ps["a714"].agent)),
			"has two payers on this chain"},
		"one agent twice on a chain, its key with 0x": {setAgent(base, "b714", "0x"+ps["a714"].agent),
			"has two payers on this chain"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			require.NotEqual(t, base, tc.text)
			assert.ErrorContains(t, validate(tc.text), tc.want)
		})
	}
}

// One payer key reached through two spellings of its path, or through a
// symlink, is one payer for two agents: refused before or at start.
func TestOneKeyBehindTwoPathsRefusesToStart(t *testing.T) {
	f, payer := newFiles(t)
	eden := fakeEden(t, escrowCode(t))
	second := edPub(sha256.Sum256([]byte("second agent")))
	dir := filepath.Dir(f.payer)
	text := configText(f, payer, eden.URL)
	text = strings.Replace(text, "agent_pubkeys = [", fmt.Sprintf("agent_pubkeys = [%q, ", second), 1)
	_, otherAddr := payerKey(t, dir, "unused")

	link := filepath.Join(dir, "payer-link.key")
	require.NoError(t, os.Symlink(f.payer, link))
	dotted := dir + string(filepath.Separator) + "." + string(filepath.Separator) + filepath.Base(f.payer)
	require.NotEqual(t, f.payer, dotted)

	for name, file := range map[string]string{"a ./ in the path": dotted, "a symlink": link} {
		t.Run(name+", the same address", func(t *testing.T) {
			cfg, err := signerd.ParseConfig([]byte(text + payerEntry{agent: second, file: file, addr: payer}.toml()))
			require.NoError(t, err)
			cfg.ApplyDefaults()
			assert.ErrorContains(t, cfg.ValidateBasic(), "share payer address")
		})
		t.Run(name+", another address", func(t *testing.T) {
			cfg, err := signerd.ParseConfig([]byte(text + payerEntry{agent: second, file: file, addr: otherAddr}.toml()))
			require.NoError(t, err)
			cfg.ApplyDefaults()
			require.NoError(t, cfg.ValidateBasic())
			_, err = signerd.Build(context.Background(), cfg, quiet)
			require.Error(t, err, "the same key under two agents never starts")
		})
	}
}
