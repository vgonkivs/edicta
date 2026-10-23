// SPDX-License-Identifier: Apache-2.0

package importguard_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// The principal key signs mandates; its standalone tool stays as light as
// the signer.
func TestPrincipalToolIsLight(t *testing.T) {
	for _, args := range [][]string{
		{"list", "-deps", "./cmd/edicta-principal"},
		{"list", "-deps", "-tags", "edictadev", "./cmd/edicta-principal"},
	} {
		out := goOutIn(t, ".", args...)
		assert.Contains(t, out, "github.com/vgonkivs/edicta/internal/principalcli", "the guard lists the tool's packages")
		assert.Emptyf(t, heavyLines(out, heavyPrefixes...), "edicta-principal must stay light: go %s", strings.Join(args, " "))
	}
}

// edicta dev init writes DEV keys; only the edictadev build links it.
func TestDevInitOnlyInDevBuilds(t *testing.T) {
	const devinit = "github.com/vgonkivs/edicta/services/cli/devinitcmd"
	prod := goOutIn(t, "services/cli", "list", "-deps", "./cmd/edicta")
	assert.Contains(t, prod, "github.com/vgonkivs/edicta/services/cli/edictacli\n", "the guard lists the binary's packages")
	assert.NotContains(t, prod, devinit+"\n")

	dev := goOutIn(t, "services/cli", "list", "-deps", "-tags", "edictadev", "./cmd/edicta")
	assert.Contains(t, dev, devinit+"\n")
}

// No module but examples itself may link an example package.
func TestNoProductionPackageImportsExamples(t *testing.T) {
	const examples = "github.com/vgonkivs/edicta/examples"
	for _, dir := range []string{".", "plugins/celestia", "services/gate", "services/signer", "services/cli"} {
		for _, tags := range []string{"", "edictadev"} {
			args := []string{"list", "-deps"}
			if tags != "" {
				args = append(args, "-tags", tags)
			}
			out := goOutIn(t, dir, append(args, "./...")...)
			assert.Emptyf(t, heavyLines(out, examples), "%s (tags %q) links an example", dir, tags)
		}
	}
}
