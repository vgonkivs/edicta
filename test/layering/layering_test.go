// SPDX-License-Identifier: Apache-2.0

// Package layering_test checks the production imports of every package in
// the root module and in the nested modules that build against it.
// Packages are classified by today's paths: moving a package without
// updating the table fails the test, and so does an exception or a rule
// whose packages no longer exist.
package layering_test

import (
	"bytes"
	"io/fs"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/internal/testkit"
)

type class string

const (
	internalPkg  class = "internal"
	format       class = "format"
	principalsig class = "principalsig"
	sdk          class = "sdk"
	engine       class = "engine"
	api          class = "api"
	config       class = "config"
	service      class = "service"
	contracts    class = "contracts"
	example      class = "example"
	testsupport  class = "testsupport"
	// nested covers the packages of the Celestia-linked nested modules that
	// have no class of their own yet; only the global rules apply to them.
	nested class = "nested"

	plugin = "plugin:"
)

// classes maps a path relative to the root module to its class; the
// longest matching prefix wins.
var classes = map[string]class{
	"internal":                        internalPkg,
	"engine/commitment":               format,
	"engine/dacommit":                 format,
	"engine/dacommit/blobv1":          engine,
	"engine/principalsig":             principalsig,
	"sdk":                             sdk,
	"engine/policy":                   engine,
	"engine/gate":                     engine,
	"engine/retention":                engine,
	"engine/retention/retentionstore": testsupport,
	"engine/archive":                  engine,
	"engine/verifier":                 engine,
	"api/edictaapi":                   api,

	"plugins/banksend": plugin + "banksend",

	"plugins/edenescrow": plugin + "edenescrow",
	"plugins/ibkr":       plugin + "ibkr",

	"examples":  example,
	"signer":    service,
	"cmd":       service,
	"contracts": contracts,
	"test":      testsupport,

	"celestia/config":  config,
	"celestia/keyfile": internalPkg,
	"celestia/secret":  internalPkg,
}

// allowed lists the classes each class may import, besides the global
// rules below.
var allowed = map[class][]class{
	internalPkg:  {internalPkg},
	format:       {format, internalPkg},
	principalsig: {format, internalPkg},
	sdk:          {format, sdk, internalPkg},
	engine:       {format, principalsig, sdk, engine, internalPkg},
	api:          {format, principalsig, sdk, engine, internalPkg},
	contracts:    {contracts, internalPkg},
}

// configDataTables are the rail packages config may read: presets use the
// compiled escrow table so that preset, signer and verifier cannot disagree.
var configDataTables = []string{"plugins/edenescrow"}

// narrow forbids edges the class rules allow.
var narrow = []struct {
	why  string
	from []string
	to   func(rel string) bool
}{
	{
		why:  "storage, verification and the DA committer must not depend on the authorizer",
		from: []string{"engine/archive", "engine/archive/fsarchive", "engine/archive/httparchive", "engine/verifier", "celestia/fibrecommit"},
		to:   under("engine/gate"),
	},
	{
		why:  "agent binaries must not link the gate",
		from: []string{"sdk", "sdk/blob", "sdk/payload", "api/edictaapi"},
		to:   under("engine/gate"),
	},
	{
		why:  "the signer core must stay rail-agnostic",
		from: []string{"signer"},
		to:   func(rel string) bool { return strings.HasPrefix(string(classify(rel, false)), plugin) },
	},
}

// exceptions are today's known violations, as importer -> imported paths
// relative to the root module. Each entry must still occur.
var exceptions = map[string][]string{
	// The demo and edicta-live drive the tia-transfer example agent and
	// its price feed.
	"celestia/demo": {"examples/tia-transfer/pricefeed"},
	"celestia/cmd/edicta-live": {
		"examples/tia-transfer/agent", "examples/tia-transfer/pricefeed",
		"examples/tia-transfer/pricetrigger",
	},

	// The archive and the verifier take the DA source interfaces, the
	// committer interface and their sentinels from the gate package.
	"engine/archive":           {"engine/gate"},
	"engine/archive/fsarchive": {"engine/gate"},
	"engine/verifier":          {"engine/gate"},
	"celestia/fibrecommit":     {"engine/gate"},

	// The agent HTTP client maps error codes to the gate's sentinels.
	"api/edictaapi": {"engine/gate"},

	// The signer core takes wallet signature types and requirement errors
	// from the Eden escrow profile.
	"signer": {"plugins/edenescrow"},
}

func TestLayering(t *testing.T) {
	pkgs := listAll(t, testkit.ModulePath(t))
	require.NotEmpty(t, pkgs)
	classOf := func(rel string) class {
		if p, ok := pkgs[rel]; ok {
			return classify(rel, p.nested)
		}
		return classify(rel, false)
	}

	used := map[string]bool{}
	for prefix := range classes {
		used[prefix] = false
	}
	for rel := range pkgs {
		if p, ok := longestPrefix(rel); ok {
			used[p] = true
		}
	}
	for prefix, ok := range used {
		assert.Truef(t, ok, "class entry %q matches no package", prefix)
	}
	for _, r := range narrow {
		for _, from := range r.from {
			assert.Containsf(t, pkgs, from, "rule %q names %s, which is not a package", r.why, from)
		}
	}

	hit := map[string]bool{}
	var bad []string
	for _, rel := range sortedKeys(pkgs) {
		p := pkgs[rel]
		for _, imp := range p.imports {
			if why := violation(rel, classOf(rel), imp, classOf(imp)); why != "" {
				if slices.Contains(exceptions[rel], imp) {
					hit[rel+" -> "+imp] = true
					continue
				}
				bad = append(bad, rel+" -> "+imp+": "+why)
			}
		}
	}
	assert.Empty(t, bad, "layering violations")
	for from, tos := range exceptions {
		for _, to := range tos {
			assert.Truef(t, hit[from+" -> "+to], "exception %s -> %s no longer occurs; remove it", from, to)
		}
	}
}

func violation(from string, fc class, to string, tc class) string {
	if fc == "" {
		return "importer has no class"
	}
	if fc == testsupport {
		return ""
	}
	if tc == testsupport {
		return "production code imports a test package"
	}
	if hasElem(to, "examples") && !hasElem(from, "examples") {
		return "production code imports an example"
	}
	for _, r := range narrow {
		if slices.Contains(r.from, from) && r.to(to) {
			return r.why
		}
	}
	switch {
	case fc == example, fc == service, fc == nested:
		return ""
	case fc == config:
		if slices.Contains(configDataTables, to) {
			return ""
		}
		return check(fc, tc, []class{format, principalsig, engine, internalPkg})
	case strings.HasPrefix(string(fc), plugin):
		return check(fc, tc, []class{format, principalsig, sdk, engine, api, internalPkg, fc})
	default:
		return check(fc, tc, allowed[fc])
	}
}

func check(fc, tc class, ok []class) string {
	if slices.Contains(ok, tc) {
		return ""
	}
	return string(fc) + " must not import " + string(tc)
}

// classify returns the class of a path relative to the root module. A
// package of a nested module without an entry of its own is nested.
func classify(rel string, isNested bool) class {
	if isTestSupport(rel) {
		return testsupport
	}
	if p, ok := longestPrefix(rel); ok {
		return classes[p]
	}
	if isNested {
		return nested
	}
	return ""
}

func longestPrefix(rel string) (string, bool) {
	best := ""
	for p := range classes {
		if (rel == p || strings.HasPrefix(rel, p+"/")) && len(p) > len(best) {
			best = p
		}
	}
	return best, best != ""
}

func isTestSupport(rel string) bool {
	if hasElem(rel, "test") || hasElem(rel, "testdata") {
		return true
	}
	last := rel[strings.LastIndex(rel, "/")+1:]
	return strings.HasSuffix(last, "test") || strings.HasSuffix(last, "fake") || last == "testkit"
}

func hasElem(rel, elem string) bool {
	return slices.Contains(strings.Split(rel, "/"), elem)
}

func under(prefix string) func(string) bool {
	return func(rel string) bool { return rel == prefix || strings.HasPrefix(rel, prefix+"/") }
}

type pkg struct {
	nested  bool
	imports []string
}

// listAll lists the production imports of every package of the root module
// and of each nested module that builds against it, with and without the
// development build tag. Paths are relative to the root module.
func listAll(t *testing.T, module string) map[string]*pkg {
	t.Helper()
	root := testkit.RepoRoot(t)
	out := map[string]*pkg{}
	for _, dir := range moduleDirs(t, root) {
		isNested := dir != root
		for _, tags := range []string{"", "edictadev"} {
			for _, line := range strings.Split(goList(t, dir, tags), "\n") {
				fields := strings.Fields(line)
				if len(fields) == 0 {
					continue
				}
				rel, ok := strings.CutPrefix(fields[0], module+"/")
				require.Truef(t, ok, "%s is outside module %s", fields[0], module)
				p := out[rel]
				if p == nil {
					p = &pkg{nested: isNested}
					out[rel] = p
				}
				for _, imp := range fields[1:] {
					if r, ok := strings.CutPrefix(imp, module+"/"); ok && !slices.Contains(p.imports, r) {
						p.imports = append(p.imports, r)
					}
				}
			}
		}
	}
	return out
}

// moduleDirs returns the root and every nested module directory whose module
// path lies under the root module. The vector generators are independent of
// the code on purpose and are skipped.
func moduleDirs(t *testing.T, root string) []string {
	t.Helper()
	dirs := []string{root}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if p != root && (strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") ||
				name == "testdata" || name == "node_modules" || name == "journal" || name == "spec") {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() == "go.mod" && filepath.Dir(p) != root {
			dirs = append(dirs, filepath.Dir(p))
		}
		return nil
	})
	require.NoError(t, err)
	return dirs
}

func goList(t *testing.T, dir, tags string) string {
	t.Helper()
	args := []string{"list", "-f", "{{.ImportPath}}{{range .Imports}} {{.}}{{end}}"}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	cmd := exec.Command("go", append(args, "./...")...)
	cmd.Dir = dir
	cmd.Env = append(cmd.Environ(), "GOFLAGS=-mod=readonly", "GOWORK=off")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	require.NoError(t, err, "go list in %s: %s", dir, stderr.String())
	return string(out)
}

func sortedKeys(m map[string]*pkg) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
