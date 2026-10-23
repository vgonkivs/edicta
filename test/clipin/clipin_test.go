// SPDX-License-Identifier: Apache-2.0

//go:build clipin

// Package clipin pins the command line of every entry point: it builds the
// binaries, replays the case table and compares exit code, stdout and stderr
// with golden files. Regenerate the goldens with
//
//	go test -tags clipin ./test/clipin -update
package clipin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/internal/testkit"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// entry is how one binary is built: the module directory relative to the
// repository root, the package inside it and the build tags.
type entry struct {
	module string
	pkg    string
	tags   string
}

// tcase is one invocation. id names the golden file and never changes;
// argv[0] is a key of entries and the rest are the arguments, with the
// placeholders of expand.
type tcase struct {
	id   string
	argv []string
	// masks hide the parts of the output that differ between runs, such as
	// fresh keys, addresses and times.
	masks []mask
}

type mask struct {
	re   *regexp.Regexp
	with string
}

func TestCLIPin(t *testing.T) {
	repo := testkit.RepoRoot(t)
	bin := buildAll(t, repo)
	fix := fixtures(t, repo)
	golden := filepath.Join(repo, "test", "clipin", "testdata", "golden")

	seen := map[string]bool{}
	for _, c := range cases {
		require.Falsef(t, seen[c.id], "duplicate case id %s", c.id)
		seen[c.id] = true
		t.Run(c.id, func(t *testing.T) {
			_, ok := entries[c.argv[0]]
			require.Truef(t, ok, "no entry point %q", c.argv[0])
			work := t.TempDir()
			for _, d := range []string{"home", "tmp"} {
				require.NoError(t, os.Mkdir(filepath.Join(work, d), 0o700))
			}
			got := record(t, invoke(t, bin, fix, work, c), bin, c.argv[0], fix, work, repo, c.masks)
			path := filepath.Join(golden, filepath.FromSlash(c.id)+".golden")
			if *update {
				require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
				require.NoError(t, os.WriteFile(path, got, 0o644))
				return
			}
			want, err := os.ReadFile(path)
			require.NoError(t, err, "missing golden; run with -update")
			assert.Equal(t, string(want), string(got))
		})
	}

	if !*update {
		// A golden without a case would pin nothing.
		require.NoError(t, filepath.WalkDir(golden, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			rel, err := filepath.Rel(golden, p)
			if err != nil {
				return err
			}
			id := strings.TrimSuffix(filepath.ToSlash(rel), ".golden")
			assert.Truef(t, seen[id], "golden %s has no case", id)
			return nil
		}))
	}
}

// buildAll builds every entry point into one directory, one go build per
// module and tag set. Each group builds into its own directory first, since
// a binary takes the name of its package directory and two entries may build
// the same package with other tags.
func buildAll(t *testing.T, repo string) string {
	t.Helper()
	dir := t.TempDir()
	goBin := filepath.Join(runtime.GOROOT(), "bin", "go")
	if _, err := os.Stat(goBin); err != nil {
		goBin, err = exec.LookPath("go")
		require.NoError(t, err)
	}
	groups := map[[2]string][]string{}
	for name, e := range entries {
		k := [2]string{e.module, e.tags}
		groups[k] = append(groups[k], name)
	}
	keys := make([][2]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i][0]+keys[i][1] < keys[j][0]+keys[j][1] })
	for i, k := range keys {
		names := groups[k]
		sort.Strings(names)
		out := filepath.Join(dir, fmt.Sprintf("group%d", i))
		require.NoError(t, os.Mkdir(out, 0o755))
		args := []string{"-C", filepath.Join(repo, filepath.FromSlash(k[0])), "build", "-o", out + string(filepath.Separator)}
		if k[1] != "" {
			args = append(args, "-tags", k[1])
		}
		for _, name := range names {
			args = append(args, entries[name].pkg)
		}
		cmd := exec.Command(goBin, args...)
		// A GOROOT inherited from the shell may name another toolchain than
		// the go binary chosen here.
		cmd.Env = slices.DeleteFunc(os.Environ(), func(kv string) bool { return strings.HasPrefix(kv, "GOROOT=") })
		b, err := cmd.CombinedOutput()
		require.NoErrorf(t, err, "go %s\n%s", strings.Join(args, " "), b)
		for _, name := range names {
			require.NoError(t, os.Rename(filepath.Join(out, filepath.Base(entries[name].pkg)), filepath.Join(dir, name)))
		}
	}
	return dir
}

// fixtures writes every input file the cases read into one directory.
func fixtures(t *testing.T, repo string) string {
	t.Helper()
	dir := t.TempDir()
	td := filepath.Join(repo, "test", "clipin", "testdata")
	require.NoError(t, os.CopyFS(filepath.Join(dir, "verify"), os.DirFS(filepath.Join(td, "verify"))))
	for _, f := range []string{"edictad.toml", "signer.toml"} {
		b, err := os.ReadFile(filepath.Join(td, f))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, f), b, 0o600))
	}
	write := func(name string, b []byte) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), b, 0o600))
	}
	write("bad.toml", []byte("this is = = not toml\n"))
	write("escrow-empty.hex", []byte("\n"))
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	write("seed", seed)

	raw, err := os.ReadFile(testkit.SpecPath(t, "vectors", "policy", "mandate.json"))
	require.NoError(t, err)
	var v struct {
		Cases []struct {
			ID     string `json:"id"`
			CBOR   string `json:"mandate_cbor_hex"`
			Signed string `json:"signed_mandate_hex"`
		} `json:"cases"`
		Reject []struct {
			ID     string `json:"id"`
			Signed string `json:"signed_mandate_hex"`
		} `json:"reject"`
	}
	require.NoError(t, json.Unmarshal(raw, &v))
	want := map[string]bool{"mandate-m_full.hex": false, "signed-m_full.hex": false, "mandate-m_adr036.hex": false, "mandate-m_eip712.hex": false, "signed-sig_flipped.hex": false}
	for _, c := range v.Cases {
		for name, data := range map[string]string{"mandate-" + c.ID + ".hex": c.CBOR, "signed-" + c.ID + ".hex": c.Signed} {
			if _, ok := want[name]; ok {
				write(name, []byte(data))
				want[name] = true
			}
		}
	}
	for _, r := range v.Reject {
		if name := "signed-" + r.ID + ".hex"; r.ID == "sig_flipped" {
			write(name, []byte(r.Signed))
			want[name] = true
		}
	}
	for name, ok := range want {
		require.Truef(t, ok, "vector for %s not found", name)
	}
	return dir
}

type result struct {
	code           int
	stdout, stderr []byte
}

func invoke(t *testing.T, bin, fix, work string, c tcase) result {
	t.Helper()
	hash, err := os.ReadFile(filepath.Join(fix, "verify", "hash"))
	require.NoError(t, err)
	gateKey, err := os.ReadFile(filepath.Join(fix, "verify", "gate-key"))
	require.NoError(t, err)
	expand := strings.NewReplacer(
		"{fix}", fix,
		"{work}", work,
		"{hash}", strings.TrimSpace(string(hash)),
		"{gatekey}", strings.TrimSpace(string(gateKey)),
	)
	args := make([]string, 0, len(c.argv)-1)
	for _, a := range c.argv[1:] {
		args = append(args, expand.Replace(a))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(bin, c.argv[0]), args...)
	cmd.Dir = work
	// No inherited environment: no EDICTA_HOME, no proxies, no user config.
	cmd.Env = []string{
		"HOME=" + filepath.Join(work, "home"),
		"TMPDIR=" + filepath.Join(work, "tmp"),
		"PATH=/usr/bin:/bin",
		"LANG=C",
		"TZ=UTC",
	}
	cmd.WaitDelay = 5 * time.Second
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		require.Truef(t, errors.As(err, &ee), "%s: %v", c.id, err)
		require.NoErrorf(t, ctx.Err(), "%s timed out", c.id)
		code = ee.ExitCode()
	}
	return result{code: code, stdout: stdout.Bytes(), stderr: stderr.Bytes()}
}

// record is the golden form of a result.
func record(t *testing.T, r result, bin, name, fix, work, repo string, masks []mask) []byte {
	t.Helper()
	norm := func(b []byte) string {
		s := normalizeArgv0(string(b), filepath.Join(bin, name))
		s = replacePaths(t, s, [][2]string{{fix, "<fix>"}, {work, "<work>"}, {bin, "<bin>"}, {repo, "<repo>"}})
		for _, m := range masks {
			s = m.re.ReplaceAllString(s, m.with)
		}
		return s
	}
	var b strings.Builder
	fmt.Fprintf(&b, "exit %d\n", r.code)
	for _, sec := range []struct {
		name string
		data []byte
	}{{"stdout", r.stdout}, {"stderr", r.stderr}} {
		s := norm(sec.data)
		fmt.Fprintf(&b, "-- %s --\n%s", sec.name, s)
		if s != "" && !strings.HasSuffix(s, "\n") {
			b.WriteString("\n\\ no newline at end\n")
		}
	}
	return []byte(b.String())
}

// normalizeArgv0 rewrites the header the global flag set prints, which names
// the binary as it was invoked. It is the only line a change of the binary's
// path or command path may alter.
func normalizeArgv0(s, binPath string) string {
	lines := strings.SplitAfter(s, "\n")
	for i, l := range lines {
		body := strings.TrimSuffix(l, "\n")
		name, ok := strings.CutPrefix(body, "Usage of ")
		if !ok || !strings.HasSuffix(name, ":") {
			continue
		}
		name = strings.TrimSuffix(name, ":")
		if name == binPath || strings.HasPrefix(name, binPath+" ") {
			lines[i] = "Usage of <argv0>:" + l[len(body):]
		}
	}
	return strings.Join(lines, "")
}

// replacePaths swaps each directory, in its given and its symlink-resolved
// form, for a fixed token; longer paths go first so that a directory inside
// another keeps its own token.
func replacePaths(t *testing.T, s string, dirs [][2]string) string {
	t.Helper()
	var pairs [][2]string
	for _, d := range dirs {
		pairs = append(pairs, d)
		real, err := filepath.EvalSymlinks(d[0])
		require.NoError(t, err)
		if real != d[0] {
			pairs = append(pairs, [2]string{real, d[1]})
		}
	}
	sort.SliceStable(pairs, func(i, j int) bool { return len(pairs[i][0]) > len(pairs[j][0]) })
	for _, p := range pairs {
		s = strings.ReplaceAll(s, p[0], p[1])
	}
	return s
}
