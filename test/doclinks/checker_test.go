// SPDX-License-Identifier: Apache-2.0

// Package doclinks checks the published markdown offline: every relative link
// and every repository path in backticks resolves to a file or directory of
// the repository, every go -C names a module directory and every ./package
// after it exists, and the names of removed binaries and directories no
// longer appear. The frozen specification is not checked: its text keeps the
// paths it was frozen with, and docs/code-locations.md maps them.
package doclinks

import (
	"bufio"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
)

const modulePath = "github.com/vgonkivs/edicta"

// CodeLocations is the map of old to new paths. The first column of its
// tables names paths that no longer exist, and it may name removed commands.
const CodeLocations = "docs/code-locations.md"

// Changelog is checked in its latest section only: older sections describe
// the tree of their release.
const Changelog = "CHANGELOG.md"

// Retired are top-level directories that existed before the layout moved
// under engine/, api/, plugins/, services/ and docs/. A backticked path under
// one of them is a stale path even though nothing under it exists any more.
var Retired = []string{
	"archive", "celestia", "commitment", "dacommit", "edenescrow", "edenexec",
	"edictaapi", "fibre", "gate", "guide", "policy", "principalsig",
	"retention", "signer", "verifier",
}

// identifiers look like paths under a retired directory but name protocol
// values, such as the bank-send extractor id celestia/tia-transfer/v1.
var identifiers = regexp.MustCompile(`^celestia/[a-z0-9-]+/v[0-9]+$`)

// Removed are names of binaries, commands and directories that no longer
// exist. They may appear only in the code-locations map and the changelog.
var Removed = []string{
	"celestia/bin", "go -C celestia", "go -C fibre", "edicta demo",
	"edictad -config", "edicta-devinit", "edicta-verify",
}

// Tree is the set of repository files and of the directories that hold them,
// as slash-separated paths relative to the root.
type Tree struct {
	files, dirs map[string]bool
}

// NewTree builds a Tree from file paths.
func NewTree(files []string) Tree {
	t := Tree{files: map[string]bool{}, dirs: map[string]bool{".": true}}
	for _, f := range files {
		f = path.Clean(f)
		t.files[f] = true
		for d := path.Dir(f); d != "."; d = path.Dir(d) {
			t.dirs[d] = true
		}
	}
	return t
}

// Has reports whether p is a file or a directory of the tree.
func (t Tree) Has(p string) bool { return t.files[p] || t.dirs[p] }

// IsDir reports whether p is a directory of the tree.
func (t Tree) IsDir(p string) bool { return t.dirs[p] }

// Problem is one finding: the document, its line and what is wrong.
type Problem struct {
	Doc  string
	Line int
	Msg  string
}

func (p Problem) String() string { return fmt.Sprintf("%s:%d: %s", p.Doc, p.Line, p.Msg) }

// Published selects the documents to check: every markdown file outside the
// specification.
func Published(t Tree) []string {
	var docs []string
	for p := range t.files {
		if !strings.HasSuffix(p, ".md") {
			continue
		}
		if strings.HasPrefix(p, "spec/") || strings.HasPrefix(p, "journal/") || strings.Contains(p, "node_modules/") {
			continue
		}
		docs = append(docs, p)
	}
	slices.Sort(docs)
	return docs
}

// Check returns the problems of one document.
func Check(t Tree, doc, content string) []Problem {
	c := checker{tree: t, doc: doc, dir: path.Dir(doc)}
	lines := splitLines(content)
	first := 0
	if doc == Changelog {
		first, lines = latestSection(lines)
	}
	fence := ""
	for i, line := range lines {
		c.line = first + i + 1
		trimmed := strings.TrimLeft(line, " ")
		if fence != "" {
			if strings.HasPrefix(trimmed, fence) {
				fence = ""
				continue
			}
			c.goCommands(line)
			c.removed(line)
			continue
		}
		if f := fenceOf(trimmed); f != "" {
			fence = f
			continue
		}
		c.removed(line)
		spans, prose := codeSpans(line)
		if doc == CodeLocations {
			spans = spansAfterFirstCell(line)
		}
		for _, s := range spans {
			c.goCommands(s)
			c.repoPath(s)
		}
		for _, l := range links(prose) {
			c.link(l)
		}
	}
	return c.problems
}

type checker struct {
	tree     Tree
	doc, dir string
	line     int
	problems []Problem
}

func (c *checker) addf(format string, a ...any) {
	c.problems = append(c.problems, Problem{Doc: c.doc, Line: c.line, Msg: fmt.Sprintf(format, a...)})
}

func (c *checker) removed(line string) {
	if c.doc == CodeLocations || c.doc == Changelog {
		return
	}
	for _, r := range Removed {
		if strings.Contains(line, r) {
			c.addf("names %q, which no longer exists", r)
		}
	}
}

// link checks a relative link target against the tree.
func (c *checker) link(target string) {
	target = strings.TrimSpace(target)
	if i := strings.IndexAny(target, " \t"); i >= 0 {
		target = target[:i] // a link title follows
	}
	target = strings.TrimSuffix(strings.TrimPrefix(target, "<"), ">")
	if target == "" || strings.HasPrefix(target, "#") || hasScheme(target) {
		return
	}
	if i := strings.IndexAny(target, "#?"); i >= 0 {
		target = target[:i]
	}
	if u, err := url.PathUnescape(target); err == nil {
		target = u
	}
	p, ok := c.resolve(target)
	if !ok || !c.tree.Has(p) {
		c.addf("link %q does not resolve to a file or directory", target)
	}
}

// resolve joins a relative path onto the document's directory; a leading
// slash means the repository root.
func (c *checker) resolve(rel string) (string, bool) {
	var p string
	if strings.HasPrefix(rel, "/") {
		p = path.Clean(strings.TrimLeft(rel, "/"))
	} else {
		p = path.Clean(path.Join(c.dir, rel))
	}
	if p == ".." || strings.HasPrefix(p, "../") {
		return "", false
	}
	return p, true
}

var symbolSuffix = regexp.MustCompile(`^(.+)\.[A-Z][A-Za-z0-9_]*$`)

// repoPath checks a code span that looks like a repository path. A span is a
// path when it has a slash and its first element is a directory of the
// repository root, of the document's directory, or a retired directory.
func (c *checker) repoPath(span string) {
	s := strings.TrimSpace(span)
	if rest, ok := strings.CutPrefix(s, modulePath+"/"); ok {
		rest, _, _ = strings.Cut(rest, "@")
		rest = strings.TrimSuffix(rest, "/...")
		if !c.tree.IsDir(rest) {
			c.addf("import path `%s` is not a directory of the repository", span)
		}
		return
	}
	if s == "" || strings.ContainsAny(s, " \t{}*<>|$=:@?,()[]\"'`~") || !strings.Contains(s, "/") {
		return
	}
	if strings.HasPrefix(s, "/") || strings.HasPrefix(s, "-") || strings.HasPrefix(s, "../") {
		return
	}
	s = strings.TrimPrefix(s, "./")
	s = strings.TrimSuffix(s, "/...")
	s = strings.TrimSuffix(s, "/")
	if s == "" || s == "." || strings.Contains(s, "//") {
		return
	}
	if identifiers.MatchString(s) {
		return
	}
	head, _, nested := strings.Cut(s, "/")
	local := path.Join(c.dir, head)
	// A bare retired name such as archive/ is a directory the user has, not
	// a repository path.
	retired := nested && slices.Contains(Retired, head) && !c.tree.IsDir(head)
	if !c.tree.IsDir(head) && !c.tree.IsDir(local) && !retired {
		return
	}
	if c.exists(s) {
		return
	}
	if m := symbolSuffix.FindStringSubmatch(s); m != nil && c.exists(m[1]) {
		return // a qualified identifier: package path, then the symbol
	}
	c.addf("path `%s` is not in the repository", span)
}

func (c *checker) exists(p string) bool {
	return c.tree.Has(p) || c.tree.Has(path.Join(c.dir, p))
}

var goC = regexp.MustCompile(`\bgo -C (\S+)((?:\s+\S+)*)`)

// goCommands checks go -C DIR: DIR holds a go.mod, and every ./package
// argument after it exists inside DIR.
func (c *checker) goCommands(s string) {
	for _, m := range goC.FindAllStringSubmatch(s, -1) {
		dir := path.Clean(m[1])
		if !c.tree.files[path.Join(dir, "go.mod")] {
			c.addf("go -C %s: %s is not a module directory", m[1], m[1])
			continue
		}
		for _, arg := range strings.Fields(m[2]) {
			if arg == "#" || strings.HasPrefix(arg, "#") {
				break
			}
			if !strings.HasPrefix(arg, "./") {
				continue
			}
			pkg := strings.TrimSuffix(strings.TrimSuffix(arg, "/..."), "/")
			if p := path.Join(dir, pkg); !c.tree.Has(p) {
				c.addf("go -C %s: %s does not exist in %s", m[1], arg, m[1])
			}
		}
	}
}

func hasScheme(s string) bool {
	i := strings.Index(s, ":")
	if i <= 0 {
		return false
	}
	for j, r := range s[:i] {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || j > 0 && (r >= '0' && r <= '9' || r == '+' || r == '-' || r == '.')
		if !ok {
			return false
		}
	}
	return true
}

func splitLines(s string) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(s))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

// latestSection is the lines of the first "## " section and its offset.
func latestSection(lines []string) (int, []string) {
	start := -1
	for i, l := range lines {
		if !strings.HasPrefix(l, "## ") {
			continue
		}
		if start >= 0 {
			return start, lines[start:i]
		}
		start = i
	}
	if start < 0 {
		return 0, lines
	}
	return start, lines[start:]
}

func fenceOf(trimmed string) string {
	for _, f := range []string{"```", "~~~"} {
		if strings.HasPrefix(trimmed, f) {
			return f
		}
	}
	return ""
}

// codeSpans returns the inline code spans of a line and the line with the
// spans blanked out.
func codeSpans(line string) (spans []string, prose string) {
	var b strings.Builder
	for i := 0; i < len(line); {
		if line[i] != '`' {
			b.WriteByte(line[i])
			i++
			continue
		}
		n := 0
		for i+n < len(line) && line[i+n] == '`' {
			n++
		}
		ticks := line[i : i+n]
		end := strings.Index(line[i+n:], ticks)
		if end < 0 {
			b.WriteString(ticks)
			i += n
			continue
		}
		spans = append(spans, line[i+n:i+n+end])
		b.WriteString(strings.Repeat(" ", n+end+n))
		i += n + end + n
	}
	return spans, b.String()
}

// spansAfterFirstCell is the code spans of a table row outside its first
// cell, or of the whole line when it is not a table row.
func spansAfterFirstCell(line string) []string {
	t := strings.TrimSpace(line)
	if !strings.HasPrefix(t, "|") {
		spans, _ := codeSpans(line)
		return spans
	}
	_, prose := codeSpans(t)
	// The first cell ends at the second pipe outside code spans.
	idx := strings.Index(prose[1:], "|")
	if idx < 0 {
		return nil
	}
	spans, _ := codeSpans(t[1+idx:])
	return spans
}

var (
	inlineLink = regexp.MustCompile(`!?\[[^\]]*\]\(([^)]*)\)`)
	refLink    = regexp.MustCompile(`^\s{0,3}\[[^\]]+\]:\s*(\S+)`)
)

func links(prose string) []string {
	var out []string
	for _, m := range inlineLink.FindAllStringSubmatch(prose, -1) {
		out = append(out, m[1])
	}
	if m := refLink.FindStringSubmatch(prose); m != nil {
		out = append(out, m[1])
	}
	return out
}
