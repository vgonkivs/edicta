package recorder_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The Recorder clears its "submitted" mark when a Submitter reports
// ErrUnsupported, which is safe only if nothing was broadcast. Pluggable
// Submitters must be told.
func TestSubmitterDocSaysWhenErrUnsupportedIsAllowed(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "local.go", nil, parser.ParseComments)
	require.NoError(t, err)
	var doc string
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, s := range gd.Specs {
			if ts, ok := s.(*ast.TypeSpec); ok && ts.Name.Name == "Submitter" {
				doc = ts.Doc.Text()
				if doc == "" {
					doc = gd.Doc.Text()
				}
			}
		}
	}
	require.NotEmpty(t, doc, "the Submitter interface is documented")
	assert.Contains(t, doc, "ErrUnsupported")
	assert.Contains(t, strings.ToLower(doc), "before", "ErrUnsupported only before anything is broadcast")
	assert.Contains(t, strings.ToLower(doc), "broadcast")
}
