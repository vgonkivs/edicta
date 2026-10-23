package verifycli

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/plugins/celestia/celestiatest/cometfake"
)

// An archive that answers a missing exec/ key with an access error is a
// fault of the archive, not an absent record: no verdict, exit 4. The same
// key answered 404 is absent and the node-proven execution still passes.
func TestMissingExecKeyAccessErrorStopsTheVerification(t *testing.T) {
	ok := []cometfake.Result{{Code: 0, Data: []byte("r"), GasWanted: 10, GasUsed: 9}}
	for name, status := range map[string]int{"403": http.StatusForbidden, "500": http.StatusInternalServerError} {
		t.Run(name, func(t *testing.T) {
			w := newProvenWorld(t, provenOpts{results: ok})
			path := "/exec/" + chainID + "/" + w.ref
			var asked bool
			w.au = w.s.serveArchive(t, func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
					if r.URL.Path == path {
						asked = true
						rw.WriteHeader(status)
						return
					}
					next.ServeHTTP(rw, r)
				})
			})
			code, out := exec(t, w.args())
			require.True(t, asked, "the verifier read "+path+": "+out)
			assert.Equal(t, codeUsage, code, out)
			assert.NotContains(t, out, `"verdict":"valid"`)
			assert.NotContains(t, out, `"verdict": "valid"`)
		})
	}
	t.Run("404 is absent", func(t *testing.T) {
		w := newProvenWorld(t, provenOpts{results: ok})
		var asked bool
		w.au = w.s.serveArchive(t, hideExec(&asked, "/exec/"+chainID+"/"+w.ref))
		code, out := exec(t, w.args())
		require.True(t, asked, out)
		assert.Equal(t, exitValid, code, out)
	})
}

func hideExec(asked *bool, path string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			if r.URL.Path == path {
				*asked = true
			}
			next.ServeHTTP(rw, r)
		})
	}
}
