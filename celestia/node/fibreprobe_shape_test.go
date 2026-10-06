package node_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/celestia/node"
)

// The raw result of fibre.Download is checked strictly: a struct decoder would
// read a renamed or missing member as an empty blob.
func TestParseDownloadResultIsStrict(t *testing.T) {
	ok := map[string]string{
		"plain":              `{"data":"aGVsbG8="}`,
		"surrounding spaces": " \n{ \"data\" : \"aGVsbG8=\" }\n",
		"empty string":       `{"data":""}`,
	}
	want := map[string]string{"plain": "hello", "surrounding spaces": "hello", "empty string": ""}
	for name, raw := range ok {
		t.Run("accepts "+name, func(t *testing.T) {
			got, err := node.ParseDownloadResult([]byte(raw))
			require.NoError(t, err)
			assert.Equal(t, want[name], string(got))
		})
	}

	bad := map[string]string{
		"empty input":        ``,
		"null":               `null`,
		"empty object":       `{}`,
		"null data":          `{"data":null}`,
		"number data":        `{"data":5}`,
		"object data":        `{"data":{}}`,
		"array result":       `["aGVsbG8="]`,
		"string result":      `"aGVsbG8="`,
		"extra member":       `{"data":"aGVsbG8=","x":1}`,
		"extra null member":  `{"data":"aGVsbG8=","x":null}`,
		"renamed member":     `{"Data":"aGVsbG8="}`,
		"other member only":  `{"blob":"aGVsbG8="}`,
		"duplicate member":   `{"data":"aGVsbG8=","data":"aGVsbG8="}`,
		"not base64":         `{"data":"not base64!"}`,
		"url alphabet":       `{"data":"_-_-"}`,
		"missing padding":    `{"data":"aGVsbG8"}`,
		"trailing garbage":   `{"data":"aGVsbG8="} x`,
		"two documents":      `{"data":"aGVsbG8="}{"data":"aGVsbG8="}`,
		"truncated":          `{"data":"aGVsbG8=`,
		"base64 with spaces": `{"data":"aGVs bG8="}`,
	}
	for name, raw := range bad {
		t.Run("refuses "+name, func(t *testing.T) {
			got, err := node.ParseDownloadResult([]byte(raw))
			require.ErrorIs(t, err, node.ErrBridgeShape)
			assert.Nil(t, got)
		})
	}
}

func FuzzParseDownloadResult(f *testing.F) {
	for _, s := range []string{`{"data":"aGVsbG8="}`, `{}`, `null`, `{"data":"`, `{"data":"aGVsbG8=","data":""}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		got, err := node.ParseDownloadResult(raw)
		if err != nil {
			require.ErrorIs(t, err, node.ErrBridgeShape)
			require.Nil(t, got)
		}
	})
}
