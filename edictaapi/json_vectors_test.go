// SPDX-License-Identifier: Apache-2.0

package edictaapi_test

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/internal/testkit"
)

const vectorsRoot = "vectors"

type supersededFile struct {
	Entries []struct {
		File       string `json:"file"`
		Case       string `json:"case"`
		ReplacedBy string `json:"replaced_by"`
	} `json:"entries"`
}

// supersededCases lists the frozen cases a later revision replaced, as
// "file#case" mapped to the replacing case, from every SUPERSEDED*.json.
func supersededCases(t testing.TB) map[string]string {
	t.Helper()
	files, err := filepath.Glob(testkit.SpecPath(t, vectorsRoot, "SUPERSEDED*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, files)
	out := map[string]string{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		require.NoError(t, err)
		var sf supersededFile
		require.NoError(t, json.Unmarshal(b, &sf))
		for _, e := range sf.Entries {
			out[e.File+"#"+e.Case] = e.ReplacedBy
		}
	}
	return out
}

func TestSupersededListsTheMediaTypeCase(t *testing.T) {
	require.Equal(t, "api/errors_v1.2.json#publish_wrong_media_type", supersededCases(t)["api/errors.json#publish_wrong_media_type"])
}

// TestErrorsV12Examples runs the examples of api/errors_v1.2.json through the handler.
func TestErrorsV12Examples(t *testing.T) {
	var v struct {
		Examples []struct {
			ID           string `json:"id"`
			Endpoint     string `json:"endpoint"`
			Method       string `json:"method"`
			ContentType  string `json:"content_type"`
			RequestHex   string `json:"request_cbor_hex"`
			Status       string `json:"status"`
			MediaType    string `json:"response_media_type"`
			ResponseHex  string `json:"response_cbor_hex"`
			ResponseJSON *struct {
				Code      string `json:"code"`
				Retryable int    `json:"retryable"`
			} `json:"response_json"`
		} `json:"examples"`
	}
	loadJSON(t, "errors_v1.2.json", &v)
	require.NotEmpty(t, v.Examples)
	for _, ex := range v.Examples {
		t.Run(ex.ID, func(t *testing.T) {
			e := newEnv(t, nil)
			rec := e.do(ex.Method, ex.Endpoint, ex.ContentType, unhex(t, ex.RequestHex))
			require.Equal(t, int(u64(t, ex.Status)), rec.Code, rec.Body.String())
			require.Equal(t, ex.MediaType, rec.Header().Get("Content-Type"))
			require.Zero(t, e.pub.count())
			switch {
			case ex.ResponseHex != "":
				require.Equal(t, unhex(t, ex.ResponseHex), rec.Body.Bytes())
			case ex.ResponseJSON != nil:
				je := requireJSONErr(t, rec, rec.Code, ex.ResponseJSON.Code)
				require.Equal(t, ex.ResponseJSON.Retryable, *je.Retryable)
			default:
				t.Fatal("example has no expected body")
			}
		})
	}
}

// TestJSONCheckOrderVectors runs the size case of api/json_v1.2.json that
// needs no body construction beyond its size.
func TestJSONCheckOrderVectors(t *testing.T) {
	var v struct {
		CheckOrder []struct {
			ID       string `json:"id"`
			JSONSize string `json:"json_size"`
			Expect   struct {
				Status string `json:"status"`
				Code   string `json:"code"`
			} `json:"expect"`
		} `json:"check_order"`
	}
	loadJSON(t, "json_v1.2.json", &v)
	ran := 0
	for _, c := range v.CheckOrder {
		if c.JSONSize == "" {
			continue
		}
		ran++
		e := newEnv(t, nil)
		// An unknown member first, padded to the size: size is judged before decoding.
		body := []byte(`{"mode":"` + strings.Repeat("x", int(u64(t, c.JSONSize))-11) + `"}`)
		require.Len(t, body, int(u64(t, c.JSONSize)))
		rec := e.postJSON("/v1/authorize", body)
		requireJSONErr(t, rec, int(u64(t, c.Expect.Status)), c.Expect.Code)
		require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
		require.Zero(t, e.gate.calls())
	}
	require.Equal(t, 1, ran)
}
