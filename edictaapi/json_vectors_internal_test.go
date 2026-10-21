// SPDX-License-Identifier: Apache-2.0

package edictaapi

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vgonkivs/edicta/commitment"
)

type jsonVectors struct {
	Requests []struct {
		ID       string `json:"id"`
		Endpoint string `json:"endpoint"`
		Body     string `json:"body"`
		BodyHex  string `json:"body_hex"`
		Expect   struct {
			CBORHex string `json:"cbor_hex"`
			Error   string `json:"error"`
		} `json:"expect"`
		CBORWrapper string `json:"cbor_wrapper"`
	} `json:"requests"`
	MediaTypes []struct {
		ContentType string `json:"content_type"`
		Expect      string `json:"expect"`
	} `json:"media_types"`
	Accept []struct {
		Accept *string `json:"accept"`
		Expect string  `json:"expect"`
	} `json:"accept"`
	Responses []struct {
		ID     string `json:"id"`
		Schema string `json:"schema"`
		CBOR   string `json:"cbor_hex"`
		Expect struct {
			JSON json.RawMessage `json:"json"`
			Code string          `json:"code"`
		} `json:"expect"`
	} `json:"responses"`
}

func loadJSONVectors(t *testing.T) jsonVectors {
	t.Helper()
	b, err := os.ReadFile("../spec/vectors/api/json_v1.2.json")
	require.NoError(t, err)
	var v jsonVectors
	require.NoError(t, json.Unmarshal(b, &v))
	return v
}

var vectorSentinels = map[string]error{
	"ErrMalformed": commitment.ErrMalformed, "ErrWrongType": commitment.ErrWrongType,
	"ErrMissingField": commitment.ErrMissingField, "ErrFieldSize": commitment.ErrFieldSize,
}

func TestJSONVectorRequests(t *testing.T) {
	v := loadJSONVectors(t)
	require.NotEmpty(t, v.Requests)
	for _, r := range v.Requests {
		t.Run(r.ID, func(t *testing.T) {
			body := []byte(r.Body)
			if r.BodyHex != "" {
				var err error
				body, err = hex.DecodeString(r.BodyHex)
				require.NoError(t, err)
			}
			rt, ok := routeSchemas(r.Endpoint)
			require.True(t, ok)
			out, err := jsonToCBOR(body, rt.req)
			if r.Expect.Error != "" {
				require.ErrorIs(t, err, vectorSentinels[r.Expect.Error])
				return
			}
			require.NoError(t, err)
			require.Equal(t, r.Expect.CBORHex, hex.EncodeToString(out))
			if r.CBORWrapper != "" {
				_, err := decodeFields(out, rt.req)
				require.ErrorIs(t, err, vectorSentinels[r.CBORWrapper])
			}
		})
	}
}

func TestJSONVectorMediaTypes(t *testing.T) {
	for _, m := range loadJSONVectors(t).MediaTypes {
		isJSON, ok := requestMedia(m.ContentType)
		got := "415"
		switch {
		case ok && isJSON:
			got = "json"
		case ok:
			got = "cbor"
		}
		require.Equal(t, m.Expect, got, "%q", m.ContentType)
	}
}

func TestJSONVectorAccept(t *testing.T) {
	for _, a := range loadJSONVectors(t).Accept {
		accept := ""
		if a.Accept != nil {
			accept = *a.Accept
		}
		want := a.Expect == "json"
		require.Equal(t, want, wantsJSON(accept), "%q", accept)
	}
}

func TestJSONVectorResponses(t *testing.T) {
	schemas := map[string][]fspec{
		"authorize_response": jsonAuthorizeResp, "record_response": jsonRecordResp,
		"publish_response": publishResponseSchema, "health_response": healthSchema, "error": jsonErrorBody,
	}
	for _, r := range loadJSONVectors(t).Responses {
		t.Run(r.ID, func(t *testing.T) {
			raw, err := hex.DecodeString(r.CBOR)
			require.NoError(t, err)
			out, err := cborToJSON(raw, schemas[r.Schema])
			if r.Expect.Code != "" {
				require.Error(t, err, "a uint above 2^53-1 has no JSON form")
				require.True(t, errors.Is(err, commitment.ErrIntRange))
				return
			}
			require.NoError(t, err)
			require.JSONEq(t, string(r.Expect.JSON), string(out))
		})
	}
}
