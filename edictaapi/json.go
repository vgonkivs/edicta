// SPDX-License-Identifier: Apache-2.0

package edictaapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/vgonkivs/edicta/commitment"
)

// JSON is a transport for the CBOR wrapper maps and nothing else. The request
// body is converted to the exact canonical CBOR the wrapper schema would have
// carried and then takes the unchanged CBOR path, so every check is the same.
// Embedded signed or hashed objects travel as base64 of their canonical bytes.

const jsonContentType = "application/json"

// maxJSONInt is the largest integer a JSON number may carry (2^53 - 1), the
// last value every JSON implementation reads exactly.
const maxJSONInt = 1<<53 - 1

// jsonSlack covers keys, quotes, braces and whitespace around the values.
const jsonSlack = 1024

// jsonLimit is the body limit for a route whose CBOR limit is limit.
func jsonLimit(limit uint64) uint64 { return (limit+2)/3*4 + jsonSlack }

var (
	jsonAuthorizeResp = []fspec{
		{key: 1, name: "signed_authorization", kind: fBytes},
		{key: 5, name: "policy_verdict", kind: fBytes},
	}
	jsonRecordResp = []fspec{{key: 1, name: "signed_receipt", kind: fBytes}}
	jsonErrorBody  = []fspec{
		{key: 1, name: "code", kind: fText},
		{key: 2, name: "message", kind: fText},
		{key: 3, name: "retryable", kind: fUint},
		{key: 4, name: "stored", kind: fBytes},
		{key: 5, name: "policy_verdict", kind: fBytes},
	}
)

// jsonRoute holds the JSON field names of a route: req for the request body
// (nil for GET), resp for a 200 body.
type jsonRoute struct{ req, resp []fspec }

func routeSchemas(path string) (jsonRoute, bool) {
	switch path {
	case "/v1/publish":
		return jsonRoute{publishRequestSchema, publishResponseSchema}, true
	case "/v1/authorize":
		return jsonRoute{authorizeSchema, jsonAuthorizeResp}, true
	case "/v1/record":
		return jsonRoute{recordSchema, jsonRecordResp}, true
	case "/v1/health":
		return jsonRoute{nil, healthSchema}, true
	}
	return jsonRoute{}, false
}

// MediaType classifies a Content-Type header the way the handler does: ok is
// false for a type the API refuses with ErrMediaType, isJSON tells the two
// accepted ones apart. A wrapper that must act before the handler (for
// example a token check) uses it so both agree on what is accepted.
func MediaType(h string) (isJSON, ok bool) { return requestMedia(h) }

// requestMedia classifies a Content-Type header: the media type and whether it
// is one this server accepts.
func requestMedia(h string) (isJSON, ok bool) {
	mt, params, err := mime.ParseMediaType(h)
	if err != nil {
		return false, false
	}
	switch mt {
	case contentType:
		return false, true
	case jsonContentType:
		if cs, has := params["charset"]; has && !strings.EqualFold(cs, "utf-8") {
			return false, false
		}
		return true, true
	}
	return false, false
}

// wantsJSON reports whether an Accept header prefers application/json over
// application/cbor. No header, a wildcard or a tie answers CBOR.
func wantsJSON(accept string) bool {
	jq, cq := -1.0, -1.0
	for _, part := range strings.Split(accept, ",") {
		mt, params, err := mime.ParseMediaType(strings.TrimSpace(part))
		if err != nil {
			continue
		}
		q := 1.0
		if s, ok := params["q"]; ok {
			v, perr := strconv.ParseFloat(s, 64)
			if perr != nil || v < 0 || v > 1 {
				continue
			}
			q = v
		}
		switch mt {
		case jsonContentType:
			jq = max(jq, q)
		case contentType:
			cq = max(cq, q)
		}
	}
	return jq > 0 && jq > cq
}

// responseIsJSON decides the media type of every response, errors included: a
// GET follows Accept, any other method follows the request's Content-Type.
func responseIsJSON(r *http.Request) bool {
	if r.Method == http.MethodGet {
		return wantsJSON(r.Header.Get("Accept"))
	}
	isJSON, _ := requestMedia(r.Header.Get("Content-Type"))
	return isJSON
}

func jsonFail(format string, args ...any) error {
	return fmt.Errorf("%w: json: %s", commitment.ErrMalformed, fmt.Sprintf(format, args...))
}

// ---- JSON to CBOR ----

type jkind uint8

const (
	jStr jkind = iota
	jNum
	jArr
)

type jvalue struct {
	kind jkind
	s    []byte // aliases the input when the string has no escapes
	u    uint64
	arr  []uint64
}

type jparser struct {
	in  []byte
	pos int
}

// jsonToCBOR converts one JSON object to the canonical CBOR map of schema.
// Unknown keys, duplicate keys (compared after unescaping), non-canonical
// base64, integers above 2^53-1, negative, fractional or exponent numbers and
// every JSON construct other than strings, integers and integer arrays are
// ErrMalformed. A value of the wrong JSON type for its field is ErrWrongType.
// Required fields, lengths and charsets are left to the CBOR path.
func jsonToCBOR(in []byte, schema []fspec) ([]byte, error) {
	p := &jparser{in: in}
	vals, err := p.object(schema)
	if err != nil {
		return nil, err
	}
	p.space()
	if p.pos != len(in) {
		return nil, jsonFail("data after the top-level object")
	}
	byKey := make([]fspec, 0, len(vals))
	for _, f := range schema {
		if _, ok := vals[f.name]; ok {
			byKey = append(byKey, f)
		}
	}
	sort.Slice(byKey, func(i, j int) bool { return byKey[i].key < byKey[j].key })
	items := make([]kv, 0, len(byKey))
	for _, f := range byKey {
		v := vals[f.name]
		it := kv{key: f.key, kind: f.kind}
		switch f.kind {
		case fBytes:
			if v.kind != jStr {
				return nil, fmt.Errorf("%w: %s", commitment.ErrWrongType, f.name)
			}
			b, err := decodeBase64(v.s)
			if err != nil {
				return nil, fmt.Errorf("%w: %s", err, f.name)
			}
			it.b = b
		case fText:
			if v.kind != jStr {
				return nil, fmt.Errorf("%w: %s", commitment.ErrWrongType, f.name)
			}
			it.s = string(v.s)
		case fUint:
			if v.kind != jNum {
				return nil, fmt.Errorf("%w: %s", commitment.ErrWrongType, f.name)
			}
			it.u = v.u
		case fUintArray:
			if v.kind != jArr {
				return nil, fmt.Errorf("%w: %s", commitment.ErrWrongType, f.name)
			}
			it.arr = v.arr
		}
		items = append(items, it)
	}
	return encodeMap(items...), nil
}

// decodeBase64 accepts exactly the padded RFC 4648 section 4 alphabet in its
// canonical form: no line breaks, no missing padding, no stray trailing bits.
func decodeBase64(s []byte) ([]byte, error) {
	// The decoder skips CR and LF; padded input of the standard alphabet in
	// strict mode is otherwise exactly the canonical form.
	if len(s)%4 != 0 || bytes.IndexAny(s, "\r\n") >= 0 {
		return nil, jsonFail("base64 is not canonical")
	}
	dst := make([]byte, base64.StdEncoding.DecodedLen(len(s)))
	n, err := base64.StdEncoding.Strict().Decode(dst, s)
	if err != nil {
		return nil, jsonFail("base64")
	}
	return dst[:n], nil
}

func (p *jparser) space() {
	for p.pos < len(p.in) {
		switch p.in[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *jparser) object(schema []fspec) (map[string]jvalue, error) {
	p.space()
	if p.pos >= len(p.in) || p.in[p.pos] != '{' {
		return nil, jsonFail("top-level value is not an object")
	}
	p.pos++
	vals := make(map[string]jvalue)
	p.space()
	if p.pos < len(p.in) && p.in[p.pos] == '}' {
		p.pos++
		return vals, nil
	}
	for {
		p.space()
		raw, err := p.str()
		if err != nil {
			return nil, err
		}
		key := ""
		for _, f := range schema {
			if f.name == string(raw) {
				key = f.name
				break
			}
		}
		if key == "" {
			return nil, jsonFail("unknown key %q", truncate(string(raw)))
		}
		if _, dup := vals[key]; dup {
			return nil, jsonFail("duplicate key %q", key)
		}
		p.space()
		if p.pos >= len(p.in) || p.in[p.pos] != ':' {
			return nil, jsonFail("expected ':' at offset %d", p.pos)
		}
		p.pos++
		p.space()
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		vals[key] = v
		p.space()
		if p.pos >= len(p.in) {
			return nil, jsonFail("truncated object")
		}
		switch p.in[p.pos] {
		case ',':
			p.pos++
		case '}':
			p.pos++
			return vals, nil
		default:
			return nil, jsonFail("expected ',' or '}' at offset %d", p.pos)
		}
	}
}

func truncate(s string) string {
	if len(s) > 32 {
		return s[:32]
	}
	return s
}

func (p *jparser) value() (jvalue, error) {
	if p.pos >= len(p.in) {
		return jvalue{}, jsonFail("truncated value")
	}
	switch c := p.in[p.pos]; {
	case c == '"':
		s, err := p.str()
		return jvalue{kind: jStr, s: s}, err
	case c >= '0' && c <= '9' || c == '-':
		u, err := p.num()
		return jvalue{kind: jNum, u: u}, err
	case c == '[':
		return p.array()
	}
	return jvalue{}, jsonFail("unsupported value at offset %d", p.pos)
}

func (p *jparser) array() (jvalue, error) {
	p.pos++
	v := jvalue{kind: jArr}
	p.space()
	if p.pos < len(p.in) && p.in[p.pos] == ']' {
		p.pos++
		return v, nil
	}
	for {
		p.space()
		if p.pos >= len(p.in) || !(p.in[p.pos] >= '0' && p.in[p.pos] <= '9' || p.in[p.pos] == '-') {
			return jvalue{}, jsonFail("array element at offset %d is not an integer", p.pos)
		}
		u, err := p.num()
		if err != nil {
			return jvalue{}, err
		}
		if len(v.arr) >= maxEntries {
			return jvalue{}, jsonFail("array above %d entries", maxEntries)
		}
		v.arr = append(v.arr, u)
		p.space()
		if p.pos >= len(p.in) {
			return jvalue{}, jsonFail("truncated array")
		}
		switch p.in[p.pos] {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return v, nil
		default:
			return jvalue{}, jsonFail("expected ',' or ']' at offset %d", p.pos)
		}
	}
}

func (p *jparser) num() (uint64, error) {
	start := p.pos
	if p.in[p.pos] == '-' {
		return 0, jsonFail("negative number")
	}
	for p.pos < len(p.in) && p.in[p.pos] >= '0' && p.in[p.pos] <= '9' {
		p.pos++
	}
	digits := p.in[start:p.pos]
	if len(digits) > 1 && digits[0] == '0' {
		return 0, jsonFail("leading zero")
	}
	if p.pos < len(p.in) {
		switch p.in[p.pos] {
		case '.', 'e', 'E':
			return 0, jsonFail("number is not an integer")
		}
	}
	if len(digits) > 16 {
		return 0, jsonFail("integer above 2^53-1")
	}
	u, err := strconv.ParseUint(string(digits), 10, 64)
	if err != nil || u > maxJSONInt {
		return 0, jsonFail("integer above 2^53-1")
	}
	return u, nil
}

// str returns the unescaped bytes of a string. Without escapes the result
// aliases the input, so a large base64 value is not copied before decoding.
func (p *jparser) str() ([]byte, error) {
	if p.pos >= len(p.in) || p.in[p.pos] != '"' {
		return nil, jsonFail("expected a string at offset %d", p.pos)
	}
	p.pos++
	start := p.pos
	i := start
	for i < len(p.in) && p.in[i] != '"' && p.in[i] != '\\' && p.in[i] >= 0x20 {
		i++
	}
	if i < len(p.in) && p.in[i] == '"' {
		p.pos = i + 1
		if !utf8.Valid(p.in[start:i]) {
			return nil, jsonFail("invalid UTF-8")
		}
		return p.in[start:i], nil
	}
	out := make([]byte, 0, i-start+16)
	out = append(out, p.in[start:i]...)
	p.pos = i
	for {
		if p.pos >= len(p.in) {
			return nil, jsonFail("unterminated string")
		}
		c := p.in[p.pos]
		switch {
		case c == '"':
			p.pos++
			if !utf8.Valid(out) {
				return nil, jsonFail("invalid UTF-8")
			}
			return out, nil
		case c < 0x20:
			return nil, jsonFail("control character in string")
		case c != '\\':
			out = append(out, c)
			p.pos++
			continue
		}
		p.pos++
		if p.pos >= len(p.in) {
			return nil, jsonFail("unterminated escape")
		}
		e := p.in[p.pos]
		p.pos++
		switch e {
		case '"', '\\', '/':
			out = append(out, e)
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			r, err := p.hex4()
			if err != nil {
				return nil, err
			}
			if utf16.IsSurrogate(r) {
				if r >= 0xdc00 || p.pos+1 >= len(p.in) || p.in[p.pos] != '\\' || p.in[p.pos+1] != 'u' {
					return nil, jsonFail("unpaired surrogate")
				}
				p.pos += 2
				lo, err := p.hex4()
				if err != nil {
					return nil, err
				}
				if lo < 0xdc00 || lo > 0xdfff {
					return nil, jsonFail("unpaired surrogate")
				}
				r = utf16.DecodeRune(r, lo)
			}
			out = utf8.AppendRune(out, r)
		default:
			return nil, jsonFail("invalid escape")
		}
	}
}

func (p *jparser) hex4() (rune, error) {
	if p.pos+4 > len(p.in) {
		return 0, jsonFail("truncated \\u escape")
	}
	var r rune
	for _, c := range p.in[p.pos : p.pos+4] {
		var d byte
		switch {
		case c >= '0' && c <= '9':
			d = c - '0'
		case c >= 'a' && c <= 'f':
			d = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			d = c - 'A' + 10
		default:
			return 0, jsonFail("bad \\u escape")
		}
		r = r<<4 | rune(d)
	}
	p.pos += 4
	return r, nil
}

// ---- CBOR to JSON ----

// cborToJSON renders a canonical CBOR wrapper map as a JSON object with the
// field names of schema. The input is produced by this package or already
// accepted by the CBOR decoder; an unknown key or a value that does not fit a
// JSON integer is an error.
func cborToJSON(in []byte, schema []fspec) ([]byte, error) {
	root, err := scanTop(in)
	if err != nil {
		return nil, err
	}
	if root.major != majMap {
		return nil, fmt.Errorf("%w: top-level item is not a map", commitment.ErrWrongType)
	}
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, e := range root.entries {
		name := ""
		for _, f := range schema {
			if f.key == e.key {
				name = f.name
				break
			}
		}
		if name == "" {
			return nil, fmt.Errorf("%w: key %d", commitment.ErrUnknownKey, e.key)
		}
		if i > 0 {
			buf.WriteByte(',')
		}
		writeJSONString(&buf, name)
		buf.WriteByte(':')
		if err := writeJSONNode(&buf, e.val); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

func writeJSONNode(buf *bytes.Buffer, n *node) error {
	switch n.major {
	case majUint:
		if n.u > maxJSONInt {
			return fmt.Errorf("%w: integer above 2^53-1", commitment.ErrIntRange)
		}
		buf.WriteString(strconv.FormatUint(n.u, 10))
	case majBstr:
		writeJSONString(buf, base64.StdEncoding.EncodeToString(n.b))
	case majTstr:
		writeJSONString(buf, string(n.b))
	case majArr:
		buf.WriteByte('[')
		for i, el := range n.entries {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeJSONNode(buf, el.val); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	default:
		return fmt.Errorf("%w: item has no JSON form", commitment.ErrWrongType)
	}
	return nil
}

func writeJSONString(buf *bytes.Buffer, s string) {
	var tmp bytes.Buffer
	enc := json.NewEncoder(&tmp)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s) // a valid-UTF-8 string always encodes
	buf.Write(bytes.TrimSuffix(tmp.Bytes(), []byte("\n")))
}
