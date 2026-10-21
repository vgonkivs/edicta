# SPDX-License-Identifier: Apache-2.0
"""The JSON transport of the HTTP API (core section 18.4, rules JT1 to JT11), written for the v1.2 vector generator
and checker: media-type classification, Accept negotiation, the strict JSON reader and its conversion to the CBOR
wrapper map, and the JSON rendering of a CBOR response.
"""

from __future__ import annotations

import base64
import binascii

from cbor_strict import decode_strict, encode, to_plain

MAX_JSON_INT = (1 << 53) - 1

# Field tables: name -> (CBOR key, kind). kind: "bytes", "text", "uint", "uints".
SCHEMAS = {
    "publish_request": {"blob": (1, "bytes"), "agent_id": (2, "text"), "requested_at": (3, "uint"), "signature": (4, "bytes")},
    "publish_response": {"payload_ref": (1, "bytes"), "block_time": (2, "uint"), "retention_start": (3, "uint")},
    "authorize_request": {"envelope": (1, "bytes"), "action": (2, "bytes"), "action_salt": (3, "bytes")},
    "authorize_response": {"signed_authorization": (1, "bytes"), "policy_verdict": (5, "bytes")},
    "record_request": {"envelope": (1, "bytes"), "rail_ref": (2, "text"), "executor_pubkey": (3, "bytes"),
                       "executor_signature": (4, "bytes")},
    "record_response": {"signed_receipt": (1, "bytes")},
    "health_response": {"status": (1, "uint"), "chain_id": (2, "text"), "head_height": (3, "uint"), "head_time": (4, "uint"),
                        "gate_id": (5, "text"), "gate_pubkey": (6, "bytes"), "recorder_signer": (7, "bytes"),
                        "namespace": (8, "bytes"), "allowed_da": (9, "uints")},
    "error": {"code": (1, "text"), "message": (2, "text"), "retryable": (3, "uint"), "stored": (4, "bytes"),
              "policy_verdict": (5, "bytes")},
}
ROUTES = {"/v1/publish": ("publish_request", "publish_response"), "/v1/authorize": ("authorize_request", "authorize_response"),
          "/v1/record": ("record_request", "record_response"), "/v1/health": (None, "health_response")}


class Refusal(Exception):
    def __init__(self, sentinel: str, why: str):
        super().__init__(f"{sentinel}: {why}")
        self.sentinel = sentinel
        self.why = why


def _malformed(why: str):
    raise Refusal("ErrMalformed", why)


# ---------------------------------------------------------------- media types (JT1, JT2)

def _parse_media(h: str):
    """RFC 9110 media type: (type/subtype lower case, params with lower-case names) or None."""
    parts = h.split(";")
    mt = parts[0].strip().lower()
    if "/" not in mt or mt.count("/") != 1 or not all(mt.split("/")) or any(c in mt for c in " \t\"(),:<=>?@[\\]{}"):
        return None
    params = {}
    for i, p in enumerate(parts[1:]):
        p = p.strip()
        if not p and i == len(parts) - 2:
            break
        if "=" not in p:
            return None
        k, v = p.split("=", 1)
        k = k.strip().lower()
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] == '"':
            v = v[1:-1]
        if not k or k in params:
            return None
        params[k] = v
    return mt, params


def request_media(content_type: str | None) -> str | None:
    """JT1: 'cbor', 'json' or None (415)."""
    if not content_type:
        return None
    p = _parse_media(content_type)
    if p is None:
        return None
    mt, params = p
    if mt == "application/cbor":
        return "cbor"
    if mt == "application/json":
        cs = params.get("charset")
        return "json" if cs is None or cs.lower() == "utf-8" else None
    return None


def wants_json(accept: str | None) -> bool:
    """JT2 for a GET: JSON iff application/json has q > 0 and above the q of application/cbor."""
    if not accept:
        return False
    jq = cq = -1.0
    for part in accept.split(","):
        p = _parse_media(part.strip())
        if p is None:
            continue
        mt, params = p
        q = 1.0
        if "q" in params:
            try:
                q = float(params["q"])
            except ValueError:
                continue
            if not 0 <= q <= 1:
                continue
        if mt == "application/json":
            jq = max(jq, q)
        elif mt == "application/cbor":
            cq = max(cq, q)
    return jq > 0 and jq > cq


# ---------------------------------------------------------------- strict JSON reader (JT3, JT4)

WS = b" \t\n\r"


class _Reader:
    def __init__(self, b: bytes):
        self.b = b
        self.i = 0

    def space(self):
        while self.i < len(self.b) and self.b[self.i] in WS:
            self.i += 1

    def string(self) -> str:
        b = self.b
        if self.i >= len(b) or b[self.i] != 0x22:
            _malformed(f"expected a string at offset {self.i}")
        self.i += 1
        out = bytearray()
        while True:
            if self.i >= len(b):
                _malformed("unterminated string")
            c = b[self.i]
            if c == 0x22:
                self.i += 1
                break
            if c < 0x20:
                _malformed("control character in a string")
            if c != 0x5C:
                out.append(c)
                self.i += 1
                continue
            self.i += 1
            if self.i >= len(b):
                _malformed("unterminated escape")
            e = b[self.i]
            self.i += 1
            simple = {0x22: 0x22, 0x5C: 0x5C, 0x2F: 0x2F, 0x62: 8, 0x66: 12, 0x6E: 10, 0x72: 13, 0x74: 9}
            if e in simple:
                out.append(simple[e])
                continue
            if e != 0x75:
                _malformed("invalid escape")
            r = self._hex4()
            if 0xD800 <= r <= 0xDFFF:
                if r >= 0xDC00 or self.b[self.i:self.i + 2] != b"\\u":
                    _malformed("unpaired surrogate")
                self.i += 2
                lo = self._hex4()
                if not 0xDC00 <= lo <= 0xDFFF:
                    _malformed("unpaired surrogate")
                r = 0x10000 + ((r - 0xD800) << 10) + (lo - 0xDC00)
            out += chr(r).encode("utf-8")
        try:
            return out.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            _malformed("invalid UTF-8")

    def _hex4(self) -> int:
        h = self.b[self.i:self.i + 4]
        if len(h) != 4 or any(c not in b"0123456789abcdefABCDEF" for c in h):
            _malformed("bad \\u escape")
        self.i += 4
        return int(h, 16)

    def number(self) -> int:
        b, start = self.b, self.i
        if b[self.i] == 0x2D:
            _malformed("negative number")
        while self.i < len(b) and 0x30 <= b[self.i] <= 0x39:
            self.i += 1
        digits = b[start:self.i]
        if len(digits) > 1 and digits[0] == 0x30:
            _malformed("leading zero")
        if self.i < len(b) and b[self.i] in b".eE":
            _malformed("not an integer")
        v = int(digits)
        if v > MAX_JSON_INT:
            _malformed("integer above 2^53 - 1")
        return v

    def value(self):
        if self.i >= len(self.b):
            _malformed("truncated value")
        c = self.b[self.i]
        if c == 0x22:
            return ("str", self.string())
        if 0x30 <= c <= 0x39 or c == 0x2D:
            return ("num", self.number())
        if c == 0x5B:
            return ("arr", self.array())
        _malformed(f"unsupported value at offset {self.i}")

    def array(self) -> list:
        self.i += 1
        out = []
        self.space()
        if self.i < len(self.b) and self.b[self.i] == 0x5D:
            self.i += 1
            return out
        while True:
            self.space()
            if self.i >= len(self.b) or not (0x30 <= self.b[self.i] <= 0x39 or self.b[self.i] == 0x2D):
                _malformed("array element is not an integer")
            out.append(self.number())
            if len(out) > 16:
                _malformed("array above 16 entries")
            self.space()
            if self.i >= len(self.b):
                _malformed("truncated array")
            c = self.b[self.i]
            self.i += 1
            if c == 0x5D:
                return out
            if c != 0x2C:
                _malformed("expected ',' or ']'")

    def obj(self, names: dict) -> dict:
        self.space()
        if self.i >= len(self.b) or self.b[self.i] != 0x7B:
            _malformed("top-level value is not an object")
        self.i += 1
        out: dict = {}
        self.space()
        if self.i < len(self.b) and self.b[self.i] == 0x7D:
            self.i += 1
            return out
        while True:
            self.space()
            key = self.string()
            if key not in names:
                _malformed(f"unknown member {key[:32]!r}")
            if key in out:
                _malformed(f"duplicate member {key!r}")
            self.space()
            if self.i >= len(self.b) or self.b[self.i] != 0x3A:
                _malformed("expected ':'")
            self.i += 1
            self.space()
            out[key] = self.value()
            self.space()
            if self.i >= len(self.b):
                _malformed("truncated object")
            c = self.b[self.i]
            self.i += 1
            if c == 0x7D:
                return out
            if c != 0x2C:
                _malformed("expected ',' or '}'")


def decode_base64(s: str) -> bytes:
    if len(s) % 4 or any(c in s for c in "\r\n") or not s.isascii():
        _malformed("base64 is not canonical")
    try:
        b = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        _malformed("base64")
    if base64.b64encode(b).decode() != s:
        _malformed("base64 is not canonical")
    return b


def json_to_cbor(body: bytes, schema_name: str) -> bytes:
    """JT3 to JT5: the canonical CBOR wrapper map that a JSON request body converts to, or a Refusal."""
    schema = SCHEMAS[schema_name]
    r = _Reader(body)
    vals = r.obj(schema)
    r.space()
    if r.i != len(body):
        _malformed("data after the top-level object")
    out = {}
    for name in sorted(vals, key=lambda n: schema[n][0]):
        key, kind = schema[name]
        jt, v = vals[name]
        want = {"bytes": "str", "text": "str", "uint": "num", "uints": "arr"}[kind]
        if jt != want:
            raise Refusal("ErrWrongType", name)
        out[key] = decode_base64(v) if kind == "bytes" else v
    return encode(out)


def body_limit(cbor_limit: int) -> int:
    """JT6: the JSON body limit of a route whose CBOR request limit is cbor_limit."""
    return 4 * -(-cbor_limit // 3) + 1024


# ---------------------------------------------------------------- rendering (JT7, JT8)

def cbor_to_json(body: bytes, schema_name: str) -> dict:
    """The JSON object a server renders for a CBOR response body (as a parsed value)."""
    schema = SCHEMAS[schema_name]
    by_key = {k: (n, kind) for n, (k, kind) in schema.items()}
    m = to_plain(decode_strict(body))
    out = {}
    for k in sorted(m):
        name, kind = by_key[k]
        v = m[k]
        if kind == "bytes":
            out[name] = base64.b64encode(v).decode()
        elif kind in ("uint", "uints"):
            for x in (v if kind == "uints" else [v]):
                if x > MAX_JSON_INT:
                    raise Refusal("ErrInternal", f"{name} above 2^53 - 1")
            out[name] = v
        else:
            out[name] = v
    return out
