"""Edicta policy v1 rules (spec/policy-v1.md, policy-v1-draft.4).

The generator's rules module: facts, mandate, render, engine, state, verdict,
archive records and the verifier outcome rules. check_policy.py re-implements
the same rules separately; agreement of the two, and of both with the Go
implementation through the vectors, is the point.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone

from cbor_strict import encode
from edicta_v0 import ID_CHARS, Reject, _verify_tagged_hash
from ed25519_point import public_key_problem

FAMILY = b"edicta/policy/v1/"
TAG = {n: FAMILY + n.encode() for n in
       ("mandate", "mandate-sig", "verdict", "verdict-sig", "bucket", "closed", "state", "counter", "successor")}

MAX_INT = (1 << 63) - 1
MAX_AMOUNT = (1 << 256) - 1
MAX_RFC3339 = 253402300799
HOUR = 3600
RETAIN = 767
MAX_HOURS = 744
MAX_PAIRS = 64
# Scale map of a counter cell: the cell decoder's per-map limit, so every map
# the gate writes also decodes.
MAX_SCALES = 1024
MAX_WALK_STEPS = 10000
DEPTH = 6
ENTRIES = 1024
CAP = {"facts": 512, "mandate": 16384, "verdict": 16384, "bucket": 16384, "state": 16384, "closed": 36864}

KIND_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
ASSET_CHARS = frozenset(chr(c) for c in range(0x21, 0x7F))
EXTRACTOR_RE = re.compile(r"^[a-z0-9][a-z0-9./-]{0,63}$")
DENY_P = {"ErrAgentNotCovered": 1, "ErrNoExtractor": 2, "ErrFactsInvalid": 3, "ErrOutsideMandate": 4,
          "ErrKindNotAllowed": 5, "ErrAssetNotAllowed": 6, "ErrRecipientNotAllowed": 7, "ErrAmountAboveMax": 8,
          "ErrDecisionAge": 9, "ErrMinSpacing": 11, "ErrPeriodLimit": 12, "ErrCountLimit": 13, "ErrHistoryFull": 14}
REASONS = sorted(DENY_P)

TEST_EXTRACTOR = "edicta/test-facts/v1"
TEST_ACTION_TYPE = "application/vnd.edicta.test-facts.v1+cbor"


class PolicyError(Exception):
    def __init__(self, sentinel: str, cause: str = "", detail: str = ""):
        super().__init__(f"{sentinel} ({cause}): {detail}" if cause or detail else sentinel)
        self.sentinel = sentinel
        self.cause = cause


def tagged(name: str) -> bytes:
    t = TAG[name]
    return bytes([len(t)]) + t


def thash(name: str, data: bytes) -> bytes:
    return hashlib.sha256(tagged(name) + data).digest()


def k(t: int) -> int:
    return t // HOUR


def amt(n: int) -> bytes:
    if not 0 <= n <= MAX_AMOUNT:
        raise ValueError("amount out of range")
    return n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")


def amt_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


# Generic strict decoding (section 3, stage 2).

class _D:
    def __init__(self, data: bytes, sentinel: str):
        self.d, self.i, self.s = data, 0, sentinel

    def fail(self, cause):
        raise PolicyError(self.s, cause)

    def head(self):
        if self.i >= len(self.d):
            self.fail("ErrMalformed")
        ib = self.d[self.i]
        self.i += 1
        major, ai = ib >> 5, ib & 31
        if 28 <= ai <= 30:
            self.fail("ErrMalformed")
        if ai == 31:
            self.fail("ErrIndefiniteLength" if major in (2, 3, 4, 5) else "ErrMalformed")
        if major == 7:
            self.fail("ErrFloat" if ai in (25, 26, 27) else "ErrSimpleValue")
        if major == 6:
            self.fail("ErrTag")
        if ai < 24:
            return major, ai
        n = 1 << (ai - 24)
        if self.i + n > len(self.d):
            self.fail("ErrMalformed")
        arg = int.from_bytes(self.d[self.i:self.i + n], "big")
        self.i += n
        if arg < {1: 24, 2: 256, 4: 65536, 8: 1 << 32}[n]:
            self.fail("ErrNonMinimalInt")
        return major, arg

    def item(self, depth):
        major, arg = self.head()
        if major in (0, 1):
            return (major, arg)
        if major in (2, 3):
            if arg > len(self.d) - self.i:
                self.fail("ErrMalformed")
            raw = bytes(self.d[self.i:self.i + arg])
            self.i += arg
            if major == 3:
                try:
                    return (3, raw.decode("utf-8"))
                except UnicodeDecodeError:
                    self.fail("ErrInvalidString")
            return (2, raw)
        if depth + 1 > DEPTH:
            self.fail("ErrNestingTooDeep")
        if arg > ENTRIES:
            self.fail("ErrTooLarge")
        if major == 4:
            if arg > len(self.d) - self.i:
                self.fail("ErrMalformed")
            return (4, [self.item(depth + 1) for _ in range(arg)])
        if 2 * arg > len(self.d) - self.i:
            self.fail("ErrMalformed")
        pairs, prev = [], None
        for _ in range(arg):
            kk = self.item(depth + 1)
            if kk[0] != 0:
                self.fail("ErrKeyType")
            if prev is not None and kk[1] == prev:
                self.fail("ErrDuplicateKey")
            if prev is not None and kk[1] < prev:
                self.fail("ErrUnsortedMap")
            prev = kk[1]
            pairs.append((kk[1], self.item(depth + 1)))
        return (5, pairs)


def parse(data: bytes, sentinel: str, cap: int):
    if len(data) > cap:
        raise PolicyError(sentinel, "ErrTooLarge")
    d = _D(data, sentinel)
    it = d.item(0)
    if d.i != len(data):
        raise PolicyError(sentinel, "ErrTrailingData")
    return it


# Schemas (stage 3). A field: key -> (name, type, required, limits).
# Types: "uint", "bstr", "tstr", ("map", schema), ("arr", element type, lo, hi).

def S_FACTS():
    return {1: ("kind", "tstr", True, (1, 32, ASSET_CHARS)), 2: ("asset", "tstr", True, (1, 128, ASSET_CHARS)),
            3: ("amount", "bstr", True, (1, 32)), 4: ("scale", "uint", True, None),
            5: ("recipient", "tstr", False, (1, 128, ASSET_CHARS))}


S_PERIOD = {1: ("hours", "uint", True, None), 2: ("max", "bstr", True, (1, 32))}
S_COUNT = {1: ("hours", "uint", True, None), 2: ("max_count", "uint", True, None)}
S_ASSET = {1: ("asset", "tstr", True, (1, 128, ASSET_CHARS)), 2: ("scale", "uint", True, None),
           3: ("per_action_max", "bstr", False, (1, 32)), 4: ("periods", ("arr", ("map", S_PERIOD), 1, 4), False, None),
           5: ("recipients", ("arr", ("tstr", (1, 128, ASSET_CHARS)), 1, 256), False, None)}
S_MANDATE = {1: ("format", "uint", True, None), 2: ("principal", "bstr", True, (32, 32)),
             3: ("gate_id", "tstr", True, (1, 64, ID_CHARS)),
             4: ("agents", ("arr", ("bstr", (32, 32)), 1, 64), True, None),
             5: ("not_before", "uint", True, None), 6: ("not_after", "uint", True, None),
             7: ("assets", ("arr", ("map", S_ASSET), 1, 16), True, None),
             8: ("count_limits", ("arr", ("map", S_COUNT), 1, 4), False, None),
             9: ("mandate_id", "bstr", True, (16, 16)), 10: ("version", "uint", True, None),
             11: ("max_decision_age", "uint", False, None), 12: ("min_spacing", "uint", False, None),
             13: ("kinds", ("arr", ("tstr", (1, 32, ASSET_CHARS)), 1, 8), False, None)}
S_SIGNED_MANDATE = {1: ("mandate", ("map", S_MANDATE), True, None), 2: ("signature", "bstr", True, (64, 64))}
S_SUM = {1: ("asset", "tstr", True, (1, 128, ASSET_CHARS)), 2: ("scale", "uint", True, None),
         3: ("sum", "bstr", True, (1, 32))}
S_BUCKET = {1: ("format", "uint", True, None), 2: ("index", "uint", True, None), 3: ("count", "uint", True, None),
            4: ("sums", ("arr", ("map", S_SUM), 1, MAX_PAIRS), True, None)}
S_REF = {1: ("index", "uint", True, None), 2: ("hash", "bstr", True, (32, 32))}
S_CLOSED = {1: ("format", "uint", True, None), 2: ("buckets", ("arr", ("map", S_REF), 0, RETAIN), True, None)}
S_STATE = {1: ("format", "uint", True, None), 2: ("seq", "uint", True, None), 3: ("last_t", "uint", False, None),
           4: ("last_th", "uint", False, None), 5: ("closed_root", "bstr", True, (32, 32)),
           6: ("open", ("map", S_BUCKET), False, None)}
S_VERDICT = {1: ("format", "uint", True, None), 2: ("gate_id", "tstr", True, (1, 64, ID_CHARS)),
             3: ("mandate_hash", "bstr", True, (32, 32)), 4: ("commitment_hash", "bstr", True, (32, 32)),
             5: ("action_hash", "bstr", True, (32, 32)), 6: ("agent_pubkey", "bstr", True, (32, 32)),
             7: ("outcome", "uint", True, None), 8: ("reason", "tstr", False, (4, 64, ID_CHARS)),
             9: ("extractor", "tstr", False, (1, 64, ID_CHARS)), 10: ("facts", ("map", S_FACTS()), False, None),
             11: ("anchor_time", "uint", False, None), 12: ("eval_time", "uint", False, None),
             13: ("prev_state", ("map", S_STATE), False, None), 14: ("new_state_hash", "bstr", False, (32, 32)),
             15: ("prev_commitment_hash", "bstr", False, (32, 32)), 16: ("prev_verdict_hash", "bstr", False, (32, 32)),
             17: ("decided_at", "uint", True, None), 18: ("gate_clock", "uint", False, None)}
S_SIGNED_VERDICT = {1: ("verdict", ("map", S_VERDICT), True, None), 2: ("signature", "bstr", True, (64, 64))}


def _conv(it, typ, lim, s):
    major, val = it
    if typ == "uint":
        if major != 0:
            raise PolicyError(s, "ErrWrongType")
        if val > MAX_INT:
            raise PolicyError(s, "ErrIntRange")
        return val
    if typ == "bstr" or (isinstance(typ, tuple) and typ[0] == "bstr"):
        lim = typ[1] if isinstance(typ, tuple) else lim
        if major != 2:
            raise PolicyError(s, "ErrWrongType")
        if not lim[0] <= len(val) <= lim[1]:
            raise PolicyError(s, "ErrFieldSize")
        return val
    if typ == "tstr" or (isinstance(typ, tuple) and typ[0] == "tstr"):
        lim = typ[1] if isinstance(typ, tuple) else lim
        if major != 3:
            raise PolicyError(s, "ErrWrongType")
        b = val.encode("utf-8")
        if not lim[0] <= len(b) <= lim[1]:
            raise PolicyError(s, "ErrFieldSize")
        if any(ch not in lim[2] for ch in val):
            raise PolicyError(s, "ErrInvalidString")
        return val
    if typ[0] == "map":
        return sdecode(it, typ[1], s)
    if typ[0] == "arr":
        if major != 4:
            raise PolicyError(s, "ErrWrongType")
        if not typ[2] <= len(val) <= typ[3]:
            raise PolicyError(s, "ErrFieldSize")
        return [_conv(x, typ[1], None, s) for x in val]
    raise AssertionError(typ)


def sdecode(it, schema, s):
    if it[0] != 5:
        raise PolicyError(s, "ErrWrongType")
    out = {}
    for key, v in it[1]:
        if key not in schema:
            raise PolicyError(s, "ErrUnknownKey")
        name, typ, _, lim = schema[key]
        out[name] = _conv(v, typ, lim, s)
    for key in sorted(schema):
        name, _, req, _ = schema[key]
        if req and name not in out:
            raise PolicyError(s, "ErrMissingField")
    return out


def to_cbor(v: dict, schema: dict) -> dict:
    out = {}
    for key, (name, typ, _, _) in schema.items():
        if name not in v:
            continue
        x = v[name]
        if isinstance(typ, tuple) and typ[0] == "map":
            x = to_cbor(x, typ[1])
        elif isinstance(typ, tuple) and typ[0] == "arr" and isinstance(typ[1], tuple) and typ[1][0] == "map":
            x = [to_cbor(e, typ[1][1]) for e in x]
        out[key] = x
    return out


def _value(cond: bool, s: str, cause: str, detail: str = ""):
    if not cond:
        raise PolicyError(s, cause, detail)


def _amount_ok(b: bytes) -> bool:
    return 1 <= len(b) <= 32 and (len(b) == 1 or b[0] != 0)


def _ascending(xs, key=lambda x: x) -> bool:
    return all(key(a) < key(b) for a, b in zip(xs, xs[1:]))


# Facts (section 4).

def check_facts(f: dict, s: str = "ErrFactsInvalid"):
    _value(KIND_RE.match(f["kind"]) is not None, s, "ErrInvalidString", "kind")
    _value(_amount_ok(f["amount"]), s, "ErrNonMinimalAmount", "amount")
    _value(f["scale"] <= 255, s, "ErrIntRange", "scale")


def encode_facts(f: dict) -> bytes:
    check_facts(f)
    return encode(to_cbor(f, S_FACTS()))


def decode_facts(b: bytes) -> dict:
    it = parse(b, "ErrFactsInvalid", CAP["facts"])
    f = sdecode(it, S_FACTS(), "ErrFactsInvalid")
    check_facts(f)
    if encode(to_cbor(f, S_FACTS())) != b:
        raise PolicyError("ErrFactsInvalid", "ErrNonCanonical")
    return f


def test_extract(action: bytes) -> dict:
    return decode_facts(action)


# Mandate (section 6).

def check_mandate(m: dict):
    s = "ErrMandateInvalid"
    _value(m["format"] == 1, s, "ErrUnsupportedVersion")
    _value(public_key_problem(m["principal"]) is None, s, "ErrInvalidPublicKey", "principal")
    _value(_ascending(m["agents"]), s, "ErrOrder", "agents")
    for a in m["agents"]:
        _value(public_key_problem(a) is None, s, "ErrInvalidPublicKey", "agent")
    _value(m["principal"] not in m["agents"], s, "ErrKeyRole", "principal is an agent")
    _value(m["not_before"] >= 1, s, "ErrZeroValue", "not_before")
    _value(m["not_before"] < m["not_after"] <= MAX_RFC3339, s, "ErrIntRange", "not_after")
    _value(all(KIND_RE.match(x) for x in m.get("kinds", [])), s, "ErrInvalidString", "kinds")
    _value(_ascending(m.get("kinds", []), lambda x: x.encode()), s, "ErrOrder", "kinds")
    _value(_ascending(m["assets"], lambda r: r["asset"].encode()), s, "ErrOrder", "assets")
    for r in m["assets"]:
        _value(r["scale"] <= 255, s, "ErrIntRange", "scale")
        _value("per_action_max" in r or "periods" in r, s, "ErrMissingField", "per_action_max or periods")
        if "per_action_max" in r:
            _value(_amount_ok(r["per_action_max"]), s, "ErrNonMinimalAmount", "per_action_max")
            _value(amt_int(r["per_action_max"]) >= 1, s, "ErrZeroValue", "per_action_max")
        for p in r.get("periods", []):
            _value(1 <= p["hours"] <= MAX_HOURS, s, "ErrIntRange", "hours")
            _value(_amount_ok(p["max"]), s, "ErrNonMinimalAmount", "max")
            _value(amt_int(p["max"]) >= 1, s, "ErrZeroValue", "max")
        _value(_ascending(r.get("periods", []), lambda p: p["hours"]), s, "ErrOrder", "periods")
        _value(_ascending(r.get("recipients", []), lambda x: x.encode()), s, "ErrOrder", "recipients")
    for c in m.get("count_limits", []):
        _value(1 <= c["hours"] <= MAX_HOURS, s, "ErrIntRange", "hours")
        _value(1 <= c["max_count"] <= 1 << 32, s, "ErrIntRange", "max_count")
    _value(_ascending(m.get("count_limits", []), lambda c: c["hours"]), s, "ErrOrder", "count_limits")
    _value(m["version"] >= 1, s, "ErrZeroValue", "version")
    if "max_decision_age" in m:
        _value(1 <= m["max_decision_age"] <= 86400, s, "ErrIntRange", "max_decision_age")
    if "min_spacing" in m:
        _value(1 <= m["min_spacing"] <= 2678400, s, "ErrIntRange", "min_spacing")


def mandate_cbor(m: dict) -> bytes:
    check_mandate(m)
    return encode(to_cbor(m, S_MANDATE))


def mandate_hash(canon: bytes) -> bytes:
    return thash("mandate", canon)


def signed_message(name: str, h: bytes) -> bytes:
    return tagged(name) + h


def counter_key(principal: bytes, mandate_id: bytes) -> bytes:
    return thash("counter", principal + mandate_id)


def ed_sign(seed: bytes, msg: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.from_private_bytes(seed).sign(msg)


def ed_pub(seed: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def sign_mandate(seed: bytes, m: dict) -> tuple:
    canon = mandate_cbor(m)
    h = mandate_hash(canon)
    sig = ed_sign(seed, signed_message("mandate-sig", h))
    return encode({1: to_cbor(m, S_MANDATE), 2: sig}), h, sig


def decode_signed_mandate(b: bytes) -> tuple:
    s = "ErrMandateInvalid"
    it = parse(b, s, CAP["mandate"])
    sm = sdecode(it, S_SIGNED_MANDATE, s)
    check_mandate(sm["mandate"])
    if encode({1: to_cbor(sm["mandate"], S_MANDATE), 2: sm["signature"]}) != b:
        raise PolicyError(s, "ErrNonCanonical")
    return sm, mandate_hash(encode(to_cbor(sm["mandate"], S_MANDATE)))


def verify_mandate(b: bytes) -> tuple:
    sm, h = decode_signed_mandate(b)
    try:
        _verify_tagged_hash(sm["mandate"]["principal"], h, sm["signature"], TAG["mandate-sig"])
    except Reject as e:
        raise PolicyError("ErrMandateSignature", e.sentinel)
    return sm["mandate"], h


def asset_rule(m: dict, asset: str):
    return next((r for r in m["assets"] if r["asset"] == asset), None)


def adopt(cell, m: dict, mh: bytes) -> tuple[str, dict]:
    """Adoption of a verified mandate against the counter cell (section 6.3).

    cell is None or {"version", "mandate_hash", "scales": {asset: scale}}.
    Returns (action, next cell); a refusal raises ErrInvalidConfig."""
    if cell is None:
        return "genesis", {"version": m["version"], "mandate_hash": mh,
                           "scales": {r["asset"]: r["scale"] for r in m["assets"]}}
    if cell["version"] > m["version"]:
        raise PolicyError("ErrInvalidConfig", "version")
    if cell["version"] == m["version"]:
        if cell["mandate_hash"] != mh:
            raise PolicyError("ErrInvalidConfig", "same_version_other_hash")
        return "use", cell
    scales = dict(cell["scales"])
    for r in m["assets"]:
        if scales.get(r["asset"], r["scale"]) != r["scale"]:
            raise PolicyError("ErrInvalidConfig", "scale", r["asset"])
        scales[r["asset"]] = r["scale"]
    if len(scales) > MAX_SCALES:
        raise PolicyError("ErrInvalidConfig", "scales_full")
    return "switch", {"version": m["version"], "mandate_hash": mh, "scales": scales}


# Render (section 7).

def fmt_amount(b: bytes, scale: int) -> str:
    digits = str(amt_int(b))
    if scale == 0:
        return digits
    digits = digits.rjust(scale + 1, "0")
    return digits[:-scale] + "." + digits[-scale:]


def rfc3339(t: int) -> str:
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


NOTES = [
    "Limits are measured on the anchor time of each decision (block time of its payload), not on execution time.",
    "Limits use hourly buckets; a bucket partly inside a window counts fully, so a limit may cover up to one extra "
    "hour (a \"per 1h\" limit may span up to 2h): the gate may deny early, never allow extra.",
    "Limits count authorizations, not executions.",
    "Counters continue across versions of this mandate_id; a new mandate_id starts from zero.",
]


def render(m: dict) -> str:
    check_mandate(m)
    out = ["Edicta mandate v1", f"principal: {m['principal'].hex()}", f"mandate_id: {m['mandate_id'].hex()}",
           f"version: {m['version']}", f"gate: {m['gate_id']}",
           f"valid: anchor time from {rfc3339(m['not_before'])} ; decision valid_until up to {rfc3339(m['not_after'])}",
           f"max decision age: {m['max_decision_age']}s" if "max_decision_age" in m
           else "max decision age: default (MaxTTL of the payload's DA)",
           f"min spacing: {m['min_spacing']}s" if "min_spacing" in m else "min spacing: none",
           f"agents ({len(m['agents'])}, shared counter):"]
    out += [f"  - {a.hex()}" for a in m["agents"]]
    out.append("kinds: " + (", ".join(m["kinds"]) if "kinds" in m else "any"))
    for r in m["assets"]:
        s = r["scale"]
        out.append(f"asset {r['asset']} (scale {s}):")
        out.append(f"  per action: max {fmt_amount(r['per_action_max'], s)}" if "per_action_max" in r
                   else "  per action: no limit")
        if r.get("periods"):
            out += [f"  period: max {fmt_amount(p['max'], s)} per rolling {p['hours']}h (may count up to "
                    f"{p['hours'] + 1}h)" for p in r["periods"]]
        else:
            out.append("  period: no limit")
        if "recipients" in r:
            out.append("  recipients:")
            out += [f"    - {x}" for x in r["recipients"]]
        else:
            out.append("  recipients: any")
    if m.get("count_limits"):
        out += [f"count: max {c['max_count']} actions per rolling {c['hours']}h (may count up to {c['hours'] + 1}h)"
                for c in m["count_limits"]]
    else:
        out.append("count: no limit")
    out.append("notes:")
    out += [f"  - {n}" for n in NOTES]
    return "\n".join(out) + "\n"


# State (section 9).

def check_bucket(b: dict, s: str = "ErrStateInvalid"):
    _value(b["format"] == 1, s, "ErrUnsupportedVersion")
    _value(b["count"] >= 1, s, "ErrZeroValue", "count")
    for x in b["sums"]:
        _value(x["scale"] <= 255, s, "ErrIntRange", "scale")
        _value(_amount_ok(x["sum"]), s, "ErrNonMinimalAmount", "sum")
    _value(_ascending(b["sums"], lambda x: (x["asset"].encode(), x["scale"])), s, "ErrOrder", "sums")


def check_closed(c: dict, s: str = "ErrStateInvalid"):
    _value(c["format"] == 1, s, "ErrUnsupportedVersion")
    _value(_ascending(c["buckets"], lambda r: r["index"]), s, "ErrOrder", "buckets")


def check_state(st: dict, s: str = "ErrStateInvalid"):
    _value(st["format"] == 1, s, "ErrUnsupportedVersion")
    if st["seq"] == 0:
        _value(not ({"last_t", "last_th", "open"} & set(st)), s, "ErrPresence", "genesis fields")
        _value(st["closed_root"] == EMPTY_ROOT, s, "ErrPresence", "genesis closed_root")
    else:
        _value({"last_t", "last_th", "open"} <= set(st), s, "ErrPresence", "seq >= 1 fields")
        check_bucket(st["open"], s)
        _value(st["last_th"] <= st["last_t"], s, "ErrOrder", "last_th")
        _value(st["open"]["index"] == k(st["last_t"]), s, "ErrOrder", "open index")


def bucket_cbor(b: dict) -> bytes:
    check_bucket(b)
    return encode(to_cbor(b, S_BUCKET))


def closed_cbor(c: dict) -> bytes:
    check_closed(c)
    return encode(to_cbor(c, S_CLOSED))


def state_cbor(st: dict) -> bytes:
    check_state(st)
    return encode(to_cbor(st, S_STATE))


def bucket_hash(b: dict) -> bytes:
    return thash("bucket", bucket_cbor(b))


def closed_root(c: dict) -> bytes:
    return thash("closed", closed_cbor(c))


def state_hash(st: dict) -> bytes:
    return thash("state", state_cbor(st))


EMPTY_CLOSED = {"format": 1, "buckets": []}
EMPTY_ROOT = thash("closed", encode(to_cbor(EMPTY_CLOSED, S_CLOSED)))
GENESIS = {"format": 1, "seq": 0, "closed_root": EMPTY_ROOT}


def _decode_struct(b: bytes, schema, cap, check):
    s = "ErrStateInvalid"
    it = parse(b, s, cap)
    v = sdecode(it, schema, s)
    check(v)
    if encode(to_cbor(v, schema)) != b:
        raise PolicyError(s, "ErrNonCanonical")
    return v


def decode_bucket(b: bytes) -> dict:
    return _decode_struct(b, S_BUCKET, CAP["bucket"], check_bucket)


def decode_closed(b: bytes) -> dict:
    return _decode_struct(b, S_CLOSED, CAP["closed"], check_closed)


def decode_state(b: bytes) -> dict:
    return _decode_struct(b, S_STATE, CAP["state"], check_state)


def check_ledger(led: dict):
    """Section 9.2 on a ledger {state, set, buckets}."""
    s = "ErrStateInvalid"
    st, cs = led["state"], led["set"]
    _value(closed_root(cs) == st["closed_root"], s, "ErrHashMismatch", "closed_root")
    if st["seq"] == 0:
        _value(not cs["buckets"], s, "ErrPresence", "genesis set")
        return
    oi = st["open"]["index"]
    for r in cs["buckets"]:
        _value(max(0, oi - RETAIN) <= r["index"] < oi, s, "ErrOrder", "closed index")
    refs = {r["index"]: r["hash"] for r in cs["buckets"]}
    for i, b in led["buckets"].items():
        _value(i in refs and b["index"] == i and bucket_hash(b) == refs[i], s, "ErrHashMismatch", "bucket")


# Engine (section 8).

def admit(m: dict, extractors: dict, d: dict):
    """P1 to P8. Returns (reason, extractor_id, facts); reason None on admit."""
    if d["agent_pubkey"] not in m["agents"]:
        return "ErrAgentNotCovered", None, None
    xid = extractors.get(d["action_type"])
    if xid is None:
        return "ErrNoExtractor", None, None
    try:
        f = EXTRACTORS[xid](d["action"])
        check_facts(f)
    except PolicyError:
        return "ErrFactsInvalid", xid, None
    if d["valid_until"] > m["not_after"]:
        return "ErrOutsideMandate", xid, f
    if "kinds" in m and f["kind"] not in m["kinds"]:
        return "ErrKindNotAllowed", xid, f
    r = asset_rule(m, f["asset"])
    if r is None or r["scale"] != f["scale"]:
        return "ErrAssetNotAllowed", xid, f
    if "recipients" in r and f.get("recipient") not in r["recipients"]:
        return "ErrRecipientNotAllowed", xid, f
    if "per_action_max" in r and amt_int(f["amount"]) > amt_int(r["per_action_max"]):
        return "ErrAmountAboveMax", xid, f
    return None, xid, f


def _rolled(led: dict, teff: int) -> tuple:
    """Rollover to k(teff). Returns (state fields, set, buckets with contents, closed bucket or None)."""
    st = led["state"]
    refs = [dict(r) for r in led["set"]["buckets"]]
    buckets = dict(led["buckets"])
    kk = k(teff)
    closed = None
    if st["seq"] == 0:
        open_b = {"format": 1, "index": kk, "count": 0, "sums": []}
    elif kk > st["open"]["index"]:
        closed = st["open"]
        refs.append({"index": closed["index"], "hash": bucket_hash(closed)})
        buckets[closed["index"]] = closed
        refs = [r for r in refs if r["index"] >= kk - RETAIN]
        buckets = {i: b for i, b in buckets.items() if i >= kk - RETAIN}
        open_b = {"format": 1, "index": kk, "count": 0, "sums": []}
    else:
        open_b = {"format": 1, "index": st["open"]["index"], "count": st["open"]["count"],
                  "sums": [dict(x) for x in st["open"]["sums"]]}
    return refs, buckets, open_b, closed


def _window(refs, buckets, open_b, t, hours):
    lo = k(t - HOUR * hours + 1) if t >= HOUR * hours else 0
    out = [open_b] if lo <= open_b["index"] <= k(t) else []
    for r in refs:
        if lo <= r["index"] <= k(t):
            if r["index"] not in buckets:
                raise KeyError(f"bucket {r['index']} needed")
            out.append(buckets[r["index"]])
    return out


def _sum(bs, asset, scale):
    return sum(amt_int(x["sum"]) for b in bs for x in b["sums"] if x["asset"] == asset and x["scale"] == scale)


def apply(led: dict, delta: dict) -> dict:
    """The allow transition alone. delta = {asset, scale, amount, t_h}."""
    st = led["state"]
    teff = delta["t_h"] if st["seq"] == 0 else max(delta["t_h"], st["last_t"])
    refs, buckets, open_b, closed = _rolled(led, teff)
    sums = open_b["sums"]
    key = (delta["asset"].encode(), delta["scale"])
    for x in sums:
        if (x["asset"].encode(), x["scale"]) == key:
            x["sum"] = amt(amt_int(x["sum"]) + amt_int(delta["amount"]))
            break
    else:
        sums.append({"asset": delta["asset"], "scale": delta["scale"], "sum": delta["amount"]})
        sums.sort(key=lambda x: (x["asset"].encode(), x["scale"]))
    open_b["count"] += 1
    cs = {"format": 1, "buckets": refs}
    nst = {"format": 1, "seq": st["seq"] + 1, "last_t": teff, "last_th": delta["t_h"],
           "closed_root": closed_root(cs), "open": open_b}
    nxt = {"state": nst, "set": cs, "buckets": buckets}
    return {"next": nxt, "new_hash": state_hash(nst), "eval_time": teff, "closed_bucket": closed,
            "closed_set": cs if closed is not None else None}


def evaluate(m: dict, led: dict, f: dict, th: int) -> dict:
    """P10 to P14. Returns {"deny": reason, "cause"?, "eval_time"?} or the apply() step."""
    st = led["state"]
    if th < m["not_before"]:
        return {"deny": "ErrOutsideMandate"}
    teff = th if st["seq"] == 0 else max(th, st["last_t"])
    if "min_spacing" in m and st["seq"] >= 1 and th < min(MAX_INT, st["last_th"] + m["min_spacing"]):
        return {"deny": "ErrMinSpacing", "eval_time": teff}
    refs, buckets, open_b, _ = _rolled(led, teff)
    r = asset_rule(m, f["asset"])
    a = amt_int(f["amount"])
    for p in r.get("periods", []):
        if _sum(_window(refs, buckets, open_b, teff, p["hours"]), f["asset"], f["scale"]) + a > amt_int(p["max"]):
            return {"deny": "ErrPeriodLimit", "eval_time": teff}
    for c in m.get("count_limits", []):
        if sum(b["count"] for b in _window(refs, buckets, open_b, teff, c["hours"])) + 1 > c["max_count"]:
            return {"deny": "ErrCountLimit", "eval_time": teff}
    cur = next((x for x in open_b["sums"] if x["asset"] == f["asset"] and x["scale"] == f["scale"]), None)
    if cur is not None and amt_int(cur["sum"]) + a > MAX_AMOUNT:
        return {"deny": "ErrHistoryFull", "cause": "sum", "eval_time": teff}
    if open_b["count"] + 1 > MAX_INT:
        return {"deny": "ErrHistoryFull", "cause": "count", "eval_time": teff}
    if cur is None and len(open_b["sums"]) + 1 > MAX_PAIRS:
        return {"deny": "ErrHistoryFull", "cause": "pairs", "eval_time": teff}
    if st["seq"] + 1 > MAX_INT:
        return {"deny": "ErrHistoryFull", "cause": "seq", "eval_time": teff}
    return apply(led, {"asset": f["asset"], "scale": f["scale"], "amount": f["amount"], "t_h": th})


def needed_buckets(m: dict, asset: str, eval_time: int, refs: list) -> list:
    r = asset_rule(m, asset) or {}
    w = max([p["hours"] for p in r.get("periods", [])] + [c["hours"] for c in m.get("count_limits", [])] + [0])
    return [x for x in refs if x["index"] >= k(eval_time) - w]


# Verdict (section 10).

def check_verdict(v: dict):
    s = "ErrVerdictInvalid"
    _value(v["format"] == 1, s, "ErrUnsupportedVersion")
    _value(v["outcome"] in (1, 2), s, "ErrInvalidEnum", "outcome")
    _value(v["decided_at"] >= 1, s, "ErrZeroValue", "decided_at")
    if "extractor" in v:
        _value(EXTRACTOR_RE.match(v["extractor"]) is not None, s, "ErrInvalidString", "extractor")
    if "facts" in v:
        check_facts(v["facts"], s)
    if "prev_state" in v:
        check_state(v["prev_state"], s)
    has = set(v) - {"format", "gate_id", "mandate_hash", "commitment_hash", "action_hash", "agent_pubkey",
                    "outcome", "decided_at"}
    if v["outcome"] == 1:
        want = {"extractor", "facts", "anchor_time", "eval_time", "prev_state", "new_state_hash"}
        if "prev_state" in v and v["prev_state"]["seq"] >= 1:
            want |= {"prev_commitment_hash", "prev_verdict_hash"}
    else:
        _value("reason" in v and v["reason"] in DENY_P, s, "ErrInvalidEnum", "reason")
        p = DENY_P[v["reason"]]
        if v["reason"] == "ErrOutsideMandate" and "anchor_time" in v:
            p = 10
        want = {"reason"}
        if p >= 3:
            want.add("extractor")
        if p >= 4:
            want.add("facts")
        if p >= 9:
            want.add("anchor_time")
        if p == 9:
            want.add("gate_clock")
        if p >= 10:
            want.add("prev_state")
        if p >= 11:
            want.add("eval_time")
    _value(has <= want, s, "ErrUnknownKey", f"present but not allowed: {sorted(has - want)}")
    _value(want <= has, s, "ErrMissingField", f"missing: {sorted(want - has)}")
    if "gate_clock" in v:
        _value(v["gate_clock"] == 1, s, "ErrInvalidEnum", "gate_clock")


def verdict_cbor(v: dict) -> bytes:
    check_verdict(v)
    return encode(to_cbor(v, S_VERDICT))


def verdict_hash_of(v: dict) -> bytes:
    return thash("verdict", verdict_cbor(v))


def sign_verdict(seed: bytes, v: dict) -> tuple:
    h = verdict_hash_of(v)
    sig = ed_sign(seed, signed_message("verdict-sig", h))
    return encode({1: to_cbor(v, S_VERDICT), 2: sig}), h


def decode_signed_verdict(b: bytes) -> tuple:
    s = "ErrVerdictInvalid"
    it = parse(b, s, CAP["verdict"])
    sv = sdecode(it, S_SIGNED_VERDICT, s)
    check_verdict(sv["verdict"])
    if encode({1: to_cbor(sv["verdict"], S_VERDICT), 2: sv["signature"]}) != b:
        raise PolicyError(s, "ErrNonCanonical")
    return sv, thash("verdict", encode(to_cbor(sv["verdict"], S_VERDICT)))


def verify_verdict(b: bytes, gate_pub: bytes) -> tuple:
    sv, h = decode_signed_verdict(b)
    try:
        _verify_tagged_hash(gate_pub, h, sv["signature"], TAG["verdict-sig"])
    except Reject as e:
        raise PolicyError("ErrVerdictSignature", e.sentinel)
    return sv["verdict"], h


def delta_of(v: dict) -> dict:
    f = v["facts"]
    return {"asset": f["asset"], "scale": f["scale"], "amount": f["amount"], "t_h": v["anchor_time"]}


def successor_key(gate_id: str, ck: bytes, sh: bytes) -> bytes:
    g = gate_id.encode()
    return thash("successor", bytes([len(g)]) + g + ck + sh)


# Archive records (section 12).

KIND_NAMES = {7: "mandate", 8: "policy_allow", 9: "policy_deny", 10: "policy_bucket", 11: "policy_closed",
              12: "policy_successor"}
PATHS = {7: "mandate", 8: "policy-allow", 9: "policy-deny", 10: "policy-bucket", 11: "policy-closed",
         12: "policy-successor"}
REC_CAP = {7: 16448, 8: 16448, 9: 16448, 10: 16448, 11: 36928, 12: 256}


def record(kind: int, **f) -> bytes:
    m = {1: 0, 2: kind}
    if kind in (7, 8, 9, 10, 11):
        m[3] = f["body"]
    else:
        m.update({3: f["gate_id"], 4: f["counter_key"], 5: f["state_hash"], 6: f["commitment_hash"]})
    return encode(m)


def decode_record(b: bytes) -> dict:
    """Policy kinds only. Raises PolicyError('archive.ErrCorrupt', cause). Returns
    {kind, key, path, body} where key is the logical key bytes."""
    s = "archive.ErrCorrupt"
    if len(b) > 36928:
        raise PolicyError(s, "ErrTooLarge")
    d = _D(b, s)
    it = d.item(0)
    if d.i != len(b):
        raise PolicyError(s, "ErrTrailingData")
    if it[0] != 5:
        raise PolicyError(s, "ErrWrongType")
    m = dict(it[1])
    for key in (1, 2):
        if key not in m:
            raise PolicyError(s, "ErrMissingField")
        if m[key][0] != 0:
            raise PolicyError(s, "ErrWrongType")
    if m[1][1] != 0:
        raise PolicyError(s, "ErrUnsupportedVersion")
    kind = m[2][1]
    if kind not in KIND_NAMES:
        raise PolicyError(s, "ErrInvalidEnum")
    if len(b) > REC_CAP[kind]:
        raise PolicyError(s, "ErrTooLarge")
    fields = {3: (2, 1, 36864 if kind == 11 else 16384)} if kind != 12 else {3: (3, 1, 64), 4: (2, 32, 32), 5: (2, 32, 32), 6: (2, 32, 32)}
    for key, (major, val) in it[1]:
        if key in (1, 2):
            continue
        if key not in fields:
            raise PolicyError(s, "ErrUnknownKey")
        want, lo, hi = fields[key]
        if major != want:
            raise PolicyError(s, "ErrWrongType")
        if not lo <= len(val) <= hi:
            raise PolicyError(s, "ErrFieldSize")
        if major == 3 and any(c not in ID_CHARS for c in val):
            raise PolicyError(s, "ErrInvalidString")
    for key in fields:
        if key not in m:
            raise PolicyError(s, "ErrMissingField")
    out = {"kind": kind}
    try:
        if kind == 7:
            sm, h = decode_signed_mandate(m[3][1])
            out.update(key=h, body=m[3][1])
        elif kind in (8, 9):
            sv, _ = decode_signed_verdict(m[3][1])
            v = sv["verdict"]
            if v["outcome"] != (1 if kind == 8 else 2):
                raise PolicyError(s, "ErrInvalidEnum")
            out.update(key=v["commitment_hash"], reason=v.get("reason"), body=m[3][1])
        elif kind == 10:
            out.update(key=thash("bucket", m[3][1]), body=m[3][1], bucket=decode_bucket(m[3][1]))
        elif kind == 11:
            out.update(key=thash("closed", m[3][1]), body=m[3][1], closed=decode_closed(m[3][1]))
        else:
            out.update(key=successor_key(m[3][1], m[4][1], m[5][1]), gate_id=m[3][1], counter_key=m[4][1],
                       state_hash=m[5][1], commitment_hash=m[6][1])
    except PolicyError as e:
        if e.sentinel == s:
            raise
        raise PolicyError(s, e.sentinel)
    if encode({kk: vv[1] for kk, vv in it[1]}) != b:
        raise PolicyError(s, "ErrNonCanonical")
    out["path"] = f"{PATHS[kind]}/{out['key'].hex()}" + (f"/{out['reason']}" if kind == 9 else "")
    return out


# Verifier (section 13). The archive is a dict path -> record bytes.

class Archive:
    def __init__(self, recs: dict):
        self.recs = recs

    def get(self, kind: int, key: bytes):
        """Returns ('absent'|'corrupt'|'ok', decoded)."""
        path = f"{PATHS[kind]}/{key.hex()}"
        if path not in self.recs:
            return "absent", None
        try:
            r = decode_record(self.recs[path])
        except PolicyError:
            return "corrupt", None
        if r["kind"] != kind or r["key"] != key:
            return "corrupt", None
        return "ok", r


EXTRACTORS = {TEST_EXTRACTOR: test_extract}


def verify_policy(case: dict) -> dict:
    """case: decision{commitment_hash, agent_pubkey, action_type, action, action_hash, valid_until, gate_id},
    t_h (int or None), gate_pub, principals (list), extractors {type: id}, archive (Archive),
    full (bool), max_walk_steps (int or None: the default), evidence (list of bytes). Returns the expectation dict."""
    A, d, gp = case["archive"], case["decision"], case["gate_pub"]
    res = {"fail": None, "fast_unchecked": None, "walk_unchecked": None, "violations": [], "walk_ran": False,
           "blocked_th": False, "walk": None}

    def violated(*vs):
        if not res["violations"]:
            res["violations"] = [verdict_hash_of(x) for x in vs]

    def read_allow(ch):
        st, r = A.get(8, ch)
        if st != "ok":
            return st, None
        try:
            v, _ = verify_verdict(r["body"], gp)
        except PolicyError:
            return "corrupt", None
        return "ok", v

    def read_mandate(h):
        st, r = A.get(7, h)
        if st != "ok":
            return st, None
        try:
            mm, _ = verify_mandate(r["body"])
        except PolicyError:
            return "corrupt", None
        return "ok", mm

    def ledger_for(v, m, need_contents):
        root = v["prev_state"]["closed_root"]
        if root == EMPTY_ROOT:
            cs = EMPTY_CLOSED
        else:
            st, r = A.get(11, root)
            if st != "ok":
                return st, None
            cs = r["closed"]
        buckets = {}
        if need_contents:
            for ref in needed_buckets(m, v["facts"]["asset"], v["eval_time"], cs["buckets"]):
                st, r = A.get(10, ref["hash"])
                if st != "ok":
                    return st, None
                buckets[ref["index"]] = r["bucket"]
        led = {"state": v["prev_state"], "set": cs, "buckets": buckets}
        try:
            check_ledger(led)
        except PolicyError:
            return "inconsistent", None
        return "ok", led

    src = {"absent": "state_history_unavailable", "corrupt": "source_corrupt"}

    # Step 1.
    st, V = read_allow(d["commitment_hash"])
    if st != "ok":
        return finish(res | {"fast_unchecked": "policy_verdict_unavailable" if st == "absent" else "source_corrupt",
                             "no_target": True})
    if (V["action_hash"], V["agent_pubkey"], V["gate_id"]) != (d["action_hash"], d["agent_pubkey"], d["gate_id"]):
        violated(V)
    held = [V]

    def fast():
        st, m = read_mandate(V["mandate_hash"])
        if st != "ok":
            return ("unchecked", "policy_mandate_unavailable" if st == "absent" else "source_corrupt"), None
        if m["principal"] not in case["principals"]:
            return ("unchecked", "policy_principal_untrusted"), None
        if m["gate_id"] != V["gate_id"]:
            return ("fail", "mandate_gate_id"), m
        xid = case["extractors"].get(d["action_type"])
        if xid is None or xid != V["extractor"]:
            return ("unchecked", "policy_no_extractor"), m
        try:
            f = EXTRACTORS[xid](d["action"])
            check_facts(f)
        except PolicyError:
            return ("fail", "facts_mismatch"), m
        if f != V["facts"]:
            return ("fail", "facts_mismatch"), m
        reason, _, _ = admit(m, case["extractors"], d)
        if reason is not None:
            return ("fail", reason), m
        if case["t_h"] is not None:
            if V["anchor_time"] != case["t_h"]:
                return ("fail", "anchor_time_mismatch"), m
            if case["t_h"] < m["not_before"]:
                return ("fail", "ErrOutsideMandate"), m
        else:
            res["blocked_th"] = True
        st, led = ledger_for(V, m, True)
        if st == "inconsistent":
            violated(V)
            return None, m
        if st != "ok":
            return ("unchecked", src[st]), m
        ps = V["prev_state"]
        want = V["anchor_time"] if ps["seq"] == 0 else max(V["anchor_time"], ps["last_t"])
        if V["eval_time"] != want:
            return ("fail", "eval_time_mismatch"), m
        r = evaluate(m, led, V["facts"], V["anchor_time"])
        if "deny" in r:
            return ("fail", r["deny"]), m
        if r["new_hash"] != V["new_state_hash"]:
            violated(V)
        return None, m

    out, mV = fast()
    if out and out[0] == "fail":
        res["fail"] = out[1]
    elif out:
        res["fast_unchecked"] = out[1]

    mandates = {}

    def mandate_of(v):
        h = v["mandate_hash"]
        if h not in mandates:
            mandates[h] = read_mandate(h)
        return mandates[h]

    cap = case["max_walk_steps"] or MAX_WALK_STEPS

    def walk():
        res["walk_ran"] = True
        n, hops = V, 0
        walked = [V]
        known = {}
        while n["prev_state"]["seq"] >= 1:
            if hops >= cap:
                return "policy_walk_truncated", walked
            st, p = read_allow(n["prev_commitment_hash"])
            if st != "ok":
                return src[st], walked
            if p["commitment_hash"] != n["prev_commitment_hash"]:
                return "source_corrupt", walked
            if verdict_hash_of(p) != n["prev_verdict_hash"] or p["new_state_hash"] != state_hash(n["prev_state"]) \
                    or p["prev_state"]["seq"] + 1 != n["prev_state"]["seq"]:
                violated(p, n)
                return None, walked
            sp, mp = mandate_of(p)
            sn, mn = mandate_of(n)
            if sp != "ok" or sn != "ok":
                return src[sp if sp != "ok" else sn], walked
            same = all(mp[x] == mn[x] for x in ("principal", "mandate_id", "gate_id"))
            if not same or mp["version"] > mn["version"]:
                violated(p, n)
                return None, walked
            for r in mn["assets"]:
                known[r["asset"]] = (r["scale"], n)
            clash = next((known[r["asset"]][1] for r in mp["assets"]
                          if known.get(r["asset"], (r["scale"],))[0] != r["scale"]), None)
            if clash is not None:
                violated(p, clash)
                return None, walked
            st, led = ledger_for(p, mp, False)
            if st == "inconsistent":
                violated(p)
                return None, walked
            if st != "ok":
                return src[st], walked
            if apply(led, delta_of(p))["new_hash"] != p["new_state_hash"]:
                violated(p)
                return None, walked
            walked.append(p)
            n, hops = p, hops + 1
        return None, walked

    walked = [V]
    if case["full"] and not res["violations"]:
        res["walk_unchecked"], walked = walk()
        end = "genesis" if walked[-1]["prev_state"]["seq"] == 0 else \
            "max_steps" if res["walk_unchecked"] == "policy_walk_truncated" else "finding"
        res["walk"] = {"max_steps": str(cap), "steps": str(len(walked) - 1),
                       "from_seq": str(walked[-1]["prev_state"]["seq"]), "to_seq": str(V["prev_state"]["seq"]),
                       "total": str(V["prev_state"]["seq"] + 1), "end": end}
        held = list(walked)
        if not res["violations"]:
            for w in walked:
                ms, mw = mandate_of(w)
                if ms != "ok":
                    continue
                key = successor_key(w["gate_id"], counter_key(mw["principal"], mw["mandate_id"]),
                                    state_hash(w["prev_state"]))
                st, r = A.get(12, key)
                if st == "ok" and r["commitment_hash"] != w["commitment_hash"]:
                    s2, x = read_allow(r["commitment_hash"])
                    if s2 == "ok":
                        held.append(x)
    for e in case["evidence"]:
        try:
            x, _ = verify_verdict(e, gp)
        except PolicyError:
            continue
        if x["outcome"] == 1:
            held.append(x)
    if not res["violations"]:
        info = []
        for x in held:
            ms, mx = mandate_of(x)
            if ms == "ok" and x["gate_id"] == V["gate_id"]:
                info.append((counter_key(mx["principal"], mx["mandate_id"]), x["prev_state"]["seq"], x))
        for i in range(len(info)):
            for j in range(i + 1, len(info)):
                a, b = info[i], info[j]
                if a[0] == b[0] and a[1] == b[1] and a[2]["commitment_hash"] != b[2]["commitment_hash"]:
                    violated(a[2], b[2])
                    break
            if res["violations"]:
                break
    return finish(res)


def finish(res: dict) -> dict:
    viol = bool(res["violations"])
    if res.get("no_target"):
        policy = {"status": "unchecked", "reason": res["fast_unchecked"]}
    elif res["fail"]:
        policy = {"status": "fail", "rule": res["fail"]}
    elif viol:
        policy = {"status": "unchecked", "reason": "blocked"}
    elif res["blocked_th"]:
        policy = {"status": "unchecked", "reason": "blocked"}
    elif res["fast_unchecked"]:
        policy = {"status": "unchecked", "reason": res["fast_unchecked"]}
    elif res["walk_unchecked"] and res["walk_unchecked"] != "policy_walk_truncated":
        policy = {"status": "unchecked", "reason": res["walk_unchecked"]}
    else:
        policy = {"status": "pass"}
    if viol:
        gi = {"status": "violated", "reason": "gate_equivocation", "evidence": [h.hex() for h in res["violations"]]}
    elif res["walk_ran"] and res["walk_unchecked"]:
        gi = {"status": "unchecked", "reason": res["walk_unchecked"], "evidence": []}
    elif res["walk_ran"]:
        gi = {"status": "ok", "reason": None, "evidence": []}
    else:
        gi = {"status": "not_checked", "reason": None, "evidence": []}
    if res["walk"] is not None:
        gi["walk"] = res["walk"]
    if policy["status"] == "fail":
        verdict, code = "invalid", 1
    elif viol:
        verdict, code = "unchecked", 5
    elif policy["status"] == "unchecked":
        verdict, code = "unchecked", 2
    else:
        verdict, code = "valid", 0
    return {"policy": policy, "gate_integrity": gi, "verdict": verdict, "exit": str(code)}
