"""Edicta policy v1 rules (spec/policy-v1.md, policy-v1-draft.8).

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
from edicta import ID_CHARS, Reject, _verify_tagged_hash
from ed25519_point import public_key_problem

FAMILY = b"edicta/policy/v1/"
TAG = {n: FAMILY + n.encode() for n in
       ("mandate", "mandate-sig", "verdict", "verdict-sig", "bucket", "closed", "state", "counter", "successor",
        "private-part", "private", "private-dek", "state-blind", "blind-key")}
TAG_AUDITOR_KID = b"edicta/v1/auditor-kid"

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
          "ErrDecisionAge": 9, "ErrMinSpacing": 11, "ErrPeriodLimit": 12, "ErrCountLimit": 13, "ErrHistoryFull": 14,
          "ErrFastModeNotAllowed": 15}
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
HRP_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789")
SIG_ED25519, SIG_ADR036, SIG_EIP712 = None, 2, 3
# Label charset: printable ASCII without '"' and '\\', so a label can break neither the quoting nor the line.
LABEL_CHARS = frozenset(chr(c) for c in range(0x20, 0x7F)) - {'"', "\\"}
S_AUDITOR = {1: ("kid", "bstr", True, (16, 16)), 2: ("pubkey", "bstr", True, (32, 32)),
             3: ("label", "tstr", True, (1, 64, LABEL_CHARS))}
S_MANDATE = {1: ("format", "uint", True, None), 2: ("principal", "bstr", True, (20, 33)),
             3: ("gate_id", "tstr", True, (1, 64, ID_CHARS)),
             4: ("agents", ("arr", ("bstr", (32, 32)), 1, 64), True, None),
             5: ("not_before", "uint", True, None), 6: ("not_after", "uint", True, None),
             7: ("assets", ("arr", ("map", S_ASSET), 1, 16), True, None),
             8: ("count_limits", ("arr", ("map", S_COUNT), 1, 4), False, None),
             9: ("mandate_id", "bstr", True, (16, 16)), 10: ("version", "uint", True, None),
             11: ("max_decision_age", "uint", False, None), 12: ("min_spacing", "uint", False, None),
             13: ("kinds", ("arr", ("tstr", (1, 32, ASSET_CHARS)), 1, 8), False, None),
             14: ("sig_type", "uint", False, None), 15: ("principal_hrp", "tstr", False, (1, 16, HRP_CHARS)),
             16: ("fast_mode_max_delay", "uint", False, None),
             17: ("auditors", ("arr", ("map", S_AUDITOR), 1, 16), False, None),
             18: ("state_salt", "bstr", False, (32, 32))}
S_SIGNED_MANDATE = {1: ("mandate", ("map", S_MANDATE), True, None), 2: ("signature", "bstr", True, (64, 65))}
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
             17: ("decided_at", "uint", False, None), 18: ("gate_clock", "uint", False, None),
             19: ("private_hash", "bstr", False, (32, 32)), 20: ("prev_state_hash", "bstr", False, (32, 32))}
# The verdict keys moved out of a private-form verdict, under the same numbers, plus a per-verdict salt.
S_PRIVATE_PART = {1: ("format", "uint", True, None), 2: ("salt", "bstr", True, (32, 32)),
                  8: ("reason", "tstr", False, (4, 64, ID_CHARS)), 9: ("extractor", "tstr", False, (1, 64, ID_CHARS)),
                  10: ("facts", ("map", S_FACTS()), False, None), 11: ("anchor_time", "uint", False, None),
                  12: ("eval_time", "uint", False, None), 13: ("prev_state", ("map", S_STATE), False, None),
                  17: ("decided_at", "uint", True, None), 18: ("gate_clock", "uint", False, None)}
PRIVATE_MOVED = ("reason", "extractor", "facts", "anchor_time", "eval_time", "prev_state", "decided_at", "gate_clock")
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

def x25519_low_order(pub: bytes) -> bool:
    """X25519 with the scalar of 32 bytes 0x01 (clamped to a multiple of 8) gives zero exactly for the
    low-order points; OpenSSL refuses an all-zero shared secret, which is that case."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    try:
        return X25519PrivateKey.from_private_bytes(b"\x01" * 32).exchange(
            X25519PublicKey.from_public_bytes(pub)) == bytes(32)
    except ValueError:
        return True


def check_mandate(m: dict):
    """Value rules in reporting order: format, scheme, principal, HRP, then the draft.4 rules, then fast mode
    and auditors."""
    import principal_crypto as pc
    s = "ErrMandateInvalid"
    _value(m["format"] == 1, s, "ErrUnsupportedVersion")
    st = m.get("sig_type")
    _value(st in (None, SIG_ADR036, SIG_EIP712), s, "ErrInvalidEnum", "sig_type")
    if st is None:
        _value(len(m["principal"]) == 32, s, "ErrFieldSize", "principal")
        _value(public_key_problem(m["principal"]) is None, s, "ErrInvalidPublicKey", "principal")
    elif st == SIG_ADR036:
        _value(len(m["principal"]) == 33, s, "ErrFieldSize", "principal")
        _value(pc.decompress(m["principal"]) is not None, s, "ErrInvalidPublicKey", "principal")
    else:
        _value(len(m["principal"]) == 20, s, "ErrFieldSize", "principal")
    _value(("principal_hrp" in m) == (st == SIG_ADR036), s,
           "ErrMissingField" if st == SIG_ADR036 else "ErrUnknownKey", "principal_hrp")
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
    if "fast_mode_max_delay" in m:
        _value(1 <= m["fast_mode_max_delay"] <= 1000, s, "ErrIntRange", "fast_mode_max_delay")
    if "auditors" in m:
        for a in m["auditors"]:
            _value(a["label"] == a["label"].strip(" "), s, "ErrInvalidString", "auditor_label")
            _value(a["kid"] == auditor_kid(a["pubkey"]), s, "ErrAuditorKidMismatch", "auditor_kid")
        _value(_ascending(m["auditors"], lambda a: a["kid"]), s, "ErrOrder", "auditors")
        labels = [a["label"] for a in m["auditors"]]
        _value(len(set(labels)) == len(labels), s, "ErrDuplicate", "auditor_label_duplicate")
        for a in m["auditors"]:
            _value(not x25519_low_order(a["pubkey"]), s, "ErrInvalidPublicKey", "auditor")
    _value(("state_salt" in m) == ("auditors" in m), s,
           "ErrMissingField" if "auditors" in m else "ErrUnknownKey", "state_salt")


def auditor_kid(pubkey: bytes) -> bytes:
    """kid = SHA-256(tag("edicta/v1/auditor-kid") || X25519 pubkey)[0..16] (policy 6.1)."""
    return hashlib.sha256(bytes([len(TAG_AUDITOR_KID)]) + TAG_AUDITOR_KID + pubkey).digest()[:16]


def fingerprint(kid: bytes) -> str:
    """The full 128-bit kid as 8 groups of 4 lower-case hex digits."""
    h = kid.hex()
    return " ".join(h[i:i + 4] for i in range(0, 32, 4))


def mandate_cbor(m: dict) -> bytes:
    check_mandate(m)
    return encode(to_cbor(m, S_MANDATE))


def mandate_hash(canon: bytes) -> bytes:
    return thash("mandate", canon)


def signed_message(name: str, h: bytes) -> bytes:
    return tagged(name) + h


def counter_key(principal: bytes, mandate_id: bytes, sig_type: int | None = None) -> bytes:
    if sig_type is None:
        return thash("counter", principal + mandate_id)
    return thash("counter", bytes([sig_type, len(principal)]) + principal + mandate_id)


def counter_key_of(m: dict) -> bytes:
    return counter_key(m["principal"], m["mandate_id"], m.get("sig_type"))


# Principal signatures (section 6.2).

EIP712_DOMAIN_TYPE = b"EIP712Domain(string name,string version)"
EIP712_NAME = b"Edicta Mandate"
EIP712_VERSION = b"1"
EIP712_MANDATE_TYPE = b"Mandate(bytes32 mandateHash,bytes16 mandateId,uint64 version,string gateId)"


def eip712_parts(m: dict, mh: bytes) -> dict:
    from principal_crypto import keccak256 as kk
    dom = kk(kk(EIP712_DOMAIN_TYPE) + kk(EIP712_NAME) + kk(EIP712_VERSION))
    th = kk(EIP712_MANDATE_TYPE)
    hs = kk(th + mh + m["mandate_id"] + bytes(16) + m["version"].to_bytes(32, "big") + kk(m["gate_id"].encode()))
    return {"domain_separator": dom, "type_hash": th, "hash_struct": hs,
            "digest": kk(b"\x19\x01" + dom + hs)}


def eip712_typed_data(m: dict, mh: bytes) -> dict:
    """The eth_signTypedData_v4 JSON a wallet is given (bytes as 0x hex, uint64 as a decimal string)."""
    return {"types": {"EIP712Domain": [{"name": "name", "type": "string"}, {"name": "version", "type": "string"}],
                      "Mandate": [{"name": "mandateHash", "type": "bytes32"}, {"name": "mandateId", "type": "bytes16"},
                                  {"name": "version", "type": "uint64"}, {"name": "gateId", "type": "string"}]},
            "primaryType": "Mandate", "domain": {"name": EIP712_NAME.decode(), "version": EIP712_VERSION.decode()},
            "message": {"mandateHash": "0x" + mh.hex(), "mandateId": "0x" + m["mandate_id"].hex(),
                        "version": str(m["version"]), "gateId": m["gate_id"]}}


def adr036_data(m: dict, mh: bytes) -> str:
    return render(m) + "\n" + "mandate hash: " + mh.hex()


def adr036_signer(m: dict) -> str:
    import principal_crypto as pc
    return pc.cosmos_address(m["principal"], m["principal_hrp"])


def adr036_signdoc(data: str, signer: str) -> bytes:
    import base64
    b64 = base64.b64encode(data.encode("ascii")).decode("ascii")
    doc = ('{"account_number":"0","chain_id":"","fee":{"amount":[],"gas":"0"},"memo":"",'
           '"msgs":[{"type":"sign/MsgSignData","value":{"data":"' + b64 + '","signer":"' + signer + '"}}],'
           '"sequence":"0"}')
    return doc.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026").encode("ascii")


def ed_sign(seed: bytes, msg: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.from_private_bytes(seed).sign(msg)


def ed_pub(seed: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def principal_sign(seed: bytes, m: dict, h: bytes) -> bytes:
    import principal_crypto as pc
    st = m.get("sig_type")
    if st is None:
        return ed_sign(seed, signed_message("mandate-sig", h))
    if st == SIG_ADR036:
        return pc.sign_cosmos(seed, adr036_signdoc(adr036_data(m, h), adr036_signer(m)))
    return pc.sign_eth(seed, eip712_parts(m, h)["digest"])


def sign_mandate(seed: bytes, m: dict) -> tuple:
    canon = mandate_cbor(m)
    h = mandate_hash(canon)
    sig = principal_sign(seed, m, h)
    return encode({1: to_cbor(m, S_MANDATE), 2: sig}), h, sig


def decode_signed_mandate(b: bytes) -> tuple:
    s = "ErrMandateInvalid"
    it = parse(b, s, CAP["mandate"])
    sm = sdecode(it, S_SIGNED_MANDATE, s)
    _value(len(sm["signature"]) == (65 if sm["mandate"].get("sig_type") == SIG_EIP712 else 64), s, "ErrFieldSize",
           "signature")
    check_mandate(sm["mandate"])
    if encode({1: to_cbor(sm["mandate"], S_MANDATE), 2: sm["signature"]}) != b:
        raise PolicyError(s, "ErrNonCanonical")
    return sm, mandate_hash(encode(to_cbor(sm["mandate"], S_MANDATE)))


def verify_mandate(b: bytes, schemes=(None, SIG_ADR036, SIG_EIP712)) -> tuple:
    """Decoding with the value rules, then the principal signature of the mandate's scheme. A scheme outside
    `schemes` (a build without it) raises principal_scheme_unsupported."""
    import principal_crypto as pc
    sm, h = decode_signed_mandate(b)
    m, sig = sm["mandate"], sm["signature"]
    st = m.get("sig_type")
    if st not in schemes:
        raise PolicyError("principal_scheme_unsupported", str(st))
    if st is None:
        try:
            _verify_tagged_hash(m["principal"], h, sig, TAG["mandate-sig"])
        except Reject as e:
            raise PolicyError("ErrMandateSignature", e.sentinel)
    elif st == SIG_ADR036:
        if not pc.verify_cosmos(m["principal"], adr036_signdoc(adr036_data(m, h), adr036_signer(m)), sig):
            raise PolicyError("ErrMandateSignature", "adr036")
    elif not pc.verify_eth(m["principal"], eip712_parts(m, h)["digest"], sig):
        raise PolicyError("ErrMandateSignature", "eip712")
    return m, h


def asset_rule(m: dict, asset: str):
    return next((r for r in m["assets"] if r["asset"] == asset), None)


def adopt(cell, m: dict, mh: bytes) -> tuple[str, dict]:
    """Adoption of a verified mandate against the counter cell (section 6.3).

    cell is None or {"version", "mandate_hash", "scales": {asset: scale}, optional "state_salt"}.
    Returns (action, next cell); a refusal raises ErrInvalidConfig."""
    salt = {"state_salt": m["state_salt"]} if "state_salt" in m else {}
    if cell is None:
        return "genesis", {"version": m["version"], "mandate_hash": mh,
                           "scales": {r["asset"]: r["scale"] for r in m["assets"]}, **salt}
    if cell["version"] > m["version"]:
        raise PolicyError("ErrInvalidConfig", "version")
    if cell["version"] == m["version"]:
        if cell["mandate_hash"] != mh:
            raise PolicyError("ErrInvalidConfig", "same_version_other_hash")
        return "use", cell
    if cell.get("state_salt") != m.get("state_salt"):
        raise PolicyError("ErrInvalidConfig", "state_salt_changed")
    scales = dict(cell["scales"])
    for r in m["assets"]:
        if scales.get(r["asset"], r["scale"]) != r["scale"]:
            raise PolicyError("ErrInvalidConfig", "scale", r["asset"])
        scales[r["asset"]] = r["scale"]
    if len(scales) > MAX_SCALES:
        raise PolicyError("ErrInvalidConfig", "scales_full")
    return "switch", {"version": m["version"], "mandate_hash": mh, "scales": scales, **salt}


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
    "Limits are measured on the reference time of each decision (block time at its payload reference height), not "
    "on execution time.",
    "Limits use hourly buckets; a bucket partly inside a window counts fully, so a limit may cover up to one extra "
    "hour (a \"per 1h\" limit may span up to 2h): the gate may deny early, never allow extra.",
    "Limits count authorizations, not executions.",
    "Counters continue across versions of this mandate_id; a new mandate_id starts from zero.",
    "In fast mode the gate may authorize before the payload is anchored on L1; the anchor must land within the "
    "stated number of blocks or the decision is invalid.",
]
LABEL_NOTE = "Labels are not verified; check each key fingerprint or address out of band."


def principal_line(m: dict) -> str:
    st = m.get("sig_type")
    if st is None:
        return f"principal: ed25519 {m['principal'].hex()}"
    if st == SIG_ADR036:
        return f"principal: cosmos {adr036_signer(m)} (adr-036)"
    return f"principal: ethereum 0x{m['principal'].hex()} (eip-712)"


def render(m: dict) -> str:
    check_mandate(m)
    out = ["Edicta mandate v1", f"mandate_id: {m['mandate_id'].hex()}", f"version: {m['version']}",
           f"gate: {m['gate_id']}", principal_line(m),
           f"fast mode: allowed, anchor at most {m['fast_mode_max_delay']} blocks after the reference height"
           if "fast_mode_max_delay" in m else "fast mode: not allowed"]
    if "auditors" in m:
        out.append(f"auditors: {len(m['auditors'])} (private mandate)")
        out += [f"  - Auditor \"{a['label']}\" (label not verified) - key fingerprint: {fingerprint(a['kid'])}"
                for a in m["auditors"]]
    else:
        out.append("auditors: none (public mandate)")
    out += [f"valid: reference time from {rfc3339(m['not_before'])} ; decision valid_until up to "
            f"{rfc3339(m['not_after'])}",
            f"max decision age: {m['max_decision_age']}s" if "max_decision_age" in m
            else "max decision age: default (MaxTTL of the payload's DA)",
            f"min spacing: {m['min_spacing']}s" if "min_spacing" in m else "min spacing: none",
            f"agents ({len(m['agents'])}, shared counter):"]
    out += [f"  - {a.hex()}" for a in m["agents"]]
    out.append("kinds: " + (", ".join(m["kinds"]) if "kinds" in m else "any"))
    for r in m["assets"]:
        sc = r["scale"]
        out.append(f"asset {r['asset']} (scale {sc}):")
        out.append(f"  per action: max {fmt_amount(r['per_action_max'], sc)}" if "per_action_max" in r
                   else "  per action: no limit")
        if r.get("periods"):
            out += [f"  period: max {fmt_amount(p['max'], sc)} per rolling {p['hours']}h (may count up to "
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
    if "auditors" in m:
        out.append(f"  - {LABEL_NOTE}")
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
GENESIS_HASH = state_hash(GENESIS)


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
    """P1, P15, P2 to P8. Returns (reason, extractor_id, facts); reason None on admit. d["pending"]: the
    commitment's reference is pending (absent: included)."""
    if d["agent_pubkey"] not in m["agents"]:
        return "ErrAgentNotCovered", None, None
    if d.get("pending") and "fast_mode_max_delay" not in m:
        return "ErrFastModeNotAllowed", None, None
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

def verdict_form(v: dict) -> str:
    """'private' iff key 19 is present, else 'public'."""
    return "private" if "private_hash" in v else "public"


def prev_state_hash_of(v: dict) -> bytes:
    """Key 20 in private form; state_hash(prev_state) in public form (public mode never blinds)."""
    return v["prev_state_hash"] if "prev_state_hash" in v else state_hash(v["prev_state"])


def reads_genesis(v: dict) -> bool:
    return v["prev_state_hash"] == GENESIS_HASH if "private_hash" in v else v["prev_state"]["seq"] == 0


def _deny_row(v: dict) -> int:
    p = DENY_P[v["reason"]]
    if v["reason"] == "ErrOutsideMandate" and "anchor_time" in v:
        p = 10
    return 1 if p == 15 else p


def _public_presence(v: dict, s: str):
    """The presence table of 10.2 for a public-form (or merged) verdict."""
    has = set(v) - {"format", "gate_id", "mandate_hash", "commitment_hash", "action_hash", "agent_pubkey",
                    "outcome", "decided_at"}
    if v["outcome"] == 1:
        want = {"extractor", "facts", "anchor_time", "eval_time", "new_state_hash", "prev_state"}
        if "prev_state" in v and v["prev_state"]["seq"] >= 1:
            want |= {"prev_commitment_hash", "prev_verdict_hash"}
    else:
        _value("reason" in v and v["reason"] in DENY_P, s, "ErrInvalidEnum", "reason")
        p = _deny_row(v)
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
    _value("decided_at" in v, s, "ErrMissingField", "decided_at")


def check_verdict(v: dict):
    s = "ErrVerdictInvalid"
    _value(v["format"] == 1, s, "ErrUnsupportedVersion")
    _value(v["outcome"] in (1, 2), s, "ErrInvalidEnum", "outcome")
    if "decided_at" in v:
        _value(v["decided_at"] >= 1, s, "ErrZeroValue", "decided_at")
    if "extractor" in v:
        _value(EXTRACTOR_RE.match(v["extractor"]) is not None, s, "ErrInvalidString", "extractor")
    if "facts" in v:
        check_facts(v["facts"], s)
    if "prev_state" in v:
        check_state(v["prev_state"], s)
    if verdict_form(v) == "public":
        _value("prev_state_hash" not in v, s, "ErrUnknownKey", "key 20 in public form")
        _public_presence(v, s)
    else:
        moved = [k for k in PRIVATE_MOVED if k in v]
        _value(not moved, s, "ErrUnknownKey", f"private form with {moved}")
        has = set(v) - {"format", "gate_id", "mandate_hash", "commitment_hash", "action_hash", "agent_pubkey",
                        "outcome", "private_hash"}
        want = set()
        if v["outcome"] == 1:
            want = {"new_state_hash", "prev_state_hash"}
            if "prev_state_hash" in v and v["prev_state_hash"] != GENESIS_HASH:
                want |= {"prev_commitment_hash", "prev_verdict_hash"}
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


# Private mode (sections 9.1, 9.5, 10.1).

PRIVATE_CAP = 65536
PRIVATE_ACTION_CAP = 69632
PLAINTEXT_KINDS = {1: "mandate", 2: "bucket", 3: "closed_set", 4: "private_part", 5: "action"}


def state_hash_p(st: dict, salt: bytes | None) -> bytes:
    """The state hash of a counter: blinded with the mandate's state_salt in private mode (salt given), the
    public state_hash otherwise; Genesis keeps the public constant in both modes."""
    if salt is None or st == GENESIS:
        return state_hash(st)
    return hashlib.sha256(tagged("state-blind") + salt + state_cbor(st)).digest()


def blind_key(salt: bytes | None, h: bytes) -> bytes:
    """The kind 15 key of a bucket or ClosedSet in private mode."""
    if salt is None:
        return h
    return hashlib.sha256(tagged("blind-key") + salt + h).digest()


def check_private_part(pp: dict, s: str = "ErrVerdictInvalid"):
    _value(pp["format"] == 1, s, "ErrUnsupportedVersion", "private part")
    _value(pp["decided_at"] >= 1, s, "ErrZeroValue", "decided_at")
    if "extractor" in pp:
        _value(EXTRACTOR_RE.match(pp["extractor"]) is not None, s, "ErrInvalidString", "extractor")
    if "facts" in pp:
        check_facts(pp["facts"], s)
    if "prev_state" in pp:
        check_state(pp["prev_state"], s)
    if "gate_clock" in pp:
        _value(pp["gate_clock"] == 1, s, "ErrInvalidEnum", "gate_clock")


def private_part_cbor(pp: dict) -> bytes:
    check_private_part(pp)
    return encode(to_cbor(pp, S_PRIVATE_PART))


def private_hash(pp: dict) -> bytes:
    return thash("private-part", private_part_cbor(pp))


def decode_private_part(b: bytes) -> dict:
    return _decode_struct(b, S_PRIVATE_PART, CAP["state"], check_private_part)


def split_verdict(v: dict, salt: bytes) -> tuple:
    """A public-form verdict of a private-mode gate split into (private-form public part, PrivatePart).
    new_state_hash must already be blinded; key 20 is state_hash_p of prev_state, given by the caller in
    v["_prev_state_hash"] for allows."""
    pp = {"format": 1, "salt": salt, **{k: v[k] for k in PRIVATE_MOVED if k in v}}
    pub = {k: x for k, x in v.items() if k not in PRIVATE_MOVED and not k.startswith("_")}
    if v["outcome"] == 1:
        pub["prev_state_hash"] = v["_prev_state_hash"]
    pub["private_hash"] = private_hash(pp)
    return pub, pp


def merge_verdict(pub: dict, pp: dict) -> dict:
    """The logical (public-form) verdict: public part without keys 19, 20, plus the PrivatePart without 1, 2."""
    out = {k: x for k, x in pub.items() if k not in ("private_hash", "prev_state_hash")}
    out.update({k: x for k, x in pp.items() if k not in ("format", "salt")})
    return out


def check_merged(pub: dict, pp: dict):
    """PrivatePart presence against the public outcome (10.2 public row). ErrVerdictInvalid."""
    _public_presence(merge_verdict(pub, pp), "ErrVerdictInvalid")


def plaintext_hash(pk: int, b: bytes, action_type: str | None = None) -> bytes:
    """The plaintext's hash under its own tag; raises PolicyError when the bytes do not decode."""
    if pk == 1:
        return decode_signed_mandate(b)[1]
    if pk == 2:
        decode_bucket(b)
        return thash("bucket", b)
    if pk == 3:
        decode_closed(b)
        return thash("closed", b)
    if pk == 5:
        if action_type is None or len(b) < 33:
            raise PolicyError("ErrVerdictInvalid", "action plaintext")
        t = action_type.encode()
        return hashlib.sha256(bytes([16]) + b"edicta/v1/action" + bytes([len(t)]) + t + b).digest()
    decode_private_part(b)
    return thash("private-part", b)


def private_seal(plaintext: bytes, auditors: list, salt: bytes, dek: bytes, aead_nonce: bytes, sk_es: list,
                 info: bytes | None = None, aead_aad: bytes | None = None) -> tuple:
    """The core payload blob layout with the policy tags. Returns (envelope, per-auditor trace)."""
    import edicta_payload as pl
    rs = [pl.Recipient(a["kid"], a["pubkey"], sk) for a, sk in zip(auditors, sk_es)]
    return pl.seal(salt, plaintext, rs, dek, aead_nonce, info=tagged("private-dek") if info is None else info,
                   aead_aad=tagged("private") if aead_aad is None else aead_aad, check=False)


def private_open(env: bytes, keys: list, pk: int, want: bytes, action_type: str | None = None) -> tuple:
    """Reader rules of section 9.5. keys: X25519 private keys. Returns ('ok', plaintext, kid),
    ('corrupt', cause, None) or ('private', None, None). A reader tries the entry of its own derived kid first."""
    import hpke_base as hpke
    import edicta_payload as pl
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    if len(env) > (PRIVATE_ACTION_CAP if pk == 5 else PRIVATE_CAP):
        return "corrupt", "ErrTooLarge", None
    try:
        b = pl.blob_decode(env)
    except Reject as e:
        return "corrupt", e.sentinel, None
    for sk in keys:
        own = auditor_kid(hpke._pk_bytes(sk))
        for e in sorted(b.recipients, key=lambda e: e.kid != own):
            try:
                dek = hpke.setup_base_r(e.enc, sk, tagged("private-dek")).open(bytes([len(e.kid)]) + e.kid,
                                                                              e.wrapped_dek)
            except hpke.HPKEError:
                continue
            if len(dek) != 32:
                return "corrupt", "dek size", None
            try:
                pt = ChaCha20Poly1305(dek).decrypt(b.aead_nonce, b.ciphertext, tagged("private"))
            except InvalidTag:
                return "corrupt", "aead", None
            pt = pt[32:]
            try:
                h = plaintext_hash(pk, pt, action_type)
            except PolicyError as x:
                return "corrupt", x.sentinel, None
            if h != want:
                return "corrupt", "hash mismatch", None
            return "ok", pt, e.kid
    return "private", None, None


# Archive records (section 12).

KIND_NAMES = {7: "mandate", 8: "policy_allow", 9: "policy_deny", 10: "policy_bucket", 11: "policy_closed",
              12: "policy_successor", 15: "private_blob"}
PATHS = {7: "mandate", 8: "policy-allow", 9: "policy-deny", 10: "policy-bucket", 11: "policy-closed",
         12: "policy-successor", 15: "private"}
REC_CAP = {7: 16448, 8: 16448, 9: 16448, 10: 16448, 11: 36928, 12: 256, 15: 69760}


def record(kind: int, **f) -> bytes:
    m = {1: 1, 2: kind}
    if kind in (7, 8, 9, 10, 11):
        m[3] = f["body"]
    elif kind == 15:
        m.update({3: f["plaintext_kind"], 4: f["hash"], 5: f["envelope"]})
    else:
        m.update({3: f["gate_id"], 4: f["counter_key"], 5: f["state_hash"], 6: f["commitment_hash"]})
    return encode(m)


def decode_record(b: bytes) -> dict:
    """Policy kinds only. Raises PolicyError('archive.ErrCorrupt', cause). Returns
    {kind, key, path, body} where key is the logical key bytes."""
    s = "archive.ErrCorrupt"
    if len(b) > REC_CAP[15]:
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
    if m[1][1] != 1:
        raise PolicyError(s, "ErrUnsupportedVersion")
    kind = m[2][1]
    if kind not in KIND_NAMES:
        raise PolicyError(s, "ErrInvalidEnum")
    if len(b) > REC_CAP[kind]:
        raise PolicyError(s, "ErrTooLarge")
    fields = {3: (2, 1, 36864 if kind == 11 else 16384)} if kind not in (12, 15) else \
        {3: (3, 1, 64), 4: (2, 32, 32), 5: (2, 32, 32), 6: (2, 32, 32)} if kind == 12 else \
        {3: (0, None, None), 4: (2, 32, 32), 5: (2, 1, PRIVATE_ACTION_CAP)}
    for key, (major, val) in it[1]:
        if key in (1, 2):
            continue
        if key not in fields:
            raise PolicyError(s, "ErrUnknownKey")
        want, lo, hi = fields[key]
        if major != want:
            raise PolicyError(s, "ErrWrongType")
        if major == 0:
            if val not in PLAINTEXT_KINDS:
                raise PolicyError(s, "ErrInvalidEnum")
            continue
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
            # Key segment of kind 9: the bare reason in public form, "private" in private form (no public reason).
            out.update(key=v["commitment_hash"], reason="private" if "private_hash" in v else v.get("reason"),
                       body=m[3][1])
        elif kind == 10:
            out.update(key=thash("bucket", m[3][1]), body=m[3][1], bucket=decode_bucket(m[3][1]))
        elif kind == 11:
            out.update(key=thash("closed", m[3][1]), body=m[3][1], closed=decode_closed(m[3][1]))
        elif kind == 15:
            if m[3][1] != 5 and len(m[5][1]) > PRIVATE_CAP:
                raise PolicyError(s, "ErrFieldSize")
            out.update(key=m[4][1], plaintext_kind=m[3][1], envelope=m[5][1])
        else:
            out.update(key=successor_key(m[3][1], m[4][1], m[5][1]), gate_id=m[3][1], counter_key=m[4][1],
                       state_hash=m[5][1], commitment_hash=m[6][1])
    except PolicyError as e:
        if e.sentinel == s:
            raise
        raise PolicyError(s, e.sentinel)
    if encode({kk: vv[1] for kk, vv in it[1]}) != b:
        raise PolicyError(s, "ErrNonCanonical")
    if kind == 15:
        out["path"] = f"private/{out['plaintext_kind']}/{out['key'].hex()}"
    else:
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

    def get_private(self, pk: int, key: bytes):
        path = f"private/{pk}/{key.hex()}"
        if path not in self.recs:
            return "absent", None
        try:
            r = decode_record(self.recs[path])
        except PolicyError:
            return "corrupt", None
        if r["kind"] != 15 or r["plaintext_kind"] != pk or r["key"] != key:
            return "corrupt", None
        return "ok", r


EXTRACTORS = {TEST_EXTRACTOR: test_extract}


def principal_trusted(m: dict, principals: list) -> bool:
    """principals: Ed25519 keys as bytes, ("cosmos", bech32 address) or ("eth", 20-byte address)."""
    import principal_crypto as pc
    st = m.get("sig_type")
    if st is None:
        return m["principal"] in principals
    if st == SIG_ADR036:
        return ("cosmos", pc.cosmos_address(m["principal"], m["principal_hrp"])) in principals
    return ("eth", m["principal"]) in principals


def verify_policy(case: dict) -> dict:
    """case: decision{commitment_hash, agent_pubkey, action_type, action, action_hash, valid_until, gate_id, and
    for a v1 decision version = 1, mandate_ref (None: absent), mode (1 strict, 2 fast), h0, anchor_deadline},
    t_h (int or None), gate_pub, principals (see principal_trusted), extractors {type: id}, archive (Archive),
    full (bool), max_walk_steps (int or None: the default), evidence (list of bytes), optional schemes (the
    principal schemes of this build) and auditor_keys (X25519 private keys). Returns the expectation dict."""
    A, d, gp = case["archive"], case["decision"], case["gate_pub"]
    keys = case.get("auditor_keys", [])
    schemes = case.get("schemes", (None, SIG_ADR036, SIG_EIP712))
    v1 = True
    res = {"fail": None, "fast_unchecked": None, "walk_unchecked": None, "violations": [], "walk_ran": False,
           "blocked_th": False, "walk": None, "report": {}}

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

    def read_private(pk, key, want):
        """('ok', plaintext bytes, kid) or (status, None, None); status absent, corrupt, private."""
        st, r = A.get_private(pk, key)
        if st != "ok":
            return st, None, None
        return private_open(r["envelope"], keys, pk, want)

    mandates = {}

    def read_mandate(h):
        """('ok', mandate, kid or None) or (status, None, None); status absent, corrupt, private, unsupported."""
        if h in mandates:
            return mandates[h]
        st, r = A.get(7, h)
        kid = None
        if st == "ok":
            body = r["body"]
        elif st == "absent":
            st, body, kid = read_private(1, h, h)
        if st != "ok":
            mandates[h] = (st, None, None)
            return mandates[h]
        try:
            mm, _ = verify_mandate(body, schemes)
            mandates[h] = ("ok", mm, kid)
        except PolicyError as e:
            mandates[h] = ("unsupported" if e.sentinel == "principal_scheme_unsupported" else "corrupt", None, None)
        return mandates[h]

    def salt_of(m):
        return m.get("state_salt") if m is not None else None

    logicals = {}

    def logical(v, m):
        """The public-form verdict: v itself in public form; in private form the merge with its PrivatePart.
        Returns (status, verdict): ok, absent, corrupt, private, inconsistent (a decrypted state that does not
        hash to key 20 under the mandate's salt), or self_inconsistent (a PrivatePart that hashes to the signed
        private_hash but breaks the presence rule: the gate signed a contradiction)."""
        if verdict_form(v) == "public":
            return "ok", v
        h = v["private_hash"]
        if h not in logicals:
            st, pt, _ = read_private(4, h, h)
            if st != "ok":
                logicals[h] = (st, None)
            else:
                pp = decode_private_part(pt)
                merged = merge_verdict(v, pp)
                if v["outcome"] == 1 and "prev_state" in pp and \
                        state_hash_p(pp["prev_state"], salt_of(m)) != v["prev_state_hash"]:
                    logicals[h] = ("inconsistent", merged)
                else:
                    try:
                        check_merged(v, pp)
                        logicals[h] = ("ok", merged)
                    except PolicyError:
                        logicals[h] = ("self_inconsistent", merged)
        return logicals[h]

    def read_struct(kind, pk, h, dec, m):
        if salt_of(m) is None:
            st, r = A.get(kind, h)
            if st == "ok":
                return "ok", r["closed" if kind == 11 else "bucket"]
            if st != "absent":
                return st, None
        st, pt, _ = read_private(pk, blind_key(salt_of(m), h), h)
        if st == "ok":
            return "ok", dec(pt)
        return st, None

    def ledger_for(v, ps, m, need_contents):
        root = ps["closed_root"]
        if root == EMPTY_ROOT:
            cs = EMPTY_CLOSED
        else:
            st, cs = read_struct(11, 3, root, decode_closed, m)
            if st != "ok":
                return st, None
        buckets = {}
        if need_contents:
            for ref in needed_buckets(m, v["facts"]["asset"], v["eval_time"], cs["buckets"]):
                st, b = read_struct(10, 2, ref["hash"], decode_bucket, m)
                if st != "ok":
                    return st, None
                buckets[ref["index"]] = b
        led = {"state": ps, "set": cs, "buckets": buckets}
        try:
            check_ledger(led)
        except PolicyError:
            return "inconsistent", None
        return "ok", led

    src = {"absent": "state_history_unavailable", "corrupt": "source_corrupt", "private": "policy_private",
           "unsupported": "principal_scheme_unsupported"}

    # Step 1.
    st, V = read_allow(d["commitment_hash"])
    if st != "ok":
        return finish(res | {"fast_unchecked": "policy_verdict_unavailable" if st == "absent" else "source_corrupt",
                             "no_target": True})
    if (V["action_hash"], V["agent_pubkey"], V["gate_id"]) != (d["action_hash"], d["agent_pubkey"], d["gate_id"]):
        violated(V)
    held = [V]
    if v1:
        ms, mm, _ = read_mandate(V["mandate_hash"])
        private_mode = ms == "private" or (mm is not None and "auditors" in mm) or \
            (mm is None and verdict_form(V) == "private")
        res["report"]["mode"] = "private" if private_mode else "public"

    def facts_check(VL):
        xid = case["extractors"].get(d["action_type"])
        if xid is None or xid != VL["extractor"]:
            return "unchecked", "policy_no_extractor"
        try:
            f = EXTRACTORS[xid](d["action"])
            check_facts(f)
        except PolicyError:
            return "fail", "facts_mismatch"
        if f != VL["facts"]:
            return "fail", "facts_mismatch"
        return None

    def fast():
        if v1:
            if d["mandate_ref"] is not None and d["mandate_ref"] != V["mandate_hash"]:
                return ("fail", "mandate_ref_mismatch"), None
            res["report"]["mandate_ref"] = "absent" if d["mandate_ref"] is None else "match"
        st, m, kid = read_mandate(V["mandate_hash"])
        if st == "private":
            # Without an auditor key only step 1 runs; the facts, times, rules and state are private.
            return ("unchecked", "policy_private"), None
        if st != "ok":
            return ("unchecked", "policy_mandate_unavailable" if st == "absent" else src[st]), None
        if kid is not None and v1:
            res["report"]["auditor_kid"] = fingerprint(kid)
        if not principal_trusted(m, case["principals"]):
            return ("unchecked", "policy_principal_untrusted"), None
        if m["gate_id"] != V["gate_id"]:
            return ("fail", "mandate_gate_id"), m
        if (verdict_form(V) == "private") != ("auditors" in m):
            violated(V)
            return None, m
        st, VL = logical(V, m)
        if st == "inconsistent":
            violated(V)
            return None, m
        if st == "self_inconsistent":
            # The verdict itself is the evidence. The policy is still judged on what the verifier derives on
            # its own: its extractor's facts stand in for missing ones, and a deny on them is a fail.
            res["pp_violation"] = [V]
            if "facts" not in VL:
                xid = case["extractors"].get(d["action_type"])
                if xid is None:
                    return ("unchecked", "policy_no_extractor"), m
                try:
                    VL = dict(VL, facts=EXTRACTORS[xid](d["action"]), extractor=xid)
                except PolicyError:
                    return ("unchecked", "blocked"), m
            if any(k not in VL for k in ("extractor", "anchor_time", "eval_time", "prev_state")):
                return ("unchecked", "blocked"), m
            st = "ok"
        if st != "ok":
            return ("unchecked", src[st]), m
        out = facts_check(VL)
        if out:
            return out, m
        reason, _, _ = admit(m, case["extractors"], d | {"pending": d.get("mode") == 2})
        if reason in ("ErrAgentNotCovered", "ErrFastModeNotAllowed"):
            return ("fail", reason), m
        if d.get("mode") == 2 and d["anchor_deadline"] - d["h0"] > m["fast_mode_max_delay"]:
            return ("fail", "fast_mode_delay"), m
        if reason is not None:
            return ("fail", reason), m
        if case["t_h"] is not None:
            if VL["anchor_time"] != case["t_h"]:
                return ("fail", "anchor_time_mismatch"), m
            if case["t_h"] < m["not_before"]:
                return ("fail", "ErrOutsideMandate"), m
        else:
            res["blocked_th"] = True
        ps = VL["prev_state"]
        st, led = ledger_for(VL, ps, m, True)
        if st == "inconsistent":
            violated(V)
            return None, m
        if st != "ok":
            return ("unchecked", src[st]), m
        want = VL["anchor_time"] if ps["seq"] == 0 else max(VL["anchor_time"], ps["last_t"])
        if VL["eval_time"] != want:
            return ("fail", "eval_time_mismatch"), m
        r = evaluate(m, led, VL["facts"], VL["anchor_time"])
        if "deny" in r:
            return ("fail", r["deny"]), m
        if state_hash_p(r["next"]["state"], salt_of(m)) != V["new_state_hash"]:
            violated(V)
        return None, m

    out, mV = fast()
    if out and out[0] == "fail":
        res["fail"] = out[1]
    elif out:
        res["fast_unchecked"] = out[1]
    no_key = read_mandate(V["mandate_hash"])[0] == "private"

    cap = case["max_walk_steps"] or MAX_WALK_STEPS

    def merged_of(v):
        ms, m, _ = read_mandate(v["mandate_hash"])
        if ms != "ok":
            return ms, None, None
        st, vl = logical(v, m)
        return st, vl, m

    def hop(p, n, known):
        """L1 to L5 for one hop; returns None, or an unchecked reason, after recording any violation."""
        if verdict_hash_of(p) != n["prev_verdict_hash"] or p["new_state_hash"] != prev_state_hash_of(n):
            violated(p, n)
            return None
        if no_key:
            return None
        sp_, lp, mp = merged_of(p)
        sn_, ln, mn = merged_of(n)
        for s_, x in ((sn_, n), (sp_, p)):
            if s_ == "inconsistent":
                violated(x)
                return None
            if s_ == "self_inconsistent":
                res["pp_violation"] = res.get("pp_violation") or [x]
                return None
        if sp_ != "ok" or sn_ != "ok":
            return src[sp_ if sp_ != "ok" else sn_]
        if lp["prev_state"]["seq"] + 1 != ln["prev_state"]["seq"]:
            violated(p, n)
            return None
        same = all(mp.get(x) == mn.get(x) for x in ("sig_type", "principal", "mandate_id", "gate_id"))
        if not same or mp["version"] > mn["version"]:
            violated(p, n)
            return None
        for r in mn["assets"]:
            known[r["asset"]] = (r["scale"], n)
        clash = next((known[r["asset"]][1] for r in mp["assets"]
                      if known.get(r["asset"], (r["scale"],))[0] != r["scale"]), None)
        if clash is not None:
            violated(p, clash)
            return None
        st, led = ledger_for(lp, lp["prev_state"], mp, False)
        if st == "inconsistent":
            violated(p)
            return None
        if st != "ok":
            return src[st]
        if state_hash_p(apply(led, delta_of(lp))["next"]["state"], salt_of(mp)) != p["new_state_hash"]:
            violated(p)
        return None

    def walk():
        res["walk_ran"] = True
        n, walked, known = V, [V], {}
        while not reads_genesis(n):
            if len(walked) - 1 >= cap:
                return "policy_walk_truncated", walked
            st, p = read_allow(n["prev_commitment_hash"])
            if st == "ok" and p["commitment_hash"] != n["prev_commitment_hash"]:
                st = "corrupt"
            if st != "ok":
                return src[st], walked
            u = hop(p, n, known)
            if u or res["violations"]:
                return u, walked
            walked.append(p)
            n = p
        return None, walked

    def seq_of(v):
        st, vl, _ = merged_of(v)
        return vl["prev_state"]["seq"] if st == "ok" else None

    walked = [V]
    if case["full"] and not res["violations"]:
        res["walk_unchecked"], walked = walk()
        end = "genesis" if reads_genesis(walked[-1]) else \
            "max_steps" if res["walk_unchecked"] == "policy_walk_truncated" else "finding"
        res["walk"] = {"max_steps": str(cap), "steps": str(len(walked) - 1)}
        if not no_key and seq_of(V) is not None and seq_of(walked[-1]) is not None:
            res["walk"] |= {"from_seq": str(seq_of(walked[-1])), "to_seq": str(seq_of(V)),
                            "total": str(seq_of(V) + 1)}
        res["walk"]["end"] = end
        if no_key and not res["walk_unchecked"] and not res["violations"]:
            res["walk_unchecked"] = "policy_private"
        held = list(walked)
        if not res["violations"] and not no_key:
            for w in walked:
                ms, mw, _ = read_mandate(w["mandate_hash"])
                if ms != "ok":
                    continue
                key = successor_key(w["gate_id"], counter_key_of(mw), prev_state_hash_of(w))
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
            ms, mx, _ = read_mandate(x["mandate_hash"])
            if ms not in ("ok", "private") or x["gate_id"] != V["gate_id"]:
                continue
            ck = counter_key_of(mx) if ms == "ok" else None
            sq = seq_of(x) if ms == "ok" else None
            info.append((ck, sq, x))
        for i in range(len(info)):
            for j in range(i + 1, len(info)):
                a, b = info[i], info[j]
                if a[2]["commitment_hash"] == b[2]["commitment_hash"]:
                    continue
                by_seq = a[0] is not None and a[0] == b[0] and a[1] is not None and a[1] == b[1]
                by_hash = a[2]["mandate_hash"] == b[2]["mandate_hash"] and \
                    prev_state_hash_of(a[2]) == prev_state_hash_of(b[2])
                if by_seq or by_hash:
                    violated(a[2], b[2])
                    break
            if res["violations"]:
                break
    return finish(res)


def finish(res: dict) -> dict:
    viol = bool(res["violations"])
    pp = res.get("pp_violation") if not viol else None
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
    policy |= res.get("report", {})
    if viol:
        gi = {"status": "violated", "reason": "gate_equivocation", "evidence": [h.hex() for h in res["violations"]]}
    elif pp:
        gi = {"status": "violated", "reason": "gate_signed_inconsistent_private_part",
              "evidence": [verdict_hash_of(x).hex() for x in pp]}
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
    elif viol or pp:
        verdict, code = "unchecked", 5
    elif policy["status"] == "unchecked":
        verdict, code = "unchecked", 2
    else:
        verdict, code = "valid", 0
    return {"policy": policy, "gate_integrity": gi, "verdict": verdict, "exit": str(code)}
