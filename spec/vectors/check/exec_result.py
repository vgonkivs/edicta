"""Archived execution result, archive kind 19 (core sections 19.2 and 20.2.2, since spec revision v1.1).

The v1.1 reader of kind 19 (strict decoding, key, path), its encoder, and the XR rules on decoded records.
Independent of the Go implementation and of the vector tool on purpose. One part of XR4 is not here: the NMT
range proofs of the shares against their row roots are checked by spec/vectors/tools/execresult-gen -check
with upstream code; this module checks every other point of XR4, the row proofs against data_hash included.

A v1.0 reader refuses kind 19 (ErrInvalidEnum, records.py); this module is the v1.1 addition only.
"""

from __future__ import annotations

import hashlib

import archive as A
from cbor_strict import CBORError, encode
from check_fibre_cert import every, fields, header_hash, int64, last, put_uvarint
from edicta import MAX_INT, Reject

KIND_EXEC = 19
MAX_EXEC_SIZE = 1 << 25
MAX_PART = 1 << 22
MAX_PATH = 2048
CHAIN_ID_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-")
PINNED_APP_VERSION = 10

TX_NS = bytes(28) + b"\x01"
PFB_NS = bytes(28) + b"\x04"
PFF_NS = bytes(28) + b"\x05"
KEY_NAMESPACE = {9: TX_NS, 10: PFB_NS, 11: PFF_NS}

SHARE_SIZE = 512
FIRST_COMPACT = SHARE_SIZE - 29 - 1 - 4 - 4
CONTINUATION_COMPACT = SHARE_SIZE - 29 - 1 - 4

R, O = "R", "O"
SCHEMA = {
    3: ("chain_id", "chainid", R, (1, 50)),
    4: ("rail_ref", "bstr", R, (32, 32)),
    5: ("height", "uint", R, None),
    6: ("tx_index", "uint", R, None),
    7: ("header", "bstr", R, (1, MAX_PART)),
    8: ("next_header", "bstr", R, (1, MAX_PART)),
    9: ("tx_proof", "bstr", R, (1, MAX_PART)),
    10: ("pfb_proof", "bstr", O, (1, MAX_PART)),
    11: ("pff_proof", "bstr", O, (1, MAX_PART)),
    12: ("closing_proof", "bstr", O, (1, MAX_PART)),
    13: ("result", "bstr", R, (0, MAX_PART)),
    14: ("results_total", "uint", R, None),
    15: ("result_path", "bstr", R, (0, MAX_PATH)),
}
NAMES = {f[0]: k for k, f in SCHEMA.items()}
NONZERO = ("height", "results_total")


def encode_record(rec: dict) -> bytes:
    """rec: field name -> value (no format or kind)."""
    m = {1: A.FORMAT, 2: KIND_EXEC}
    for name, v in rec.items():
        m[NAMES[name]] = v
    return encode(m)


def decode_record(data: bytes) -> dict:
    """Strict decoding of core 19.1 for kind 19. Raises Reject with the cause."""
    if len(data) > A.MAX_RECORD_SIZE:
        raise Reject("ErrTooLarge", f"{len(data)} bytes")
    try:
        it = A._generic(data)
    except CBORError as e:
        raise Reject(e.sentinel, e.detail)
    if it.major != 5:
        raise Reject("ErrWrongType", "record: expected map")
    top = {k.value: v for k, v in it.value}
    for key, name in ((1, "format"), (2, "kind")):
        if key not in top:
            raise Reject("ErrMissingField", f"record.{name}")
        if top[key].major != 0:
            raise Reject("ErrWrongType", f"record.{name}")
    if top[1].value != A.FORMAT:
        raise Reject("ErrUnsupportedVersion", f"format {top[1].value}")
    if top[2].value != KIND_EXEC:
        raise Reject("ErrInvalidEnum", f"kind {top[2].value} (this reader adds kind 19 only)")
    if len(data) > MAX_EXEC_SIZE:
        raise Reject("ErrTooLarge", f"execution_result record of {len(data)} bytes")
    out = {}
    for k, v in it.value:
        key = k.value
        if key in (1, 2):
            continue
        if key not in SCHEMA:
            raise Reject("ErrUnknownKey", f"execution_result: key {key}")
        name, typ, _, limit = SCHEMA[key]
        want = {"uint": 0, "bstr": 2, "chainid": 3}[typ]
        if v.major != want:
            raise Reject("ErrWrongType", f"execution_result.{name}: major {v.major}, want {want}")
        if typ != "uint":
            lo, hi = limit
            n = len(v.value) if typ == "bstr" else len(v.value.encode("utf-8"))
            if not lo <= n <= hi:
                raise Reject("ErrFieldSize", f"execution_result.{name}: {n} bytes")
        if name == "result_path" and len(v.value) % 32:
            raise Reject("ErrFieldSize", f"execution_result.result_path: {len(v.value)} bytes, not 32-byte aunts")
        if typ == "chainid" and (any(c not in CHAIN_ID_CHARS for c in v.value) or v.value.startswith(".")):
            raise Reject("ErrInvalidString", f"execution_result.chain_id {v.value!r}")
        out[name] = v.value
    for key, (name, _, cond, _) in SCHEMA.items():
        if cond == R and name not in out:
            raise Reject("ErrMissingField", f"execution_result.{name}")
    for key in sorted(SCHEMA):
        name, typ = SCHEMA[key][0], SCHEMA[key][1]
        if typ == "uint" and out[name] > MAX_INT:
            raise Reject("ErrIntRange", f"{name} = {out[name]}")
    for name in NONZERO:
        if out[name] == 0:
            raise Reject("ErrZeroValue", name)
    if encode_record(out) != data:
        raise Reject("ErrNonCanonical", "re-encoding differs")
    return out


def key_of(rec: dict) -> tuple:
    return (rec["chain_id"], rec["rail_ref"])


def path_of(key: tuple) -> str:
    return f"exec/{key[0]}/{key[1].hex()}"


# ---------------------------------------------------------------- XR rules

class SetAside(Exception):
    def __init__(self, rule: str, reason: str, why: str):
        super().__init__(f"{rule} ({reason}): {why}")
        self.rule, self.reason = rule, reason


def _header(b: bytes) -> dict:
    fs = fields(b)
    version = fields(last(fs, 1, 2, b""))
    return {"app": last(version, 2, 0, 0), "chain_id": last(fs, 2, 2, b"").decode(), "height": int64(last(fs, 3, 0, 0)),
            "data_hash": last(fs, 7, 2, b""), "last_results_hash": last(fs, 12, 2, b""), "hash": header_hash(b)}


def _share_proof(b: bytes) -> dict:
    fs = fields(b)
    rp = fields(last(fs, 4, 2, b""))
    proofs = []
    for p in every(rp, 2):
        pf = fields(p)
        proofs.append({"total": int64(last(pf, 1, 0, 0)), "index": int64(last(pf, 2, 0, 0)),
                       "leaf_hash": last(pf, 3, 2, b""), "aunts": every(pf, 4)})
    nmt = []
    for p in every(fs, 2):
        pf = fields(p)
        nmt.append({"start": int64(last(pf, 1, 0, 0)), "end": int64(last(pf, 2, 0, 0))})
    return {"data": every(fs, 1), "share_proofs": nmt, "namespace_id": last(fs, 3, 2, b""),
            "namespace_version": last(fs, 5, 0, 0), "row_roots": every(rp, 1), "row_proofs": proofs,
            "start_row": last(rp, 4, 0, 0), "end_row": last(rp, 5, 0, 0)}


def _sha(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def _split_point(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def root_from_aunts(index: int, total: int, leaf_hash: bytes, aunts: list) -> bytes | None:
    """CometBFT crypto/merkle computeHashFromAunts: None where it errors."""
    if index >= total or index < 0 or total <= 0:
        return None
    if total == 1:
        return leaf_hash if not aunts else None
    if not aunts:
        return None
    left = _split_point(total)
    if index < left:
        h = root_from_aunts(index, left, leaf_hash, aunts[:-1])
        return None if h is None else _sha(b"\x01" + h + aunts[-1])
    h = root_from_aunts(index - left, total - left, leaf_hash, aunts[:-1])
    return None if h is None else _sha(b"\x01" + aunts[-1] + h)


def _width(sp: dict) -> int:
    if not sp["row_proofs"]:
        return 0
    t = sp["row_proofs"][0]["total"]
    if t < 4 or t % 4:
        return 0
    k = t // 4
    return k if k & (k - 1) == 0 else 0


def _span(sp: dict, k: int):
    rows = len(sp["row_roots"])
    if (k == 0 or rows == 0 or len(sp["row_proofs"]) != rows or len(sp["share_proofs"]) != rows
            or sp["end_row"] - sp["start_row"] + 1 != rows):
        return None
    for i, p in enumerate(sp["row_proofs"]):
        if p["total"] != 4 * k or p["index"] != sp["start_row"] + i or p["index"] >= k:
            return None
    for i, p in enumerate(sp["share_proofs"]):
        if p["start"] < 0 or p["end"] <= p["start"] or p["end"] > k:
            return None
        if (i > 0 and p["start"] != 0) or (i < rows - 1 and p["end"] != k):
            return None
    return (sp["start_row"] * k + sp["share_proofs"][0]["start"], sp["end_row"] * k + sp["share_proofs"][-1]["end"])


def _rows_reach(sp: dict, data_hash: bytes) -> bool:
    """The RFC 6962 part of ShareProof.Validate: every row root is a leaf of data_hash."""
    for root, p in zip(sp["row_roots"], sp["row_proofs"]):
        lh = _sha(b"\x00" + root)
        if p["leaf_hash"] != lh or root_from_aunts(p["index"], p["total"], lh, p["aunts"]) != data_hash:
            return False
    return True


def _uvarint(b: bytes, i: int):
    v = shift = 0
    while True:
        if i >= len(b) or shift >= 64:
            raise ValueError("varint")
        c = b[i]
        i += 1
        v |= (c & 0x7F) << shift
        if c < 0x80:
            return v, i
        shift += 7


def compact_shares(seq_len: int) -> int:
    if seq_len <= FIRST_COMPACT:
        return 1
    return 1 + (seq_len - FIRST_COMPACT + CONTINUATION_COMPACT - 1) // CONTINUATION_COMPACT


def compact_units(shares: list) -> list:
    """go-square ParseTxs over one whole compact sequence: the length-delimited units."""
    seq_len = int.from_bytes(shares[0][30:34], "big")
    data = b"".join(s[34 + 4:] if i == 0 else s[30 + 4:] for i, s in enumerate(shares))[:seq_len]
    if len(data) != seq_len:
        raise ValueError("sequence shorter than its length")
    out, i = [], 0
    while i < len(data):
        n, i = _uvarint(data, i)
        if n == 0 or i + n > len(data):
            raise ValueError("unit length")
        out.append(data[i:i + n])
        i += n
    return out


def results_leaf(code: int, data: bytes, gas_wanted: int, gas_used: int) -> bytes:
    def vint(n: int, v: int) -> bytes:
        return put_uvarint(n << 3) + put_uvarint(v & (2 ** 64 - 1)) if v else b""
    return (vint(1, code) + (put_uvarint(2 << 3 | 2) + put_uvarint(len(data)) + data if data else b"")
            + vint(5, gas_wanted) + vint(6, gas_used))


def _leaf_fields(leaf: bytes) -> tuple:
    fs = fields(leaf)
    code = last(fs, 1, 0, 0)
    return (code, last(fs, 2, 2, b""), int64(last(fs, 5, 0, 0)), int64(last(fs, 6, 0, 0)))


def xr(rec: dict, query: dict, trusted: dict) -> dict:
    """XR1 to XR8 on a decoded record. query: chain_id and rail_ref (bytes) the verifier looks up;
    trusted: height (int) -> hash HT3 reached. Returns the facts or raises SetAside."""
    from check_fibre_cert import Failure

    if rec["chain_id"] != query["chain_id"] or rec["rail_ref"] != query["rail_ref"]:
        raise SetAside("XR1", "tx_proof_invalid", "the record carries another key")
    height, idx, total = rec["height"], rec["tx_index"], rec["results_total"]
    try:
        h = _header(rec["header"])
    except (Failure, UnicodeDecodeError):
        raise SetAside("XR2", "tx_proof_invalid", "header does not decode")
    if h["height"] != height or h["chain_id"] != rec["chain_id"]:
        raise SetAside("XR2", "tx_proof_invalid", "header is not the header at height")
    try:
        nh = _header(rec["next_header"])
    except (Failure, UnicodeDecodeError):
        raise SetAside("XR2", "tx_proof_invalid", "next_header does not decode")
    if nh["height"] != height + 1 or nh["chain_id"] != rec["chain_id"]:
        raise SetAside("XR2", "tx_proof_invalid", "next_header is not the header at height + 1")
    for x in (h, nh):
        if x["height"] not in trusted:
            raise SetAside("XR2", "result_header_unreachable", f"no trusted hash at {x['height']}")
        if x["hash"] != trusted[x["height"]]:
            raise SetAside("XR2", "header_not_linking", f"header at {x['height']} is not on the trusted chain")
    if h["app"] != PINNED_APP_VERSION:
        raise SetAside("XR3", "result_index_unbound", f"app version {h['app']}")

    end, k, closed, counts, tx_units = 0, 0, False, {}, None
    for key, name in ((9, "tx_proof"), (10, "pfb_proof"), (11, "pff_proof"), (12, "closing_proof")):
        if name not in rec:
            continue
        try:
            sp = _share_proof(rec[name])
        except Failure as e:
            raise SetAside("XR4", "tx_proof_invalid", f"key {key}: {e}")
        ns = bytes([sp["namespace_version"]]) + sp["namespace_id"] if sp["namespace_version"] < 256 else b""
        if len(ns) != 29 or (key in KEY_NAMESPACE and ns != KEY_NAMESPACE[key]) or (key == 12 and not ns > PFF_NS):
            raise SetAside("XR4", "tx_proof_invalid", f"key {key}: namespace {ns.hex()}")
        kw = _width(sp)
        se = _span(sp, kw)
        if se is None or len(sp["data"]) != se[1] - se[0]:
            raise SetAside("XR4", "tx_proof_invalid", f"key {key} does not prove consecutive shares of the original square")
        if not _rows_reach(sp, h["data_hash"]):
            raise SetAside("XR4", "tx_proof_invalid", f"key {key}: row proof does not reach data_hash")
        shares = sp["data"]
        if any(len(s) != SHARE_SIZE or s[:29] != ns for s in shares):
            raise SetAside("XR4", "tx_proof_invalid", f"key {key} holds a share of another namespace")
        if k and kw != k:
            raise SetAside("XR4", "tx_proof_invalid", f"key {key}: another square width")
        k = kw
        if se[0] != end:
            raise SetAside("XR5", "tx_proof_invalid", f"key {key} starts at {se[0]}, the previous range ends at {end}")
        end = se[1]
        if key == 12:
            if se[1] - se[0] != 1:
                raise SetAside("XR5", "tx_proof_invalid", "the closing proof covers more than one share")
            closed = True
            continue
        first = shares[0][29] & 1
        seq_len = int.from_bytes(shares[0][30:34], "big")
        if not first or compact_shares(seq_len) != len(shares):
            raise SetAside("XR5", "tx_proof_invalid", f"key {key} is not one whole compact sequence")
        if any(s[29] & 1 for s in shares[1:]):
            raise SetAside("XR5", "tx_proof_invalid", f"key {key}: a second sequence")
        try:
            units = compact_units(shares)
        except ValueError as e:
            raise SetAside("XR5", "tx_proof_invalid", f"key {key} units: {e}")
        counts[key] = len(units)
        if key == 9:
            tx_units = units
    if "tx_proof" not in rec:
        raise SetAside("XR5", "tx_proof_invalid", "no transaction namespace proof")
    if not closed and end != k * k:
        raise SetAside("XR5", "tx_proof_invalid", f"the transaction namespaces end at {end}, not at a closing share "
                                                  f"or the square's end {k * k}")
    if sum(counts.values()) != total:
        raise SetAside("XR6", "result_index_unbound", f"{sum(counts.values())} txs, results_total {total}")
    hits = [j for j, u in enumerate(tx_units) if _sha(u) == rec["rail_ref"]]
    if not hits:
        raise SetAside("XR7", "tx_hash_mismatch", "no ordinary tx hashes to rail_ref")
    if len(hits) > 1:
        raise SetAside("XR7", "result_index_unbound", f"{len(hits)} ordinary txs hash to rail_ref")
    if hits[0] != idx or idx >= total:
        raise SetAside("XR7", "result_index_unbound", f"the tx is unit {hits[0]}, tx_index {idx}")
    leaf = rec["result"]
    try:
        code, data, gw, gu = _leaf_fields(leaf)
    except Failure:
        raise SetAside("XR8", "results_root_mismatch", "result does not decode")
    if code >= 1 << 32 or results_leaf(code, data, gw, gu) != leaf:
        raise SetAside("XR8", "results_root_mismatch", "result is not the deterministic leaf")
    p = rec["result_path"]
    aunts = [p[i:i + 32] for i in range(0, len(p), 32)]
    if root_from_aunts(idx, total, _sha(b"\x00" + leaf), aunts) != nh["last_results_hash"]:
        raise SetAside("XR8", "results_root_mismatch", "the result path does not reach last_results_hash")
    return {"height": str(height), "header_hash": h["hash"].hex(), "tx_index": str(idx),
            "tx_hex": tx_units[idx].hex(), "inclusion": "proven", "result": "proven", "code": str(code),
            "outcome": "success" if code == 0 else "failure"}
