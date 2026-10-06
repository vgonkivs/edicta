#!/usr/bin/env python3
"""Verifies spec/vectors/da/fibre_anchor.json (v0-draft.23) without Go and
without the network.

The expected values come from upstream celestia-app, celestia-node, go-square
and nmt code (spec/vectors/tools/fibreanchor-gen). This script rebuilds them
from the raw bytes with its own code:
- the DAH checks (equal row and column counts within bounds, RFC 6962 root
  over row_roots || column_roots against data_hash);
- protobuf decoding of the namespace data stream and of the DAH;
- the rows whose root range covers the PayForFibre namespace, and the NMT
  namespace proof of each row (leaf and node hashing with the ignored
  maximum namespace, range-proof root computation, completeness);
- the compact-share reassembly: go-square's ParseTxs, transcribed, followed
  by the re-split of the parsed txs with a transcribed CompactShareSplitter;
- the PFF promises (protobuf, as check_fibre_cert.py) and the candidate
  selection of every query;
- the archive form of the proof (strict CBOR) and its hash;
- every mutation and every reassembly case;
- the live PFF at 1402819 against fibre_cert.json.

Usage: python3 spec/vectors/check/check_fibre_anchor.py [--file FILE] [--cert FILE]
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import copy
import hashlib
import json
from pathlib import Path

from cbor_strict import CBORError, decode_strict, encode, to_plain
from check_fibre_cert import Failure, every, expect, fields, int64, last, parse_pff, put_uvarint

HERE = Path(__file__).resolve().parent
VECTORS = HERE.parent
FORMAT = "edicta-vectors/v0"
REVISION = "v0-draft.23"

NS_SIZE = 29
SHARE_SIZE = 512
INFO_AT = NS_SIZE
SEQ_LEN_AT = NS_SIZE + 1
FIRST_RESERVED_AT = SEQ_LEN_AT + 4
CONT_RESERVED_AT = NS_SIZE + 1
FIRST_CONTENT = SHARE_SIZE - NS_SIZE - 1 - 4 - 4
CONT_CONTENT = SHARE_SIZE - NS_SIZE - 1 - 4
PFF_NS = bytes(28) + b"\x05"
COMPACT_NS = {bytes(28) + b"\x01", bytes(28) + b"\x04", PFF_NS}
MAX_NS = b"\xff" * NS_SIZE
NODE_SIZE = 2 * NS_SIZE + 32
MIN_EDS, MAX_EDS = 2, 1024
MAX_ROW_MESSAGE = 1 << 20


class Reject(Exception):
    def __init__(self, rule: str, why: str):
        super().__init__(f"{rule}: {why}")
        self.rule = rule


def arg(name: str, default: Path) -> Path:
    if name in sys.argv:
        return Path(sys.argv[sys.argv.index(name) + 1]).resolve()
    return default


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def merkle(items: list) -> bytes:
    if not items:
        return sha256(b"")
    if len(items) == 1:
        return sha256(b"\x00" + items[0])
    k = 1
    while k * 2 < len(items):
        k *= 2
    return sha256(b"\x01" + merkle(items[:k]) + merkle(items[k:]))


# ---- the DAH ----

def check_dah(rows: list, cols: list, data_hash: bytes):
    if not (MIN_EDS <= len(rows) <= MAX_EDS and MIN_EDS <= len(cols) <= MAX_EDS):
        raise Reject("NA2", "root count out of range")
    if len(rows) != len(cols):
        raise Reject("NA2", "unequal row and column counts")
    if merkle(rows + cols) != data_hash:
        raise Reject("NA2", "DAH hash differs from data_hash")


def dah_proto(rows: list, cols: list) -> bytes:
    out = bytearray()
    for r in rows:
        out += b"\x0a" + put_uvarint(len(r)) + r
    for c in cols:
        out += b"\x12" + put_uvarint(len(c)) + c
    return bytes(out)


def parse_dah_proto(b: bytes):
    fs = fields(b)
    for n, w, _ in fs:
        expect(n in (1, 2) and w == 2, "DAH proto: unexpected field")
    return every(fs, 1), every(fs, 2)


# ---- namespace data ----

def read_uvarint(b: bytes, i: int):
    v = shift = 0
    for k in range(10):
        if i >= len(b):
            raise Reject("NA3", "truncated length prefix")
        c = b[i]
        i += 1
        if c < 0x80:
            if k == 9 and c > 1:
                raise Reject("NA3", "length prefix overflow")
            return v | c << shift, i
        v |= (c & 0x7F) << shift
        shift += 7
    raise Reject("NA3", "length prefix overflow")


def decode_stream(b: bytes) -> list:
    """NamespaceData.ReadFrom: uvarint-length-prefixed RowNamespaceData until
    the end; a partial message is an error."""
    rows, i = [], 0
    while i < len(b):
        n, i = read_uvarint(b, i)
        if n > MAX_ROW_MESSAGE:
            raise Reject("NA3", "row message too large")
        if i + n > len(b):
            raise Reject("NA3", "truncated row message")
        msg, i = b[i:i + n], i + n
        try:
            fs = fields(msg)
            shares = [last(fields(s), 1, 2, b"") for s in every(fs, 1)]
            pb = last(fs, 2, 2)
            proof = None
            if pb is not None:
                pf = fields(pb)
                proof = {
                    "start": int64(last(pf, 1, 0, 0)), "end": int64(last(pf, 2, 0, 0)), "nodes": every(pf, 3),
                    "leaf_hash": last(pf, 4, 2, b""), "ignore_max": bool(last(pf, 5, 0, 0)),
                }
        except Failure as e:
            raise Reject("NA3", f"row protobuf: {e}")
        for s in shares:
            if len(s) != SHARE_SIZE:
                raise Reject("NA3", "share size")
        rows.append({"shares": shares, "proof": proof})
    return rows


def node_ok(node: bytes) -> bool:
    return len(node) == NODE_SIZE and node[:NS_SIZE] <= node[NS_SIZE:2 * NS_SIZE]


def hash_leaf(leaf: bytes) -> bytes:
    ns = leaf[:NS_SIZE]
    return ns + ns + sha256(b"\x00" + leaf)


def hash_node(left: bytes, right: bytes, ignore_max: bool) -> bytes:
    if not (node_ok(left) and node_ok(right)):
        raise ValueError("node format")
    lmin, lmax = left[:NS_SIZE], left[NS_SIZE:2 * NS_SIZE]
    rmin, rmax = right[:NS_SIZE], right[NS_SIZE:2 * NS_SIZE]
    if rmin < lmax:
        raise ValueError("unordered siblings")
    mx = lmax if ignore_max and rmin == MAX_NS else rmax
    return lmin + mx + sha256(b"\x01" + left + right)


def split_point(n: int) -> int:
    k = 1 << (n.bit_length() - 1)
    return k >> 1 if k == n else k


def next_subtree(start: int, end: int) -> int:
    ideal = (start & -start).bit_length() - 1 if start else 64
    max_bits = (end - start).bit_length() - 1
    return 1 << (max_bits if ideal > max_bits else ideal)


def nmt_verify_namespace(proof: dict, ns: bytes, leaves: list, root: bytes) -> bool:
    """nmt Proof.VerifyNamespace at v0.24.5."""
    start, end, nodes, leaf_hash, ign = (proof["start"], proof["end"], list(proof["nodes"]),
                                        proof["leaf_hash"], proof["ignore_max"])
    absence = len(leaf_hash) > 0
    if start == end:
        if nodes or leaf_hash or leaves:
            return False
        if not node_ok(root):
            return False
        return ns < root[:NS_SIZE] or root[NS_SIZE:2 * NS_SIZE] < ns or root == bytes(2 * NS_SIZE) + sha256(b"")
    if absence:
        hashes = [leaf_hash]
    else:
        hashes = []
        for leaf in leaves:
            if len(leaf) < NS_SIZE or leaf[:NS_SIZE] != ns:
                return False
            hashes.append(hash_leaf(leaf))
    if start < 0 or start >= end or len(hashes) != end - start:
        return False
    if absence and (not node_ok(leaf_hash) or not ns < leaf_hash[:NS_SIZE]):
        return False
    if not all(node_ok(n) for n in nodes) or not all(node_ok(h) for h in hashes) or not node_ok(root):
        return False
    if not absence and any(h[:NS_SIZE] != ns or h[NS_SIZE:2 * NS_SIZE] != ns for h in hashes):
        return False
    # Completeness: subtrees left of the range end below ns, right of it start above.
    idx, rest, left = 0, list(nodes), []
    while idx != start and rest:
        left.append(rest.pop(0))
        idx += next_subtree(idx, start)
    if idx != start:
        return False
    if any(ns <= n[NS_SIZE:2 * NS_SIZE] for n in left):
        return False
    if any(n[:NS_SIZE] <= ns for n in rest):
        return False
    pn, lh = list(nodes), list(hashes)

    def pop(s):
        return s.pop(0) if s else None

    def compute(s: int, e: int):
        if e - s == 1:
            return pop(lh) if start <= s < end else pop(pn)
        if e <= start or s >= end:
            return pop(pn)
        k = split_point(e - s)
        lft, rgt = compute(s, s + k), compute(s + k, e)
        if rgt is None:
            return lft
        return hash_node(lft, rgt, ign)

    try:
        est = 1 if end == 1 else split_point(end) * 2
        r = compute(0, est)
        for n in pn:
            r = hash_node(r, n, ign)
    except (ValueError, TypeError):
        return False
    return r is not None and node_ok(r) and r == root


def outside(ns: bytes, root: bytes) -> bool:
    return ns < root[:NS_SIZE] or not ns <= root[NS_SIZE:2 * NS_SIZE]


def verify_rows(rows: list, row_roots: list, ns: bytes):
    """NamespaceData.Verify: one entry per row whose range covers ns."""
    want = [i for i, r in enumerate(row_roots) if not outside(ns, r)]
    if len(want) != len(rows):
        raise Reject("NA3", f"expected {len(want)} rows, found {len(rows)}")
    for j, row in enumerate(rows):
        p = row["proof"]
        if p is None or (p["start"] == p["end"] and not p["nodes"] and not p["leaf_hash"]):
            raise Reject("NA3", "nil proof")
        absence = len(p["leaf_hash"]) > 0
        if not row["shares"] and not absence:
            raise Reject("NA3", "empty shares with inclusion proof")
        if row["shares"] and absence:
            raise Reject("NA3", "shares with absence proof")
        root = row_roots[want[j]]
        if outside(ns, root):
            raise Reject("NA3", "namespace outside row range")
        leaves = [s[:NS_SIZE] + s for s in row["shares"]]
        if not nmt_verify_namespace(p, ns, leaves, root):
            raise Reject("NA3", f"row {want[j]} proof")
    return want


# ---- reassembly ----

def go_uvarint_padded(b: bytes):
    """binary.ReadUvarint over the first 10 bytes, zero padded."""
    buf = (b[:10] + bytes(10))[:10]
    v = shift = 0
    for k in range(10):
        c = buf[k]
        if c < 0x80:
            if k == 9 and c > 1:
                raise ValueError("overflow")
            return v | c << shift
        v |= (c & 0x7F) << shift
        shift += 7
    raise ValueError("overflow")


def parse_txs(shares: list) -> list:
    """go-square ParseTxs (parseCompactShares), transcribed."""
    if not shares:
        return []
    for s in shares:
        if s[INFO_AT] >> 1 != 0:
            raise ValueError("share version")
    raw = bytearray()
    for i, s in enumerate(shares):
        start = s[INFO_AT] & 1
        compact = s[:NS_SIZE] in COMPACT_NS
        if i == 0:
            idx = NS_SIZE + 1 + (4 if start else 0)
            if compact:
                r = int.from_bytes(s[idx:idx + 4], "big")
                if r >= SHARE_SIZE:
                    raise ValueError("reserved bytes")
                raw += s[r:] if r else b""
            else:
                raw += s[idx:]
        else:
            idx = NS_SIZE + 1 + (4 if start else 0) + (4 if compact else 0)
            raw += s[idx:]
    units, data = [], bytes(raw)
    while True:
        if not data:
            return units
        n = go_uvarint_padded(data)
        rest = data[len(put_uvarint(n)):]
        if n == 0 or n > len(rest):
            return units
        units.append(rest[:n])
        data = rest[n:]


def split_txs(txs: list, ns: bytes) -> list:
    """go-square CompactShareSplitter (share version 0), transcribed."""
    shares = []

    def new(first: bool) -> bytearray:
        return bytearray(ns + bytes([1 if first else 0]) + (bytes(4) if first else b"") + bytes(4))

    b, first = new(True), True
    for tx in txs:
        at = FIRST_RESERVED_AT if first else CONT_RESERVED_AT
        if b[at:at + 4] == bytes(4):
            b[at:at + 4] = len(b).to_bytes(4, "big")
        data = put_uvarint(len(tx)) + tx
        while True:
            left = SHARE_SIZE - len(b)
            if len(data) <= left:
                b += data
                break
            b += data[:left]
            shares.append(bytes(b))
            b, first = new(False), False
            data = data[left:]
        if len(b) == SHARE_SIZE:
            shares.append(bytes(b))
            b, first = new(False), False
    empty_len = NS_SIZE + 1 + (4 if first else 0) + 4
    if not shares and len(b) == empty_len:
        return []
    pad = 0
    if len(b) != empty_len:
        pad = SHARE_SIZE - len(b)
        shares.append(bytes(b) + bytes(pad))
    seq = FIRST_CONTENT - pad if len(shares) == 1 else FIRST_CONTENT + (len(shares) - 1) * CONT_CONTENT - pad
    s0 = bytearray(shares[0])
    s0[SEQ_LEN_AT:SEQ_LEN_AT + 4] = seq.to_bytes(4, "big")
    shares[0] = bytes(s0)
    return shares


def reassemble(shares: list) -> list:
    if not shares:
        return []
    try:
        txs = parse_txs(shares)
    except ValueError as e:
        raise Reject("NA4", f"parse: {e}")
    if split_txs(txs, PFF_NS) != list(shares):
        raise Reject("NA4", "re-split differs")
    return txs


# ---- the lookup ----

def run(data_hash: bytes, rows: list, cols: list, stream: bytes, ns: bytes = PFF_NS, edit=None):
    check_dah(rows, cols, data_hash)
    nd = decode_stream(stream)
    if edit is not None:
        nd = edit(nd)
    want = verify_rows(nd, rows, ns)
    shares = [s for r in nd for s in r["shares"]]
    return want, shares, reassemble(shares)


def raw_inputs(raw: dict):
    return (bytes.fromhex(raw["data_hash"]), [bytes.fromhex(x) for x in raw["row_roots"]],
            [bytes.fromhex(x) for x in raw["column_roots"]], bytes.fromhex(raw["namespace_data_hex"]))


def select(cands: list, ps: dict) -> str:
    if not cands:
        return "none"
    best = cands[0]
    for c in cands[1:]:
        if ps[c]["unix_nanos"] < ps[best]["unix_nanos"]:
            best = c
    return str(best)


def check_live(f: dict, cert: dict) -> int:
    n = 0
    for c in f["live"]["cases"]:
        e = c["expect"]
        dh, rows, cols, stream = raw_inputs(c["raw"])
        expect(c["id"] == "h" + c["raw"]["height"], f"{c['id']}: id")
        want, shares, txs = run(dh, rows, cols, stream)
        expect(e["square_size"] == str(len(rows) // 2), f"{c['id']}: square size")
        expect(e["rows"] == [str(x) for x in want], f"{c['id']}: rows")
        expect(e["share_count"] == str(len(shares)), f"{c['id']}: share count")
        expect(len(e["txs"]) == len(txs), f"{c['id']}: tx count")
        ps = {}
        for i, (t, tx) in enumerate(zip(e["txs"], txs)):
            expect(t["position"] == str(i) and t["length"] == str(len(tx)) and t["sha256"] == sha256(tx).hex(),
                   f"{c['id']}: tx {i}")
            expect(t["fibre"], f"{c['id']}: tx {i} is not a PFF in the vector")
            p = parse_pff(tx)
            pd = t["promise"]
            nanos = p["sec"] * 10**9 + p["nanos"]
            expect(pd["chain_id"] == p["chain_id"] and pd["height"] == str(p["height"])
                   and pd["namespace"] == p["namespace"].hex() and pd["commitment"] == p["commitment"].hex()
                   and pd["blob_size"] == str(p["blob_size"]) and pd["blob_version"] == str(p["blob_version"])
                   and pd["creation_unix_nanos"] == str(nanos), f"{c['id']}: tx {i} promise")
            ps[i] = {**p, "unix_nanos": nanos}
        for q in e["queries"]:
            cands = [i for i, p in ps.items()
                     if p["namespace"].hex() == q["namespace"] and p["commitment"].hex() == q["commitment"]
                     and str(p["blob_version"]) == q["blob_version"] and p["chain_id"] == q["chain_id"]]
            expect(q["candidates"] == [str(x) for x in cands], f"{c['id']}: candidates of {q['description']}")
            expect(q["anchor"] == select(cands, ps), f"{c['id']}: anchor of {q['description']}")
        ap = bytes.fromhex(e["archive_proof"]["hex"])
        expect(e["archive_proof"]["sha256"] == sha256(ap).hex() and e["archive_proof"]["size"] == str(len(ap)),
               f"{c['id']}: archive proof hash")
        try:
            m = to_plain(decode_strict(ap))
        except CBORError as err:
            raise Failure(f"{c['id']}: archive proof CBOR: {err}")
        expect(isinstance(m, dict) and sorted(m) == [1, 2, 3] and m[1] == 1, f"{c['id']}: archive proof keys")
        expect(encode(m) == ap, f"{c['id']}: archive proof not canonical")
        pr, pc = parse_dah_proto(m[2])
        expect(pr == rows and pc == cols and m[2] == dah_proto(rows, cols), f"{c['id']}: archive DAH")
        expect(m[3] == stream, f"{c['id']}: archive namespace data")
        expect(e["sizes"] == {"dah_proto": str(len(m[2])), "namespace_data": str(len(stream)),
                              "archive_proof": str(len(ap))}, f"{c['id']}: sizes")
        n += 1
    live = {c["id"]: c for c in f["live"]["cases"]}
    pff = bytes.fromhex(cert["live"]["raw"]["pff_tx_hex"])
    first = live["h1402819"]["expect"]["txs"][0]
    expect(first["sha256"] == sha256(pff).hex() == cert["live"]["raw"]["tx_hash"].lower(),
           "h1402819: the reassembled PFF is not the tx of fibre_cert.json")
    return n


def apply_op(m: dict, f: dict):
    case = next(c for c in f["live"]["cases"] if c["id"] == m["case"])
    dh, rows, cols, stream = raw_inputs(case["raw"])
    o, ns, edit = m["op"], PFF_NS, None

    def flip(b: bytes, off: int, x: int) -> bytes:
        c = bytearray(b)
        c[off] ^= x
        return bytes(c)

    def pick(xs: list, v: str) -> int:
        return len(xs) - 1 if v == "last" else int(v)

    k = o["kind"]
    if k == "flip" and o["target"] == "data_hash":
        dh = flip(dh, int(o["offset"]), int(o["xor"], 16))
    elif k == "flip" and o["target"] in ("row_root", "column_root"):
        xs = list(rows if o["target"] == "row_root" else cols)
        xs[int(o["index"])] = flip(xs[int(o["index"])], int(o["offset"]), int(o["xor"], 16))
        if o["target"] == "row_root":
            rows = xs
        else:
            cols = xs
    elif k == "flip" and o["target"] == "share":
        def edit(nd):
            r = pick(nd, o["row"])
            s = pick(nd[r]["shares"], o["share"])
            nd[r]["shares"][s] = flip(nd[r]["shares"][s], int(o["offset"]), int(o["xor"], 16))
            return nd
    elif k == "move_column_root_to_rows":
        rows, cols = rows + [cols[0]], cols[1:]
    elif k == "drop_share":
        def edit(nd):
            r = pick(nd, o["row"])
            del nd[r]["shares"][pick(nd[r]["shares"], o["share"])]
            return nd
    elif k == "drop_row":
        def edit(nd):
            del nd[pick(nd, o["row"])]
            return nd
    elif k == "dup_row":
        def edit(nd):
            r = pick(nd, o["row"])
            return nd[:r + 1] + [copy.deepcopy(nd[r])] + nd[r + 1:]
    elif k == "swap_rows":
        def edit(nd):
            a, b = int(o["row"]), int(o["row2"])
            nd[a], nd[b] = nd[b], nd[a]
            return nd
    elif k == "set_max_ns_ignored":
        def edit(nd):
            nd[int(o["row"])]["proof"]["ignore_max"] = o["value"] == "true"
            return nd
    elif k == "truncate_stream":
        stream = stream[:-int(o["bytes"])]
    elif k == "verify_namespace":
        ns = bytes.fromhex(o["namespace"])
    else:
        raise Failure(f"unknown op {k}")
    return dh, rows, cols, stream, ns, edit


def check_mutations(f: dict) -> int:
    n = 0
    for m in f["mutations"]:
        dh, rows, cols, stream, ns, edit = apply_op(m, f)
        base = next(c for c in f["live"]["cases"] if c["id"] == m["case"])
        try:
            _, _, txs = run(dh, rows, cols, stream, ns, edit)
            got = {"verdict": "accept"}
            _, _, ref = run(*raw_inputs(base["raw"]))
            got["same_txs"] = txs == ref
        except Reject as r:
            got = {"verdict": "reject", "fails": r.rule}
        want = {k: v for k, v in m["expect"].items() if k != "upstream_error"}
        expect(got == want, f"mutation {m['id']}: got {got}, vector {want}")
        n += 1
    return n


def check_reassembly(f: dict) -> int:
    n = 0
    for c in f["reassembly"]:
        shares = [bytes.fromhex(x) for x in c["shares_hex"]]
        expect(all(len(s) == SHARE_SIZE for s in shares), f"{c['id']}: share size")
        try:
            txs = reassemble(shares)
            got = {"verdict": "accept", "txs_sha256": [sha256(t).hex() for t in txs]}
        except Reject as r:
            got = {"verdict": "reject", "fails": r.rule}
        expect(got == c["expect"], f"reassembly {c['id']}: got {got}, vector {c['expect']}")
        try:
            up = f"{len(parse_txs(shares))} txs"
        except ValueError:
            up = "error"
        expect(up == c["upstream_parse_txs"], f"reassembly {c['id']}: ParseTxs gives {up}")
        n += 1
    return n


def check(path: Path, cert_path: Path) -> str:
    f = json.loads(path.read_text())
    expect(f.get("format") == FORMAT, "format")
    expect(f.get("revision") == REVISION, "revision")
    expect(f.get("generator") == "spec/vectors/tools/fibreanchor-gen", "generator")
    expect(f.get("pff_namespace") == PFF_NS.hex(), "PayForFibre namespace")
    expect("celestia-node v0.34.2-mocha" in f["upstream"]["replace_set"], "upstream pin")
    nl = check_live(f, json.loads(cert_path.read_text()))
    nm = check_mutations(f)
    nr = check_reassembly(f)
    return f"{nl} live, {nm} mutations, {nr} reassembly"


def main() -> int:
    path = arg("--file", VECTORS / "da" / "fibre_anchor.json")
    cert = arg("--cert", VECTORS / "da" / "fibre_cert.json")
    try:
        summary = check(path, cert)
    except (Failure, Reject, KeyError, StopIteration, ValueError, UnicodeDecodeError) as e:
        print(f"FAIL (fibre_anchor.json): {e!r}", file=sys.stderr)
        return 1
    print(f"OK (fibre_anchor.json, {REVISION}): {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
