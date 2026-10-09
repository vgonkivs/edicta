#!/usr/bin/env python3
"""Writes spec/vectors/da/absence.json (v1-draft.4, core v1 section 10.4). Deterministic.

Synthetic absence proofs over one synthetic chain: blocks whose squares are
built here (compact shares, NMT rows and their namespace proofs, the DAH,
signed headers chained by hash, block results), packed as kind 14 archive
records. The expected outcome of every height comes from how the block was
built, not from running the AB rules; check_absence.py runs the rules on the
bytes with the code of check_fibre_anchor.py and check_execution_outcomes.py.

What is synthetic (no AB rule reads it): the parity quadrants are
pseudo-random bytes, not Reed-Solomon; the commit of each signed header
carries one placeholder signature (header trust is a case input, the trusted
hash per height); PFF signatures and keys are placeholders; the system blobs
that go-square adds for every PFF are left out of the square.

The live Mocha cases (live, live_source, live_tail_rule) are captured by
spec/vectors/tools/absence-gen (read-only network, upstream code) and only
carried over here: from --live FILE when given, else unchanged from the
existing absence.json.

Usage: python3 spec/vectors/check/gen_absence.py [--out DIR] [--live FILE]
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import base64
import hashlib
import json
from pathlib import Path

import archive as A

VECTORS = Path(__file__).resolve().parent.parent
OUT = VECTORS / "da"
if "--out" in sys.argv:
    OUT = Path(sys.argv[sys.argv.index("--out") + 1]).resolve()
LIVE_FILE = None
if "--live" in sys.argv:
    LIVE_FILE = Path(sys.argv[sys.argv.index("--live") + 1]).resolve()
FORMAT, REVISION = "edicta-vectors/v1", "v1-draft.5"
LIVE_KEYS = ("live", "live_source", "live_tail_rule")


def live_sections() -> dict:
    src = LIVE_FILE or (VECTORS / "da" / "absence.json")
    d = json.loads(src.read_text())
    out = {k: d[k] for k in LIVE_KEYS}
    for case in out["live"]:
        for r in case["records"]:
            r.update(record_entry_format_1(bytes.fromhex(r["record_hex"])))
    return out


def record_entry_format_1(b: bytes) -> dict:
    """A captured kind 14 record under the archive header of format 1. The capture tool wrote the header of
    the earlier format 0; only that value changes, every Celestia byte stays as captured."""
    assert b[0] in range(0xa0, 0xb8) and b[1] == 0x01 and b[2] in (0x00, 0x01), b[:3].hex()
    b = b[:2] + b"\x01" + b[3:]
    rec = A.decode_record(b)
    assert rec["kind"] == A.KIND_ABSENCE
    return {"record_hex": b.hex(), "sha256": hashlib.sha256(b).hexdigest(), "size": str(len(b))}
APP_VERSION = 10

CHAIN_ID = "edicta-synth-1"
BASE = 4200200
T_BASE = 1791000000
NS = 29
SHARE = 512
TX_NS = bytes(28) + b"\x01"
PFF_NS = bytes(28) + b"\x05"
USER_NS = bytes(19) + b"user-blob1"
TAIL_NS = b"\xff" * 28 + b"\xfe"
PARITY_NS = b"\xff" * NS
PFF_URL = b"/celestia.fibre.v1.MsgPayForFibre"


def sha(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def stream(label: str, n: int) -> bytes:
    out, i = b"", 0
    while len(out) < n:
        out += sha(f"{label}/{i}".encode())
        i += 1
    return out[:n]


# ---- protobuf ----

def uv(v: int) -> bytes:
    out = bytearray()
    while v >= 0x80:
        out.append(v & 0x7F | 0x80)
        v >>= 7
    out.append(v)
    return bytes(out)


def pint(n: int, v: int) -> bytes:
    return uv(n << 3) + uv(v) if v else b""


def plen(n: int, b: bytes, keep: bool = False) -> bytes:
    return uv(n << 3 | 2) + uv(len(b)) + b if b or keep else b""


# ---- RFC 6962 and NMT ----

def split(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def rfc6962(items: list) -> bytes:
    if not items:
        return sha(b"")
    if len(items) == 1:
        return sha(b"\x00" + items[0])
    k = split(len(items))
    return sha(b"\x01" + rfc6962(items[:k]) + rfc6962(items[k:]))


def nmt_leaf(data: bytes) -> bytes:
    ns = data[:NS]
    return ns + ns + sha(b"\x00" + data)


def nmt_node(left: bytes, right: bytes) -> bytes:
    # nmt with IgnoreMaxNamespace: a right subtree of parity shares does not raise the max.
    lmin, lmax, rmin, rmax = left[:NS], left[NS:2 * NS], right[:NS], right[NS:2 * NS]
    if lmin == PARITY_NS:
        mx = PARITY_NS
    elif rmin == PARITY_NS:
        mx = lmax
    else:
        mx = max(lmax, rmax)
    return min(lmin, rmin) + mx + sha(b"\x01" + left + right)


def nmt_root(hashes: list) -> bytes:
    if len(hashes) == 1:
        return hashes[0]
    k = split(len(hashes))
    return nmt_node(nmt_root(hashes[:k]), nmt_root(hashes[k:]))


def nmt_prove(hashes: list, start: int, end: int, lo: int = 0, hi: int | None = None) -> list:
    """Roots of the maximal subtrees outside [start, end), left to right (nmt ProveRange)."""
    hi = len(hashes) if hi is None else hi
    if hi <= start or lo >= end:
        return [nmt_root(hashes[lo:hi])]
    if hi - lo == 1:
        return []
    k = split(hi - lo)
    return nmt_prove(hashes, start, end, lo, lo + k) + nmt_prove(hashes, start, end, lo + k, hi)


# ---- shares ----

def compact_shares(ns: bytes, units: list) -> list:
    """go-square CompactShareSplitter, share version 0."""
    data = b"".join(uv(len(u)) + u for u in units)
    starts, pos = [], 0
    for u in units:
        starts.append(pos)
        pos += len(uv(len(u))) + len(u)
    first_cap, cont_cap = SHARE - NS - 1 - 4 - 4, SHARE - NS - 1 - 4
    chunks, off = [], 0
    while off < len(data) or not chunks:
        cap = first_cap if not chunks else cont_cap
        chunks.append((off, data[off:off + cap]))
        off += cap
    shares = []
    for i, (off, chunk) in enumerate(chunks):
        cap = first_cap if i == 0 else cont_cap
        head = NS + 1 + (4 if i == 0 else 0) + 4
        unit_at = next((s for s in starts if off <= s < off + cap), None)
        reserved = head + unit_at - off if unit_at is not None else 0
        sh = ns + bytes([1 if i == 0 else 0])
        if i == 0:
            sh += len(data).to_bytes(4, "big")
        sh += reserved.to_bytes(4, "big") + chunk
        shares.append(sh + bytes(SHARE - len(sh)))
    return shares


def sparse_share(ns: bytes, blob: bytes) -> bytes:
    sh = ns + b"\x01" + len(blob).to_bytes(4, "big") + blob
    return sh + bytes(SHARE - len(sh))


def tail_share() -> bytes:
    sh = TAIL_NS + b"\x01" + bytes(4)
    return sh + bytes(SHARE - len(sh))


# ---- square, DAH, namespace data ----

def square(original: list, label: str) -> dict:
    """original: 4 shares, row-major, namespace-sorted. EDS width 4 with pseudo-random parity."""
    assert len(original) == 4 and [s[:NS] for s in original] == sorted(s[:NS] for s in original)
    k = 2
    eds = [[None] * 4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            if r < k and c < k:
                eds[r][c] = original[r * k + c]
            else:
                eds[r][c] = stream(f"{label}/parity/{r}/{c}", SHARE)

    def leaf(r, c):
        ns = eds[r][c][:NS] if r < k and c < k else PARITY_NS
        return nmt_leaf(ns + eds[r][c])

    row_hashes = [[leaf(r, c) for c in range(4)] for r in range(4)]
    rows = [nmt_root(h) for h in row_hashes]
    cols = [nmt_root([row_hashes[r][c] for r in range(4)]) for c in range(4)]
    return {"eds": eds, "row_hashes": row_hashes, "rows": rows, "cols": cols, "k": k,
            "data_hash": rfc6962(rows + cols)}


def dah_bytes(rows: list, cols: list) -> bytes:
    return b"".join(plen(1, r) for r in rows) + b"".join(plen(2, c) for c in cols)


def row_message(shares: list, start: int, end: int, nodes: list, leaf_hash: bytes) -> bytes:
    proof = pint(1, start) + pint(2, end) + b"".join(plen(3, n) for n in nodes) + plen(4, leaf_hash) + pint(5, 1)
    return b"".join(plen(1, plen(1, s)) for s in shares) + plen(2, proof)


def namespace_entries(sq: dict, ns: bytes) -> list:
    """One RowNamespaceData per original row whose root range holds ns."""
    out = []
    for r in range(sq["k"]):
        root = sq["rows"][r]
        if not (root[:NS] <= ns <= root[NS:2 * NS]):
            continue
        orig = [sq["eds"][r][c] for c in range(sq["k"])]
        idx = [c for c, s in enumerate(orig) if s[:NS] == ns]
        h = sq["row_hashes"][r]
        if idx:
            s, e = idx[0], idx[-1] + 1
            out.append({"row": r, "msg": row_message(orig[s:e], s, e, nmt_prove(h, s, e), b""), "shares": e - s})
        else:
            at = next(c for c, x in enumerate(orig) if x[:NS] > ns)
            out.append({"row": r, "msg": row_message([], at, at + 1, nmt_prove(h, at, at + 1), h[at]), "shares": 0})
    return out


def ns_stream(entries: list) -> bytes:
    return b"".join(uv(len(e["msg"])) + e["msg"] for e in entries)


# ---- transactions ----

def bech32(hrp: str, data: bytes) -> str:
    cs = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    five, acc, bits = [], 0, 0
    for b in data:
        acc, bits = acc << 8 | b, bits + 8
        while bits >= 5:
            bits -= 5
            five.append(acc >> bits & 31)
    if bits:
        five.append(acc << (5 - bits) & 31)

    def polymod(values):
        gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
        chk = 1
        for v in values:
            top = chk >> 25
            chk = (chk & 0x1FFFFFF) << 5 ^ v
            for i in range(5):
                chk ^= gen[i] if top >> i & 1 else 0
        return chk

    exp = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
    pm = polymod(exp + five + [0] * 6) ^ 1
    return hrp + "1" + "".join(cs[c] for c in five + [pm >> 5 * (5 - i) & 31 for i in range(6)])


def tx_raw(body_msgs: list, label: str) -> bytes:
    body = b"".join(plen(1, m) for m in body_msgs)
    fee = plen(1, plen(1, b"utia") + plen(2, b"2000")) + pint(2, 200000)
    auth = plen(2, fee)
    return plen(1, body) + plen(2, auth) + plen(3, stream(f"{label}/sig", 64))


def pff_tx(label: str, namespace: bytes, commitment: bytes, chain_id: str, promise_height: int,
           blob_version: int = 0) -> bytes:
    promise = (plen(1, chain_id.encode()) + pint(2, promise_height) + plen(3, namespace) + pint(4, 4096)
               + pint(5, blob_version) + plen(6, commitment) + plen(7, pint(1, T_BASE) + pint(2, 250000000), True)
               + plen(8, plen(1, b"\x02" + stream(f"{label}/key", 32))) + plen(9, stream(f"{label}/owner", 64)))
    msg = plen(1, bech32("celestia", stream(f"{label}/signer", 20)).encode()) + plen(2, promise)
    return tx_raw([plen(1, PFF_URL) + plen(2, msg)], label)


def normal_tx(label: str) -> bytes:
    send = plen(1, b"/cosmos.bank.v1beta1.MsgSend") + plen(2, stream(f"{label}/send", 60))
    return tx_raw([send], label)


# ---- headers ----

def cdc(b: bytes) -> bytes:
    return plen(1, b)


def header(height: int, data_hash: bytes, last_block: bytes, last_results: bytes, app: int = APP_VERSION) -> tuple:
    version = pint(1, 11) + pint(2, app)
    time = pint(1, T_BASE + 6 * (height - BASE)) + pint(2, 500000000)
    parts = pint(1, 1) + plen(2, stream(f"parts/{height - 1}", 32))
    block_id = plen(1, last_block) + plen(2, parts)
    hashes = [stream(f"last_commit/{height}", 32), data_hash, stream("validators", 32), stream("validators", 32),
              stream("consensus", 32), stream(f"app/{height}", 32), last_results, stream("evidence", 32),
              stream("proposer", 20)]
    pb = (plen(1, version) + plen(2, CHAIN_ID.encode()) + pint(3, height) + plen(4, time, True)
          + plen(5, block_id) + b"".join(plen(6 + i, h) for i, h in enumerate(hashes)))
    leaves = [version, cdc(CHAIN_ID.encode()), pint(1, height), time, block_id] + [cdc(h) for h in hashes]
    return pb, rfc6962(leaves)


def signed_header(hpb: bytes, hh: bytes, height: int) -> bytes:
    parts = pint(1, 1) + plen(2, stream(f"parts/{height}", 32))
    sig = (pint(1, 2) + plen(2, stream("proposer", 20)) + plen(3, pint(1, T_BASE + 6 * (height - BASE) + 1), True)
           + plen(4, stream(f"commit/{height}", 64)))
    commit = pint(1, height) + plen(3, plen(1, hh) + plen(2, parts)) + plen(4, sig)
    return plen(1, hpb) + plen(2, commit)


def results_json(height: int, codes: list) -> bytes:
    txs = [{"code": c, "data": "", "log": "", "info": "", "gas_wanted": "200000",
            "gas_used": str(80000 + 1000 * i), "events": [], "codespace": "sdk" if c else ""}
           for i, c in enumerate(codes)]
    return json.dumps({"height": str(height), "txs_results": txs, "finalize_block_events": [],
                       "validator_updates": None, "consensus_param_updates": None,
                       "app_hash": base64.b64encode(stream(f"app/{height + 1}", 32)).decode()},
                      separators=(",", ":")).encode()


def results_leaf(code: int, gas_used: int) -> bytes:
    return pint(1, code) + pint(5, 200000) + pint(6, gas_used)


# ---- the chain ----

def build_chain(query: dict, app_at: dict | None = None, codes_at: dict | None = None) -> dict:
    ns, cm = query["namespace"], query["commitment"]
    h0 = BASE + 1
    other_cm = sha(b"another commitment")
    n1, n2 = normal_tx("normal/1"), normal_tx("normal/2")
    blocks = {}

    def block(height, original, normals, pffs, codes, layout, label):
        sq = square(original, label)
        blocks[height] = {"square": sq, "normals": normals, "pffs": pffs, "codes": codes, "layout": layout}

    user = sparse_share(USER_NS, stream("user blob", 300))
    tx1 = compact_shares(TX_NS, [n1])
    tx2 = compact_shares(TX_NS, [n1, n2])
    # A: the transaction namespace fills row 0; no row holds PFF_NS.
    tx_long = compact_shares(TX_NS, [n1, n2, normal_tx("normal/3"), normal_tx("normal/4")])
    assert len(tx_long) == 2
    block(BASE + 1, tx_long + [user, tail_share()], 4, [], [0, 0, 0, 0],
          "row 0: tx, tx; row 1: user blob, tail padding (no row holds PFF_NS)", "A")
    # C: three PFFs, none a candidate.
    c_pffs = [("other commitment", pff_tx("c/0", ns, other_cm, CHAIN_ID, h0)),
              ("other chain_id", pff_tx("c/1", ns, cm, "other-chain-9", h0)),
              ("promise.height = h + 1", pff_tx("c/2", ns, cm, CHAIN_ID, BASE + 3))]
    c_sh = compact_shares(PFF_NS, [t for _, t in c_pffs])
    assert len(c_sh) == 3
    block(BASE + 2, tx1 + c_sh, 1, c_pffs, [0, 0, 0, 0],
          "row 0: tx, pff; row 1: pff, pff (two rows hold PFF_NS, three PFFs, no candidate)", "C")
    # D: a candidate whose result code is 11; the PFF results are the tail of the block's results.
    d_pffs = [("blob_version 1", pff_tx("d/0", ns, cm, CHAIN_ID, h0, 1)),
              ("candidate", pff_tx("d/1", ns, cm, CHAIN_ID, h0))]
    d_sh = compact_shares(PFF_NS, [t for _, t in d_pffs])
    assert len(d_sh) == 2
    assert len(tx2) == 1
    block(BASE + 3, tx2 + d_sh + [user], 2, d_pffs, [0, 0, 0, 11],
          "row 0: tx, pff; row 1: pff, user blob (candidate at PFF position 1, result index 3, code 11)", "D")
    # B: PFF_NS lies inside row 0's range with no share of it: an NMT absence proof.
    user2 = sparse_share(USER_NS, stream("user blob 2", 100))
    block(BASE + 4, tx1 + [user, user2, tail_share()], 1, [], [0],
          "row 0: tx, user blob; row 1: user blob, tail padding (row 0 holds PFF_NS in its range, absence proof)", "B")
    # E: the candidate succeeded (code 0); the first normal tx failed, so only the tail binding gives code 0.
    e_pffs = [("candidate", pff_tx("e/0", ns, cm, CHAIN_ID, h0))]
    e_sh = compact_shares(PFF_NS, [t for _, t in e_pffs])
    assert len(e_sh) == 1
    block(BASE + 5, tx2 + e_sh + [user, tail_share()], 2, e_pffs, [7, 0, 0],
          "row 0: tx, pff; row 1: user blob, tail padding (candidate at PFF position 0, result index 2, code 0)", "E")
    block(BASE + 6, tx1 + [user, tail_share(), tail_share()], 1, [], [0],
          "row 0: tx, user blob; row 1: tail padding (header for the results of the block before)", "F")

    for h, codes in (codes_at or {}).items():
        blocks[h]["codes"] = codes
    prev = stream(f"block/{BASE}", 32)
    prev_results = rfc6962([])
    for h in sorted(blocks):
        b = blocks[h]
        hpb, hh = header(h, b["square"]["data_hash"], prev, prev_results, (app_at or {}).get(h, APP_VERSION))
        b["header"], b["hash"] = signed_header(hpb, hh, h), hh
        b["results_bytes"] = results_json(h, b["codes"])
        prev, prev_results = hh, rfc6962([results_leaf(c, 80000 + 1000 * i) for i, c in enumerate(b["codes"])])
    return blocks


def record(query: dict, blocks: dict, h: int, entries_edit=None, dah_edit=None, header_edit=None,
           results_edit=None, drop_results: bool = False) -> bytes:
    b = blocks[h]
    sq = b["square"]
    entries = namespace_entries(sq, PFF_NS)
    if entries_edit:
        entries = entries_edit(entries)
    dah = dah_bytes(sq["rows"], sq["cols"]) if dah_edit is None else dah_edit(sq)
    rec = {"kind": A.KIND_ABSENCE, "da": 1, "commitment": query["commitment"], "namespace": query["namespace"],
           "height": h, "header": b["header"] if header_edit is None else header_edit(h),
           "dah": dah, "namespace_data": ns_stream(entries)}
    if b["pffs"] and any(lbl.startswith("candidate") for lbl, _ in b["pffs"]) and not drop_results:
        res = b["results_bytes"] if results_edit is None else results_edit(h)
        rec["results"], rec["next_header"] = res, blocks[h + 1]["header"]
    data = A.encode_record(rec)
    assert A.decode_record(data) == rec
    return data


def expected_height(blocks: dict, h: int, result: str, rule: str, why: str) -> dict:
    b = blocks[h]
    sq = b["square"]
    rows = [str(e["row"]) for e in namespace_entries(sq, PFF_NS)]
    out = {"height": str(h), "result": result, "rule": rule, "why": why, "rows": rows,
           "pff_txs": str(len(b["pffs"]))}
    cands = []
    for j, (lbl, _) in enumerate(b["pffs"]):
        if lbl.startswith("candidate"):
            i = len(b["codes"]) - len(b["pffs"]) + j
            cands.append({"position": str(j), "result_index": str(i), "code": str(b["codes"][i])})
    if cands:
        out["candidates"] = cands
    return out


def window(heights: list) -> dict:
    present = next((x["height"] for x in heights if x["result"] == "present"), None)
    if present:
        return {"result": "present", "anchor_height": present}
    miss = next((x["height"] for x in heights if x["result"] != "absent"), None)
    return {"result": "absent"} if miss is None else {"result": "unproven", "first_unproven": miss}


def build() -> dict:
    valid = json.loads((VECTORS / "v1" / "valid.json").read_text())
    pf = next(c for c in valid["cases"] if c["id"] == "v1_pending_fibre")["input"]["payload_ref"]
    query = {"namespace": bytes.fromhex(pf["namespace"]), "commitment": bytes.fromhex(pf["commitment"])}
    blocks = build_chain(query)
    trusted = {str(h): blocks[h]["hash"].hex() for h in sorted(blocks)}
    other_app = build_chain(query, {BASE + 3: 11})
    other_nonzero = build_chain(query, {BASE + 3: 11}, {BASE + 3: [5, 5, 5, 11]})
    other_zero = build_chain(query, {BASE + 3: 11}, {BASE + 3: [0, 0, 0, 0]})
    short = build_chain(query, None, {BASE + 3: [11]})
    th = lambda ch: {str(h): ch[h]["hash"].hex() for h in sorted(ch)}  # noqa: E731

    def q(h0, d):
        return {"da": "1", "namespace": query["namespace"].hex(), "commitment": query["commitment"].hex(),
                "chain_id": CHAIN_ID, "h0": str(h0), "anchor_deadline": str(d)}

    def recs(pairs):
        return [{"height": str(h), "record_hex": r.hex(), "sha256": sha(r).hex(), "size": str(len(r))}
                for h, r in pairs]

    absent_a = lambda: expected_height(blocks, BASE + 1, "absent", "AB4", "no row holds PFF_NS: S is empty")
    absent_c = lambda: expected_height(blocks, BASE + 2, "absent", "AB4",
                                       "three PFFs in PFF_NS, none a candidate (other commitment, other chain_id, "
                                       "promise.height above h)")
    absent_d = lambda: expected_height(blocks, BASE + 3, "absent", "AB5",
                                       "one candidate; its result (index n - p + j = 4 - 2 + 1 = 3) has code 11")
    absent_b = lambda: expected_height(blocks, BASE + 4, "absent", "AB4",
                                       "row 0 holds PFF_NS in its range; its entry is an NMT absence proof, S is empty")
    present_e = lambda: expected_height(blocks, BASE + 5, "present", "AB5",
                                        "one candidate; its result (index 3 - 1 + 0 = 2) has code 0")

    def case(cid, desc, h0, d, pairs, heights, extra=None, trusted_headers=None):
        c = {"id": cid, "description": desc, "query": q(h0, d),
             "trusted_headers": trusted if trusted_headers is None else trusted_headers, "records": recs(pairs),
             "expect": {"heights": heights, "window": window(heights)}}
        if extra:
            c.update(extra)
        return c

    def bad(h, rule, why):
        return {"height": str(h), "result": "unproven", "rule": rule, "why": why}

    def flip_row_root(sq):
        rows = list(sq["rows"])
        rows[1] = rows[1][:-1] + bytes([rows[1][-1] ^ 1])
        return dah_bytes(rows, sq["cols"])

    def other_app_hash(h):
        hb = blocks[h]["header"]
        old = stream(f"app/{h}", 32)
        assert hb.count(old) == 1
        return hb.replace(old, stream(f"app/{h}/forged", 32))

    def code_zero(h):
        j = json.loads(blocks[h]["results_bytes"])
        j["txs_results"][3]["code"] = 0
        return json.dumps(j, separators=(",", ":")).encode()

    synthetic = [
        case("window_three_heights_proven",
             "Window [h0, h0 + 2], one kind 14 record per height, each absent by a different rule: no row holds "
             "PFF_NS; PFFs but no candidate; a candidate with a proven nonzero code. Absence over the window holds, "
             "so a pending reference with this window fails anchor_absent (10.2).",
             BASE + 1, BASE + 3, [(h, record(query, blocks, h)) for h in (BASE + 1, BASE + 2, BASE + 3)],
             [absent_a(), absent_c(), absent_d()]),
        case("window_one_height_missing",
             "Window [h0, h0 + 2] with no record for h0 + 1. The other heights are absent (PFFs without a candidate; "
             "an NMT absence proof inside a row range). Absence is not proven: absence_unproven names h0 + 1.",
             BASE + 2, BASE + 4, [(h, record(query, blocks, h)) for h in (BASE + 2, BASE + 4)],
             [absent_c(), {"height": str(BASE + 3), "result": "unproven", "rule": "none",
                           "why": "no absence proof for this height"}, absent_b()]),
        case("fibre_candidate_nonzero_code",
             "One height. Two PFFs match on commitment; one has blob_version 1, so one candidate. Its result is "
             "bound as the tail of the block's results (index n - p + j) and has code 11: absent. Binding by the "
             "PFF position alone would read index 1, code 0, and wrongly find the anchor.",
             BASE + 3, BASE + 3, [(BASE + 3, record(query, blocks, BASE + 3))], [absent_d()]),
        case("fibre_present",
             "Window [h0, h0 + 1]: absent at h0 (absence proof inside a row range), the anchor present at h0 + 1 (a "
             "candidate with proven code 0). The proof is used as evidence at H = h0 + 1 (10.2). The first normal tx "
             "failed (code 7): binding by the PFF position alone would read code 7 and wrongly prove absence.",
             BASE + 4, BASE + 5, [(h, record(query, blocks, h)) for h in (BASE + 4, BASE + 5)],
             [absent_b(), present_e()]),
        case("tampered_row_root",
             "The record of h0 + 1 of the chain (PFFs, no candidate) with one bit of row root 1 flipped in the DAH: Hash() "
             "differs from data_hash (AB2).",
             BASE + 2, BASE + 2, [(BASE + 2, record(query, blocks, BASE + 2, dah_edit=flip_row_root))],
             [bad(BASE + 2, "AB2", "DAH hash differs from data_hash")]),
        case("cut_namespace_entry",
             "The same record with the entry of row 1 removed from the namespace data: two rows hold PFF_NS, one "
             "entry is given (AB3 completeness). The remaining entry still verifies on its own.",
             BASE + 2, BASE + 2, [(BASE + 2, record(query, blocks, BASE + 2, entries_edit=lambda e: e[:1]))],
             [bad(BASE + 2, "AB3", "two rows hold PFF_NS, one entry")]),
        case("header_not_trusted",
             "The record of h0 with another app_hash in its header: the header hash differs from the trusted one "
             "(AB1).",
             BASE + 1, BASE + 1, [(BASE + 1, record(query, blocks, BASE + 1, header_edit=other_app_hash))],
             [bad(BASE + 1, "AB1", "header hash differs from the trusted hash")]),
        case("results_root_mismatch",
             "The candidate's record with its result code rewritten to 0 in results: the results no longer hash to "
             "last_results_hash of the next header (AB5).",
             BASE + 3, BASE + 3, [(BASE + 3, record(query, blocks, BASE + 3, results_edit=code_zero))],
             [bad(BASE + 3, "AB5", "results do not hash to last_results_hash of header(h + 1)")]),
        case("candidate_without_results",
             "A candidate and no results or next_header: its code is not proven (AB5). The record layer accepts "
             "this pairing (both absent); the presence rule of key 10 is the writer's.",
             BASE + 3, BASE + 3, [(BASE + 3, record(query, blocks, BASE + 3, drop_results=True))],
             [bad(BASE + 3, "AB5", "a candidate whose code is not proven")]),
        case("candidate_other_app_version",
             "The chain with version.app = 11 in the header of h (block D, otherwise the same txs, results and "
             "codes; the later headers relinked). The tail rule binds only under the pinned app version 10; at another "
             "version only every code 0 proves anything, and the codes are 0, 0, 0, 11: not proven (AB5).",
             BASE + 3, BASE + 3, [(BASE + 3, record(query, other_app, BASE + 3))],
             [bad(BASE + 3, "AB5", "another app version without every code 0: not proven")],
             extra={"app_versions": {str(BASE + 3): "11"}},
             trusted_headers={str(h): other_app[h]["hash"].hex() for h in sorted(other_app)}),
        case("candidate_other_app_version_all_nonzero",
             "version.app = 11 at h and every result code nonzero (5, 5, 5, 11): at another app version only every "
             "code 0 proves anything, and nothing proves absence (fail-closed against a false anchor_absent).",
             BASE + 3, BASE + 3, [(BASE + 3, record(query, other_nonzero, BASE + 3))],
             [bad(BASE + 3, "AB5", "another app version without every code 0: not proven")],
             extra={"app_versions": {str(BASE + 3): "11"}}, trusted_headers=th(other_nonzero)),
        case("candidate_other_app_version_all_zero",
             "version.app = 11 at h and every result code 0: the candidate's code is 0 whatever its index, so the "
             "anchor is present at h (the safe direction).",
             BASE + 3, BASE + 3, [(BASE + 3, record(query, other_zero, BASE + 3))],
             [{"height": str(BASE + 3), "result": "present", "rule": "AB5",
               "why": "another app version, every result code 0", "rows": ["0", "1"], "pff_txs": "2",
               "candidates": [{"position": "1", "code": "0"}]}],
             extra={"app_versions": {str(BASE + 3): "11"}}, trusted_headers=th(other_zero)),
        case("tail_n_less_than_p",
             "Pinned app version, but the block's results hold one result while two units of PFF_NS were "
             "reassembled: n >= p fails, so the height is not proven (no uniform-code path at the pinned version).",
             BASE + 3, BASE + 3, [(BASE + 3, record(query, short, BASE + 3))],
             [bad(BASE + 3, "AB5", "n >= p >= 1 does not hold")], trusted_headers=th(short),
             extra={"results_counts": {str(BASE + 3): "1"}}),
    ]
    blocks_out = [{"height": str(h), "layout": blocks[h]["layout"], "header_hash": blocks[h]["hash"].hex(),
                   "data_hash": blocks[h]["square"]["data_hash"].hex(), "txs": str(len(blocks[h]["codes"])),
                   "pff_txs": str(len(blocks[h]["pffs"]))} for h in sorted(blocks)]
    return {"absence.json": {
        "format": FORMAT,
        "revision": REVISION,
        "generator": "spec/vectors/check/gen_absence.py",
        "description": (
            "Absence proofs (core v1 10.4). Each case gives the query (da, payload namespace, commitment, the "
            "expected chain_id, the window [h0, anchor_deadline]), trusted_headers (height -> header hash, the "
            "result of header trust, an input here), and kind 14 records (record_hex, as archived). expect gives per "
            "height absent, present or unproven with the deciding rule, and the window result as 10.2 reads it. "
            "results is the JSON result object of CometBFT /block_results (RP1 reads its txs_results). A "
            "candidate's result index is n - p + j: n results, p units of PFF_NS, j the candidate's position among "
            "them (Fibre txs are the tail of the block's txs), when header(h) has version.app 10 (the pinned app "
            "version), and n >= p >= 1 must hold; at any other app version only every result code 0 proves "
            "presence, and nothing proves absence. A case with app_versions uses a chain whose headers "
            "carry those app versions; its trusted_headers are that chain's. Synthetic: parity quadrants are pseudo-random, not "
            "Reed-Solomon; commit and PFF signatures are placeholders; system blobs are left out; no AB rule reads "
            "any of them. live: Mocha heights captured by spec/vectors/tools/absence-gen, with their own chain_id "
            "(live_source); live_tail_rule shows the tail rule of AB5 on live blocks."),
        "chain_id": CHAIN_ID,
        "pff_namespace": PFF_NS.hex(),
        "blocks": blocks_out,
        "synthetic": synthetic,
        **live_sections(),
    }}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for name, obj in build().items():
        p = OUT / name
        p.write_text(json.dumps(obj, indent=2, ensure_ascii=True) + "\n")
        print(f"wrote {p}")


if __name__ == "__main__":
    main()
