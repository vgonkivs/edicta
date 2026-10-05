#!/usr/bin/env python3
"""Verifies the structure of spec/vectors/da/fibre_commit.json (v0-draft.17).

The commitments are upstream celestia-app output (fibre.NewBlob) and are
checked by Go only. This script checks everything else:
- file header, upstream pin and the blob version 0 parameters;
- every blob description (inline hex or pattern) against its SHA-256 and size;
- row size and upload size against the arithmetic of section 10.4;
- BlobID = 0x00 || commitment; 32-byte lowercase hex commitments;
- the live Mocha vector's locator fields and namespace rule;
- reject cases: what each one is built from (flipped byte, trailing zero,
  header in front, the da = 2 commitment, empty, over the maximum), and that
  no reject pairs a blob with its own accepted commitment;
- anchor_k2_with_fibre_committer against anchor.json.

Usage: python3 spec/vectors/check/check_fibre_commit.py [--file FILE] [--core DIR]
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import hashlib
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
VECTORS = HERE.parent
FORMAT = "edicta-vectors/v0"
REVISION = "v0-draft.17"
ROWS = 4096
PARITY = 12288
MIN_ROW = 64
HEADER = 5
MAX_DATA = (1 << 27) - HEADER
HEX32 = re.compile(r"^[0-9a-f]{64}$")


class Failure(Exception):
    pass


def expect(cond: bool, msg: str):
    if not cond:
        raise Failure(msg)


def arg(name: str, default: Path) -> Path:
    if name in sys.argv:
        return Path(sys.argv[sys.argv.index(name) + 1]).resolve()
    return default


def pattern(size: int) -> bytes:
    period = bytes((7 * i + 3) & 0xFF for i in range(256))
    return (period * (size // 256 + 1))[:size]


def blob_of(v: dict) -> bytes:
    size = int(v["size"])
    if "blob_hex" in v:
        expect("blob_pattern" not in v, f"{v['id']}: both blob_hex and blob_pattern")
        b = bytes.fromhex(v["blob_hex"])
        expect(len(b) <= 1024, f"{v['id']}: inline blob above 1024 bytes")
    else:
        expect(v.get("blob_pattern") == "affine-7-3", f"{v['id']}: unknown blob pattern")
        expect(size > 1024, f"{v['id']}: pattern used for a small blob")
        b = pattern(size)
    expect(len(b) == size, f"{v['id']}: size {size} but blob has {len(b)} bytes")
    expect(hashlib.sha256(b).hexdigest() == v["blob_sha256_hex"], f"{v['id']}: blob_sha256_hex mismatch")
    return b


def row_size(n: int) -> int:
    r = -(-(n + HEADER) // ROWS)
    return -(-r // MIN_ROW) * MIN_ROW


def check(path: Path, core: Path) -> str:
    f = json.loads(path.read_text())
    expect(f.get("format") == FORMAT, "format")
    expect(f.get("revision") == REVISION, "revision")
    expect(f.get("generator") == "spec/vectors/tools/fibrecommit-gen", "generator")
    expect("v10.4.0-mocha" in f["upstream"]["celestia-app"] and "fibre.NewBlob" in f["upstream"]["celestia-app"],
           "upstream pin")
    expect("celestia-node v0.34.2-mocha" in f["upstream"]["replace_set"], "replace set")
    expect(f["params"] == {"blob_version": "0", "original_rows": str(ROWS), "parity_rows": str(PARITY),
                           "min_row_size": str(MIN_ROW), "header_size": str(HEADER), "max_data_size": str(MAX_DATA)},
           f"params {f['params']}")
    expect(set(f["patterns"]) == {"affine-7-3"}, "patterns")

    ids = [v["id"] for v in f["cases"] + f["reject"]]
    expect(len(ids) == len(set(ids)), "duplicate ids")

    accepted = {}
    for v in f["cases"]:
        b = blob_of(v)
        n = len(b)
        expect(1 <= n <= MAX_DATA, f"{v['id']}: size outside 1..2^27-5")
        expect(HEX32.match(v["commitment_hex"]) is not None, f"{v['id']}: commitment not 32-byte lowercase hex")
        expect(v["blob_id_hex"] == "00" + v["commitment_hex"], f"{v['id']}: BlobID is not 0x00 || commitment")
        rs = row_size(n)
        expect(v["row_size"] == str(rs), f"{v['id']}: row_size {v['row_size']}, expected {rs}")
        expect(v["upload_size"] == str(ROWS * rs), f"{v['id']}: upload_size")
        expect("expect_error" not in v, f"{v['id']}: accepted case carries expect_error")
        accepted[v["id"]] = (b, v["commitment_hex"])

    sizes = {int(v["size"]) for v in f["cases"]}
    for n in (1, 262139, 262140):
        expect(n in sizes, f"missing size {n}")
    expect(any(row_size(n) > 2 * MIN_ROW for n in sizes), "no case with a row size above 128")
    expect(row_size(262139) == MIN_ROW and row_size(262140) == 2 * MIN_ROW, "row-size boundary arithmetic")

    live = next(v for v in f["cases"] if v["id"] == "fibre_live_mocha_popsmin1")
    lr = live["live"]
    expect(lr["chain_id"] == "mocha-5" and lr["height"] == "1402819", "live: chain or height")
    expect(re.fullmatch(r"[0-9A-F]{64}", lr["tx_hash"]) is not None, "live: tx hash")
    ns = bytes.fromhex(lr["namespace_hex"])
    expect(len(ns) == 29 and ns[0] == 0 and not any(ns[1:19]) and any(ns[19:28]), "live: namespace rule (S8)")
    expect(lr["upload_size"] == live["upload_size"] == "262144", "live: upload size")
    expect(live["blob_hex"] == "65", "live: payload")
    expect(live["commitment_hex"] == "0af738097b64a00bff6820c48a3ae26160b8054c9a9b79bd3cac2100d1833b2e",
           "live: commitment differs from the one read from the chain")
    expect(sum(1 for v in f["cases"] if "live" in v) == 1, "exactly one live case")

    payload = json.loads((core / "payload.json").read_text())
    small = next(c for c in payload["cases"] if c["id"] == "ciphertext_hash_small_blob")
    p = bytes.fromhex(small["blob_hex"])
    expect(accepted["fibre_minimal_lmt_payload"][0] == p, "fibre_minimal_lmt_payload is not the minimal_lmt blob")
    pc = accepted["fibre_minimal_lmt_payload"][1]
    da = json.loads((core / "da_blob.json").read_text())
    da2 = next(c for c in da["cases"] if c["id"] == "blob_v1_minimal_lmt_payload")["commitment_hex"]

    rej = {}
    for v in f["reject"]:
        expect(v.get("expect_error") == "ErrDACommitmentMismatch", f"{v['id']}: expect_error")
        expect(HEX32.match(v["commitment_hex"]) is not None, f"{v['id']}: commitment hex")
        for k in ("row_size", "upload_size", "blob_id_hex", "live"):
            expect(k not in v, f"{v['id']}: reject carries {k}")
        b = blob_of(v) if int(v["size"]) <= MAX_DATA + 1 else None
        for ab, ac in accepted.values():
            expect(not (b == ab and v["commitment_hex"] == ac), f"{v['id']}: equals an accepted case")
        rej[v["id"]] = (b, v["commitment_hex"])

    flipped = bytearray(p)
    flipped[-1] ^= 1
    expect(rej["fibre_anchor_x_sign_hash_y"] == (bytes(flipped), pc), "fibre_anchor_x_sign_hash_y")
    expect(rej["fibre_trailing_zero"] == (p + b"\x00", pc), "fibre_trailing_zero")
    hdr = b"\x00" + len(p).to_bytes(4, "big")
    expect(rej["fibre_with_header"] == (hdr + p, pc), "fibre_with_header")
    expect(rej["fibre_da2_commitment"] == (p, da2), "fibre_da2_commitment")
    expect(rej["fibre_live_commitment_other_bytes"] == (p, live["commitment_hex"]), "fibre_live_commitment_other_bytes")
    expect(rej["fibre_empty"][0] == b"", "fibre_empty")
    expect(rej[f"fibre_size_{MAX_DATA + 1}"][0] is not None and len(rej[f"fibre_size_{MAX_DATA + 1}"][0]) == MAX_DATA + 1,
           "over-maximum reject")

    anchor = json.loads((core / "anchor.json").read_text())
    k2 = {c["id"]: c for c in anchor["k2"]}
    listed = set()
    for r in f["anchor_k2_with_fibre_committer"]:
        c = k2.get(r["anchor_ref"])
        expect(c is not None, f"anchor ref {r['anchor_ref']} not in anchor.json")
        expect(c["da"] == "1" and c["expect"].get("within") is False, f"{r['anchor_ref']}: not a failing da = 1 K2 case")
        expect(c["expect"].get("expect_error") == r["without_committer"] == "ErrArchiveRecomputeUnsupported",
               f"{r['anchor_ref']}: without_committer")
        expect(r["route"] == "archive", f"{r['anchor_ref']}: route")
        listed.add(r["anchor_ref"])
    want = {i for i, c in k2.items() if c["expect"].get("expect_error") == "ErrArchiveRecomputeUnsupported"}
    expect(listed == want, f"anchor routes {sorted(listed)} != {sorted(want)}")

    return (f"{len(f['cases'])} cases, {len(f['reject'])} reject, "
            f"{len(f['anchor_k2_with_fibre_committer'])} anchor routes")


def main() -> int:
    path = arg("--file", VECTORS / "da" / "fibre_commit.json")
    core = arg("--core", VECTORS / "v0")
    try:
        summary = check(path, core)
    except (Failure, KeyError, StopIteration, ValueError) as e:
        print(f"FAIL (fibre_commit.json): {e!r}", file=sys.stderr)
        return 1
    print(f"OK (fibre_commit.json, {REVISION}): {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
