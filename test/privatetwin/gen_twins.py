"""Private twins of the public policy verifier cases.

Replays the scenario of spec/vectors/policy/verify.json with every mandate in
private mode (two auditors, a state_salt per counter) and writes twins.json:
the same case ids, the private-mode records, the reference outcome with
auditor-1's key and the reference outcome without any key.

The scenario is the reference generator's own source with the few public-only
record paths rewritten, so a scenario change upstream shows up here as a
failed rewrite instead of a silently stale twin.

Usage: python3 test/privatetwin/gen_twins.py  (needs spec/vectors/check/requirements.txt)
"""
from __future__ import annotations

import inspect
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CHECK = HERE.parent.parent / "spec" / "vectors" / "check"
sys.path.insert(0, str(CHECK))

import gen_policy as G  # noqa: E402

P = G.P
KEY = "auditor-1"
BaseSim = G.Sim


def privatize(m: dict, salt: bytes) -> dict:
    if "auditors" in m:
        return m
    return {**m, "auditors": G.AUDITORS, "state_salt": salt}


class TwinSim(BaseSim):
    def __init__(self, label, m=None, signer="p1", blind_salt=None):
        salt = G.state_salt("twin|" + label)
        super().__init__(label, privatize(m or G.base_mandate(label), salt), signer, blind_salt)

    def adopt(self, m):
        super().adopt(privatize(m, self.m["state_salt"]))


def bucket_at(sim, path: str) -> dict:
    key = bytes.fromhex(path.split("/")[2])
    for b in sim.led["buckets"].values():
        if P.blind_key(sim.salt, P.bucket_hash(b)) == key:
            return P.decode_bucket(P.bucket_cbor(b))
    raise AssertionError(path)


def reseal(sim, path: str, pk: int, plaintext: bytes) -> bytes:
    return G.private_record(pk, plaintext, bytes.fromhex(path.split("/")[2]), sim.m["auditors"])[0]


REWRITES = [
    ('p.startswith("policy-bucket/")', 'p.startswith("private/2/")'),
    ('p.startswith("policy-closed/") and p != "policy-closed/" + P.EMPTY_ROOT.hex()',
     'p.startswith("private/3/") and p != "private/3/" + P.blind_key(A.salt, P.EMPTY_ROOT).hex()'),
    ('f"mandate/{A.mh.hex()}"', 'f"private/1/{A.mh.hex()}"'),
    ('P.decode_bucket(P.decode_record(A.recs[b0_path])["body"])', 'bucket_at(A, b0_path)'),
    ('{b0_path: P.record(10, body=P.bucket_cbor(ob))}', '{b0_path: reseal(A, b0_path, 2, P.bucket_cbor(ob))}'),
    ('v["new_state_hash"] = P.state_hash(skip["state"])', 'v["new_state_hash"] = SG.sh(skip["state"])'),
    ("res = P.verify_policy(inp)", "res = twin_verify(i, inp, exp)"),
    ("    private_cases(case, dec, sims)\n", ""),
]

WITHOUT_KEY = {}


def twin_verify(i, inp, exp):
    assert not inp["auditor_keys"], i
    res = P.verify_policy({**inp, "auditor_keys": [G.AUDITOR_SK[KEY]]})
    got = (res["policy"]["status"], res["policy"].get("rule") or res["policy"].get("reason"),
           res["gate_integrity"]["status"], res["exit"])
    # The reference itself must give the public outcome with the key.
    assert got == exp, (i, got, exp)
    WITHOUT_KEY[i] = P.verify_policy(inp)
    return res


def main() -> int:
    src = inspect.getsource(G.gen_verify) + "\n\n" + inspect.getsource(G.draft5_cases)
    for old, new in REWRITES:
        assert old in src, old
        src = src.replace(old, new)
    ns = dict(G.__dict__)
    ns.update(Sim=TwinSim, bucket_at=bucket_at, reseal=reseal, twin_verify=twin_verify)
    exec(compile(src, "gen_verify_twin", "exec"), ns)
    doc = ns["gen_verify"]()[0]
    for c in doc["cases"]:
        c["config"]["auditor_keys"] = [G.AUDITOR_SK[KEY].hex()]
        c["expect_without_key"] = WITHOUT_KEY[c["id"]]
    doc = {"format": "edicta-test-private-twins", "auditor": KEY, **doc}
    out = HERE / "twins.json"
    out.write_text(json.dumps(doc, indent=1, sort_keys=False) + "\n")
    print(f"{out}: {len(doc['cases'])} cases, {len(doc['records'])} records")
    return 0


if __name__ == "__main__":
    sys.exit(main())
