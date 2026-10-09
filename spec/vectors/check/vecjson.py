"""JSON form of vector inputs: uints as decimal strings, byte strings as lowercase hex."""

from __future__ import annotations

from edicta import AUTHORIZATION, COMMITMENT, RECEIPT, Params


def _conv(obj: dict, schema: dict, to_json: bool) -> dict:
    by_name = {f[0]: f for f in schema.values()}
    out = {}
    for name, val in obj.items():
        _, typ, _, _ = by_name[name]
        if isinstance(typ, dict):
            out[name] = _conv(val, typ, to_json)
        elif typ == "uint":
            out[name] = str(val) if to_json else int(val)
        elif typ == "bstr":
            out[name] = val.hex() if to_json else bytes.fromhex(val)
        else:
            out[name] = val
    return out


def commitment_to_json(c: dict) -> dict:
    return _conv(c, COMMITMENT, True)


def commitment_from_json(j: dict) -> dict:
    return _conv(j, COMMITMENT, False)


def receipt_to_json(r: dict) -> dict:
    return _conv(r, RECEIPT, True)


def receipt_from_json(j: dict) -> dict:
    return _conv(j, RECEIPT, False)


def authorization_to_json(a: dict) -> dict:
    return _conv(a, AUTHORIZATION, True)


def authorization_from_json(j: dict) -> dict:
    return _conv(j, AUTHORIZATION, False)


def gate_to_json(g: dict) -> dict:
    return {"gate_id": g["gate_id"], "action_types": list(g["action_types"])}


def gate_from_json(j: dict) -> dict:
    return {"gate_id": j["gate_id"], "action_types": list(j["action_types"])}


def params_to_json(p: Params) -> dict:
    return {"fibre_retention_s": str(p.fibre_retention_s),
            "blob_retention_s": str(p.blob_retention_s),
            "skew_s": str(p.skew_s)}


def params_from_json(j: dict) -> Params:
    return Params(int(j["fibre_retention_s"]), int(j["blob_retention_s"]), int(j["skew_s"]))


PATTERNS = {"affine-7-3": "byte i of the action is (7*i + 3) mod 256, for i from 0"}


def pattern_bytes(name: str, size: int) -> bytes:
    if name != "affine-7-3":
        raise ValueError(f"unknown pattern {name}")
    return bytes((7 * i + 3) & 0xFF for i in range(size))


def action_from_case(case: dict) -> bytes:
    """Action bytes of a vector case: inline hex, or a pattern for large actions."""
    if "action_hex" in case:
        return bytes.fromhex(case["action_hex"])
    return pattern_bytes(case["action_pattern"], int(case["action_size"]))
