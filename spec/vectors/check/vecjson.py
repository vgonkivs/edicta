"""JSON form of vector inputs: uints as decimal strings, byte strings as lowercase hex."""

from __future__ import annotations

from edicta_v0 import COMMITMENT, IBKR_ORDER_V0, PARAMS_BY_KIND, RECEIPT, Params


def _conv(obj: dict, schema: dict, to_json: bool) -> dict:
    by_name = {f[0]: f for f in schema.values()}
    out = {}
    for name, val in obj.items():
        _, typ, _, _ = by_name[name]
        if isinstance(typ, dict):
            out[name] = _conv(val, typ, to_json)
        elif typ == "params":
            out[name] = _conv(val, PARAMS_BY_KIND.get(obj.get("kind"), IBKR_ORDER_V0), to_json)
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


def order_to_json(o: dict) -> dict:
    return _conv(o, IBKR_ORDER_V0, True)


def order_from_json(j: dict) -> dict:
    return _conv(j, IBKR_ORDER_V0, False)


def gate_to_json(g: dict) -> dict:
    return {k: (str(v) if k == "rail" else v) for k, v in g.items()}


def gate_from_json(j: dict) -> dict:
    return {k: (int(v) if k == "rail" else v) for k, v in j.items()}


def params_to_json(p: Params) -> dict:
    return {"fibre_retention_s": str(p.fibre_retention_s),
            "blob_retention_s": str(p.blob_retention_s),
            "skew_s": str(p.skew_s)}


def params_from_json(j: dict) -> Params:
    return Params(int(j["fibre_retention_s"]), int(j["blob_retention_s"]), int(j["skew_s"]))
