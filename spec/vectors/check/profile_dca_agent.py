"""Rules of the dca-agent profile (IBKR order action, DCA context, client order id, executor checks).

Python side of the cross-language check for examples/dca-agent. The core
(edicta_v0.py) never imports this module: to the core an IBKR order is an
opaque byte string with a type.

Sentinel names carry the Go package that owns them: ibkrorder.ErrX, dca.ErrX
and ibkr.ErrX.
"""

from __future__ import annotations

from cbor_strict import CBORError, Item, decode_strict, encode
from edicta_v0 import ID_CHARS, MAX_INT, PRINTABLE, Reject, _schema_decode, to_cbor

ACTION_TYPE_IBKR_ORDER_V0 = "application/vnd.edicta.ibkr.order.v0+cbor"
MEDIA_TYPE_DCA_V0 = "application/vnd.edicta.dca.v0+cbor"

QTY_SCALE = 10_000
MONEY_SCALE = 100_000_000
UPPER = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ")

SIDE_BUY, SIDE_SELL = 1, 2
TYPE_LMT, TYPE_MKT = 1, 2
TIF = {1: "DAY", 2: "GTC", 3: "IOC"}

ORDER = {
    1: ("account", "tstr", True, (1, 32, ID_CHARS)),
    2: ("conid", "uint", True, None),
    3: ("symbol", "tstr", False, (1, 32, PRINTABLE)),
    4: ("side", "uint", True, None),
    5: ("qty", "uint", True, None),
    6: ("order_type", "uint", True, None),
    7: ("limit_price", "uint", False, None),
    8: ("currency", "tstr", True, (3, 3, UPPER)),
    9: ("tif", "uint", True, None),
}


def order_encode(o: dict) -> bytes:
    return encode(to_cbor(o, ORDER))


def order_decode(b: bytes) -> dict:
    """Strict decoding of an IBKR order body. Every encoding or schema failure is ibkrorder.ErrMalformed."""
    try:
        it = decode_strict(b)
        o = _schema_decode(it, ORDER, "order")
    except (CBORError, Reject) as e:
        raise Reject("ibkrorder.ErrMalformed", str(e))
    if order_encode(o) != b:
        raise Reject("ibkrorder.ErrMalformed", "re-encoding differs")
    return o


def order_validate(o: dict):
    """Order rules in this fixed order. Every failure is ibkrorder.ErrInvalid."""
    def bad(detail: str):
        raise Reject("ibkrorder.ErrInvalid", detail)

    for name in ("conid", "side", "qty", "order_type", "limit_price", "tif"):
        if name in o and o[name] > MAX_INT:
            bad(f"{name} above 2^63-1")
    if o["side"] not in (SIDE_BUY, SIDE_SELL):
        bad(f"side={o['side']}")
    if o["order_type"] not in (TYPE_LMT, TYPE_MKT):
        bad(f"order_type={o['order_type']}")
    if o["tif"] not in TIF:
        bad(f"tif={o['tif']}")
    if o["order_type"] == TYPE_MKT:
        bad("MKT orders are not allowed")
    for name in ("conid", "qty", "limit_price"):
        if o.get(name) == 0:
            bad(f"{name} is zero")
    if ("limit_price" in o) != (o["order_type"] == TYPE_LMT):
        bad("limit_price present if and only if order_type is LMT")


def notional_within(qty: int, limit_price: int, max_notional: int) -> bool:
    """qty * limit_price <= max_notional * 10^4, in exact integers (no uint64 wrap)."""
    return qty * limit_price <= max_notional * QTY_SCALE


def executor_static_check(order_bytes: bytes, account: str, max_notional: int) -> dict:
    """The executor's checks on the authorized bytes after VerifyAuthorization:
    decode, validate, own account, operator risk limit (0 disables it)."""
    o = order_decode(order_bytes)
    order_validate(o)
    if o["account"] != account:
        raise Reject("ibkr.ErrAccountMismatch", f"{o['account']} != {account}")
    if max_notional and not notional_within(o["qty"], o["limit_price"], max_notional):
        raise Reject("ibkr.ErrRiskLimit", "notional above the executor limit")
    return o


def client_order_id(commitment_hash: bytes) -> str:
    if len(commitment_hash) != 32:
        raise ValueError("commitment_hash must be 32 bytes")
    return commitment_hash.hex()


def decimal(v: int, scale_digits: int) -> str:
    """Exact decimal string of v / 10^scale_digits, without trailing zeros. No floats."""
    q, r = divmod(v, 10 ** scale_digits)
    if r == 0:
        return str(q)
    frac = str(r).rjust(scale_digits, "0").rstrip("0")
    return f"{q}.{frac}"


# application/vnd.edicta.dca.v0+cbor

DCA_MAX_FILLS = 8

DCA_SCHEDULE = {
    1: ("period_s", "uint", True, None),
    2: ("period_start", "uint", True, None),
}

DCA_BUDGET = {
    1: ("currency", "tstr", True, (3, 3, UPPER)),
    2: ("per_period", "uint", True, None),
    3: ("spent", "uint", True, None),
}

DCA_PRICE = {
    1: ("source", "tstr", True, (1, 64, ID_CHARS)),
    2: ("conid", "uint", True, None),
    3: ("price", "uint", True, None),
    4: ("observed_at", "uint", True, None),
}

DCA_FILL = {
    1: ("filled_at", "uint", True, None),
    2: ("side", "uint", True, None),
    3: ("qty", "uint", True, None),
    4: ("price", "uint", True, None),
}

DCA_ORDER = {
    1: ("side", "uint", True, None),
    2: ("qty", "uint", True, None),
    3: ("limit_price", "uint", True, None),
}

DCA = {
    1: ("strategy_id", "tstr", True, (1, 64, ID_CHARS)),
    2: ("schedule", DCA_SCHEDULE, True, None),
    3: ("budget", DCA_BUDGET, True, None),
    4: ("price", DCA_PRICE, True, None),
    5: ("last_fills", "fills", False, None),
    6: ("order", DCA_ORDER, True, None),
}

DCA_NONZERO = {
    ("schedule", "period_s"), ("schedule", "period_start"), ("budget", "per_period"),
    ("price", "conid"), ("price", "price"), ("price", "observed_at"),
    ("order", "qty"), ("order", "limit_price"),
}


def dca_to_cbor(d: dict) -> dict:
    out = {}
    for key, (name, typ, _, _) in DCA.items():
        if name not in d:
            continue
        if typ == "fills":
            out[key] = [to_cbor(f, DCA_FILL) for f in d[name]]
        elif isinstance(typ, dict):
            out[key] = to_cbor(d[name], typ)
        else:
            out[key] = d[name]
    return out


def dca_encode(d: dict) -> bytes:
    return encode(dca_to_cbor(d))


def dca_decode(b: bytes) -> dict:
    """Strict decoding of an application/vnd.edicta.dca.v0+cbor body. Every failure is dca.ErrMalformed."""
    def bad(detail: str):
        raise Reject("dca.ErrMalformed", detail)

    try:
        it = decode_strict(b)
    except CBORError as e:
        bad(str(e))
    if it.major != 5:
        bad("top level is not a map")
    fills = [v for k, v in it.value if k.value == 5]
    rest = [(k, v) for k, v in it.value if k.value != 5]
    try:
        out = _schema_decode(Item(5, rest, it.start, it.end), {k: f for k, f in DCA.items() if k != 5}, "dca")
    except Reject as e:
        bad(str(e))
    if fills:
        v = fills[0]
        if v.major != 4 or not 1 <= len(v.value) <= DCA_MAX_FILLS:
            bad("last_fills must be an array of 1..8 fills")
        try:
            out["last_fills"] = [_schema_decode(f, DCA_FILL, "last_fills[]") for f in v.value]
        except Reject as e:
            bad(str(e))

    def uints(x):
        for val in (x.values() if isinstance(x, dict) else x):
            if isinstance(val, (dict, list)):
                yield from uints(val)
            elif isinstance(val, int):
                yield val

    if any(u > MAX_INT for u in uints(out)):
        bad("uint above 2^63-1")
    for m, f in DCA_NONZERO:
        if out[m][f] == 0:
            bad(f"{m}.{f} is zero")
    for f in out.get("last_fills", []):
        if f["side"] not in (1, 2) or f["qty"] == 0 or f["price"] == 0 or f["filled_at"] == 0:
            bad("fill: side, qty, price or filled_at out of range")
    if out["order"]["side"] not in (1, 2):
        bad("order.side out of range")
    if dca_encode(out) != b:
        bad("re-encoding differs")
    return out


DCA_CHECKS = ("DCA1", "DCA2", "DCA3", "DCA4", "DCA5")


def dca_consistency(d: dict, o: dict) -> list:
    """Replay checks between a DCA context and the authorized order. Returns the failed check ids."""
    failed = []
    if (d["order"]["side"], d["order"]["qty"], d["order"]["limit_price"]) != (o["side"], o["qty"], o.get("limit_price")):
        failed.append("DCA1")
    if d["price"]["conid"] != o["conid"]:
        failed.append("DCA2")
    if d["budget"]["currency"] != o["currency"]:
        failed.append("DCA3")
    if d["budget"]["spent"] > d["budget"]["per_period"]:
        failed.append("DCA4")
    elif not notional_within(d["order"]["qty"], d["order"]["limit_price"],
                             d["budget"]["per_period"] - d["budget"]["spent"]):
        failed.append("DCA5")
    return failed
