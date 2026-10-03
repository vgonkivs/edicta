"""Minimal Ed25519 point arithmetic for the public-key validity check and
the cofactorless verification equation.

Written from RFC 8032 section 5.1 (curve, encoding, decoding). Affine
coordinates and modular inversion: slow but simple, and only used on a few
points per vector. Not constant time; never use with secrets.
"""

from __future__ import annotations

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
IDENTITY = (0, 1)
_BY = 4 * pow(5, P - 2, P) % P


def _inv(a: int) -> int:
    return pow(a, P - 2, P)


def on_curve(pt) -> bool:
    x, y = pt
    return (-x * x + y * y - 1 - D * x * x * y * y) % P == 0


def add(p1, p2):
    """Complete twisted Edwards addition, a = -1."""
    x1, y1 = p1
    x2, y2 = p2
    t = D * x1 * x2 * y1 * y2 % P
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + t) % P
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - t) % P
    return (x3, y3)


def mul(k: int, pt):
    acc = IDENTITY
    while k:
        if k & 1:
            acc = add(acc, pt)
        pt = add(pt, pt)
        k >>= 1
    return acc


def neg(pt):
    return ((-pt[0]) % P, pt[1])


def _recover_x(y: int, sign: int, strict: bool):
    u = (y * y - 1) % P
    v = (D * y * y + 1) % P
    x2 = u * _inv(v) % P
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if x == 0 and sign == 1:
        if strict:
            return None  # RFC 8032 5.1.3 step 4: "negative zero" fails
        return 0
    if x & 1 != sign:
        x = P - x
    return x


def decode(enc: bytes, strict: bool = True):
    """RFC 8032 section 5.1.3. strict=False mimics lenient decoders that reduce
    y mod p and accept x = 0 with the sign bit set."""
    if len(enc) != 32:
        return None
    n = int.from_bytes(enc, "little")
    sign = n >> 255
    y = n & ((1 << 255) - 1)
    if y >= P:
        if strict:
            return None  # RFC 8032 5.1.3 step 1: y >= p fails
        y -= P
    x = _recover_x(y, sign, strict)
    if x is None:
        return None
    return (x, y)


def encode(pt) -> bytes:
    x, y = pt
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def is_small_order(pt) -> bool:
    return mul(8, pt) == IDENTITY


def public_key_problem(enc: bytes):
    """The key must be a canonical point encoding and not of small order.
    Returns None if the key is acceptable, else a reason string."""
    pt = decode(enc, strict=True)
    if pt is None:
        return "not a canonical encoding of a curve point"
    if is_small_order(pt):
        return "small-order point"
    return None


def torsion_points() -> list:
    """The 8 points of the 8-torsion subgroup, ordered by multiple of a fixed
    order-8 generator (index 0 is the identity)."""
    y = 2
    while True:
        pt = decode(y.to_bytes(32, "little"))
        if pt is not None:
            t = mul(L, pt)
            if mul(4, t) != IDENTITY:
                return [mul(k, t) for k in range(8)]
        y += 1


def order(pt) -> int:
    for o in (1, 2, 4, 8):
        if mul(o, pt) == IDENTITY:
            return o
    return 0


BASE = decode(_BY.to_bytes(32, "little"))  # RFC 8032 5.1: y = 4/5, x even


def challenge(r_enc: bytes, a_enc: bytes, msg: bytes) -> int:
    """k = SHA-512(R || A || M) mod L (RFC 8032 5.1.7 step 2)."""
    import hashlib
    return int.from_bytes(hashlib.sha512(r_enc + a_enc + msg).digest(), "little") % L


def cofactorless_ok(a_enc: bytes, msg: bytes, sig: bytes) -> bool:
    """Accept iff encode([S]B - [k]A) == R bytewise. The caller has already
    checked that A is canonical and not of small order, and that S < L."""
    a = decode(a_enc, strict=True)
    if a is None or len(sig) != 64:
        return False
    s = int.from_bytes(sig[32:], "little")
    k = challenge(sig[:32], a_enc, msg)
    return encode(add(mul(s, BASE), neg(mul(k, a)))) == sig[:32]


def cofactored_ok(a_enc: bytes, msg: bytes, sig: bytes) -> bool:
    """[8][S]B == [8]R + [8][k]A (RFC 8032 5.1.7 step 3, cofactored form).
    Not used by any Edicta rule; only to show that a vector separates the two."""
    a = decode(a_enc, strict=True)
    r = decode(sig[:32], strict=True)
    if a is None or r is None or len(sig) != 64:
        return False
    s = int.from_bytes(sig[32:], "little")
    k = challenge(sig[:32], a_enc, msg)
    return mul(8, mul(s, BASE)) == mul(8, add(r, mul(k, a)))
