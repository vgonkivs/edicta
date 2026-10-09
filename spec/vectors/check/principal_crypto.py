"""Principal signature primitives for policy v1 sig_type 2 (Cosmos ADR-036) and 3 (EIP-712).

Keccak-256 is written out here because neither hashlib nor 'cryptography'
offers it (hashlib's sha3_256 is FIPS 202 SHA3, which pads differently); the
module runs its known-answer tests on import. ECDSA signing uses OpenSSL's
RFC 6979 deterministic nonces through 'cryptography'; verification goes
through OpenSSL too, and public-key recovery (EIP-712) uses the curve
arithmetic below, cross-checked against OpenSSL verification.
"""

from __future__ import annotations

import hashlib

from profile_bank_send import bech32_encode

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

# Keccak-f[1600], rate 1088 bits, Keccak padding 0x01 (not SHA3's 0x06).
_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
       0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
       0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
       0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
       0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M64 = (1 << 64) - 1


def _rol(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & _M64 if n else x


def _f1600(a):
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(a[x][y], _ROT[x][y])
        a = [[b[x][y] ^ (~b[(x + 1) % 5][y] & b[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        a[0][0] ^= rc
    return a


def keccak256(data: bytes) -> bytes:
    rate = 136
    msg = bytearray(data) + b"\x01" + bytes((-len(data) - 1) % rate)
    msg[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(msg), rate):
        block = msg[off:off + rate]
        for i in range(rate // 8):
            x, y = i % 5, i // 5
            a[x][y] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        a = _f1600(a)
    out = b"".join(a[i % 5][i // 5].to_bytes(8, "little") for i in range(4))
    return out


for _msg, _want in ((b"", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
                    (b"abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"),
                    (b"The quick brown fox jumps over the lazy dog",
                     "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15")):
    if keccak256(_msg).hex() != _want:
        raise RuntimeError("Keccak-256 known-answer test failed")


# secp256k1 affine arithmetic (verification-side only: recovery, decompression).

def _inv(x: int, m: int) -> int:
    return pow(x, m - 2, m)


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and (p1[1] + p2[1]) % P == 0:
        return None
    if p1 == p2:
        lam = 3 * p1[0] * p1[0] * _inv(2 * p1[1], P) % P
    else:
        lam = (p2[1] - p1[1]) * _inv(p2[0] - p1[0], P) % P
    x = (lam * lam - p1[0] - p2[0]) % P
    return x, (lam * (p1[0] - x) - p1[1]) % P


def _mul(k: int, pt):
    out = None
    while k:
        if k & 1:
            out = _add(out, pt)
        pt = _add(pt, pt)
        k >>= 1
    return out


def decompress(pub33: bytes):
    """Point of a 33-byte SEC1 compressed key, or None when it is not on the curve."""
    if len(pub33) != 33 or pub33[0] not in (2, 3):
        return None
    x = int.from_bytes(pub33[1:], "big")
    if x >= P:
        return None
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if y * y % P != y2:
        return None
    if (y & 1) != (pub33[0] & 1):
        y = P - y
    return x, y


def recover(digest: bytes, r: int, s: int, recid: int):
    """Public point Q with s*R = z*G + r*Q, R the point with x = r and y parity recid; None if none."""
    if not (1 <= r < N and 1 <= s < N and recid in (0, 1)):
        return None
    rp = decompress(bytes([2 + recid]) + r.to_bytes(32, "big"))
    if rp is None:
        return None
    z = int.from_bytes(digest, "big") % N
    rinv = _inv(r, N)
    q = _add(_mul(s * rinv % N, rp), _mul((-z * rinv) % N, (GX, GY)))
    return q


def uncompressed(pt) -> bytes:
    return b"\x04" + pt[0].to_bytes(32, "big") + pt[1].to_bytes(32, "big")


def eth_address(pt) -> bytes:
    return keccak256(uncompressed(pt)[1:])[12:]


def cosmos_address(pub33: bytes, hrp: str) -> str:
    return bech32_encode(hrp, hashlib.new("ripemd160", hashlib.sha256(pub33).digest()).digest())


# Keys and signing (OpenSSL, RFC 6979).

def _priv(seed: bytes):
    from cryptography.hazmat.primitives.asymmetric import ec
    d = int.from_bytes(seed, "big")
    if not 1 <= d < N:
        raise ValueError("secp256k1 seed out of range")
    return ec.derive_private_key(d, ec.SECP256K1())


def pub_compressed(seed: bytes) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    return _priv(seed).public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)


def pub_point(seed: bytes):
    return decompress(pub_compressed(seed))


def _sign_rs(seed: bytes, data: bytes, prehashed: bool) -> tuple:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature
    algo = Prehashed(hashes.SHA256()) if prehashed else hashes.SHA256()
    der = _priv(seed).sign(data, ec.ECDSA(algo, deterministic_signing=True))
    return decode_dss_signature(der)


def sign_cosmos(seed: bytes, msg: bytes) -> bytes:
    """r || s over SHA-256(msg), RFC 6979 nonce, s normalized to the lower half (Cosmos SDK form)."""
    r, s = _sign_rs(seed, msg, False)
    if s > N // 2:
        s = N - s
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def sign_eth(seed: bytes, digest: bytes) -> bytes:
    """r || s || v over a 32-byte digest, RFC 6979 nonce (HMAC-SHA-256), low s, v = 27 + recovery id."""
    r, s = _sign_rs(seed, digest, True)
    if s > N // 2:
        s = N - s
    want = pub_point(seed)
    recid = next(i for i in (0, 1) if recover(digest, r, s, i) == want)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([27 + recid])


def verify_cosmos(pub33: bytes, msg: bytes, sig: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    if len(sig) != 64 or decompress(pub33) is None:
        return False
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if not (1 <= r < N and 1 <= s <= N // 2):
        return False
    key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pub33)
    try:
        key.verify(encode_dss_signature(r, s), msg, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def verify_eth(address: bytes, digest: bytes, sig: bytes) -> bool:
    """s in the lower half, v in {27, 28}, recovered address equals the principal."""
    import hmac
    if len(sig) != 65 or sig[64] not in (27, 28):
        return False
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:64], "big")
    if not (1 <= r < N and 1 <= s <= N // 2):
        return False
    q = recover(digest, r, s, sig[64] - 27)
    return q is not None and hmac.compare_digest(eth_address(q), address)
