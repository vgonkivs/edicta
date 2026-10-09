"""Payload blob and payload plaintext rules (spec/decision-commitment-v1.md, v1.0).

Python side of the cross-language check for the published payload. Like
edicta.py it must not be ported from, or to, the Go implementation.

Sentinel names carry the Go package that owns them: blob.ErrX, payload.ErrX
and sdk.ErrX. Context media types (for example the DCA context of the
dca-agent profile) are not core rules; see profile_dca_agent.py.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

import hpke_base as hpke
from cbor_strict import CBORError, decode_strict, encode
from edicta import (ACTION_SALT_SIZE, MAX_ACTION_SIZE, MAX_ACTION_TYPE_SIZE, MAX_PAYLOAD_SIZE, MIN_ACTION_TYPE_SIZE,
                    PRINTABLE, Reject, _schema_decode, action_hash, tagged, to_cbor)
from edicta import media_type_ok as _media_ok

TAG_PAYLOAD_AEAD = b"edicta/v1/payload"
TAG_PAYLOAD_DEK = b"edicta/v1/payload-dek"

BLOB_VERSION = 1
MIN_RECIPIENTS = 1
MAX_RECIPIENTS = 16
MAX_KID_SIZE = 32
ENC_SIZE = 32
DEK_SIZE = 32
WRAPPED_DEK_SIZE = DEK_SIZE + 16
NONCE_SIZE = 12
SALT_SIZE = 32
TAG_SIZE = 16
MIN_CIPHERTEXT_SIZE = SALT_SIZE + 1 + TAG_SIZE
MAX_DECODE_SIZE = MAX_PAYLOAD_SIZE
MAX_SEAL_SIZE = MAX_PAYLOAD_SIZE - 5

PAYLOAD_VERSION = 1
MEDIA_TYPE_MAX = 64
MEDIA_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789!#$&^_.+-/")


def hpke_info() -> bytes:
    return tagged(TAG_PAYLOAD_DEK)


def hpke_aad(kid: bytes) -> bytes:
    if not 1 <= len(kid) <= MAX_KID_SIZE:
        raise ValueError("kid length out of range")
    return bytes([len(kid)]) + kid


def payload_aad() -> bytes:
    return tagged(TAG_PAYLOAD_AEAD)


def media_type_ok(s: str) -> bool:
    return _media_ok(s, 1, MEDIA_TYPE_MAX)


# ---------------------------------------------------------------- blob layout

@dataclass
class Entry:
    kid: bytes
    enc: bytes
    wrapped_dek: bytes


@dataclass
class Blob:
    version: int
    recipients: list
    aead_nonce: bytes
    ciphertext: bytes


def blob_encode(b: Blob) -> bytes:
    return encode({
        1: b.version,
        2: [{1: e.kid, 2: e.enc, 3: e.wrapped_dek} for e in b.recipients],
        3: b.aead_nonce,
        4: b.ciphertext,
    })


class _Seq:
    """Sequential reader for the fixed blob layout. Every structural defect is blob.ErrMalformed."""

    def __init__(self, d: bytes):
        self.d = d
        self.i = 0

    def fail(self, detail: str):
        raise Reject("blob.ErrMalformed", f"offset {self.i}: {detail}")

    def head(self) -> tuple[int, int]:
        if self.i >= len(self.d):
            self.fail("truncated")
        ib = self.d[self.i]
        self.i += 1
        major, ai = ib >> 5, ib & 0x1F
        if ai >= 28:
            self.fail(f"additional info {ai}")
        if major in (6, 7):
            self.fail(f"major type {major}")
        if ai < 24:
            return major, ai
        n = 1 << (ai - 24)
        if self.i + n > len(self.d):
            self.fail("truncated head")
        arg = int.from_bytes(self.d[self.i:self.i + n], "big")
        self.i += n
        if arg < {1: 24, 2: 1 << 8, 4: 1 << 16, 8: 1 << 32}[n]:
            self.fail("non-minimal head")
        return major, arg

    def expect(self, major: int, arg: int, what: str):
        m, a = self.head()
        if (m, a) != (major, arg):
            self.fail(f"{what}: got major {m} argument {a}")

    def bstr(self, lo: int, hi: int, what: str) -> bytes:
        m, n = self.head()
        if m != 2:
            self.fail(f"{what}: major {m}, want byte string")
        if n > len(self.d) - self.i:
            self.fail(f"{what}: length exceeds input")
        if not lo <= n <= hi:
            self.fail(f"{what}: {n} bytes")
        v = self.d[self.i:self.i + n]
        self.i += n
        return bytes(v)


def blob_decode(raw: bytes) -> Blob:
    """Strict blob decoding; the first failing check in byte order decides the sentinel."""
    if len(raw) > MAX_DECODE_SIZE:
        raise Reject("blob.ErrTooLarge", f"{len(raw)} bytes")
    r = _Seq(raw)
    r.expect(5, 4, "top-level map of 4 pairs")
    r.expect(0, 1, "key 1")
    m, version = r.head()
    if m != 0:
        r.fail("version is not a uint")
    if version != BLOB_VERSION:
        raise Reject("blob.ErrVersion", f"version {version}")
    r.expect(0, 2, "key 2")
    m, n = r.head()
    if m != 4:
        r.fail("recipients is not an array")
    if not MIN_RECIPIENTS <= n <= MAX_RECIPIENTS:
        raise Reject("blob.ErrRecipients", f"{n} recipients")
    entries = []
    seen = set()
    for _ in range(n):
        r.expect(5, 3, "recipient map of 3 pairs")
        r.expect(0, 1, "recipient key 1")
        kid = r.bstr(1, MAX_KID_SIZE, "kid")
        if kid in seen:
            raise Reject("blob.ErrDuplicateKID", kid.hex())
        seen.add(kid)
        r.expect(0, 2, "recipient key 2")
        enc = r.bstr(ENC_SIZE, ENC_SIZE, "enc")
        r.expect(0, 3, "recipient key 3")
        wrapped = r.bstr(WRAPPED_DEK_SIZE, WRAPPED_DEK_SIZE, "wrapped_dek")
        entries.append(Entry(kid, enc, wrapped))
    r.expect(0, 3, "key 3")
    nonce = r.bstr(NONCE_SIZE, NONCE_SIZE, "aead_nonce")
    r.expect(0, 4, "key 4")
    ct = r.bstr(MIN_CIPHERTEXT_SIZE, MAX_DECODE_SIZE, "ciphertext")
    if r.i != len(raw):
        r.fail(f"{len(raw) - r.i} trailing bytes")
    b = Blob(version, entries, nonce, ct)
    if blob_encode(b) != raw:
        raise Reject("blob.ErrMalformed", "re-encoding differs")
    return b


# ---------------------------------------------------------------- seal and open

@dataclass
class Recipient:
    kid: bytes
    pk: bytes
    sk_e: bytes  # ephemeral private key; fixed only in test vectors


def seal(salt: bytes, plaintext: bytes, recipients: list, dek: bytes, aead_nonce: bytes,
         info: bytes | None = None, aad_of=None, aead_aad: bytes | None = None,
         check: bool = True) -> tuple[bytes, list]:
    """Seals salt || plaintext. info, aad_of and aead_aad override the normative values (reject vectors only).
    Returns (blob bytes, per-recipient trace)."""
    if check:
        if len(salt) != SALT_SIZE or len(dek) != DEK_SIZE or len(aead_nonce) != NONCE_SIZE:
            raise ValueError("bad salt, DEK or nonce size")
        if not MIN_RECIPIENTS <= len(recipients) <= MAX_RECIPIENTS:
            raise Reject("blob.ErrRecipients", f"{len(recipients)} recipients")
        if len({r.kid for r in recipients}) != len(recipients):
            raise Reject("blob.ErrDuplicateKID", "")
    info = hpke_info() if info is None else info
    aad_of = hpke_aad if aad_of is None else aad_of
    aead_aad = payload_aad() if aead_aad is None else aead_aad
    entries, trace = [], []
    for r in recipients:
        enc, ctx = hpke.setup_base_s(r.pk, info, r.sk_e)
        wrapped = ctx.seal(aad_of(r.kid), dek)
        entries.append(Entry(r.kid, enc, wrapped))
        trace.append({"enc": enc, "shared_secret": ctx.trace["shared_secret"], "key": ctx.key,
                      "base_nonce": ctx.base_nonce, "wrapped_dek": wrapped})
    ct = ChaCha20Poly1305(dek).encrypt(aead_nonce, salt + plaintext, aead_aad)
    raw = blob_encode(Blob(BLOB_VERSION, entries, aead_nonce, ct))
    if check and len(raw) > MAX_SEAL_SIZE:
        raise Reject("payload.ErrTooLarge", f"{len(raw)} bytes")
    return raw, trace


def open_blob(raw: bytes, sk_r: bytes, kid: bytes | None = None) -> bytes:
    """Decode, select an entry, unwrap the DEK and decrypt. Returns the AEAD plaintext (salt || plaintext).

    With kid given, only the entry with that kid is tried. Without, entries are tried in blob order
    and the first one that unwraps is used; its DEK is final."""
    b = blob_decode(raw)
    if kid is not None:
        candidates = [e for e in b.recipients if e.kid == kid]
        if not candidates:
            raise Reject("blob.ErrNoRecipient", kid.hex())
    else:
        candidates = b.recipients
    dek = None
    for e in candidates:
        try:
            ctx = hpke.setup_base_r(e.enc, sk_r, hpke_info())
            dek = ctx.open(hpke_aad(e.kid), e.wrapped_dek)
            break
        except hpke.HPKEError:
            continue
    if dek is None or len(dek) != DEK_SIZE:
        raise Reject("blob.ErrUnwrap", "no entry unwraps under this key")
    try:
        return ChaCha20Poly1305(dek).decrypt(b.aead_nonce, b.ciphertext, payload_aad())
    except InvalidTag:
        raise Reject("blob.ErrDecrypt", "")


def payload_matches_action(p: dict, action_type: str, committed_hash: bytes) -> bool:
    """The payload carries the committed action: same type bytes, and its data with its salt hashes to
    action.hash."""
    a = p["action"]
    return a["type"] == action_type and hmac.compare_digest(action_hash(a["type"], a["action_salt"], a["data"]),
                                                            committed_hash)


def open_payload(raw: bytes, sk_r: bytes, kid: bytes | None, plaintext_hash: bytes,
                 action_type: str, committed_action_hash: bytes) -> dict:
    """Blob steps of the opening procedure, given the commitment's plaintext_hash, action.type and action.hash."""
    aead_pt = open_blob(raw, sk_r, kid)
    if hashlib.sha256(aead_pt).digest() != plaintext_hash:
        raise Reject("sdk.ErrPlaintextHashMismatch", "")
    return o8(aead_pt, action_type, committed_action_hash)


def o8(aead_plaintext: bytes, action_type: str, committed_hash: bytes) -> dict:
    """PV2, PV3 and O8 on the AEAD plaintext that passed O7."""
    p = payload_decode(aead_plaintext[SALT_SIZE:])
    if p["action"]["type"] != action_type:
        raise Reject("sdk.ErrPayloadMismatch", "action type")
    if not payload_matches_action(p, action_type, committed_hash):
        raise Reject("sdk.ErrPayloadMismatch", "action hash")
    return p


# ---------------------------------------------------------------- payload plaintext

ANY_BYTES = (0, MAX_PAYLOAD_SIZE)

MODEL = {
    1: ("id", "tstr", True, (1, 128, PRINTABLE)),
    2: ("version", "tstr", False, (1, 64, PRINTABLE)),
    3: ("digest", "bstr", False, (32, 32)),
}

POLICY = {
    1: ("id", "tstr", True, (1, 128, PRINTABLE)),
    2: ("version", "tstr", False, (1, 64, PRINTABLE)),
    3: ("digest", "bstr", False, (32, 32)),
    4: ("text", "bstr", False, (1, MAX_PAYLOAD_SIZE)),
}

CONTEXT = {
    1: ("media_type", "tstr", True, (1, MEDIA_TYPE_MAX, MEDIA_CHARS)),
    2: ("data", "bstr", True, ANY_BYTES),
}

METADATA = {
    1: ("media_type", "tstr", True, (1, MEDIA_TYPE_MAX, MEDIA_CHARS)),
    2: ("data", "bstr", True, (1, MAX_PAYLOAD_SIZE)),
}

# Keys 1 and 2 are unassigned: a present one is malformed.
PAYLOAD_ACTION = {
    3: ("type", "media", True, (MIN_ACTION_TYPE_SIZE, MAX_ACTION_TYPE_SIZE)),
    4: ("data", "bstr", True, (1, MAX_ACTION_SIZE)),
    5: ("action_salt", "bstr", True, (ACTION_SALT_SIZE, ACTION_SALT_SIZE)),
}

# Key 6 is unassigned: a present one is malformed.
PAYLOAD = {
    1: ("version", "uint", True, None),
    2: ("model", MODEL, True, None),
    3: ("policy", POLICY, True, None),
    4: ("context", CONTEXT, True, None),
    5: ("action", PAYLOAD_ACTION, True, None),
    7: ("metadata", METADATA, False, None),
}


def payload_encode(p: dict) -> bytes:
    return encode(to_cbor(p, PAYLOAD))


def payload_decode(b: bytes) -> dict:
    """Strict decoding of the payload plaintext. Structural failures are payload.ErrMalformed."""
    try:
        it = decode_strict(b)
        p = _schema_decode(it, PAYLOAD, "payload")
    except (CBORError, Reject) as e:
        raise Reject("payload.ErrMalformed", str(e))
    for k in ("context", "metadata"):
        if k in p and not media_type_ok(p[k]["media_type"]):
            raise Reject("payload.ErrMalformed", f"{k}.media_type {p[k]['media_type']!r}")
    if payload_encode(p) != b:
        raise Reject("payload.ErrMalformed", "re-encoding differs")
    if p["version"] != PAYLOAD_VERSION:
        raise Reject("payload.ErrVersion", f"version {p['version']}")
    return p
