"""Strict CBOR subset for Prior v0 (RFC 8949 section 4.2.1 core deterministic).

Hand-written on purpose: general-purpose libraries are too lenient to report
the specific sentinel each malformed input must produce. Only the subset the
commitment needs is supported: unsigned and negative integers, byte strings,
text strings, arrays and maps. Floats, simple values, tags and indefinite
lengths are rejected by the decoder.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass


class CBORError(Exception):
    def __init__(self, sentinel: str, detail: str = ""):
        super().__init__(f"{sentinel}: {detail}" if detail else sentinel)
        self.sentinel = sentinel
        self.detail = detail


MAX_DEPTH = 4
MAX_PAIRS = 16


@dataclass(frozen=True)
class Raw:
    """Pre-encoded bytes spliced verbatim; used to build malformed vectors."""
    data: bytes


@dataclass(frozen=True)
class Pairs:
    """A map whose pairs are emitted in the given order, without sorting."""
    items: tuple


def head(major: int, arg: int) -> bytes:
    if arg < 0:
        raise ValueError("negative argument")
    if arg < 24:
        return bytes([(major << 5) | arg])
    if arg < 1 << 8:
        return bytes([(major << 5) | 24, arg])
    if arg < 1 << 16:
        return bytes([(major << 5) | 25]) + struct.pack(">H", arg)
    if arg < 1 << 32:
        return bytes([(major << 5) | 26]) + struct.pack(">I", arg)
    if arg < 1 << 64:
        return bytes([(major << 5) | 27]) + struct.pack(">Q", arg)
    raise ValueError("argument does not fit in 64 bits")


def encode(v) -> bytes:
    """Canonical encoding. dict keys must be unsigned ints and are sorted."""
    if isinstance(v, Raw):
        return v.data
    if isinstance(v, bool) or v is None or isinstance(v, float):
        raise TypeError(f"type not allowed in Prior CBOR: {type(v).__name__}")
    if isinstance(v, int):
        return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, (bytes, bytearray)):
        return head(2, len(v)) + bytes(v)
    if isinstance(v, str):
        b = v.encode("utf-8")
        return head(3, len(b)) + b
    if isinstance(v, list):
        return head(4, len(v)) + b"".join(encode(x) for x in v)
    if isinstance(v, Pairs):
        return head(5, len(v.items)) + b"".join(encode(k) + encode(x) for k, x in v.items)
    if isinstance(v, dict):
        for k in v:
            if not isinstance(k, int) or isinstance(k, bool) or k < 0:
                raise TypeError("map keys must be unsigned integers")
        out = head(5, len(v))
        for k in sorted(v):
            out += encode(k) + encode(v[k])
        return out
    raise TypeError(f"unsupported type {type(v).__name__}")


@dataclass
class Item:
    """Decoded item plus the exact byte span it occupied in the input."""
    major: int
    value: object  # int | bytes | str | list[Item] | list[tuple[Item, Item]]
    start: int
    end: int


class _Decoder:
    def __init__(self, data: bytes):
        self.d = data
        self.i = 0

    def _need(self, n: int):
        if self.i + n > len(self.d):
            raise CBORError("ErrMalformed", f"truncated at offset {self.i}")

    def _head(self):
        self._need(1)
        ib = self.d[self.i]
        self.i += 1
        major, ai = ib >> 5, ib & 0x1F

        if 28 <= ai <= 30:
            raise CBORError("ErrMalformed", f"reserved additional info {ai}")
        if ai == 31:
            if major in (2, 3, 4, 5):
                raise CBORError("ErrIndefiniteLength", f"major {major}")
            raise CBORError("ErrMalformed", f"additional info 31 on major {major}")
        if major == 7:
            if ai in (25, 26, 27):
                raise CBORError("ErrFloat", f"offset {self.i - 1}")
            raise CBORError("ErrSimpleValue", f"simple value ai={ai}")
        if major == 6:
            raise CBORError("ErrTag", f"offset {self.i - 1}")

        if ai < 24:
            arg = ai
        else:
            n = 1 << (ai - 24)
            self._need(n)
            arg = int.from_bytes(self.d[self.i:self.i + n], "big")
            self.i += n
            minimum = {1: 24, 2: 1 << 8, 4: 1 << 16, 8: 1 << 32}[n]
            if arg < minimum:
                raise CBORError("ErrNonMinimalInt", f"argument {arg} encoded in {n} bytes")
        return major, arg

    def item(self, depth: int) -> Item:
        start = self.i
        major, arg = self._head()
        if major in (0, 1):
            return Item(major, arg if major == 0 else -1 - arg, start, self.i)
        if major in (2, 3):
            if arg > len(self.d) - self.i:
                raise CBORError("ErrMalformed", "string length exceeds input")
            raw = self.d[self.i:self.i + arg]
            self.i += arg
            if major == 3:
                try:
                    return Item(3, raw.decode("utf-8", errors="strict"), start, self.i)
                except UnicodeDecodeError:
                    raise CBORError("ErrInvalidString", "invalid UTF-8")
            return Item(2, bytes(raw), start, self.i)

        if depth + 1 > MAX_DEPTH:
            raise CBORError("ErrNestingTooDeep", f"container at depth {depth + 1}")
        if arg > MAX_PAIRS:
            raise CBORError("ErrTooLarge", f"{arg} entries exceed {MAX_PAIRS}")
        if major == 4:
            if arg > len(self.d) - self.i:
                raise CBORError("ErrMalformed", "array length exceeds input")
            return Item(4, [self.item(depth + 1) for _ in range(arg)], start, self.i)

        if 2 * arg > len(self.d) - self.i:
            raise CBORError("ErrMalformed", "map length exceeds input")
        pairs = []
        prev = None
        for _ in range(arg):
            k = self.item(depth + 1)
            if k.major != 0:
                raise CBORError("ErrKeyType", f"map key of major type {k.major}")
            if prev is not None:
                if k.value == prev:
                    raise CBORError("ErrDuplicateKey", f"key {k.value}")
                if k.value < prev:
                    raise CBORError("ErrUnsortedMap", f"key {k.value} after {prev}")
            prev = k.value
            v = self.item(depth + 1)
            pairs.append((k, v))
        return Item(5, pairs, start, self.i)


def decode_strict(data: bytes) -> Item:
    """Generic well-formedness pass. Raises CBORError with the sentinel name."""
    dec = _Decoder(data)
    it = dec.item(0)
    if dec.i != len(data):
        raise CBORError("ErrTrailingData", f"{len(data) - dec.i} bytes after top-level item")
    return it


def to_plain(it: Item):
    """Converts an Item tree into plain Python values (dict, list, int, ...)."""
    if it.major == 5:
        return {k.value: to_plain(v) for k, v in it.value}
    if it.major == 4:
        return [to_plain(x) for x in it.value]
    return it.value
