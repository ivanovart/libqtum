import hashlib
import string
import struct
from typing import Union


def hash256(payload: bytes) -> bytes:
    hash1 = hashlib.sha256(payload)
    hash2 = hashlib.sha256(hash1.digest())
    return hash2.digest()


def hash160(data: bytes) -> bytes:
    """Return ripemd160(sha256(data))"""
    rh = hashlib.new("ripemd160", hashlib.sha256(data).digest())
    return rh.digest()


def var_int(x: int) -> bytes:
    if x < 0xFD:
        return bytes([x])
    if x < 0xFFFF:
        return b"\xfd" + struct.pack("<H", x)
    if x < 0xFFFF_FFFF:
        return b"\xfe" + struct.pack("<I", x)
    return b"\xff" + struct.pack("<Q", x)


def is_hex_string(s: Union[str, bytes]) -> bool:
    if isinstance(s, bytes):
        return all(chr(c) in string.hexdigits for c in s)
    return all(c in string.hexdigits for c in s)


__all__ = ["hash160", "hash256", "var_int", "is_hex_string"]
