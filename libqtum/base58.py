from functools import wraps
from typing import Callable, TypeVar, Union

__b58chars = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
__b58base = len(__b58chars)

bytes_types = (bytes, bytearray)  # Types acceptable as binary data
BytesTypes = Union[bytes, bytearray]
ConvertableBytesTypes = Union[str, bytes, bytearray, memoryview]
T = TypeVar("T")


def _bytes_from_decode_data(s: ConvertableBytesTypes) -> BytesTypes:
    if isinstance(s, str):
        try:
            return s.encode("ascii")
        except UnicodeEncodeError:
            raise ValueError("string argument should contain only ASCII characters")
    if isinstance(s, bytes_types):
        return s
    try:
        return memoryview(s).tobytes()
    except TypeError:
        raise TypeError(
            "argument should be a bytes-like object or ASCII "
            "string, not %r" % s.__class__.__name__
        ) from None


def arg_to_bytes(f: Callable[[BytesTypes], T]) -> Callable[[ConvertableBytesTypes], T]:
    @wraps(f)
    def decorator(arg):
        return f(_bytes_from_decode_data(arg))

    return decorator


def b58encode_int(i: int) -> bytes:
    """
    Encode an integer using Base58
    """
    string = b""
    while i:
        i, idx = divmod(i, __b58base)
        string = __b58chars[idx : idx + 1] + string
    return string


@arg_to_bytes
def b58decode_int(v: BytesTypes) -> int:
    """
    Decode a Base58 encoded string as an integer
    """
    v = v.rstrip()

    decimal = 0
    for char in v:
        decimal = decimal * __b58base + __b58chars.index(char)
    return decimal


@arg_to_bytes
def b58encode(v: BytesTypes) -> bytes:
    """
    Encode a string using Base58
    """
    n_pad = len(v)
    v = v.lstrip(b"\0")
    n_pad -= len(v)

    p, acc = 1, 0
    for c in reversed(v):
        acc += p * c
        p = p << 8
    result = b58encode_int(acc)
    return __b58chars[0:1] * n_pad + result


@arg_to_bytes
def b58decode(v: BytesTypes) -> bytes:
    """
    Decode a Base58 encoded string
    """
    v = v.rstrip()

    n_pad = len(v)
    v = v.lstrip(__b58chars[0:1])
    n_pad -= len(v)

    acc = b58decode_int(v)

    result = []
    while acc > 0:
        acc, mod = divmod(acc, 256)
        result.append(mod)

    return b"\0" * n_pad + bytes(reversed(result))
