from .base58 import b58decode


def base58_address_to_hex(address: str) -> bytes:
    raw = b58decode(address)
    return raw[1:-4]
