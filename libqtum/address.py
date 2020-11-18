from .base58 import b58decode, b58encode
from .network import Network
from .utils import hash256


def base58_address_to_hex(address: str) -> bytes:
    raw = b58decode(address)
    return raw[1:-4]


def hex_address_to_base58(address: bytes, network: Network) -> str:
    # Prepend the network address byte
    network_hash160_bytes = network.PUBKEY_ADDRESS.to_bytes(1, "big") + address
    # Return a base58 encoded address with a checksum
    checksum = hash256(network_hash160_bytes)
    return b58encode(network_hash160_bytes + checksum[:4]).decode("utf-8")


def base58_address_validate(address: str, network: Network) -> bool:
    raw = b58decode(address)
    return network.PUBKEY_ADDRESS.to_bytes(1, "big") == raw[:1] and (
        hash256(network.PUBKEY_ADDRESS.to_bytes(1, "big") + raw[1:-4])[:4]
        == raw[-4:]
    )
