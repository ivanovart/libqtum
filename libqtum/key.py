import hashlib
import struct
from collections import namedtuple
from typing import Optional, Type, Union, cast

from ecdsa.curves import SECP256k1
from ecdsa.ellipticcurve import Point as _ECDSA_Point
from ecdsa.keys import SigningKey, VerifyingKey
from ecdsa.numbertheory import square_root_mod_prime
from ecdsa.util import sigencode_der_canonize

from . import base58
from .network import Network, QtumTestNet
from .sighash import SigHashType
from .utils import hash160, hash256, is_hex_string

PublicPair = namedtuple("PublicPair", ["x", "y"])


class Key:
    def __init__(self, network: Type[Network], compressed: bool = False):
        """Construct a Key."""
        # Set network first because set_key needs it
        self.network = network
        self.compressed = compressed

    def __eq__(self, other):
        return (
            other
            and self.network == other.network
            and isinstance(other, self.__class__)
        )

    def __ne__(self, other):
        return not self == other


class PrivateKey(Key):
    def __init__(
        self,
        secret_exponent: int,
        network: Type[Network] = QtumTestNet,
        **kwargs,
    ):
        if not isinstance(secret_exponent, int):
            raise ValueError("secret_exponent must be an int")
        super().__init__(network, **kwargs)
        self._private_key = SigningKey.from_secret_exponent(
            secret_exponent, curve=SECP256k1, hashfunc=hashlib.sha256
        )

    def get_key(self) -> bytes:
        """Get the key - a hex formatted private exponent for the curve."""
        return cast(bytes, self.ecdsa_key.to_string())

    def _get_public_key(self) -> "PublicKey":
        """Get the PublicKey for this PrivateKey."""
        return PublicKey.from_verifying_key(
            self.ecdsa_key.get_verifying_key(),
            network=self.network,
            compressed=self.compressed,
        )

    @property
    def public_key(self) -> "PublicKey":
        return cast(PublicKey, self._get_public_key())

    @property
    def ecdsa_key(self) -> SigningKey:
        return self._private_key

    def get_extended_key(self) -> bytes:
        """Get the extended key.
        Extended keys contain the network bytes and the public or private
        key.
        """
        network_hex_chars = self.network.SECRET_KEY.to_bytes(1, "big")
        return network_hex_chars + self.get_key()

    def export_to_wif(self, compressed: Optional[bool] = None) -> str:
        """Export a key to WIF.
        :param compressed: False if you want a standard WIF export (the most
            standard option). True if you want the compressed form (Note that
            not all clients will accept this form). Defaults to None, which
            in turn uses the self.compressed attribute.
        :type compressed: bool
        See https://en.bitcoin.it/wiki/Wallet_import_format for a full
        description.
        """
        # Add the network byte, creating the "extended key"
        extended_key = self.get_extended_key()
        if compressed is None:
            compressed = self.compressed
        if compressed:
            extended_key += b"\01"
        checksum = hash256(extended_key)
        return base58.b58encode(extended_key + checksum[:4]).decode("utf-8")

    @classmethod
    def from_wif(
        cls, wif: str, network: Type[Network] = QtumTestNet
    ) -> "PrivateKey":
        wif_encoded = base58.b58decode(wif)
        key_full = wif_encoded
        network_byte = key_full[:1]
        key = key_full[1:-4]
        if network_byte != network.SECRET_KEY.to_bytes(1, "big"):
            raise incompatible_network_exception_factory(
                network_name=network.NAME,
                expected_prefix=network.SECRET_KEY,
                given_prefix=int.from_bytes(network_byte, "big"),
            )

        checksum = hash256(network_byte + key)[:4]
        key_checksum = key_full[-4:]
        if checksum != key_checksum:
            raise ValueError("Invalid checksum")

        compressed = False
        if key[-1] == 1:
            compressed = True
            key = key[:-1]

        new_key = cls(
            int.from_bytes(key, "big"), network=network, compressed=compressed
        )
        return new_key

    @classmethod
    def from_hex_key(
        cls, key: Union[str, bytes], network: Type[Network] = QtumTestNet
    ) -> "PrivateKey":
        if isinstance(key, bytes):
            if len(key) == 32:
                return cls(int.from_bytes(key, "big"), network)
            if not is_hex_string(key) or len(key) != 64:
                raise ValueError("Invalid hex key")
            return cls(int(key, 16), network)

        if not is_hex_string(key) or len(key) != 64:
            raise ValueError("Invalid hex key")
        return cls(int(key, 16), network)

    @classmethod
    def from_master_password(
        cls, password: Union[bytes, str], network: Type[Network] = QtumTestNet
    ):
        """Generate a new key from a master password.
        This password is hashed via a single round of sha256 and is highly
        breakable, but it's the standard brain wallet approach.
        See `PrivateKey.from_master_password_slow` for a slightly more
        secure generation method (which will still be subject to a rainbow
        table attack
        """
        if not isinstance(password, bytes):
            password = password.encode("utf-8")
        key = hashlib.sha256(password).hexdigest()
        return cls.from_hex_key(key, network)

    def sign(self, data: bytes) -> bytes:
        return self.ecdsa_key.sign_deterministic(
            data, sigencode=sigencode_der_canonize
        )

    def sign_tx(self, tx_data: bytes, sighash_type: Union[int, SigHashType]):
        # Encode the hash type as a 4-byte hex value.
        sighash = struct.pack("<I", sighash_type)
        payload = hashlib.sha256(tx_data + sighash).digest()
        signed = self.sign(payload)
        return signed + struct.pack("B", sighash_type & 0xFF)

    def __eq__(self, other):
        return (
            super(PrivateKey, self).__eq__(other)
            and self.ecdsa_key.curve == other.ecdsa_key.curve
            and (self.ecdsa_key.to_string() == other.ecdsa_key.to_string())
            and (
                self.ecdsa_key.privkey.secret_multiplier
                == other.ecdsa_key.privkey.secret_multiplier
            )
            and self.public_key == other.public_key
        )

    def __sub__(self, other):
        if not isinstance(other, self.__class__):
            raise ValueError(
                f"can't subtract {type(other)} from {self.__class__}"
            )
        if self.network == other.network:
            raise ValueError("trying to subtract keys from different networks")
        k1 = self._private_key.privkey.secret_multiplier
        k2 = other._private_key.privkey.secret_multiplier
        result = (k1 - k2) % SECP256k1.order
        return self.__class__(result, network=self.network)

    __hash__ = object.__hash__


class PublicKey(Key):
    def __init__(
        self,
        verifying_key: VerifyingKey,
        network: Type[Network] = QtumTestNet,
        **kwargs,
    ):
        """Create a public key.
        :param verifying_key: The ECDSA VerifyingKey corresponding to this
            public key.
        :param network: The network you want (Networks just define certain
            constants, like byte-prefixes on public addresses).
        """
        super().__init__(network, **kwargs)
        self._verifying_key = verifying_key
        self.x = verifying_key.pubkey.point.x()
        self.y = verifying_key.pubkey.point.y()

    def get_key(self, compressed: bool = None) -> bytes:
        """Get the hex-encoded key.
        :param compressed: False if you want a standard 65 Byte key (the most
            standard option). True if you want the compressed 33 Byte form.
            Defaults to None, which in turn uses the self.compressed attribute.
        PublicKeys consist of an ID byte, the x, and the y coordinates
        on the elliptic curve.
        In the case of uncompressed keys, the ID byte is 04.
        Compressed keys use the SEC1 format:
            If Y is odd: id_byte = 03
            else: id_byte = 02
        Note that I pieced this algorithm together from the pycoin source.
        This is documented in http://www.secg.org/collateral/sec1_final.pdf
        but, honestly, it's pretty confusing.
        I guess this is a pretty big warning that I'm not *positive* this
        will do the right thing in all cases. The tests pass, and this does
        exactly what pycoin does, but I'm not positive pycoin works either!
        """
        if compressed is None:
            compressed = self.compressed
        if compressed:
            parity = 2 + (self.y & 1)  # 0x02 even, 0x03 odd
            return bytes([parity]) + int(self.x).to_bytes(32, "big")

        return (
            b"\x04"
            + int(self.x).to_bytes(32, "big")
            + int(self.y).to_bytes(32, "big")
        )

    @classmethod
    def from_hex_key(
        cls, key: Union[str, bytes], network: Type[Network] = QtumTestNet
    ) -> "PublicKey":
        """Load the PublicKey from a compressed or uncompressed hex key.
        This format is defined in PublicKey.get_key()
        """
        if len(key) == 130 or len(key) == 66:
            # It might be a hexlified bytes / string
            if isinstance(key, bytes):
                if not is_hex_string(key):
                    raise ValueError("Invalid hex key")
                key = bytes.fromhex(key.decode())
            else:
                if not is_hex_string(key):
                    raise ValueError("Invalid hex key")
                key = bytes.fromhex(key)
        key = cast(bytes, key)
        compressed = False
        id_byte = key[0]
        if id_byte == 4:
            # Uncompressed public point
            # 1B ID + 32B x coord + 32B y coord = 65 B
            if len(key) != 65:
                raise KeyParseError("Invalid key length")
            public_pair = PublicPair(
                int.from_bytes(key[1:33], "big"),
                int.from_bytes(key[33:], "big"),
            )
        elif id_byte in [2, 3]:
            # Compressed public point!
            compressed = True
            if len(key) != 33:
                raise KeyParseError("Invalid key length")
            y_odd = bool(id_byte & 0x01)  # 0 even, 1 odd
            x = int.from_bytes(key[1:], "big")
            # The following x-to-pair algorithm was lifted from pycoin
            # I still need to sit down an understand it. It is also described
            # in http://www.secg.org/collateral/sec1_final.pdf
            curve = SECP256k1.curve
            p = curve.p()
            # For SECP256k1, curve.a() is 0 and curve.b() is 7, so this is
            # effectively (x ** 3 + 7) % p, but the full equation is kept
            # for just-in-case-the-curve-is-broken future-proofing
            alpha = (pow(x, 3, p) + curve.a() * x + curve.b()) % p
            beta = square_root_mod_prime(alpha, p)
            y_even = not y_odd
            if y_even == bool(beta & 1):
                public_pair = PublicPair(x, p - beta)
            else:
                public_pair = PublicPair(x, beta)
        else:
            raise KeyParseError("The given key is not in a known format.")
        return cls.from_public_pair(
            public_pair, network=network, compressed=compressed
        )

    @staticmethod
    def create_point(x: int, y: int) -> _ECDSA_Point:
        """Create an ECDSA point on the SECP256k1 curve with the given coords.
        :param x: The x coordinate on the curve
        :param y: The y coordinate on the curve
        """
        if not isinstance(x, int) or not isinstance(y, int):
            raise ValueError("The coordinates must be ints.")
        return _ECDSA_Point(SECP256k1.curve, x, y)

    def to_point(self):
        return self._verifying_key.pubkey.point

    @classmethod
    def from_point(cls, point: _ECDSA_Point, **kwargs) -> "PublicKey":
        """Create a PublicKey from a point on the SECP256k1 curve.
        :param point: A point on the SECP256k1 curve.
        :type point: SECP256k1.point
        """
        verifying_key = VerifyingKey.from_public_point(point, curve=SECP256k1)
        return cls.from_verifying_key(verifying_key, **kwargs)

    @classmethod
    def from_verifying_key(
        cls, verifying_key: VerifyingKey, **kwargs
    ) -> "PublicKey":
        return cls(verifying_key, **kwargs)

    def to_address(self, compressed: Optional[bool] = None) -> str:
        """Create a public address from this key.
        :param compressed: False if you want a normal uncompressed address
            (the most standard option). True if you want the compressed form.
            Note that most clients will not accept compressed addresses.
            Defaults to None, which in turn uses the self.compressed attribute.
        https://en.bitcoin.it/wiki/Technical_background_of_Bitcoin_addresses
        """
        key = self.get_key(compressed)
        # First get the hash160 of the key
        hash160_bytes = hash160(key)
        # Prepend the network address byte
        network_hash160_bytes = (
            self.network.PUBKEY_ADDRESS.to_bytes(1, "big") + hash160_bytes
        )
        # Return a base58 encoded address with a checksum
        checksum = hash256(network_hash160_bytes)
        return base58.b58encode(network_hash160_bytes + checksum[:4]).decode(
            "utf-8"
        )

    def to_public_pair(self):
        return PublicPair(self.x, self.y)

    @classmethod
    def from_public_pair(cls, pair: PublicPair, **kwargs) -> "PublicKey":
        point = _ECDSA_Point(SECP256k1.curve, pair.x, pair.y)
        return cls.from_point(point, **kwargs)

    def __eq__(self, other):
        return (
            super(PublicKey, self).__eq__(other)
            and self.x == other.x
            and self.y == other.y
        )

    __hash__ = object.__hash__


class KeyParseError(Exception):
    pass


def incompatible_network_exception_factory(
    network_name: str, expected_prefix: int, given_prefix: int
):
    return IncompatibleNetworkException(
        "Incorrect network. {net_name} expects a byte prefix of "
        "{expected_prefix}, but you supplied {given_prefix}".format(
            net_name=network_name,
            expected_prefix=expected_prefix,
            given_prefix=given_prefix,
        )
    )


class ChecksumException(Exception):
    pass


class IncompatibleNetworkException(Exception):
    pass


class InvalidChildException(Exception):
    pass
