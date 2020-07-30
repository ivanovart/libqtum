from dataclasses import dataclass
from enum import Flag, auto
from functools import wraps
from typing import List, Optional

from libqtum.script import Script
from libqtum.sighash import SigHashType
from libqtum.tx import UTXO
from libqtum.utils import hash160, var_int


@dataclass
class PartialSignature:
    pubkey: bytes
    signature: bytes

    @property
    def hex_address(self):
        return hash160(self.pubkey)


@dataclass
class PsbtIn:
    utxo: UTXO
    partial_signature: List[PartialSignature]
    sighash_type: Optional[SigHashType]
    sequence: int = 0
    redeem_script: Script = Script()
    # witness_script: Optional[Script] = None

    @property
    def size(self):
        # UTXO ref (36) + seq(4)
        inp_len = 40
        if self.redeem_script:
            inp_len += len(self.redeem_script)
        elif self.utxo.is_p2pkh:
            inp_len += 106
        elif self.partial_signature:
            inp_len += len(self.partial_signature) * 106
        else:
            # If no estimation -> count redeem script 🤷‍
            inp_len += len(self.utxo.redeem_script)
        return inp_len + len(var_int(inp_len))


class PsbtLock(Flag):
    UNLOCKED = 0
    INPUT_LOCK = auto()
    INPUT_SEQ_LOCK = auto()
    OUTPUT_LOCK = auto()


class PsbtException(Exception):
    pass


class PsbtSignException(PsbtException):
    pass


class PsbtLockedException(PsbtException):
    pass


def with_lock(lock: PsbtLock):
    def deco(f):
        @wraps(f)
        def _wrapper(self: "Psbt", *args, **kwargs):
            if self._lock & lock:
                raise PsbtLockedException(
                    f"can't proceed, PSBT is locked w/ {repr(self._lock)}"
                )
            return f(self, *args, **kwargs)

        return _wrapper

    return deco
