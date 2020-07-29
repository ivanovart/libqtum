from enum import IntFlag
from typing import TypeVar


class SigHash(IntFlag):
    """Sighash constants"""
    @property
    def sig_mod(self):
        return self & 0x1f

    ALL = 0x01
    NONE = 0x02
    SINGLE = 0x03
    ANYONECANPAY = 0x80


SigHashType = TypeVar('SigHashType', bound=SigHash)
__all__ = ['SigHashType', 'SigHash']
