import struct
from dataclasses import dataclass
from typing import Optional

from .op_codes import OpCode
from .script import Script
from .utils import var_int


@dataclass
class TxOut:
    value: int
    redeem_script: Script

    @property
    def signed(self) -> bool:
        if OpCode.OP_SENDER not in self.redeem_script:
            return True
        operations = list(self.redeem_script)
        sender_index = operations.index(OpCode.OP_SENDER)
        return bool(sender_index >= 3 and operations[sender_index - 1])

    @property
    def size(self):
        # value(8)
        out_len = 8
        out_len += len(self.redeem_script)
        if not self.signed:
            out_len += 141
        return out_len + len(var_int(out_len))

    def serialize(self):
        return struct.pack("<Q", self.value) + self.redeem_script.serialize()

    def without_signature(self) -> "TxOut":
        if OpCode.OP_SENDER not in self.redeem_script:
            return self
        operations = list(self.redeem_script)
        sender_index = operations.index(OpCode.OP_SENDER)
        if sender_index >= 3 and operations[sender_index - 1]:
            operations[sender_index - 1] = b""
            return TxOut(value=self.value, redeem_script=Script(operations))
        return self


@dataclass
class UTXO(TxOut):
    transaction_id: str
    output_index: int
    is_stake: bool
    block_height: Optional[int] = None
    confirmations: Optional[int] = None

    @property
    def is_p2pkh(self):
        ops = [op for op in self.redeem_script]
        if len(ops) != 5:
            return False
        return (
            ops[0] == OpCode.OP_DUP
            and ops[1] == OpCode.OP_HASH160
            and ops[3] == OpCode.OP_EQUALVERIFY
            and ops[4] == OpCode.OP_CHECKSIG
        )

    @property
    def bin_transaction_id(self) -> bytes:
        return bytes.fromhex(self.transaction_id)

    @property
    def le_bin_transaction_id(self) -> bytes:
        return self.bin_transaction_id[::-1]

    @property
    def prevout(self) -> bytes:
        return self.le_bin_transaction_id + struct.pack(
            "<I", self.output_index
        )

    def __eq__(self, other: "UTXO"):
        return (
            self.transaction_id == other.transaction_id
            and self.output_index == other.output_index
        )
