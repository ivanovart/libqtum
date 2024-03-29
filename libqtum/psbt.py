import copy
import struct
from typing import List, Optional, Union

from libqtum import PrivateKey
from libqtum.op_codes import OpCode
from libqtum.psbt_utils import (
    PartialSignature,
    PsbtException,
    PsbtIn,
    PsbtLock,
    PsbtSignException,
    with_lock,
)
from libqtum.script import Script
from libqtum.sighash import SigHash, SigHashType
from libqtum.tx import TxOut, UTXO
from libqtum.utils import hash160, hash256, var_int


class Psbt:
    """Partially Signed Bitcoin Transaction"""

    def __init__(self, options: Optional[dict] = None):
        if options is None:
            options = {}
        self.options = {
            "max_fee_rate": 0.05,
            "fee_rate": 0.004,
            "gas_price": 40,
            "gas_limit": 2500000,
        }.update(options)

        self._version = 2
        self._lock_time = 0
        self._inputs: List[PsbtIn] = []
        self._outputs: List[TxOut] = []
        self._lock: PsbtLock = PsbtLock.UNLOCKED

    @property
    def version(self):
        return self._version

    @version.setter
    def version(self, v: int):
        if not 0 < v < 0xFFFF_FFFF:
            raise ValueError("version should be in range: 0 < v < 0xFFFF_FFFF")
        self._version = v

    @property
    def lock_time(self):
        return self._lock_time

    @lock_time.setter
    def lock_time(self, lt: int):
        if not 0 < lt < 0xFFFF_FFFF:
            raise ValueError(
                "lock time should be in range: 0 < v < 0xFFFF_FFFF"
            )
        self._lock_time = lt

    @property
    def inputs_num(self):
        return len(self._inputs)

    @property
    def outputs_num(self):
        return len(self._outputs)

    @property
    def in_val(self):
        return sum(inp.utxo.value for inp in self._inputs)

    @property
    def estimated_size(self) -> int:
        # version(4) + inputs_num(1 - 9) + outputs_num(1 - 9) + lock_time(4)
        size = (
            8 + len(var_int(self.inputs_num)) + len(var_int(self.outputs_num))
        )
        for inp in self._inputs:
            size += inp.size

        for out in self._outputs:
            size += out.size

        return size

    @property
    def out_val(self):
        reg_out = sum(out.value for out in self._outputs)
        call_outs = filter(
            lambda out: OpCode.OP_CALL in out.redeem_script, self._outputs
        )
        gas_out = 0
        for out in call_outs:
            ops = list(out.redeem_script)
            call_index = ops.index(OpCode.OP_CALL)
            if call_index < 5:
                continue
            gas_out += int.from_bytes(
                ops[call_index - 4], "little"
            ) * int.from_bytes(ops[call_index - 3], "little")
        return reg_out + gas_out

    @property
    def fee(self):
        return self.in_val - self.out_val

    @with_lock(PsbtLock.INPUT_LOCK)
    def add_input(
        self, utxo: Union[UTXO], sighash_type: Optional[SigHashType] = None
    ) -> "Psbt":
        if utxo in [p.utxo for p in self._inputs]:
            raise Exception("UTXO already added")
        self._inputs.append(
            PsbtIn(utxo=utxo, partial_signature=[], sighash_type=sighash_type,)
        )
        return self

    @with_lock(PsbtLock.OUTPUT_LOCK)
    def add_output(self, out: TxOut) -> "Psbt":
        if out.value < 0:
            raise ValueError("out.value should be >= 0")
        self._outputs.append(out)
        return self

    def serialize(self, include_witness: bool = True) -> bytes:
        """ WARNING: NO SEGWIT SO FAR! """
        le_unsigned_int = struct.Struct("<I")
        tx = b""
        tx += le_unsigned_int.pack(self.version)  # Version
        # @TODO: segwit flag here
        # Inputs
        tx += var_int(self.inputs_num)
        for inp in self._inputs:
            tx += inp.utxo.prevout
            tx += var_int(len(inp.redeem_script))
            tx += inp.redeem_script
            tx += le_unsigned_int.pack(inp.sequence)

        # Outputs
        tx += var_int(self.outputs_num)
        for out in self._outputs:
            tx += out.serialize()

        # @TODO: segwit data here
        tx += le_unsigned_int.pack(self.lock_time)
        return tx

    def sign_input(
        self, key: PrivateKey, sighash_types: List[SigHashType], i: int
    ):
        """
        https://github.com/qtumproject/qtum/blob/342d769cf60ccfc46c0669507dcd154988d87d4f/test/functional/test_framework/script.py#L620
        @TODO: Op_CODESEPARATOR
        """
        if i >= self.inputs_num:
            raise ValueError("i out of range")
        v_in = self._inputs[i]
        sighash_type = v_in.sighash_type or SigHash.ALL
        if sighash_type.sig_mod not in sighash_types and (
            not sighash_type & SigHash.ANYONECANPAY
            or SigHash.ANYONECANPAY in sighash_types
        ):
            raise PsbtSignException(
                f"operation sighash {repr(sighash_type)} is not allowed"
            )
        tx = copy.copy(self)
        if sighash_type.sig_mod == SigHash.NONE:
            tx._outputs = []
        elif sighash_type.sig_mod == SigHash.SINGLE:
            if self.inputs_num > self.outputs_num:
                raise PsbtSignException(
                    f"num of inputs can't exceed "
                    f"outputs for {repr(SigHash.SINGLE)}"
                )

            tx._outputs = [
                *[TxOut(value=0xFFFF_FFFF_FFFF_FFFF, redeem_script=Script())]
                * (tx.inputs_num - 1),
                tx._outputs[tx.inputs_num - 1],
            ]
            if not tx._outputs[tx.inputs_num - 1].signed:
                raise PsbtSignException("outputs should be signed first")
        else:
            if any(not t_out.signed for t_out in tx._outputs):
                raise PsbtSignException("outputs should be signed first")

        if sighash_type & SigHash.ANYONECANPAY:
            tx._inputs = [
                PsbtIn(
                    utxo=v_in.utxo,
                    sighash_type=SigHash(0),
                    sequence=v_in.sequence,
                    redeem_script=v_in.utxo.redeem_script,
                    partial_signature=[],
                )
            ]
        else:
            tx._inputs = [
                PsbtIn(
                    utxo=tx._inputs[j].utxo,
                    sighash_type=SigHash(0),
                    sequence=0,
                    redeem_script=Script(),
                    partial_signature=[],
                )
                if j != i
                else PsbtIn(
                    utxo=v_in.utxo,
                    sighash_type=SigHash(0),
                    sequence=v_in.sequence,
                    redeem_script=v_in.utxo.redeem_script,
                    partial_signature=[],
                )
                for j in range(self.inputs_num)
            ]

        to_sign = tx.serialize(include_witness=False)
        sig = key.sign_tx(to_sign, sighash_type)
        v_in.partial_signature.append(
            PartialSignature(
                pubkey=key.public_key.get_key(compressed=True), signature=sig
            )
        )
        # Lock PSBT when have PartialSigs
        if not sighash_type & SigHash.ANYONECANPAY:
            self._lock |= PsbtLock.INPUT_LOCK
        if sighash_type.sig_mod != SigHash.NONE:
            self._lock |= PsbtLock.OUTPUT_LOCK | PsbtLock.INPUT_SEQ_LOCK

    def sign_inputs(
        self, key: PrivateKey, sighash_types: List[SigHashType]
    ) -> "Psbt":
        for i in range(self.inputs_num):
            self.sign_input(key, sighash_types, i)
        return self

    def sign_output(self, key: PrivateKey, sighash_type: SigHashType, i: int):
        if sighash_type.sig_mod == SigHash.NONE:
            raise ValueError("SigHash should be specified")
        if i >= self.outputs_num:
            raise ValueError("i out of range")
        v_out = self._outputs[i]
        if v_out.signed:
            return
        pub_key = key.public_key.get_key(compressed=True)
        sender_address = hash160(pub_key)
        # Check that key is valid for signing
        script_ops = list(v_out.redeem_script)
        op_sender_index = script_ops.index(OpCode.OP_SENDER)
        if script_ops[op_sender_index - 3] == b"\x01":
            if script_ops[op_sender_index - 2] != sender_address:
                raise ValueError("sender doesn't belong to this key")
        script_code = Script.p2pkh(sender_address)

        le_unsigned_int = struct.Struct("<I")
        hash_inputs: bytes
        hash_outputs: bytes
        hash_sequence = bytes(32)

        if sighash_type & SigHash.ANYONECANPAY:
            if self.inputs_num == 0:
                raise ValueError("no inputs")
            hash_inputs = hash256(self._inputs[0].utxo.prevout)
            hash_sequence = hash256(
                le_unsigned_int.pack(self._inputs[0].sequence)
            )
        else:
            inputs = bytes()
            for inp in self._inputs:
                inputs += inp.utxo.prevout
            hash_inputs = hash256(inputs)

            if sighash_type.sig_mod != SigHash.SINGLE:
                serialize_sequence = bytes()
                for inp in self._inputs:
                    serialize_sequence += le_unsigned_int.pack(inp.sequence)
                hash_sequence = hash256(serialize_sequence)

        serialize_outputs = bytes()
        for out in (
            self._outputs
            if sighash_type.sig_mod != SigHash.SINGLE
            else [v_out]
        ):
            serialize_outputs += out.without_signature().serialize()
        hash_outputs = hash256(serialize_outputs)

        ss = bytes()
        ss += le_unsigned_int.pack(self.version)
        ss += hash_inputs
        ss += hash_sequence
        ss += v_out.serialize()
        ss += script_code.serialize()
        ss += struct.pack("<Q", v_out.value)  # Amount?
        ss += hash_outputs
        ss += le_unsigned_int.pack(self.lock_time)

        sig = key.sign_tx(ss, sighash_type)
        script_sig = Script([sig, pub_key])
        script_ops[op_sender_index - 1] = Script(
            var_int(len(script_sig)) + script_sig
        )
        v_out.redeem_script = Script(script_ops)
        # locks
        if not sighash_type & SigHash.ANYONECANPAY:
            self._lock |= PsbtLock.INPUT_LOCK
        if sighash_type.sig_mod != SigHash.SINGLE:
            self._lock |= PsbtLock.OUTPUT_LOCK | PsbtLock.INPUT_SEQ_LOCK

    def sign_outputs(
        self, key: PrivateKey, sighash_type: SigHashType
    ) -> "Psbt":
        for i in range(self.outputs_num):
            self.sign_output(key, sighash_type, i)
        return self

    def finalize_input(self, i: int) -> "Psbt":
        if i >= self.inputs_num:
            raise ValueError("i out of range")
        v_in = self._inputs[i]
        if v_in.utxo.is_p2pkh:
            sig = list(
                filter(
                    lambda s: s.hex_address in v_in.utxo.redeem_script,
                    v_in.partial_signature,
                )
            )
            if not sig:
                raise PsbtException("Input is not signed")
            v_in.redeem_script = Script([sig[0].signature, sig[0].pubkey])
        # TODO: other cases (multisig p/e)
        return self

    def finalize_inputs(self) -> "Psbt":
        for i in range(self.inputs_num):
            self.finalize_input(i)
        return self
