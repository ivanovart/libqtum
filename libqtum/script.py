from ._bignum import bn2vch
from .op_codes import OpCode
from .utils import var_int


class ScriptInvalidError(Exception):
    """Base class for Script exceptions"""

    pass


class ScriptTruncatedPushDataError(ScriptInvalidError):
    """Invalid pushdata due to truncation"""

    def __init__(self, msg, data):
        self.data = data
        super(ScriptTruncatedPushDataError, self).__init__(msg)


class Script(bytes):
    """Serialized script
    A bytes subclass, so you can use this directly whenever bytes are accepted.
    Note that this means that indexing does *not* work - you'll get an index by
    byte rather than opcode. This format was chosen for efficiency so that the
    general case would not require creating a lot of little OpCode objects.
    iter(script) however does iterate by opcode.
    """

    __slots__ = ()

    @classmethod
    def __coerce_instance(cls, other):
        # Coerce other into bytes
        if isinstance(other, OpCode):
            other = bytes([other])
        elif isinstance(other, int):
            if 0 <= other <= 16:
                other = bytes([OpCode.encode_op_n(other)])
            elif other == -1:
                other = bytes([OpCode.OP_1NEGATE])
            else:
                other = OpCode.encode_op_pushdata(bn2vch(other))
        elif isinstance(other, (bytes, bytearray)):
            other = OpCode.encode_op_pushdata(other)
        return other

    def __add__(self, other):
        # Do the coercion outside of the try block so that errors in it are
        # noticed.
        other = self.__coerce_instance(other)

        try:
            # bytes.__add__ always returns bytes instances unfortunately
            return Script(super(Script, self).__add__(other))
        except TypeError:
            raise TypeError("Can not add a %r instance to a Script" % other.__class__)

    def join(self, iterable):
        # join makes no sense for a Script()
        raise NotImplementedError

    def __new__(cls, value=b""):
        if isinstance(value, bytes) or isinstance(value, bytearray):
            return super(Script, cls).__new__(cls, value)
        else:

            def coerce_iterable(iterable):
                for instance in iterable:
                    yield cls.__coerce_instance(instance)

            # Annoyingly on both python2 and python3 bytes.join() always
            # returns a bytes instance even when subclassed.
            return super(Script, cls).__new__(cls, b"".join(coerce_iterable(value)))

    def raw_iter(self):
        """Raw iteration
        Yields tuples of (opcode, data, sop_idx) so that the different possible
        PUSHDATA encodings can be accurately distinguished, as well as
        determining the exact opcode byte indexes. (sop_idx)
        """
        i = 0
        while i < len(self):
            sop_idx = i
            opcode = self[i]
            i += 1

            if opcode > OpCode.OP_PUSHDATA4:
                yield opcode, None, sop_idx
            else:
                if opcode < OpCode.OP_PUSHDATA1:
                    pushdata_type = "PUSHDATA(%d)" % opcode
                    data_size = opcode

                elif opcode == OpCode.OP_PUSHDATA1:
                    pushdata_type = "PUSHDATA1"
                    if i >= len(self):
                        raise ScriptInvalidError("PUSHDATA1: missing data length")
                    data_size = self[i]
                    i += 1

                elif opcode == OpCode.OP_PUSHDATA2:
                    pushdata_type = "PUSHDATA2"
                    if i + 1 >= len(self):
                        raise ScriptInvalidError("PUSHDATA2: missing data length")
                    data_size = self[i] + (self[i + 1] << 8)
                    i += 2

                elif opcode == OpCode.OP_PUSHDATA4:
                    pushdata_type = "PUSHDATA4"
                    if i + 3 >= len(self):
                        raise ScriptInvalidError("PUSHDATA4: missing data length")
                    data_size = (
                        self[i]
                        + (self[i + 1] << 8)
                        + (self[i + 2] << 16)
                        + (self[i + 3] << 24)
                    )
                    i += 4
                else:
                    assert False  # shouldn't happen

                data = bytes(self[i : i + data_size])

                # Check for truncation
                if len(data) < data_size:
                    raise ScriptTruncatedPushDataError(
                        "%s: truncated data" % pushdata_type, data
                    )

                i += data_size

                yield opcode, data, sop_idx

    def __iter__(self):
        """'Cooked' iteration
        Returns either a OpCode instance, an integer, or bytes, as
        appropriate.
        See raw_iter() if you need to distinguish the different possible
        PUSHDATA encodings.
        """
        for (opcode, data, sop_idx) in self.raw_iter():
            if data is not None:
                yield data
            else:
                opcode = OpCode(opcode)

                if opcode.is_small_int():
                    yield opcode.decode_op_n()
                else:
                    yield OpCode(opcode)

    def __repr__(self):
        def _repr(o):
            if isinstance(o, bytes):
                return "x('%s')" % o.hex()
            else:
                return repr(o)

        ops = []
        i = iter(self)
        while True:
            op = None
            try:
                op = _repr(next(i))
            except ScriptTruncatedPushDataError as err:
                op = "%s...<ERROR: %s>" % (_repr(err.data), err)
                break
            except ScriptInvalidError as err:
                op = "<ERROR: %s>" % err
                break
            except StopIteration:
                break
            finally:
                if op is not None:
                    ops.append(op)

        return "Script([%s])" % ", ".join(ops)

    def get_sig_op_count(self, f_accurate):
        """Get the SigOp count.
        fAccurate - Accurately count CHECKMULTISIG, see BIP16 for details.
        Note that this is consensus-critical.
        """
        n = 0
        last_opcode = OpCode.OP_INVALIDOPCODE
        for (opcode, data, sop_idx) in self.raw_iter():
            if opcode in (OpCode.OP_CHECKSIG, OpCode.OP_CHECKSIGVERIFY):
                n += 1
            elif opcode in (OpCode.OP_CHECKMULTISIG, OpCode.OP_CHECKMULTISIGVERIFY):
                if f_accurate and (OpCode.OP_1 <= last_opcode <= OpCode.OP_16):
                    n += opcode.decode_op_n()
                else:
                    n += 20
            last_opcode = opcode
        return n

    def serialize(self):
        return var_int(len(self)) + bytes(self)

    @staticmethod
    def num(n: int):
        assert -0x7FFF_FFFF <= n <= 0x7FFF_FFFF
        if n == 0:
            return b"\x00"

        result = bytes()
        abs_n = abs(n)
        while abs_n:
            result += (abs_n & 0xFF).to_bytes(1, "big")
            abs_n >>= 8

        if result[-1] & 0x80:
            result += b"\x80" if n < 0 else b"\x00"
        elif n < 0:
            result = result[:-1] + (result[-1] | 0x80).to_bytes(1, "big")

        return result

    @classmethod
    def p2pkh(cls, address: bytes):
        assert len(address) == 20
        return cls(
            [
                OpCode.OP_DUP,
                OpCode.OP_HASH160,
                address,
                OpCode.OP_EQUALVERIFY,
                OpCode.OP_CHECKSIG,
            ]
        )


__all__ = ["Script", "ScriptInvalidError", "ScriptTruncatedPushDataError"]
