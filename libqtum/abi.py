from typing import cast

from eth_abi import decode_abi, encode_abi
from eth_utils import function_abi_to_4byte_selector


def eth_abi_encode(abi: dict, args: list) -> bytes:
    """
    >> abi = {"constant":True,"inputs":[{"name":"","type":"address"}],
"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"payable":False,"stateMutability":"view","type":"function"}
    >> eth_abi_encode(abi, ['9d3d4cc1986d81f9109f2b091b7732e7d9bcf63b'])
    >> '70a082310000000000000000000000009d3d4cc1986d81f9109f2b091b7732e7d9bcf63b'
    ## address must be lower case
    Source: https://github.com/qtumproject/qtum-electrum/blob/241426fbb7e14be0eb129ab2841840d30285e369/electrum/bitcoin.py#L770
    """
    if not abi:
        return b"\x00"
    types = [inp["type"] for inp in abi.get("inputs", [])]
    if abi.get("name"):
        result = function_abi_to_4byte_selector(abi) + encode_abi(types, args)
    else:
        result = encode_abi(types, args)
    return cast(bytes, result)


def eth_output_decode(abi, result):
    types = list([x["type"] for x in abi.get("outputs", [])])
    try:
        if isinstance(result, dict):
            output = decode_abi(
                types, bytes.fromhex(result["executionResult"]["output"])
            )
        else:
            output = decode_abi(types, bytes.fromhex(result))
    except:
        return None
    return output
