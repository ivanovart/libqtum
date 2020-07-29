from typing import List, Mapping, Optional, Union

from requests import Response, Session

from .qtum import Qtum
from .script import Script
from .tx import UTXO


class QtumInfoException(Exception):
    pass


class QtumInfo(Qtum, Session):
    """https://github.com/qtumproject/qtuminfo-api"""

    def __init__(self, base_url: str):
        self.base_url = base_url
        super().__init__()

    def request(self, method: str, url: str, **kwargs) -> Response:
        return super().request(method, self.base_url + url, **kwargs)

    def get_address_utxo(self, address: str) -> List[UTXO]:
        r = self.get(f"/address/{address}/utxo")
        r.raise_for_status()
        raw_utxo = r.json()

        def _serializer(utxo: Mapping) -> UTXO:
            return UTXO(
                transaction_id=utxo.get("transactionId"),
                output_index=utxo.get("outputIndex"),
                redeem_script=Script.fromhex(utxo.get("scriptPubKey", "0")),
                value=int(utxo.get("value", 0)),
                is_stake=utxo.get("isStake", False),
                block_height=utxo.get("blockHeight"),
                confirmations=utxo.get("confirmations"),
            )

        return [_serializer(utxo) for utxo in raw_utxo]

    def send_tx(self, raw_tx: Union[bytes, str]) -> str:
        if isinstance(raw_tx, bytes):
            raw_tx = raw_tx.hex()

        r = self.post(f"/tx/send", data={"rawtx": raw_tx})
        r.raise_for_status()
        response = r.json()
        if response.get("id"):
            return response["id"]
        err_msg = response.get("message")
        raise QtumInfoException(err_msg)

    def call_contract(
        self, contract: str, data: str, sender: Optional[str] = None
    ) -> Optional[str]:
        payload = {"data": data}
        if sender:
            payload["sender"] = sender
        r = self.get(f"/contract/{contract}/call", params=payload)
        r.raise_for_status()
        response = r.json()
        return response.get("executionResult", {}).get("output")
