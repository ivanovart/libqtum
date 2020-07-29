from abc import ABCMeta, abstractmethod
from typing import List, Union

from .tx import UTXO


class Qtum(metaclass=ABCMeta):

    @abstractmethod
    def get_address_utxo(self, address: str) -> List[UTXO]:
        raise NotImplemented()

    @abstractmethod
    def send_tx(self, raw_tx: Union[bytes, str]) -> str:
        """
        returns transaction id
        """
        raise NotImplemented()
