class Network:
    NAME: str
    COIN: str
    SCRIPT_ADDRESS: int = 0x00
    PUBKEY_ADDRESS: int = 0x00
    SECRET_KEY: int = 0x00
    EXT_PUBLIC_KEY: int = 0x00000000
    EXT_SECRET_KEY: int = 0x00000000
    BIP32_PATH: str


class QtumMainNet(Network):
    """Qtum MainNet version bytes
    Primary version bytes from:
    https://github.com/qtumproject/qtum/blob/master/src/chainparams.cpp
    """
    NAME = "Qtum Main Net"
    COIN = "QTUM"
    SCRIPT_ADDRESS = 0x32  # int(0x32) = 50
    PUBKEY_ADDRESS = 0x3A  # int(0x3A) = 58  # Used to create payment addresses
    SECRET_KEY = 0x80      # int(0x80) = 128  # Used for WIF format
    EXT_PUBLIC_KEY = 0x0488B21E  # Used to serialize public BIP32 addresses
    EXT_SECRET_KEY = 0x0488ADE4  # Used to serialize private BIP32 addresses
    BIP32_PATH = "m/44'/88'/0'/"


class QtumTestNet(Network):
    """Qtum TestNet version bytes
    Primary version bytes from:
    https://github.com/qtumproject/qtum/blob/master/src/chainparams.cpp
    """
    NAME = "Qtum Test Net"
    COIN = "QTUM"
    SCRIPT_ADDRESS = 0x6E  # int(0x6e) = 110
    PUBKEY_ADDRESS = 0x78  # int(0x78) = 120
    SECRET_KEY = 0xEF      # int(0xef) = 239
    EXT_PUBLIC_KEY = 0x043587CF
    EXT_SECRET_KEY = 0x04358394
    BIP32_PATH = "m/44'/88'/0'/"
