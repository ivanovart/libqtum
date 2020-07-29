import pytest

from libqtum import PrivateKey, QtumMainNet, QtumTestNet
from libqtum.key import IncompatibleNetworkException, PublicKey
from .utils import does_not_raise


@pytest.mark.parametrize('wif,network,expected_private_key,expected_err', (
        (
                'L4L2JAfmtmpkCZaxz2XTaQLCmXUUgxpGsk6kQDo8vfMYfyUnDYXh',
                QtumMainNet,
                'd41bead49c4f29ccdc51a3a7cb68c70f29f4b3718b853ce4ea3ab78be9efaad4',
                does_not_raise()
        ),
        (
                'L4L2JAfmtmpkCZaxz2XTaQLCmXUUgxpGsk6kQDo8vfMYfyUnDYXX',
                QtumMainNet,
                '',
                pytest.raises(ValueError)
        ),
        (
                'cUh1m5fdKqX1N14ENSLawiqGPkmtMQuxwnFDWeFeRn1YviXty88U',
                QtumTestNet,
                'd41bead49c4f29ccdc51a3a7cb68c70f29f4b3718b853ce4ea3ab78be9efaad4',
                does_not_raise()
        ),
        (
                'L4L2JAfmtmpkCZaxz2XTaQLCmXUUgxpGsk6kQDo8vfMYfyUnDYXh',
                QtumTestNet,
                'd41bead49c4f29ccdc51a3a7cb68c70f29f4b3718b853ce4ea3ab78be9efaad4',
                pytest.raises(IncompatibleNetworkException)
        )
))
def test_import_from_wif(wif, network, expected_private_key, expected_err):
    with expected_err:
        key = PrivateKey.from_wif(wif, network)
        assert key.get_key().hex() == expected_private_key
        assert key.export_to_wif() == wif


key1 = PrivateKey.from_hex_key('d41bead49c4f29ccdc51a3a7cb68c70f29f4b3718b853ce4ea3ab78be9efaad4', QtumMainNet)
key2 = PrivateKey.from_hex_key(b'd41bead49c4f29ccdc51a3a7cb68c70f29f4b3718b853ce4ea3ab78be9efaad4', QtumTestNet)


@pytest.mark.parametrize('key,expected', (
        (key1, 'QcHSMSmcpehH7Jg9pevnHmBjCXvFgz1SWQ'),
        (key2, 'qZEqQBFUqqRbpBKXLfaYMY4WDotjoCuEV2')
))
def test_generate_address(key, expected):
    assert key.public_key.to_address(compressed=True) == expected


@pytest.mark.parametrize('k1,k2,expected', (
        (key1, key2, False),
        (key1, key1, True),
        (key2, key2, True),
        (key2, PrivateKey.from_hex_key('d41bead49c4f29ccdc51a3a7cb68c70f29f4b3718b853ce4ea3ab78be9efaad4'), True)
))
def test_compare_keys(k1, k2, expected):
    assert (k1 == k2) == expected


@pytest.mark.parametrize('public_hex,network,address,expected_err', (
        (
            '03b5f4caa482cbf91fe45ab28eb106ffa23c959f4967ccbdf38bda728cee761bb6',
            QtumMainNet,
            'QcHSMSmcpehH7Jg9pevnHmBjCXvFgz1SWQ',
            does_not_raise()
        ),
))
def test_public_from_hex_to_addr(public_hex, network, address, expected_err):
    with expected_err:
        key = PublicKey.from_hex_key(public_hex, network)
        assert key.to_address() == address
