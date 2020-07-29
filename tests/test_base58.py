import pytest

from libqtum import base58
from .utils import does_not_raise


@pytest.mark.parametrize('v,expected_value,expected_err',  (
        ('HelloWorld', b'54uZdajEaDdN6F', does_not_raise()),
        (b'HelloWorld', b'54uZdajEaDdN6F', does_not_raise()),
        ('D3ADB0D4', b'CQdPxL6ytwV', does_not_raise()),
        (type('test_bytes', (bytes,), {})(b'D3ADB0D4'), b'CQdPxL6ytwV', does_not_raise()),
        ('Привет', b'', pytest.raises(ValueError)),
        (None, b'', pytest.raises(TypeError)),
    ))
def test_b58encode(v, expected_value, expected_err):
    with expected_err:
        assert base58.b58encode(v) == expected_value


@pytest.mark.parametrize('v,expected_value,expected_err',  (
        (b'54uZdajEaDdN6F', b'HelloWorld', does_not_raise()),
        ('54uZdajEaDdN6F', b'HelloWorld', does_not_raise()),
        ('C7t1bx5byEq', b'ByMeBeer', does_not_raise()),
        (type('test_bytes', (bytes,), {})(b'r4j1UTw7anDX'), b'BuyMeBeer', does_not_raise()),
        ('Привет', b'', pytest.raises(ValueError)),
        ('ÂBCDÊ', b'', pytest.raises(ValueError)),
        ('!#', b'', pytest.raises(ValueError)),
        (None, b'', pytest.raises(TypeError)),
    ))
def test_b58decode(v, expected_value, expected_err):
    with expected_err:
        assert base58.b58decode(v) == expected_value
