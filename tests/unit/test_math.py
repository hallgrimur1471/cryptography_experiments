# pylint: disable=no-self-use, protected-access

import pytest

import drvn.cryptography.math as math


class TestModularExponentiation:
    def test_normal(self):
        assert math.modular_exponentiation(5, 3, 13) == 8
        assert math.modular_exponentiation(10, 0, 17) == 1
        assert math.modular_exponentiation(0, 16, 18) == 0
