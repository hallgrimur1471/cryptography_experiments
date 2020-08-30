# pylint: disable=no-self-use, protected-access

import pytest

import drvn.cryptography.mt19937 as mt19937


class TestMT19937:
    def test_refues_invalid_bit_sizes(self):
        with pytest.raises(ValueError):
            mt19937.MT19937(bits=31)

        with pytest.raises(ValueError):
            mt19937.MT19937(bits=128)

    def test_accept_valid_bit_sizes(self):
        mt19937.MT19937(bits=32)
        mt19937.MT19937(bits=64)

    def test_creates_correct_masks_for_32_bit(self):
        mt = mt19937.MT19937(bits=32)

        assert mt.lower_mask == int("1111111111111111111111111111111", 2)
        assert mt.upper_mask == int("10000000000000000000000000000000", 2)

    def test_creates_correct_masks_for_64_bit(self):
        mt = mt19937.MT19937(bits=64)

        assert mt.lower_mask == int("1111111111111111111111111111111", 2)
        assert mt.upper_mask == int(
            "1111111111111111111111111111111110000000000000000000000000000000",
            2,
        )

    def test_generates_correct_sequence(self):
        seed = 1234
        mt = mt19937.MT19937(bits=64)
        mt.seed(seed)

        nums = [mt.get_number() for _ in range(5)]

        assert nums == [
            51958938797758274,
            14487919992931548568,
            3259042221570911683,
            9131545258602306973,
            14790547962871044865,
        ]
