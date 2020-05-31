# pylint: disable=no-self-use, protected-access
import re

import pytest

import drvn.cryptography.utils as utils


class Test:
    def test_normal(self):
        hex_string = (
            "49276d206b696c6c696e6720796f757220627261696e206c696b65206120"
            "706f69736f6e6f7573206d757368726f6f6d"
        )

        results = utils.hex_string_to_base64_string(hex_string)

        expected_base64_string = (
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        )
        assert results == expected_base64_string
