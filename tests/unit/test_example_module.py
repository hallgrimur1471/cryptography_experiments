# pylint: disable=no-self-use, protected-access
import pytest

import svarmi.cryptography.example_module as example_module


class TestExampleFunction:
    def test_normal(self):
        assert example_module.example_public_function() == "Example return value"
