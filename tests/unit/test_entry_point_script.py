# pylint: disable=no-self-use, protected-access
import re

import pytest

import drvn.cryptography_challenges._entry_point_script as script


class TestGetChallengeModuleName:
    def test_normal(self):
        challenge_module = script._get_challenge_module_name(2)

        assert re.match("s01_c02_.*", challenge_module)

    def test_non_existing(self):
        with pytest.raises(ValueError):
            script._get_challenge_module_name(1040)
