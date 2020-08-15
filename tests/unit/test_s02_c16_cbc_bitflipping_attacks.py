# pylint: disable=no-self-use, protected-access

import drvn.cryptography_challenges.s02_c16_cbc_bitflipping_attacks as challenge_module


class TestParseRequest:
    def test_normal(self):
        request = (
            b"comment1=cooking%20MCs;userdata="
            + b"asdf"
            + b";comment2=%20like%20a%20pound%20of%20bacon"
        )

        victim_api = challenge_module.VictimAPI()
        data = victim_api._parse_request(request)

        assert b"comment1" in data
        assert data[b"comment1"] == b"cooking%20MCs"

    def test_contains_admin_tuple(self):
        request = (
            b"comment1=cooking%20MCs;userdata="
            + b"asdf;admin=true"
            + b";comment2=%20like%20a%20pound%20of%20bacon"
        )

        victim_api = challenge_module.VictimAPI()
        data = victim_api._parse_request(request)

        assert b"admin" in data
        assert data[b"admin"] == b"true"
