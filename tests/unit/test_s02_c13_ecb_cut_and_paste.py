# pylint: disable=no-self-use, protected-access
import pytest

import drvn.cryptography_challenges.s02_c13_ecb_cut_and_paste as challenge_module


class TestProfileFor:
    def test_normal(self):
        email = "foo@bar.com"

        profile = challenge_module.profile_for(email)

        assert profile["email"] == "foo@bar.com"
        assert profile["uid"] == 10
        assert profile["role"] == "user"

    def test_error_if_malicious_email(self):
        email = "foo@bar.com&admin=true"

        with pytest.raises(ValueError):
            challenge_module.profile_for(email)


class TestSerialiseCookie:
    def test_normal(self):
        cookie = {"foo": "bar", "baz": "qux", "zap": "zazzle"}

        cookie_string = challenge_module.serialise_cookie(cookie)

        assert cookie_string == "foo=bar&baz=qux&zap=zazzle"


class TestDeserialiseCookie:
    def test_normal(self):
        cookie_string = "foo=bar&baz=qux&zap=zazzle"

        cookie = challenge_module.deserialise_cookie(cookie_string)

        assert cookie["foo"] == "bar"
        assert cookie["baz"] == "qux"
        assert cookie["zap"] == "zazzle"
