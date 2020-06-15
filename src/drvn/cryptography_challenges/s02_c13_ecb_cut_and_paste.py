"""
ECB cut-and-paste
"""

import drvn.cryptography.aes as aes


def run_challenge():
    pass
    # 1. learn the ciphertext of the following block:
    # com&uid=10&role=
    #
    # 2. learn:
    # admin\x11\x11\x11\x11....
    #
    # now combine the ciphertext blocks


class VictimAPI:
    def __init__(self):
        self._users = set()
        self._key = aes.generate_random_aes_key()

    def create_user_profile_ciphertext_for(self, email):
        """
        Creates profile ciphertext for {email} with role=user
        """
        profile = profile_for(email)
        profile_serialised = serialise_cookie(profile)
        profile_plaintext = profile_serialised.encode()
        profile_ciphertext = aes.encrypt_ebc(profile_plaintext, self._key)
        return profile_ciphertext

    def add_profile_to_system(self, profile_ciphertext):
        """
        Add profile to system from ciphertext
        """
        profile_plaintext = aes.decrypt_ebc(profile_ciphertext, self._key)
        profile_serialised = profile_plaintext.decode()
        profile = deserialise_cookie(profile_serialised)
        self._users.add(profile)

    # pylint: disable=no-self-use
    def _decrypt_profile_ciphertext(self, profile_ciphertext):
        serialised_profile = profile_ciphertext  # TODO: implement ...
        return serialised_profile


def profile_for(email):
    if "&" in email or "=" in email:
        raise ValueError(f"email may not contain the characters '&' or '='")

    cookie_string = f"email={email}&uid=10&role=user"

    profile_cookie = deserialise_cookie(cookie_string)

    return profile_cookie


def serialise_cookie(cookie):
    cookie_string = ""
    for key, value in cookie.items():
        cookie_string += f"{key}={value}&"
    cookie_string = cookie_string[0:-1]
    return cookie_string


def deserialise_cookie(cookie_string):
    cookie_parts = cookie_string.split("&")

    cookie = dict()
    for part in cookie_parts:
        key, value = part.split("=")
        try:
            value = int(value)
        except ValueError:
            pass
        cookie[key] = value

    return cookie
