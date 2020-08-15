"""
ECB cut-and-paste
"""

import logging

import drvn.cryptography.aes as aes
import drvn.cryptography.utils as utils


def run_challenge():
    victim_api = VictimAPI()

    # TODO: figure out using code from challenge 14 that plaintext
    # being encrypted is like this:
    # 'email=foo@bar.com&uid=10&role=user'

    # 1. learn the ciphertext of the following block:
    # 'com&uid=10&role='

    # email=hey@gmail.com&uid=10&role=
    # 12345678911111111234567891111111
    #          0123456         0123456

    profile_ciphertext = victim_api.create_user_profile_ciphertext_for(
        "hey@gmail.com"
    )
    utils.print_ciphertext_blocks(profile_ciphertext)
    block_0 = utils.get_block(profile_ciphertext, 0)
    block_1 = utils.get_block(profile_ciphertext, 1)
    print("block_0:", block_0.hex(), b"email=hey@gmail.")
    print("block_1:", block_1.hex(), b"com&uid=10&role=")

    # 2. learn:
    # admin\x0b\x0b\x0b\x0b....

    # email=hey@gmail.adminbbbbbbbbbbb
    # 12345678911111111234567891111111
    #          0123456         0123456

    profile_ciphertext = victim_api.create_user_profile_ciphertext_for(
        "hey@gmail.admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
    )
    utils.print_ciphertext_blocks(profile_ciphertext)
    block_2 = utils.get_block(profile_ciphertext, 1)
    print(
        "block_2:",
        block_2.hex(),
        b"admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
    )

    forged_ciphertext = block_0 + block_1 + block_2
    print("forged_ciphertext:")
    utils.print_ciphertext_blocks(forged_ciphertext)

    # normal usage
    email = "foo@bar.com"
    logging.info(f"Creating user {email} ...")
    profile_ciphertext = victim_api.create_user_profile_ciphertext_for(email)
    victim_api.add_profile_to_system(profile_ciphertext)
    if victim_api.is_admin(email):
        logging.info(f"'{email}' is admin")
    else:
        logging.info(f"'{email}' is not admin")

    # create admin using forged_ciphertext
    email = "hey@gmail.com"
    logging.info(f"Maliciously creating user '{email}' ...")
    victim_api.add_profile_to_system(forged_ciphertext)
    if victim_api.is_admin(email):
        logging.info(f"'{email}' is admin")
    else:
        logging.info(f"'{email}' is not admin")


class VictimAPI:
    def __init__(self):
        self._profiles = dict()
        self._key = bytes.fromhex("62e76e2458801855bdafe4924b819821")

    def create_user_profile_ciphertext_for(self, email):
        """
        Creates profile ciphertext for {email} with role=user
        """
        profile = profile_for(email)
        profile_serialised = serialise_cookie(profile)
        profile_plaintext = profile_serialised.encode()
        profile_ciphertext = aes.encrypt_ecb(profile_plaintext, self._key)
        return profile_ciphertext

    def add_profile_to_system(self, profile_ciphertext):
        """
        Add profile to system from ciphertext
        """
        profile_plaintext = aes.decrypt_ebc(profile_ciphertext, self._key)
        profile_serialised = profile_plaintext.decode()
        profile = deserialise_cookie(profile_serialised)

        email = profile["email"]
        self._profiles[email] = profile

    def is_admin(self, email):
        return self._profiles[email]["role"] == "admin"

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
