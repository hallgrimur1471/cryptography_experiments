"""
Implement a SHA1-1 keyed MAC
"""

import logging

import drvn.cryptography.utils as utils
import drvn.cryptography.sha as sha


def run_challenge():
    api = VictimAPI()
    msg, mac = api.get_authenticated_message()

    assert api.is_authenticated(msg, mac)
    logging.info(f"Message {msg} is authenticated with MAC {mac.hex()}")

    tampered_msg = msg + b";admin=true"

    logging.info(f"Trying to authenticate message {tampered_msg} ...")
    assert not api.is_authenticated(tampered_msg, mac)
    logging.debug(f"Trying MAC {mac.hex()} ...")
    for _ in range(100):
        mac = utils.generate_random_bytes(20)
        logging.debug(f"Trying MAC {mac.hex()} ...")
        assert not api.is_authenticated(tampered_msg, mac)

    logging.info(
        f"Failed to authenticate message {tampered_msg} (challenge success)"
    )


class VictimAPI:
    def __init__(self):
        self._key = b"very secret key"

    def is_authenticated(self, msg, mac):
        correct_mac = self._authenticate(msg)
        return mac == correct_mac

    def get_authenticated_message(self):
        msg = b"comment1=cooking%20MCs;userid=10;admin=false"
        msg = b"hello\n"
        mac = self._authenticate(msg)
        return msg, mac

    # pylint: disable=no-self-use
    def _authenticate(self, msg):
        mac = sha.sha1(msg)
        return mac
