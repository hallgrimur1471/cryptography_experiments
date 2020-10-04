"""
Break a SHA-1 keyed MAC using length extension
"""

import logging
from dataclasses import dataclass

import drvn.cryptography.utils as utils
import drvn.cryptography.sha as sha


@dataclass
class Request:
    data: str
    mac: str

    def __repr__(self):
        return (
            "Request(\n"
            + f"    data={self.data},\n"
            + f"    mac={self.mac.hex()}\n"
            + ")"
        )


def run_challenge():
    api = VictimAPI()

    user_data = "foo"

    logging.info(f"Getting request for user_data '{user_data}' ...")
    request = api.get_request(user_data)

    logging.info(f"Got request: {request}")

    if api.is_valid_request(request):
        logging.info("It is a valid, authenticated request")

    forged_suffix = b";admin=true"
    forged_data = request.data + forged_suffix

    forged_request = request
    forged_request.data = forged_data

    if not api.is_valid_request(forged_request):
        logging.info(
            f"Forged request {forged_request} is NOT "
            + "a valid, authenticated request ... "
        )

    logging.info(
        "Calculating MAC for forged request using length extension attack ..."
    )

    forged_data, forged_mac = sha.sha1_length_extension_attack(
        request.data,
        request.mac,
        forged_suffix,
        lambda forged_data, forged_mac: api.is_valid_request(
            Request(forged_data, forged_mac)
        ),
    )
    forged_request = Request(forged_data, forged_mac)
    if api.is_valid_request(forged_request):
        logging.info(
            f"Successfully forged a valid, authenticated request: {forged_data}"
        )
    else:
        raise RuntimeError("Failed to forge a valid, authenticated request")


# pylint:disable=no-self-use
class VictimAPI:
    def __init__(self):
        self._key = b"very secret key"

    def get_request(self, user_data: str):
        data = self._get_request_data(user_data)
        mac = self._authenticate(data)
        return Request(data, mac)

    def is_valid_request(self, request: Request):
        correct_mac = self._authenticate(request.data)
        return request.mac == correct_mac

    def _get_request_data(self, user_data):
        return (
            f"comment1=cooking%20MCs;userdata={user_data};"
            + "comment2=%20like%20a%20pound%20of%20bacon"
        ).encode()

    def _authenticate(self, data):
        mac = sha.sha1(self._key + data)
        return mac
