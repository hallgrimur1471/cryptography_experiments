"""
CTR bitflipping
"""

import logging

import drvn.cryptography.aes as aes
import drvn.cryptography.utils as utils


def run_challenge():
    victim_api = VictimAPI()

    request = victim_api.create_non_admin_request(b"BBBBB?admin?true")
    print("request ciphertext:")
    utils.print_ciphertext_blocks(request)

    p1 = 32 + 5
    p2 = 32 + 11
    admin_request_forged = False
    for x in range(256):
        for y in range(256):
            r = bytearray(request)
            r[p1] = x
            r[p2] = y
            request = bytes(r)

            forged_block = utils.get_block(request, 2)
            logging.debug(f"Trying forged block 2: {forged_block.hex()}")

            success = victim_api.is_admin_request(request)

            if success:
                admin_request_forged = True
                break
        if admin_request_forged:
            break

    if admin_request_forged:
        logging.info(
            "Admin request successfully forged after "
            + f"{victim_api.num_is_admin_requests} calls to "
            + "victim_api.is_admin_request(request).\n"
            + f"request:\n{request}"
        )
    else:
        logging.info("Failed to forge an admin request")


# pylint: disable=no-self-use
class VictimAPI:
    def __init__(self):
        self.num_is_admin_requests = 0

        self._key = aes.generate_random_aes_key()
        self._nonce = aes.generate_random_nonce()

    def create_non_admin_request(self, user_input):
        prefix = "comment1=cooking%20MCs;userdata=".encode()
        safe_user_input = self._quote_out_forbidden_characters(user_input)
        suffix = ";comment2=%20like%20a%20pound%20of%20bacon".encode()

        request_plaintext = prefix + safe_user_input + suffix

        print("request_plaintext:")
        utils.print_plaintext_blocks(request_plaintext)

        request_ciphertext = aes.encrypt_ctr(
            request_plaintext, self._key, self._nonce
        )
        return request_ciphertext

    def is_admin_request(self, request_ciphertext):
        self.num_is_admin_requests += 1
        request_data = self._decrypt_request(request_ciphertext)
        return (b"admin" in request_data) and request_data[b"admin"] == b"true"

    def _decrypt_request(self, request_ciphertext):
        plaintext = aes.decrypt_ctr(request_ciphertext, self._key, self._nonce)
        data = self._parse_request(plaintext)
        return data

    def _parse_request(self, request):
        data = dict()
        parts = request.split(b";")
        for part in parts:
            splits = part.split(b"=")
            key = splits[0]
            value = b"".join(splits[1:])
            data[key] = value
        return data

    def _quote_out_forbidden_characters(self, user_input):
        quoted_user_input = user_input.replace(b";", b"%3b")
        quoted_user_input = quoted_user_input.replace(b"=", b"%3d")
        return quoted_user_input
