# pylint:disable=raise-missing-from
"""
Recover the key from CBC with IV=key
"""

import logging

import drvn.cryptography.aes as aes
import drvn.cryptography.utils as utils


def run_challenge():
    victim_api = VictimAPI()

    request = victim_api.create_non_admin_request(b"somedata")
    print("request ciphertext:")
    utils.print_ciphertext_blocks(request)

    c1 = request[0:16]

    if False:  # pylint:disable=using-constant-test
        forged_request = c1 + (b"\x00" * 16) + c1
        victim_api.is_admin_request(forged_request)

    # The above request resulted in:
    # RuntimeError: Can't decode plaintext
    # b'comment1=cooking\x17\x14s!\xc0r\xd8r\x81\x90\xc2\xe2\xeb\xdf\x08\xe9
    # .*!!*9Tbh!".9  "'

    p1_ = b"comment1=cooking"
    p3_ = b'.*!!*9Tbh!".9  "'
    iv = utils.fixed_xor(p1_, p3_)
    logging.info(f"Determined that the IV is {iv}")
    key = iv
    logging.info(f"If the cipher is using IV=key then the key is {key}")
    return

    r = request
    for i in range(0, 256):
        r = bytearray(r)
        r[32 + 2] = i
        r = bytes(r)
        print(victim_api.is_admin_request(r))


# pylint: disable=no-self-use
class VictimAPI:
    def __init__(self):
        self.num_is_admin_requests = 0

        self._key = b"MELLOW SUBMARINE"
        self._iv = self._key

    def create_non_admin_request(self, user_input):
        prefix = "comment1=cooking%20MCs;userdata=".encode()
        safe_user_input = self._quote_out_forbidden_characters(user_input)
        suffix = ";comment2=%20like%20a%20pound%20of%20bacon".encode()

        request_plaintext = prefix + safe_user_input + suffix

        print("request_plaintext:")
        utils.print_plaintext_blocks(request_plaintext)

        request_ciphertext = aes.encrypt_cbc(
            request_plaintext, self._key, self._iv
        )
        return request_ciphertext

    def is_admin_request(self, request_ciphertext):
        self.num_is_admin_requests += 1
        request_data = self._decrypt_request(request_ciphertext)
        return ("admin" in request_data) and request_data["admin"] == "true"

    def _decrypt_request(self, request_ciphertext):
        plaintext = aes.decrypt_cbc(
            request_ciphertext, self._key, self._iv, remove_padding=False
        )
        try:
            plaintext_str = plaintext.decode("ascii")
        except UnicodeDecodeError:
            raise RuntimeError(f"Can't decode plaintext {plaintext}")
        data = self._parse_request(plaintext_str)
        return data

    def _parse_request(self, request):
        data = dict()
        parts = request.split(";")
        for part in parts:
            splits = part.split("=")
            key = splits[0]
            value = "".join(splits[1:])
            data[key] = value
        return data

    def _quote_out_forbidden_characters(self, user_input):
        quoted_user_input = user_input.replace(b";", b"%3b")
        quoted_user_input = quoted_user_input.replace(b"=", b"%3d")
        return quoted_user_input
