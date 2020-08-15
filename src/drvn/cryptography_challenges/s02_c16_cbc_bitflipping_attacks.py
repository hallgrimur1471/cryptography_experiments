"""
CBC bitflipping attacks

comment1=cooking%20MCs;userdata=asdfasdf;comment2=%20like%20a%20pound%20of%20bacon
"""

import base64
import logging

import drvn.cryptography.aes as aes
import drvn.cryptography.utils as utils


def run_challenge():
    victim_api = VictimAPI()

    request = victim_api.create_non_admin_request(
        b"BBBBBBBBBBBBBBBB" + b"BBBBB?admin?true"
    )
    print("request ciphertext:")
    utils.print_ciphertext_blocks(request)

    # modifying changing bytes in position (32 + 5) and (32 + 11)
    # in ciphertext will scramble block at 32 but only modify bytes
    # (48 + 5) and (48 + 11) in plaintext block at 48
    #
    # if we can change (48 + 5) to ';' and (48 + 11) to '=' then we have
    # forged an ;admin=true; tuple in the request
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

            success = False
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
            + "victim_api.is_admin_request(request)"
        )
    else:
        logging.info("Failed to forge an admin request")


# pylint: disable=no-self-use
class VictimAPI:
    def __init__(self):
        self.num_is_admin_requests = 0

        self._key = aes.generate_random_aes_key()
        self._iv = aes.generate_random_aes_key()

        self._key = base64.b64decode(
            b"opNuv3OoX64xdS0JtVWEUw=="
        )  # TODO: remove
        self._iv = base64.b64decode(b"AcMn0ZKTRUOq28+KY9vBtA==")  # TODO: remove

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
        return (b"admin" in request_data) and request_data[b"admin"] == b"true"

    def _decrypt_request(self, request_ciphertext):
        plaintext = aes.decrypt_cbc(request_ciphertext, self._key, self._iv)
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
