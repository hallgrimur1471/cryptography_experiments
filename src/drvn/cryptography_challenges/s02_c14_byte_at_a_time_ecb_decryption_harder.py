"""
Byte at a time ECB decryption (Harder)

AES-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
"""

import random
import base64
import logging

import drvn.cryptography.aes as aes
import drvn.cryptography.utils as utils


def run_challenge():
    victim_api = VictimAPI()
    encrypt_func = victim_api.encrypt

    unknown_plaintext = aes.decrypt_ecb_encryption_with_injectable_plaintext(
        encrypt_func
    )

    logging.info(
        f"With {victim_api.num_encrypt_func_calls} calls to Victim's "
        + "encryption API 'unknown_plaintext' was found:\n"
        + unknown_plaintext.decode()
    )


class VictimAPI:
    def __init__(self):
        self.num_encrypt_func_calls = 0
        self._unknown_key = base64.b64decode("o6Jq3C2UKEprJA3bgrpE7A==")

        num_random_bytes = random.randint(0, 500)
        self._random_prefix = utils.generate_random_bytes(num_random_bytes)

    def encrypt(self, user_input):
        unknown_plaintext = base64.b64decode(
            "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGR"
            + "vd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllc"
            + "yBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpE"
            + "aWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
        )
        plaintext_to_encrypt = (
            self._random_prefix + user_input + unknown_plaintext
        )

        ciphertext = aes.encrypt_ecb(plaintext_to_encrypt, self._unknown_key)

        self.num_encrypt_func_calls += 1
        return ciphertext
