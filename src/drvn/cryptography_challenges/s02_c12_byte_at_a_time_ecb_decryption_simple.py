"""
Decrypt string encrypted by AES (ECB) with uknown key by
repeatetly encrypting the uknown string using that same unknown key
but you can prepend to the string before it gets encrypted.
"""
import logging
import base64

import drvn.cryptography.aes as aes


def run_challenge():
    logging.info("Running challenge 12 ...")

    victim_encryption_api = VictimEncryptionAPI()
    aes.decrypt_ecb_encryption_with_prependable_plaintext(
        victim_encryption_api.encrypt
    )


class VictimEncryptionAPI:
    def __init__(self):
        self._unknown_key = aes.generate_random_aes_key()

    def encrypt(self, prefix):
        unknown_plaintext = base64.b64decode(
            "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGR"
            + "vd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllc"
            + "yBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpE"
            + "aWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
        )
        plaintext_to_encrypt = prefix + unknown_plaintext

        ciphertext = aes.encrypt_ebc(plaintext_to_encrypt, self._unknown_key)

        return ciphertext
