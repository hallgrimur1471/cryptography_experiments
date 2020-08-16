"""
The CBC padding oracle attack
"""

import logging
import base64
import random

import drvn.cryptography.aes as aes
import drvn.cryptography.utils as utils


def run_challenge():
    victim_api = VictimAPI()
    ciphertext = victim_api.get_ciphertext()

    ciphertexts = set()
    logging.info("Sniffing for ciphertexts ...")
    for _ in range(100):
        ciphertext = victim_api.get_ciphertext()
        ciphertexts.add(bytes(ciphertext))

    for ciphertext in ciphertexts:
        if aes.detect_mode(ciphertext) == "ecb":
            raise RuntimeError(
                "It seems like the target cipher is encrypting in ECB mode, "
                + "so decrypting the ciphertext using a CBC padding oracle is "
                + "not possible."
            )

    ciphertexts = list(ciphertexts)
    plaintexts = []

    logging.info(
        "Decrypting the ciphertexts using CBC padding oracle attack ..."
    )
    padding_oracle = victim_api.consume
    for ciphertext in ciphertexts:
        plaintext = aes.decrypt_cbc_ciphertext_using_padding_oracle(
            ciphertext, padding_oracle
        )
        plaintexts.append(plaintext)

    msg = "The sniffed ciphertexts:\n"
    for ciphertext in ciphertexts:
        msg += f"{ciphertext.hex()}\n"
    msg += f"\nWere decrypted using {victim_api.num_consume_calls} calls to "
    msg += "the padding oracle, the first block of the plaintexts are "
    msg += "unknown (?) so the resulting plaintexts are:\n"
    for plaintext in plaintexts:
        msg += f"{plaintext}\n"
    logging.info(f"\n{msg}")


# pylint: disable=no-self-use
class VictimAPI:
    def __init__(self):
        self.num_consume_calls = 0

        self._key = aes.generate_random_aes_key()
        self._iv = aes.generate_random_aes_key()

        self._secrets = [
            base64.b64decode(txt)
            for txt in [
                "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
                "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYX"
                + "JlIHB1bXBpbic=",
                "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2"
                + "luZw==",
                "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
                "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYm"
                + "xl",
                "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
                "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
                "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
                "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
                "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
            ]
        ]

    def get_ciphertext(self):
        random_secret = random.choice(self._secrets)
        ciphertext = aes.encrypt_cbc(
            random_secret, self._key, self._iv, add_padding=True
        )
        return ciphertext

    def consume(self, ciphertext):
        """
        Returns true if resulting plaintext has a valid padding, false otherwise
        """
        self.num_consume_calls += 1
        plaintext_padded = aes.decrypt_cbc(
            ciphertext, self._key, self._iv, remove_padding=False
        )
        return utils.is_valid_pkcs7_padding(plaintext_padded)
