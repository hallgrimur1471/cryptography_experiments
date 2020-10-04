"""
Break "random access read/write" AES CTR
"""

import logging
import random
import base64

import drvn.cryptography.aes as aes
import drvn.cryptography_challenges._resources as resources


def run_challenge():
    api = VictimAPI()

    ciphertext = api.get_original_ciphertext()
    ciphertext = ciphertext[
        0:20
    ]  # speed it up a bit (should maybe optimize later)
    logging.info("Got ciphertext from victim:\n{}...".format(ciphertext[0:10]))

    logging.info("Decrypting ciphertext ...")
    plaintext = aes.decycrypt_editable_ctr_encryption(ciphertext, api.edit)

    logging.info("Recovered plaintext:\n{}".format(plaintext))


class VictimAPI:
    def __init__(self):
        self._key = aes.generate_random_aes_key()
        self._nonce = random.randint(0, 2 ** 64 - 1)

    def edit(self, ciphertext, offset, newtext):
        # This method could be optimized a whole lot ...
        # Encrypting and decrypting the whole thing is not always necessary.
        # It depends on offset and len(newtext).
        plaintext = bytearray(
            aes.decrypt_ctr(ciphertext, self._key, self._nonce)
        )
        for i, byte in enumerate(newtext):
            plaintext[offset + i] = byte
        new_ciphertext = aes.encrypt_ctr(plaintext, self._key, self._nonce)
        return new_ciphertext

    def get_original_ciphertext(self):
        plaintext = self._get_plaintext()
        ciphertext = aes.encrypt_ctr(plaintext, self._key, self._nonce)
        return ciphertext

    # pylint: disable=no-self-use
    def _get_plaintext(self):
        ciphertext = base64.b64decode(
            "".join(
                list(
                    filter(
                        None,
                        resources.get_contents(
                            "c25_break_random_access_read_write_aes_ctr.in"
                        ).split("\n"),
                    )
                )
            )
        )
        key = b"YELLOW SUBMARINE"
        plaintext = aes.decrypt_ecb(ciphertext, key, remove_padding=True)
        return plaintext
