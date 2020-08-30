"""
Break fixed-nonce CTR statistically
"""

import base64
import logging

import drvn.cryptography.aes as aes
import drvn.cryptography_challenges._resources as resources


def run_challenge():
    victim_api = VictimAPI()
    ciphertexts = victim_api.get_ciphertexts()
    plaintexts = aes.decrypt_ctr_ciphertexts_with_fixed_nonce(ciphertexts)

    for ciphertext, plaintext in zip(ciphertexts, plaintexts):
        logging.info(
            f"\nThe ciphertext:\n{ciphertext}\nwas decrypted to:\n{plaintext}\n"
        )

    msg = ""
    for ciphertext in ciphertexts:
        msg += f"{base64.b64encode(ciphertext)}\n"
    logging.info(f"ciphertexts:\n{msg}")

    msg = ""
    for plaintext in plaintexts:
        msg += f"{str(bytes(plaintext))}\n"
    logging.info(f"plaintexts:\n{msg}")


# pylint: disable=no-self-use
class VictimAPI:
    def __init__(self):
        self._nonce = 0
        self._key = aes.generate_random_aes_key()

        self._ciphertexts = None

    def get_ciphertexts(self):
        if not self._ciphertexts:
            self._produce_ciphertexts()
        return self._ciphertexts

    def _produce_ciphertexts(self):
        plaintexts = self._get_plaintexts()
        self._ciphertexts = [
            aes.encrypt_ctr(txt, self._key, self._nonce) for txt in plaintexts
        ]

    def _get_plaintexts(self):
        return [
            base64.b64decode(txt)
            for txt in list(
                filter(
                    None,
                    resources.get_contents(
                        "c20_break_fixed_nonce_ctr_statistically.in"
                    ).split("\n"),
                )
            )
        ]
