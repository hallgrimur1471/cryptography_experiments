"""
Create the MT19937 stream cipher and break it
"""

import logging
import random
import time

import drvn.cryptography.mt19937 as mt19937
import drvn.cryptography.utils as utils


def run_challenge():
    recover_16_bit_seed()
    check_password_reset_token()


def recover_16_bit_seed():
    logging.info(
        "Victim's API has an encrypt function that encrypts using "
        + "MT19937 stream cipher with a 16-bit seed."
    )
    api = VictimAPI1()

    text = b"AAAAAAAAAAAA"
    ciphertext = api.encrypt(text)

    logging.info("Breaking victim's cipher ...")
    for seed in range(0, 2 ** 16 - 1):
        if seed % 1000 == 0:
            logging.info(f"{seed / (2**16 - 1) * 100:.2f} %")

        plaintext = mt19937.stream_cipher_decrypt(ciphertext, seed)

        if text in plaintext:
            logging.info(f"Victim's cipher key is: {seed}")
            return

    raise RuntimeError("Could not break victim's cipher")


def check_password_reset_token():
    api = VictimAPI2()

    logging.info("Getting a password reset token from victim's API ...")
    token = api.get_password_reset_token()

    logging.info("Waiting a bit ...")
    time.sleep(random.randint(3, 6))

    logging.info(
        "Checking if token is a product of MT19937 "
        + "seeded with unix epoch time  ..."
    )
    for seed in reversed(range(0, int(time.time()))):
        mt = mt19937.MT19937()
        mt.seed(seed)
        if mt.get_number() == token:
            logging.info(f"Token was generated using unix epoch time '{seed}'")
            return
    logging.info("Failed to determine how token was generated")


class VictimAPI1:
    def __init__(self):
        self._seed = random.randint(0, 2 ** 16 - 1)  # 16 bits

    def encrypt(self, user_input):
        prefix_len = random.randint(10, 30)
        prefix = utils.generate_random_bytes(prefix_len)
        plaintext = prefix + user_input
        return mt19937.stream_cipher_encrypt(plaintext, self._seed)


# pylint: disable=no-self-use
class VictimAPI2:
    def get_password_reset_token(self):
        # We need 32 random bits

        mt = mt19937.MT19937()
        seed = int(time.time())
        mt.seed(seed)

        random_number = mt.get_number()
        return random_number
