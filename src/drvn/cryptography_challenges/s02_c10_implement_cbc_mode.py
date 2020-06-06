"""
Implement CBC mode
"""
import logging
import base64

import drvn.cryptography.utils as utils
import drvn.cryptography_challenges._resources as resources


def run_challenge():
    logging.info("Running challenge 10 ...")

    key = b"YELLOW SUBMARINE"
    ciphertext = base64.b64decode(
        resources.get_contents("c10_implement_cbc_mode.in")
    )
    block_size = 16
    iv = bytes([0] * block_size)

    plaintext = utils.decrypt_aes_cbc(
        ciphertext, key, iv, block_size=block_size
    )

    logging.info(f"\n**** Ciphertext ****\n{ciphertext[0:100]}...")
    logging.info(f"\n**** Initialization vector ****\n{iv}")
    logging.info(f"\n**** Plaintext ****\n{plaintext.decode()}")
