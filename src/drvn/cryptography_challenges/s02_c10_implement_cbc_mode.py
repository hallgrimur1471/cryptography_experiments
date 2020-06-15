"""
Implement CBC mode
"""
import logging
import base64

import drvn.cryptography.aes as aes
import drvn.cryptography_challenges._resources as resources


def run_challenge():
    key = b"YELLOW SUBMARINE"
    ciphertext = base64.b64decode(
        resources.get_contents("c10_implement_cbc_mode.in")
    )
    block_size = 128
    block_size_bytes = block_size // 8
    iv = bytes([0] * block_size_bytes)

    plaintext = aes.decrypt_cbc(
        ciphertext, key, iv, block_size=block_size, remove_padding=False
    )

    logging.info(f"\n**** Ciphertext ****\n{ciphertext[0:100]}...")
    logging.info(f"\n**** Initialization vector ****\n{iv}")
    logging.info(f"\n**** Plaintext ****\n{plaintext.decode()}")
