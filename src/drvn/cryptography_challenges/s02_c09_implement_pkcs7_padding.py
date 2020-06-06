"""
Implement PKCS#7 padding
"""
import logging

import drvn.cryptography.utils as utils

# About pkcs#7 padding:
# https://tools.ietf.org/html/rfc2315#section-10.3


def run_challenge():
    logging.info("Running challenge 9 ...")

    plaintext = "YELLOW_SUBMARINE".encode()

    plaintext_padded = utils.add_pkcs7_padding(plaintext, block_size=20)

    logging.info(f"Plaintext: {plaintext}")
    logging.info(f"Plaintext padded to 20 bytes: {plaintext_padded}")
