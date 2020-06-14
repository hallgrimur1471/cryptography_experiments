"""
"""
import logging
import base64

import drvn.cryptography.aes as aes


def run_challenge():
    logging.info("Running challenge 13 ...")

    # 1. learn the ciphertext of the following block:
    # com&uid=10&role=
    #
    # 2. learn:
    # admin\x11\x11\x11\x11....
    #
    # now combine the ciphertext blocks
