"""
Implementation test of repeating key XOR
"""

import binascii
import logging

import drvn.cryptography.xor as xor


def run_challenge():
    logging.info("Running challenge 5 ...")

    data = (
        b"Burning 'em, if you ain't quick and nimble\n"
        + b"I go crazy when I hear a cymbal"
    )
    key = b"ICE"

    logging.info(f"Encrypting {data}")
    logging.info(f"With key {key} ...")
    cipher = xor.encrypt(data, key)

    logging.info(f"Resulting cipher: '{binascii.hexlify(cipher).decode()}'")
