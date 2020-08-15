"""
PKCS#7 padding validation
"""

import logging

import drvn.cryptography.utils as utils


def run_challenge():
    plaintext = "ICE ICE BABY\x04\x04\x04\x04".encode()
    plaintext_no_padding = utils.remove_pkcs7_padding(plaintext)
    logging.info(
        f"The string {plaintext} has a valid padding, and produces "
        + f"the result {plaintext_no_padding}."
    )

    plaintext = "ICE ICE BABY\x05\x05\x05\x05".encode()
    try:
        plaintext_no_padding = utils.remove_pkcs7_padding(plaintext)
    except ValueError:
        logging.info(f"The string {plaintext} does not have a valid padding")
    else:
        raise RuntimeError("Padding validation should have raised a ValueError")

    plaintext = "ICE ICE BABY\x01\x02\x03\x04".encode()
    try:
        plaintext_no_padding = utils.remove_pkcs7_padding(plaintext)
    except ValueError:
        logging.info(f"The string {plaintext} does not have a valid padding")
    else:
        raise RuntimeError("Padding validation should have raised a ValueError")
