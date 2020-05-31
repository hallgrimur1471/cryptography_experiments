"""
Convert hex to base64 test
"""

import logging
import base64

import drvn.cryptography.utils as utils


def run_challenge():
    logging.info("Running challenge 1 ...")
    hex_string = (
        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120"
        "706f69736f6e6f7573206d757368726f6f6d"
    )
    base64_string = utils.hex_string_to_base64_string(hex_string)
    logging.info(f"Hex string: '{hex_string}'")
    logging.info(f"Base64 string: '{base64_string}'")
