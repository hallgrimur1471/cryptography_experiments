# pylint:disable=unnecessary-lambda
"""
Break repeating-key XOR test
"""

import base64
from functools import reduce
import logging

import drvn.cryptography.xor as xor
import drvn.cryptography_challenges._resources as resources


def run_challenge():
    logging.info("Running challenge 6 ...")

    data = resources.get_contents("c06_break_repeating_key_xor.in")
    cipher = list(map(lambda line: line.rstrip(), data.split("\n")))
    cipher = list(map(lambda line: base64.b64decode(line), cipher))
    cipher = reduce(lambda acc, elem: acc + elem, cipher, bytearray())

    decryptionResult = xor.decrypt(cipher)
    logging.info(f"********* DATA ********\n{decryptionResult.data.decode()}")
    logging.info(f"********* KEY ********\n{decryptionResult.key.decode()}")
