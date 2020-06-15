# pylint:disable=unnecessary-lambda
"""
Decrypt AES in ECB mode using known key
"""

import logging
import base64
from functools import reduce

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import drvn.cryptography_challenges._resources as resources


def run_challenge():
    key = b"YELLOW SUBMARINE"
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()

    # read cipher from file
    cipher = resources.get_contents("c07_aes_in_ecb_mode.in")
    cipher = list(map(lambda line: line.rstrip(), cipher.split("\n")))
    cipher = list(map(lambda line: base64.b64decode(line), cipher))
    cipher = reduce(lambda acc, elem: acc + elem, cipher, bytearray())
    cipher = bytes(cipher)

    logging.info(f"******** CIPHER ********\n{cipher}")

    data = decryptor.update(cipher) + decryptor.finalize()

    logging.info(f"******** DATA ********\n{data}")
