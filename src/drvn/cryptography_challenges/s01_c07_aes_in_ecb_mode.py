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

    # read ciphertext from file
    ciphertext = resources.get_contents("c07_aes_in_ecb_mode.in")
    ciphertext = list(map(lambda line: line.rstrip(), ciphertext.split("\n")))
    ciphertext = list(map(lambda line: base64.b64decode(line), ciphertext))
    ciphertext = reduce(lambda acc, elem: acc + elem, ciphertext, bytearray())
    ciphertext = bytes(ciphertext)

    logging.info(f"******** CIPHERTEXT ********\n{ciphertext}")

    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    logging.info(f"******** PLAINTEXT ********\n{plaintext}")
