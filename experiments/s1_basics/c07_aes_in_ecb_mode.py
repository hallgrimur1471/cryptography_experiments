#!/usr/bin/env python3

import os
import base64
from functools import reduce
from os.path import dirname, join, realpath

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

key = b"YELLOW SUBMARINE"
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
decryptor = cipher.decryptor()

# read cipher from file
with open(join(dirname(realpath(__file__)), "c07_aes_in_ecb_mode.in")) as f:
    cipher = list(map(lambda line: line.rstrip(), f.readlines()))
    cipher = list(map(lambda line: base64.b64decode(line), cipher))
    cipher = reduce(lambda acc, elem: acc + elem, cipher, bytearray())
    cipher = bytes(cipher)
print(cipher)
print("************")

data = decryptor.update(cipher) + decryptor.finalize()
print(data)
