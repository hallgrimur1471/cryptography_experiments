#!/usr/bin/env python3

import base64
from functools import reduce
from os.path import dirname, join, realpath

# TODO: replace with "crytography" package on PyPi
from Crypto.Cipher import AES
from Crypto import Random

key = b"YELLOW SUBMARINE"
iv = Random.new().read(AES.block_size)
aes = AES.new(key, AES.MODE_ECB, iv)

# read cipher from file
with open(join(dirname(realpath(__file__)), "c07_aes_in_ecb_mode.in")) as f:
    cipher = list(map(lambda line: line.rstrip(), f.readlines()))
    cipher = list(map(lambda line: base64.b64decode(line), cipher))
    cipher = reduce(lambda acc, elem: acc + elem, cipher, bytearray())
    cipher = bytes(cipher)
print(cipher)
print("************")

data = aes.decrypt(cipher)
print(data)
