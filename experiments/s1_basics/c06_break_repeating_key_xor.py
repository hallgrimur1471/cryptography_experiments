#!/usr/bin/env python3

"""
Break repeating-key XOR test
"""

import base64
from functools import reduce
from os.path import dirname, join, realpath

from cryptolib import xor

def main():
    root_folder = dirname(realpath(__file__))
    with open(join(root_folder, "c06_break_repeating_key_xor.in")) \
            as f:
        cipher = list(map(lambda line: line.rstrip(), f.readlines()))
        cipher = list(map(lambda line: base64.b64decode(line), cipher))
        cipher = reduce(lambda acc, elem: acc+elem, cipher, bytearray())

    decryptionResult = xor.decrypt(cipher)
    print("\n ******** data ********\n")
    print(decryptionResult.data.decode())
    print(" ******** key ********\n")
    print(decryptionResult.key.decode())

if __name__ == "__main__":
    main()
