#!/usr/bin/env python3

"""
Implementation test of repeating key XOR
"""

import binascii

from cryptolib import xor

def main():
    data = b"Burning 'em, if you ain't quick and nimble\n" \
            + b"I go crazy when I hear a cymbal"
    key = b"ICE"

    cipher = xor.encrypt(data, key)
    ciphertext = binascii.hexlify(cipher).decode()
    print(ciphertext)

    assert ciphertext == (
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63"
        "343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b202763"
        "0c692b20283165286326302e27282f")

if __name__ == "__main__":
    main()
