#!/usr/bin/env python3

"""
Single-byte XOR decryption test
"""

from cryptolib import xor

def main():
    cipher = bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c7"
                           "8373e783a393b3736")
    r = xor.single_byte_decryption(cipher, num_results=1)[0]
    print("data: ", r.data)
    print("key: ", chr(r.key))

if __name__ == "__main__":
    main()
