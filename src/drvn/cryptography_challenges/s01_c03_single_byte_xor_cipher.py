"""
Single-byte XOR decryption test
"""

import logging

import drvn.cryptography.xor as xor


def run_challenge():
    cipher = bytes.fromhex(
        "1b37373331363f78151b7f2b783431333d78397828372d363c7"
        "8373e783a393b3736"
    )
    r = xor.single_byte_decryption(cipher, num_results=1)[0]
    logging.info(f"data: {r.data}")
    logging.info(f"key: {chr(r.key)}")
