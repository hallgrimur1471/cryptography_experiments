"""
Detect AES in ECB mode
"""
import logging

import drvn.cryptography.aes as aes
import drvn.cryptography_challenges._resources as resources


def run_challenge():
    logging.info("Running challenge 8 ...")

    ciphertexts = get_ciphertexts()
    for i, ciphertext in enumerate(ciphertexts):
        mode = aes.detect_mode(ciphertext)
        if mode == "ecb":
            logging.info(
                f"line {i+1} was likely encrypted in ECB mode "
                + "since the ciphertext contains reccurring 16 byte blocks "
            )


def get_ciphertexts():
    ciphertexts = resources.get_contents("c08_detect_aes_in_ecb_mode.in")
    ciphertexts = ciphertexts.split("\n")
    ciphertexts = [line.rstrip() for line in ciphertexts]
    return ciphertexts
