"""
ECB/CBC detection oracle
"""
import logging
import base64

import drvn.cryptography.aes as aes
import drvn.cryptography_challenges._resources as resources


def run_challenge():
    logging.info("Running challenge 11 ...")

    plaintext = base64.b64decode(
        resources.get_contents("c11_ecb_cbc_detection_oracle.in")
    )
    logging.info(f"Plaintext: {plaintext[0:20]}...")

    for i in range(0, 10):
        logging.info(f"Iteration {i+1} ...")
        ciphertext = aes.encryption_oracle(plaintext)
        logging.info(f"Cipher: {ciphertext[0:20]}...")
        mode = aes.detect_mode(ciphertext)
        if mode == "ecb":
            logging.info("Plaintext was encrypted in ECB mode")
        else:
            logging.info("Plaintext was encrypted in CBC mode")
